package dnsprovider

import (
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
)

// Options are what the consumer owns when it builds a Provider: the HTTP
// client, the API endpoint and the logger. Each provider package's New
// takes them as Option values.
type Options struct {
	// HTTPClient sends the requests; nil means the adapter's own client,
	// with its request timeout. A consumer's client keeps its own
	// timeouts: no adapter adds its request timeout to it.
	HTTPClient *http.Client
	// BaseURL is the API endpoint, for tests and sandboxes; empty means
	// the Provider's production API.
	BaseURL string
	// Logger receives the adapter's diagnostics; NewOptions never leaves
	// it nil.
	Logger *slog.Logger
}

// Option sets one of the Options.
type Option func(*Options)

// WithHTTPClient makes the Provider send its requests with c.
func WithHTTPClient(c *http.Client) Option {
	return func(o *Options) { o.HTTPClient = c }
}

// WithBaseURL points the Provider at another API endpoint, such as an
// httptest server or the Provider's sandbox.
func WithBaseURL(u string) Option {
	return func(o *Options) { o.BaseURL = u }
}

// WithLogger gives the Provider a logger; without it the adapter logs
// nothing.
func WithLogger(l *slog.Logger) Option {
	return func(o *Options) { o.Logger = l }
}

// NewOptions applies opts in order. It is for adapters' New functions.
func NewOptions(opts ...Option) Options {
	var o Options

	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}

	return o
}

// Field is one credential or setting a Provider is built from, for a
// consumer that builds its forms and stores from Fields alone.
type Field struct {
	// Name is the key in the field map, e.g. "token" or "client_ip".
	Name string
	// Label is for people, e.g. "API token".
	Label string
	// Secret marks a field to hide on screen and keep sealed.
	Secret bool
	// Tenant marks the field holding the ID of the Tenant the Provider
	// acts within, one of those its TenantLister lists. A consumer that
	// picks the Tenant sets it.
	Tenant bool
	// Default makes the field optional: New fills it in when the field
	// is missing or empty. With Choices set, it is one of them.
	Default string
	// Choices, when set, are the only values the field takes, for a form
	// to offer as a picker. New refuses any other non-empty value.
	Choices []string
}

// Factory builds one Provider type from a plain field map.
type Factory struct {
	// Fields name every field the Provider takes, in form order.
	Fields []Field
	// New builds the Provider from the fields, without a network call. It
	// fills in a missing field that has a Default. A missing required
	// field, a field not in Fields and a value not among its field's
	// Choices are errors.
	New func(fields map[string]string, opts ...Option) (Provider, error)
	// Capabilities are the supported Zone writes every Provider New builds
	// declares through Capabilities, available before credentials are known.
	// Support does not imply permission or a selected Tenant.
	Capabilities []Capability
	// TTL is the TTLRange of every Provider New builds, as TTLRangeOf
	// reports it, for a consumer that knows only the Provider type. The
	// zero TTLRange stands for DefaultTTLRange; read it through
	// Factory.TTLRange.
	TTL TTLRange
	// Extras are the Record Extras every Provider New builds reads, and
	// which of them it takes on write, for a consumer that checks or
	// offers them knowing only the Provider type. A Provider that sets no
	// extras declares none.
	Extras []ExtraSpec
}

// ExtraSpec describes one Record extra a Provider reads.
type ExtraSpec struct {
	// Key is the key in Record.Extras, e.g. "proxied"; ExtraOther stands
	// for every key no other entry names.
	Key string
	// Label is for people, e.g. "Proxied".
	Label string
	// Kind is how the value reads.
	Kind ExtraKind
	// Writable marks an extra the Provider writes as given. A write
	// keeps any other extra as the Provider holds it: the Provider leaves
	// it as it is, or refuses a write that changes it.
	Writable bool
	// Types are the Record types that carry the extra; none means every
	// type.
	Types []string
}

// ProxiedExtra returns the ExtraSpec a Factory declares for the
// ExtraProxied extra of a Provider that proxies Records of types.
func ProxiedExtra(types ...string) ExtraSpec {
	return ExtraSpec{Key: ExtraProxied, Label: "Proxied", Kind: ExtraBool, Writable: true, Types: slices.Clone(types)}
}

// AppliesTo reports whether Records of type typ carry the extra.
func (s ExtraSpec) AppliesTo(typ string) bool {
	return len(s.Types) == 0 || slices.ContainsFunc(s.Types, func(t string) bool { return strings.EqualFold(t, typ) })
}

// ExtraKind is how a Record extra's value reads.
type ExtraKind string

// The kinds of Record extra.
const (
	// ExtraBool is "true" or "false".
	ExtraBool ExtraKind = "bool"
	// ExtraString is plain text.
	ExtraString ExtraKind = "string"
	// ExtraJSON is a JSON value, such as an array of tags.
	ExtraJSON ExtraKind = "json"
)

// ExtraOther is the ExtraSpec key standing for every key no other entry
// of a Factory names, for a Provider that passes through the fields of
// its API's records that the adapter does not model.
const ExtraOther = "*"

// Extra returns the ExtraSpec f declares for the Record extra key: its
// own entry, else the ExtraOther entry. It reports false when f declares
// neither.
func (f Factory) Extra(key string) (ExtraSpec, bool) {
	var other *ExtraSpec

	for i, s := range f.Extras {
		switch s.Key {
		case key:
			return s, true
		case ExtraOther:
			other = &f.Extras[i]
		}
	}

	if other != nil {
		return *other, true
	}

	return ExtraSpec{}, false
}

// CheckExtras reports an error when r carries a Record extra f does not
// declare for r's type, or a bool one (ExtraBool) whose value is not
// "true" or "false". It does not check which extras a write may
// change: that takes the Record as last read.
func (f Factory) CheckExtras(r Record) error {
	for _, key := range slices.Sorted(maps.Keys(r.Extras)) {
		s, ok := f.Extra(key)
		if !ok {
			return fmt.Errorf("Record extra %q is not one the Provider reads", key)
		}

		if !s.AppliesTo(r.Type) {
			return fmt.Errorf("Record extra %q is not one the Provider reads on %s Records", key, r.Type)
		}

		if v := r.Extras[key]; s.Kind == ExtraBool && v != "true" && v != "false" {
			return fmt.Errorf("Record extra %q is %q, not true or false", key, v)
		}
	}

	return nil
}

// ProxiableTypes returns the Record types f's Providers can proxy, as
// ProxiableTypesOf reports them: the Types of its ExtraProxied entry,
// none without one.
func (f Factory) ProxiableTypes() []string {
	for _, s := range f.Extras {
		if s.Key == ExtraProxied {
			return slices.Clone(s.Types)
		}
	}

	return nil
}

// TTLRange returns the TTLs f's Providers take: f.TTL, or DefaultTTLRange
// when f leaves it zero.
func (f Factory) TTLRange() TTLRange {
	if f.TTL == (TTLRange{}) {
		return DefaultTTLRange
	}

	return f.TTL
}

// Capability names a supported Zone write declared by a Provider or its Factory.
type Capability string

// The capabilities a Factory declares.
const (
	// CapZoneCreator declares support for Onboarding zone names.
	CapZoneCreator Capability = "ZoneCreator"
	// CapZoneUpdater declares support for changing Zone settings.
	CapZoneUpdater Capability = "ZoneUpdater"
	// CapZoneDeleter declares support for Offboarding Zones.
	CapZoneDeleter Capability = "ZoneDeleter"
)

// Can reports whether f declares its Providers support c.
func (f Factory) Can(c Capability) bool {
	return slices.Contains(f.Capabilities, c)
}

// Registry maps a Provider type, such as "cloudflare", to its Factory.
type Registry map[string]Factory

// Types returns the registered Provider types, sorted.
func (r Registry) Types() []string {
	return slices.Sorted(maps.Keys(r))
}

// New builds a Provider of type typ from its fields.
func (r Registry) New(typ string, fields map[string]string, opts ...Option) (Provider, error) {
	f, ok := r[typ]
	if !ok || f.New == nil {
		return nil, fmt.Errorf("unknown Provider type %q", typ)
	}

	return f.New(fields, opts...)
}
