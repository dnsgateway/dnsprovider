package dnsprovider

import (
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
)

// Options are what the consumer owns when it builds a Provider: the HTTP
// client, the API endpoint and the logger. Each provider package's New
// takes them as Option values.
type Options struct {
	// HTTPClient sends the requests; nil means the adapter's own client,
	// with its request timeout.
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
}

// Factory builds one Provider type from a plain field map.
type Factory struct {
	// Fields name every field the Provider takes, in form order.
	Fields []Field
	// New builds the Provider from the fields, without a network call. A
	// missing required field and a field not in Fields are errors.
	New func(fields map[string]string, opts ...Option) (Provider, error)
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
