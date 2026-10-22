// Package netim provides Netim DNS hosting through its REST API 3.0.
//
// A Provider opens one Netim session on its first call, with
// synchronous processing, and shares it between goroutines. Netim allows
// a reseller only a few sessions at once, so call Close when done.
package netim

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/rest"
)

// DefaultBaseURL is the production REST API 3.0 endpoint. Netim's OT&E
// (test) environment is reached with dnsprovider.WithBaseURL.
const DefaultBaseURL = "https://rest.netim.com/3.0"

// DefaultRequestTimeout bounds requests when no HTTP client is supplied.
const DefaultRequestTimeout = 30 * time.Second

// RequestsPerMinute is a conservative local allowance, per reseller and
// endpoint; Netim publishes no request rate.
const RequestsPerMinute = 60

// Factory credential field names.
const (
	FieldID     = "id"
	FieldSecret = "secret"
)

// Config is one reseller account's API credentials.
type Config struct {
	// ID is the reseller ID.
	ID string
	// Secret is the reseller's API secret.
	Secret string
}

// Provider is one Netim reseller account.
type Provider struct {
	dnsprovider.UnimplementedZoneWrites
	dnsprovider.UnimplementedZoneDetails
	dnsprovider.UnimplementedBatch
	dnsprovider.UnimplementedTenants

	id      string
	basic   string // the Basic credentials, base64(id:secret)
	secrets []string
	base    string
	client  *http.Client
	log     *slog.Logger
	limit   rest.Limiter
	session *session
}

// New builds a Provider without sending a request.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.ID) == "" || strings.TrimSpace(cfg.Secret) == "" {
		return nil, errors.New("netim: reseller ID and secret are required")
	}

	o := dnsprovider.NewOptions(opts...)

	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}

	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultRequestTimeout}
	}

	basic := base64.StdEncoding.EncodeToString([]byte(cfg.ID + ":" + cfg.Secret))
	identity := sha256.Sum256([]byte(cfg.ID + "\x00" + cfg.Secret))

	return &Provider{
		id: cfg.ID, basic: basic, secrets: []string{cfg.Secret, basic},
		base: base, client: client, log: o.Logger,
		limit:   rest.AccountPerMinute(fmt.Sprintf("netim %s %x", base, identity), RequestsPerMinute),
		session: &session{sem: make(chan struct{}, 1)},
	}, nil
}

// Factory builds a Provider from the reseller ID and API secret, both
// secret fields.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{{Name: FieldID, Label: "Reseller ID", Secret: true}, {Name: FieldSecret, Label: "API secret", Secret: true}}

	return fields.Factory("netim", fs, traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{ID: m[FieldID], Secret: m[FieldSecret]}, opts...)
	})
}

// traits are the Traits of every Provider, which Traits and Factory
// report. Records carry Netim's other record options, such as a TLSA's
// certificateUsage, as their raw JSON, read-only. The Provider is a
// registrar adapter (CapDSRegistrar) for domains on other DNS servers.
var traits = dnsprovider.Traits{
	Capabilities: []dnsprovider.Capability{dnsprovider.CapDSRegistrar},
	TTL:          dnsprovider.DefaultTTLRange,
	Extras:       []dnsprovider.ExtraSpec{{Key: dnsprovider.ExtraOther, Label: "Record options", Kind: dnsprovider.ExtraJSON}},
}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}
