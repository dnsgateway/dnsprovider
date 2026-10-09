// Package vultr implements the Vultr API v2 DNS service: the DNS Domains
// of the API key's Account are its Zones, and their Records are written
// one by one, by native ID.
package vultr

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/rest"
	"golang.org/x/time/rate"
)

const (
	// DefaultBaseURL is the production API v2 endpoint.
	DefaultBaseURL = "https://api.vultr.com/v2"
	// DefaultRequestTimeout bounds each request of the adapter's own client.
	DefaultRequestTimeout = 30 * time.Second
	// FieldAPIKey is the Factory field holding the API key.
	FieldAPIKey = "api_key"

	// callsPerSecond stays within the published limit of 30 requests a
	// second per originating IP address.
	callsPerSecond = 20
)

// Nameservers are the nameservers Vultr serves every DNS Domain from.
var Nameservers = []string{"ns1.vultr.com", "ns2.vultr.com"}

// Config holds a Vultr API key: the Account's key, or a user's.
type Config struct{ APIKey string }

// Factory builds the adapter from the field map without contacting Vultr.
func Factory() dnsprovider.Factory {
	return fields.Factory("vultr", []dnsprovider.Field{{Name: FieldAPIKey, Label: "API key", Secret: true}},
		func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
			return New(Config{APIKey: m[FieldAPIKey]}, opts...)
		})
}

// Provider is one Vultr Account, reached with its API key.
type Provider struct {
	key, baseURL string
	client       *http.Client
	limit        *rate.Limiter
	log          *slog.Logger
}

var _ dnsprovider.Provider = (*Provider)(nil)

// New validates the configuration locally; Account proves remote access.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.APIKey) == "" || strings.ContainsAny(cfg.APIKey, " \t\r\n") {
		return nil, errors.New("vultr: a valid API key is required")
	}

	o := dnsprovider.NewOptions(opts...)

	endpoint := strings.TrimRight(o.BaseURL, "/")
	if endpoint == "" {
		endpoint = DefaultBaseURL
	}

	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultRequestTimeout}
	}

	return &Provider{key: cfg.APIKey, baseURL: endpoint, client: client, log: o.Logger, limit: endpointLimit(endpoint)}, nil
}

// limits are the endpoints' limiters. Vultr counts requests per
// originating IP address, not per key, so every Provider of an endpoint
// shares one.
var limits = struct {
	sync.Mutex
	m map[[32]byte]*rate.Limiter
}{m: map[[32]byte]*rate.Limiter{}}

func endpointLimit(endpoint string) *rate.Limiter {
	id := sha256.Sum256([]byte(endpoint))

	limits.Lock()
	defer limits.Unlock()

	l, ok := limits.m[id]
	if !ok {
		l = rate.NewLimiter(callsPerSecond, 1)
		limits.m[id] = l
	}

	return l
}

func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "vultr", BaseURL: p.baseURL, HTTP: p.client, Limit: p.limit, Log: p.log,
		Auth:   func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+p.key) },
		Decode: p.apiError,
	}
}

// apiError decodes Vultr's error body, {"error", "status"}. 401 is an
// invalid key or a call from an address the key's access control does not
// allow, 403 a user without the permission: both match ErrUnauthorized.
func (p *Provider) apiError(res *http.Response, body []byte) error {
	var payload struct {
		Error string `json:"error"`
	}

	_ = json.Unmarshal(body, &payload)

	e := &dnsprovider.APIError{Provider: "vultr", StatusCode: res.StatusCode}
	if msg := strings.TrimSpace(payload.Error); msg != "" {
		e.Messages = append(e.Messages, p.redact(msg))
	}

	return e
}

func (p *Provider) redact(s string) string { return strings.ReplaceAll(s, p.key, "[redacted]") }

// Account reads the key's own Account, which proves the key works even
// with no DNS Domains. Vultr's answer names no Account ID: the Tenant is
// named by the Account's name or email alone.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var answer struct {
		Account *struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"account"`
	}

	var raw []byte
	if err := p.api().Do(ctx, http.MethodGet, "/account", nil, nil, &raw); err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	if json.Unmarshal(raw, &answer) != nil || answer.Account == nil {
		return dnsprovider.AccountInfo{}, errors.New("vultr: malformed Account answer")
	}

	name := strings.TrimSpace(answer.Account.Name)
	if name == "" {
		name = strings.TrimSpace(answer.Account.Email)
	}

	return dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{Name: name}, Nameservers: append([]string(nil), Nameservers...)}, nil
}

// unconfirmed marks an error after a write was sent whose outcome is not
// known: a lost, failed-server or malformed answer.
func unconfirmed(operation string, err error) error {
	if err == nil {
		return nil
	}

	var apiErr *dnsprovider.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
		return err
	}

	return fmt.Errorf("vultr: Record %s outcome is unconfirmed; re-read Records before retrying: %w", operation, err)
}
