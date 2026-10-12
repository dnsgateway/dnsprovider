// Package digitalocean implements the DigitalOcean API v2 DNS service: the
// Domains of the token's Account are its Zones, and their Domain Records
// are written one by one, by native ID.
package digitalocean

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/rest"
)

const (
	// DefaultBaseURL is the production API v2 endpoint.
	DefaultBaseURL = "https://api.digitalocean.com/v2"
	// DefaultRequestTimeout bounds each request of the adapter's own client.
	DefaultRequestTimeout = 30 * time.Second
	// FieldToken is the Factory field holding the API token.
	FieldToken = "token"

	// callsPerMinute stays within both published limits: 250 requests a
	// minute and 5,000 an hour per token.
	callsPerMinute = 80
)

// Nameservers are the nameservers DigitalOcean serves every Domain from.
var Nameservers = []string{"ns1.digitalocean.com", "ns2.digitalocean.com", "ns3.digitalocean.com"}

// Config holds a DigitalOcean API token: a personal access token or an
// OAuth token.
type Config struct{ Token string }

// Factory builds the adapter from the field map without contacting
// DigitalOcean.
func Factory() dnsprovider.Factory {
	return fields.Factory("digitalocean", []dnsprovider.Field{{Name: FieldToken, Label: "API token", Secret: true}},
		traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
			return New(Config{Token: m[FieldToken]}, opts...)
		})
}

// traits are the Traits of every Provider, which Traits and Factory
// report.
var traits = dnsprovider.Traits{}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}

// Provider is one DigitalOcean Account, reached with its token.
type Provider struct {
	dnsprovider.UnimplementedZoneWrites
	dnsprovider.UnimplementedZoneDetails

	token, baseURL string
	client         *http.Client
	limit          *rest.Window
	log            *slog.Logger
}

var _ dnsprovider.Provider = (*Provider)(nil)

// New validates the configuration locally; Account proves remote access.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.Token) == "" || strings.ContainsAny(cfg.Token, " \t\r\n") {
		return nil, errors.New("digitalocean: a valid API token is required")
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

	hash := sha256.Sum256([]byte(cfg.Token))

	return &Provider{
		token: cfg.Token, baseURL: endpoint, client: client, log: o.Logger,
		limit: rest.AccountPerMinute("digitalocean "+endpoint+" "+hex.EncodeToString(hash[:]), callsPerMinute),
	}, nil
}

func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "digitalocean", BaseURL: p.baseURL, HTTP: p.client, Limit: p.limit, Log: p.log,
		Auth:    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+p.token) },
		Secrets: []string{p.token},
		Decode:  p.apiError,
	}
}

// apiError decodes DigitalOcean's error body, {"id", "message",
// "request_id"}. A 429 without Retry-After waits until ratelimit-reset.
func (p *Provider) apiError(res *http.Response, body []byte) error {
	var payload struct {
		ID        string `json:"id"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}

	_ = json.Unmarshal(body, &payload)

	e := &dnsprovider.APIError{Provider: "digitalocean", StatusCode: res.StatusCode}

	msg := strings.TrimSpace(strings.Join(nonEmpty(payload.ID, payload.Message), ": "))
	if msg != "" {
		e.Messages = append(e.Messages, msg)
	}

	if payload.RequestID != "" {
		e.Messages = append(e.Messages, "request "+payload.RequestID)
	}

	switch {
	case res.StatusCode == http.StatusConflict:
		e.Kind = dnsprovider.ErrConflict
	case res.StatusCode == http.StatusTooManyRequests || payload.ID == "too_many_requests":
		e.Kind = dnsprovider.ErrRateLimited
	}

	if e.Kind == dnsprovider.ErrRateLimited {
		e.RetryAfter = rest.RetryAfter(res.Header.Get("Retry-After"), time.Now())
		if e.RetryAfter == 0 {
			if reset, err := strconv.ParseInt(res.Header.Get("Ratelimit-Reset"), 10, 64); err == nil {
				e.RetryAfter = max(time.Until(time.Unix(reset, 0)).Round(time.Second), 0)
			}
		}
	}

	return e
}

func nonEmpty(s ...string) []string {
	var out []string

	for _, v := range s {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}

	return out
}

// Account reads the token's own Account, which needs the account:read
// scope only: it proves the token works even with no Domains. The Tenant
// is the token's team when the answer names one, else the Account itself.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var answer struct {
		Account *struct {
			UUID  string `json:"uuid"`
			Name  string `json:"name"`
			Email string `json:"email"`
			Team  *struct {
				UUID string `json:"uuid"`
				Name string `json:"name"`
			} `json:"team"`
		} `json:"account"`
	}

	if err := p.api().Do(ctx, http.MethodGet, "/account", nil, nil, &answer); err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	a := answer.Account
	if a == nil || a.UUID == "" {
		return dnsprovider.AccountInfo{}, errors.New("digitalocean: malformed Account answer")
	}

	tenant := dnsprovider.Tenant{ID: a.UUID, Name: firstOf(a.Name, a.Email)}
	if a.Team != nil && a.Team.UUID != "" {
		tenant = dnsprovider.Tenant{ID: a.Team.UUID, Name: a.Team.Name}
	}

	return dnsprovider.AccountInfo{Tenant: tenant, Nameservers: append([]string(nil), Nameservers...)}, nil
}

func firstOf(s ...string) string {
	if v := nonEmpty(s...); len(v) > 0 {
		return v[0]
	}

	return ""
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

	return fmt.Errorf("digitalocean: Record %s outcome is unconfirmed; re-read Records before retrying: %w", operation, err)
}
