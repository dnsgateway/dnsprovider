// Package hetzner implements project-scoped DNS in the Hetzner Cloud API.
package hetzner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	// DefaultBaseURL is the current Cloud API, not the legacy DNS API.
	DefaultBaseURL = "https://api.hetzner.cloud/v1"
	// DefaultRequestTimeout bounds requests when no client is supplied.
	DefaultRequestTimeout = 30 * time.Second
	// FieldToken holds the secret project API token.
	FieldToken = "token"
	// ExtraComment is the provider's comment on this value.
	ExtraComment = "comment"
	// ExtraLabels is the JSON object of RRset labels, read-only.
	ExtraLabels = "labels"
	// ExtraProtected reports RRset change protection, read-only.
	ExtraProtected = "protected"
)

// Config scopes the adapter to the API token's project.
type Config struct{ Token string }

// Provider manages DNS through a project API token.
type Provider struct {
	dnsprovider.UnimplementedZoneWrites
	dnsprovider.UnimplementedZoneDetails
	dnsprovider.UnimplementedTenants
	dnsprovider.UnimplementedDelegationSigners

	token, baseURL string
	client         *http.Client
	limit          *rest.Window
	log            *slog.Logger
}

// New validates configuration without contacting the service.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.Token) == "" || strings.ContainsAny(cfg.Token, " \t\r\n") {
		return nil, errors.New("hetzner: a valid project API token is required")
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
	return &Provider{token: cfg.Token, baseURL: endpoint, client: client, log: o.Logger, limit: rest.AccountPerMinute("hetzner "+endpoint+" "+hex.EncodeToString(hash[:]), 60)}, nil
}

// Factory describes the single secret credential and validates field maps.
func Factory() dnsprovider.Factory {
	return fields.Factory("hetzner", []dnsprovider.Field{{Name: FieldToken, Label: "Project API token", Secret: true}}, traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Token: m[FieldToken]}, opts...)
	})
}

// traits are the Traits of every Provider, which Traits and Factory
// report.
// Writes keep each value's comment and the RRset's labels and
// protection as Hetzner holds them.
var traits = dnsprovider.Traits{
	Capabilities: []dnsprovider.Capability{dnsprovider.CapBatcher},
	TTL:          ttlRange,
	Extras: []dnsprovider.ExtraSpec{
		{Key: ExtraComment, Label: "Comment", Kind: dnsprovider.ExtraString},
		{Key: ExtraProtected, Label: "Change protection", Kind: dnsprovider.ExtraBool},
		{Key: ExtraLabels, Label: "Labels", Kind: dnsprovider.ExtraJSON},
	},
}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}

func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "hetzner", BaseURL: p.baseURL, HTTP: p.client, Limit: p.limit, Log: p.log,
		Auth:    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+p.token) },
		Secrets: []string{p.token}, Decode: p.apiError,
	}
}

func (p *Provider) apiError(res *http.Response, body []byte) error {
	var payload struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	e := &dnsprovider.APIError{Provider: "hetzner", StatusCode: res.StatusCode}
	if payload.Error.Code != "" || payload.Error.Message != "" {
		e.Messages = []string{strings.TrimSpace(payload.Error.Code + ": " + payload.Error.Message)}
	}
	e.Kind = errorKind(payload.Error.Code)
	if res.StatusCode == http.StatusConflict {
		e.Kind = dnsprovider.ErrConflict
	}
	e.RetryAfter = rest.RetryAfter(res.Header.Get("Retry-After"), time.Now())
	if (e.Kind == dnsprovider.ErrRateLimited || res.StatusCode == http.StatusTooManyRequests) && e.RetryAfter == 0 {
		if reset, err := strconv.ParseInt(res.Header.Get("Ratelimit-Reset"), 10, 64); err == nil {
			e.RetryAfter = max(time.Until(time.Unix(reset, 0)).Round(time.Second), 0)
		}
	}
	return e
}

// Account verifies authenticated DNS read access, including empty projects.
// The API supplies no project identity or Account-wide nameservers.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	zones, err := list[wireZone](ctx, p, "/zones", "zones")
	if err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	for _, z := range zones {
		if _, err := publicZone(z); err != nil {
			return dnsprovider.AccountInfo{}, err
		}
	}
	return dnsprovider.AccountInfo{}, nil
}

func errorKind(code string) error {
	switch code {
	case "unauthorized", "forbidden", "token_readonly":
		return dnsprovider.ErrUnauthorized
	case "not_found":
		return dnsprovider.ErrNotFound
	case "conflict", "uniqueness_error", "protected", "locked":
		return dnsprovider.ErrConflict
	case "rate_limit_exceeded":
		return dnsprovider.ErrRateLimited
	}
	return nil
}
