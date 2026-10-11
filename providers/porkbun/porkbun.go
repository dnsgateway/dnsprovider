// Package porkbun implements the Porkbun API v3 DNS surface.
package porkbun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

const (
	// DefaultBaseURL is the current production API v3 endpoint.
	DefaultBaseURL = "https://api.porkbun.com/api/json/v3"
	// DefaultRequestTimeout bounds requests made with the default client.
	DefaultRequestTimeout = 30 * time.Second
)

type (
	// Config authenticates one Account with its API key and secret.
	Config struct{ Key, Secret string }
	// Provider manages the Porkbun DNS copy of accessible Zones.
	Provider struct {
		dnsprovider.UnimplementedZoneWrites

		cfg Config
		api rest.Client
	}
)

// New validates credentials locally without making a network call.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.Key) == "" || strings.TrimSpace(cfg.Secret) == "" {
		return nil, errors.New("porkbun: key and secret are required")
	}
	o := dnsprovider.NewOptions(opts...)
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultRequestTimeout}
	}
	p := &Provider{cfg: cfg}
	p.api = rest.Client{Provider: "porkbun", BaseURL: strings.TrimRight(base, "/"), HTTP: client, Limit: keyLimit(strings.TrimRight(base, "/"), cfg.Key), Log: o.Logger, Auth: func(r *http.Request) {
		r.Header.Set("X-Api-Key", cfg.Key)
		r.Header.Set("X-Secret-Api-Key", cfg.Secret)
	}}
	p.api.Decode = func(r *http.Response, b []byte) error { return p.apiError(r.StatusCode, b) }
	return p, nil
}

func (p *Provider) redact(s string) string {
	for _, v := range []string{p.cfg.Key, p.cfg.Secret} {
		s = strings.ReplaceAll(s, v, "[redacted]")
		s = strings.ReplaceAll(s, url.QueryEscape(v), "[redacted]")
	}
	return s
}

type safeError struct {
	message string
	cause   error
}

func (e *safeError) Error() string { return e.message }
func (e *safeError) Unwrap() error { return e.cause }

type codedError struct {
	*dnsprovider.APIError

	code string
}

func (e *codedError) Unwrap() error { return e.APIError }

func (p *Provider) apiError(status int, b []byte) error {
	var env struct {
		Code, Message string
		TTLRemaining  int `json:"ttlRemaining"`
		// Account names the account a domain is not in, on a
		// DOMAIN_NOT_FOUND, DOMAIN_NOT_REGISTERED, or the INVALID_DOMAIN of
		// /dns/*; an INVALID_DOMAIN without it is a malformed name.
		Account string
	}
	_ = json.Unmarshal(b, &env)
	var kind error
	switch {
	case strings.HasPrefix(env.Code, "INVALID_API_KEYS"), slices.Contains([]string{
		"API_KEY_REQUIRED", "MISSING_SECRETAPIKEY", "INVALID_TOKEN", "INVALID_USER",
		"IP_NOT_ALLOWED", "DOMAIN_NOT_ALLOWED", "INSUFFICIENT_SCOPE", "API_ACCESS_DISABLED",
	}, env.Code):
		kind = dnsprovider.ErrUnauthorized
	case slices.Contains([]string{"INVALID_RECORD_ID", "DNS_RECORD_NOT_FOUND", "DOMAIN_NOT_FOUND", "DOMAIN_NOT_REGISTERED"}, env.Code),
		env.Code == "INVALID_DOMAIN" && env.Account != "":
		kind = dnsprovider.ErrNotFound
	case slices.Contains([]string{"DUPLICATE_RECORD", "RECORD_CONFLICT"}, env.Code), status == http.StatusConflict:
		kind = dnsprovider.ErrConflict
	case slices.Contains([]string{"DNSSEC_ALGORITHM_DEPRECATED"}, env.Code):
		// The registry's policy refuses the DS's algorithm or digest type.
		// DNSSEC_CREATE_FAILED is the registry refusing it for any reason.
		kind = dnsprovider.ErrUnsupported
	case env.Code == "RATE_LIMIT_EXCEEDED":
		kind = dnsprovider.ErrRateLimited
	}
	return &codedError{code: env.Code, APIError: &dnsprovider.APIError{
		Provider: "porkbun", StatusCode: status, Messages: []string{p.redact(env.Code + ": " + env.Message)},
		Kind: kind, RetryAfter: rest.RetryAfter(fmt.Sprint(env.TTLRemaining), time.Now()),
	}}
}

func (p *Provider) call(ctx context.Context, method, path string, q url.Values, in, out any) error {
	var b []byte
	if err := p.api.Do(ctx, method, path, q, in, &b); err != nil {
		return &safeError{message: p.redact(err.Error()), cause: err}
	}
	var env struct{ Status string }
	if json.Unmarshal(b, &env) != nil {
		return errors.New("porkbun: malformed JSON response")
	}
	if env.Status == "ERROR" {
		return p.apiError(0, b)
	}
	if env.Status != "SUCCESS" {
		return errors.New("porkbun: missing or invalid response status")
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return errors.New("porkbun: malformed response fields")
	}
	return nil
}

// Account verifies credentials and DNS permissions, even with no Zones.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var env struct {
		CredentialsValid bool `json:"credentialsValid"`
		Account          string
		Scopes           []string
	}
	if err := p.call(ctx, http.MethodGet, "/ping", nil, nil, &env); err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	if !env.CredentialsValid {
		return dnsprovider.AccountInfo{}, &dnsprovider.APIError{Provider: "porkbun", Kind: dnsprovider.ErrUnauthorized, Messages: []string{"ping did not validate credentials"}}
	}
	if !slices.Contains(env.Scopes, "full") && !(slices.Contains(env.Scopes, "read") && slices.Contains(env.Scopes, "dns")) {
		return dnsprovider.AccountInfo{}, &dnsprovider.APIError{Provider: "porkbun", Kind: dnsprovider.ErrUnauthorized, Messages: []string{"read and dns scopes are required"}}
	}
	return dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{Name: env.Account}}, nil
}
