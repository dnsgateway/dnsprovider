// Package cloudns implements the ClouDNS JSON HTTP API.
package cloudns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/rest"
)

// DefaultBaseURL is the production JSON API endpoint.
const DefaultBaseURL = "https://api.cloudns.net"

// DefaultRequestTimeout bounds requests made with the default client.
const DefaultRequestTimeout = 30 * time.Second

// Config requires Password and exactly one authentication identity.
type Config struct {
	Password    string
	AuthID      string
	SubAuthID   string
	SubAuthUser string
}

// Provider is one main API user or restricted sub-user.
type Provider struct {
	cfg     Config
	baseURL string
	client  *http.Client
	limit   *quota
	log     *slog.Logger
}

// New validates configuration locally, without contacting ClouDNS.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	cfg.AuthID = strings.TrimSpace(cfg.AuthID)
	cfg.SubAuthID = strings.TrimSpace(cfg.SubAuthID)
	cfg.SubAuthUser = strings.TrimSpace(cfg.SubAuthUser)
	n := 0
	for _, s := range []string{cfg.AuthID, cfg.SubAuthID, cfg.SubAuthUser} {
		if strings.TrimSpace(s) != "" {
			n++
		}
	}
	if strings.TrimSpace(cfg.Password) == "" || n != 1 {
		return nil, errors.New("cloudns: password and exactly one of auth_id, sub_auth_id or sub_auth_user are required")
	}
	for _, id := range []string{cfg.AuthID, cfg.SubAuthID} {
		if id != "" {
			if _, err := strconv.ParseUint(id, 10, 64); err != nil {
				return nil, errors.New("cloudns: auth_id and sub_auth_id must be unsigned integers")
			}
		}
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
	return &Provider{cfg: cfg, baseURL: strings.TrimRight(base, "/"), client: client, limit: endpointQuota(strings.TrimRight(base, "/")), log: o.Logger}, nil
}

func (p *Provider) call(ctx context.Context, path string, params url.Values, out any) error {
	if params == nil {
		params = url.Values{}
	}
	params.Set("auth-password", p.cfg.Password)
	switch {
	case p.cfg.AuthID != "":
		params.Set("auth-id", p.cfg.AuthID)
	case p.cfg.SubAuthID != "":
		params.Set("sub-auth-id", p.cfg.SubAuthID)
	default:
		params.Set("sub-auth-user", p.cfg.SubAuthUser)
	}
	api := rest.Client{
		Provider: "cloudns", BaseURL: p.baseURL, HTTP: p.client, Limit: p.limit, Log: p.log,
		Decode: func(res *http.Response, body []byte) error { return p.apiError(res.StatusCode, body) },
	}
	var body []byte
	if err := api.Do(ctx, http.MethodPost, path, nil, params, &body); err != nil {
		return &redactedError{message: p.redact(err.Error()), cause: err}
	}
	var envelope struct {
		Status      json.RawMessage `json:"status"`
		Description string          `json:"statusDescription"`
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || string(body) == "null" || !json.Valid(body) {
		return errors.New("cloudns: malformed JSON response")
	}
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Status) > 0 {
		var status string
		if json.Unmarshal(envelope.Status, &status) == nil && strings.EqualFold(status, "Failed") {
			return p.apiError(0, body)
		}
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("cloudns: malformed response for %s", path)
		}
	}
	return nil
}

type redactedError struct {
	message string
	cause   error
}

func (e *redactedError) Error() string { return e.message }
func (e *redactedError) Unwrap() error { return e.cause }

func (p *Provider) redact(message string) string {
	for _, secret := range []string{p.cfg.Password, p.cfg.AuthID, p.cfg.SubAuthID, p.cfg.SubAuthUser} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
			message = strings.ReplaceAll(message, url.QueryEscape(secret), "[redacted]")
		}
	}
	return message
}

func (p *Provider) apiError(status int, body []byte) error {
	var env struct {
		Description string `json:"statusDescription"`
	}
	_ = json.Unmarshal(body, &env)
	msg := p.redact(env.Description)
	lower := strings.ToLower(env.Description)
	var kind error
	switch {
	case strings.Contains(lower, "authentication"), strings.Contains(lower, "permission"), strings.Contains(lower, "access denied"), strings.Contains(lower, "not allowed"):
		kind = dnsprovider.ErrUnauthorized
	case strings.Contains(lower, "limit"), strings.Contains(lower, "quota"), strings.Contains(lower, "too many"):
		kind = dnsprovider.ErrRateLimited
	case strings.Contains(lower, "invalid record-id"), strings.Contains(lower, "missing domain name"),
		strings.Contains(lower, "missing domain-name"), strings.Contains(lower, "not found"),
		strings.Contains(lower, "does not exist"), strings.Contains(lower, "invalid record id"):
		kind = dnsprovider.ErrNotFound
	case status == http.StatusConflict, strings.Contains(lower, "already exists"), strings.Contains(lower, "duplicate"):
		kind = dnsprovider.ErrConflict
	}
	return &dnsprovider.APIError{Provider: "cloudns", StatusCode: status, Messages: []string{msg}, Kind: kind}
}

// Account verifies login and DNS-list permissions even when no Zones exist.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var env struct {
		Status string `json:"status"`
	}
	if err := p.call(ctx, "/login/login.json", nil, &env); err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	if !strings.EqualFold(env.Status, "Success") {
		return dnsprovider.AccountInfo{}, errors.New("cloudns: malformed login response")
	}
	var zones []struct {
		Name string `json:"name"`
	}
	if err := p.call(ctx, "/dns/list-zones.json", url.Values{"page": {"1"}, "rows-per-page": {strconv.Itoa(100)}}, &zones); err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	for _, z := range zones {
		if z.Name == "" {
			return dnsprovider.AccountInfo{}, errors.New("cloudns: malformed zone listing")
		}
	}
	return dnsprovider.AccountInfo{}, nil
}

// Authentication field names accepted by Factory.
const (
	FieldPassword    = "password"
	FieldAuthID      = "auth_id"
	FieldSubAuthID   = "sub_auth_id"
	FieldSubAuthUser = "sub_auth_user"
)

// Factory builds a Provider using the same validation as New.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{
		{Name: FieldPassword, Label: "API password", Secret: true},
		{Name: FieldAuthID, Label: "API authentication ID", Secret: true},
		{Name: FieldSubAuthID, Label: "Sub-user authentication ID", Secret: true},
		{Name: FieldSubAuthUser, Label: "Sub-user username", Secret: true},
	}
	f := fields.Factory("cloudns", fs, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Password: m[FieldPassword], AuthID: m[FieldAuthID], SubAuthID: m[FieldSubAuthID], SubAuthUser: m[FieldSubAuthUser]}, opts...)
	})
	f.TTL = ttlRange
	// Records carry the API's other record fields, such as status, as
	// text; writes keep them as ClouDNS holds them.
	f.Extras = []dnsprovider.ExtraSpec{{Key: dnsprovider.ExtraOther, Label: "Record metadata", Kind: dnsprovider.ExtraString}}

	return f
}

var (
	_ dnsprovider.Provider  = (*Provider)(nil)
	_ dnsprovider.TTLLimits = (*Provider)(nil)
)
