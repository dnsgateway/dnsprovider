// Package infomaniak provides Infomaniak DNS hosting through its API v2:
// the domains of the token's Account are its Zones, and their records
// are read, created, updated and deleted by native ID.
//
// As a registrar, it reads and replaces the Signing Keys of a
// Registration on other nameservers.
package infomaniak

import (
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

// DefaultBaseURL is the production API endpoint. Infomaniak has no
// sandbox.
const DefaultBaseURL = "https://api.infomaniak.com"

// DefaultRequestTimeout bounds requests when no HTTP client is supplied.
const DefaultRequestTimeout = 30 * time.Second

// RequestsPerMinute is Infomaniak's published limit per token: 60
// requests a minute, which it does not raise.
const RequestsPerMinute = 60

// Factory field names.
const (
	FieldToken     = "token"
	FieldAccountID = "account_id"
)

// Config is an Infomaniak API token, and the Account it is scoped to.
type Config struct {
	// Token is an API token with the domain:read and dns:read scopes;
	// dns:write to create and delete records, and domain:write to set
	// Signing Keys.
	Token string
	// AccountID, when set, is the positive integer ID of the Account
	// whose domains are the Zones; empty means every Account the token
	// reaches.
	AccountID string
}

// Provider is one Infomaniak Account, reached with its token.
type Provider struct {
	dnsprovider.UnimplementedZoneWrites
	dnsprovider.UnimplementedBatch
	dnsprovider.UnimplementedTenants

	token, accountID, base string
	client                 *http.Client
	log                    *slog.Logger
	limit                  rest.Limiter
}

var _ dnsprovider.Provider = (*Provider)(nil)

// New validates the configuration locally, without a request; Account
// proves remote access.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.Token) == "" || strings.ContainsAny(cfg.Token, " \t\r\n") {
		return nil, errors.New("infomaniak: a valid API token is required")
	}

	if cfg.AccountID != "" && !positiveID(cfg.AccountID) {
		return nil, errors.New("infomaniak: account_id must be a positive integer")
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

	hash := sha256.Sum256([]byte(cfg.Token))

	return &Provider{
		token: cfg.Token, accountID: cfg.AccountID, base: base, client: client, log: o.Logger,
		limit: rest.AccountPerMinute("infomaniak "+base+" "+hex.EncodeToString(hash[:]), RequestsPerMinute),
	}, nil
}

// positiveID reports whether s is an Infomaniak ID: a positive integer
// in canonical decimal form, as an Account or a record has.
func positiveID(s string) bool {
	id, err := strconv.ParseUint(s, 10, 64)

	return err == nil && id != 0 && strconv.FormatUint(id, 10) == s
}

// Factory builds a Provider from its secret token and optional
// account_id, the Tenant field.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{
		{Name: FieldToken, Label: "API token", Secret: true},
		{Name: FieldAccountID, Label: "Account ID", Tenant: true},
	}

	return fields.Factory("infomaniak", fs, traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Token: m[FieldToken], AccountID: m[FieldAccountID]}, opts...)
	})
}

// traits are the Traits of every Provider, which Traits and Factory
// report: TTLs from 60 to 86400 seconds, as Infomaniak's API schema
// bounds them, without an automatic TTL; and the registrar's Signing
// Keys of a Registration on other nameservers. Traits have no field for
// the write types; they are those of writable: the module's
// EditableTypes but URI.
var traits = dnsprovider.Traits{
	Capabilities: []dnsprovider.Capability{dnsprovider.CapDSRegistrar},
	TTL:          dnsprovider.TTLRange{Min: 60, Max: 86400},
}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}

func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "infomaniak", BaseURL: p.base, HTTP: p.client, Limit: p.limit, Log: p.log,
		Auth:    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+p.token) },
		Secrets: []string{p.token},
		Decode:  apiError,
	}
}

// wireError is the error of Infomaniak's envelope, with the detail of a
// validation failure in errors.
type wireError struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Errors      []struct {
		Code        string `json:"code"`
		Description string `json:"description"`
	} `json:"errors"`
}

// messages are the error's code and description, then each detail's.
func (e *wireError) messages() []string {
	if e == nil {
		return nil
	}

	out := nonEmpty(e.Code, e.Description)

	for _, d := range e.Errors {
		out = append(out, nonEmpty(d.Code, d.Description)...)
	}

	return out
}

func nonEmpty(code, description string) []string {
	var parts []string

	for _, s := range []string{code, description} {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}

	if len(parts) == 0 {
		return nil
	}

	return []string{strings.Join(parts, ": ")}
}

// apiError decodes Infomaniak's error envelope, {"result": "error",
// "error": {"code", "description", "errors"}}. The status sets its kind;
// too_many_requests is rate limiting whatever the status.
func apiError(res *http.Response, body []byte) error {
	var envelope struct {
		Error *wireError `json:"error"`
	}

	_ = json.Unmarshal(body, &envelope)

	return envelope.Error.apiError(res.StatusCode)
}

// apiError is the error as an APIError of the status, 0 for an error
// result in an answer of success. too_many_requests is rate limiting
// whatever the status; a duplicate record, or one a record at its name
// excludes, is ErrConflict.
func (e *wireError) apiError(status int) *dnsprovider.APIError {
	out := &dnsprovider.APIError{Provider: "infomaniak", StatusCode: status, Messages: e.messages()}

	if e != nil {
		switch e.Code {
		case "too_many_requests":
			out.Kind = dnsprovider.ErrRateLimited
		case "dns_record_already_exists", "dns_record_mutual_exclusion":
			out.Kind = dnsprovider.ErrConflict
		}
	}

	return out
}
