// Package internetbs provides Internet.bs DNS hosting through its HTTP API.
package internetbs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// DefaultBaseURL is the production API endpoint.
const DefaultBaseURL = "https://api.internet.bs"

// DefaultRequestTimeout bounds requests when no HTTP client is supplied.
const DefaultRequestTimeout = 30 * time.Second

// RequestsPerMinute is a conservative local allowance; other service quotas apply.
const RequestsPerMinute = 60

// Factory credential field names.
const (
	FieldKey      = "key"
	FieldPassword = "password"
)

// Config is one account's API credentials.
type Config struct {
	Key      string
	Password string
}

// Provider is one Internet.bs account.
type Provider struct {
	api  *rest.Client
	auth url.Values
}

// New builds a provider without sending a request.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.Key) == "" || strings.TrimSpace(cfg.Password) == "" {
		return nil, errors.New("internetbs: API key and password are required")
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
	identity := sha256.Sum256([]byte(cfg.Key + "\x00" + cfg.Password))
	p := &Provider{auth: url.Values{"ApiKey": {cfg.Key}, "Password": {cfg.Password}, "ResponseFormat": {"json"}}}
	p.api = &rest.Client{Provider: "internetbs", BaseURL: base, HTTP: client, Limit: rest.AccountPerMinute(fmt.Sprintf("internetbs %s %x", base, identity), RequestsPerMinute), Log: o.Logger}
	p.api.Decode = func(res *http.Response, data []byte) error {
		var body map[string]json.RawMessage
		_ = json.Unmarshal(data, &body)
		return p.apiError(res.StatusCode, body)
	}
	return p, nil
}

// Account verifies authenticated access, even when no currencies are returned.
// The API does not establish a tenant identity or account-wide nameservers.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	body, err := p.call(ctx, "Account/Balance/Get", nil)
	if err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	var balances []json.RawMessage
	if err := requiredList(body, "balance", &balances); err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	for _, raw := range balances {
		var balance struct {
			Currency string       `json:"currency"`
			Amount   *json.Number `json:"amount"`
		}
		if json.Unmarshal(raw, &balance) != nil || balance.Currency == "" || balance.Amount == nil {
			return dnsprovider.AccountInfo{}, errors.New("internetbs: malformed balance entry")
		}
		if _, err := balance.Amount.Float64(); err != nil {
			return dnsprovider.AccountInfo{}, errors.New("internetbs: malformed balance amount")
		}
	}
	return dnsprovider.AccountInfo{}, nil
}

// call sends one command, without retries, and validates its status envelope.
func (p *Provider) call(ctx context.Context, command string, params url.Values) (map[string]json.RawMessage, error) {
	form := make(url.Values)
	maps.Copy(form, params)
	maps.Copy(form, p.auth)
	var data []byte
	if err := p.api.Do(ctx, http.MethodPost, "/"+command, nil, form, &data); err != nil {
		return nil, p.cleanError(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, errors.New("internetbs: malformed JSON response")
	}
	var status string
	if err := json.Unmarshal(body["status"], &status); err != nil {
		return nil, errors.New("internetbs: response has no valid status")
	}
	switch strings.ToUpper(status) {
	case "SUCCESS":
		return body, nil
	case "FAILURE":
		return nil, p.apiError(0, body)
	default:
		return nil, errors.New("internetbs: unrecognized response status")
	}
}

func requiredList(body map[string]json.RawMessage, field string, out any) error {
	raw, ok := body[field]
	if !ok || len(raw) == 0 || raw[0] != '[' {
		return fmt.Errorf("internetbs: response has no valid %s list", field)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("internetbs: malformed %s list", field)
	}
	return nil
}

func (p *Provider) redact(s string) string {
	type representation struct {
		text    string
		encoded bool
	}
	values := make([]representation, 0, 6)
	for _, key := range []string{"ApiKey", "Password"} {
		secret := p.auth.Get(key)
		values = append(values, representation{text: secret}, representation{text: url.QueryEscape(secret), encoded: true}, representation{text: url.PathEscape(secret), encoded: true})
	}
	slices.SortFunc(values, func(a, b representation) int { return len(b.text) - len(a.text) })
	patterns := make([]string, 0, len(values))
	for _, form := range values {
		value := form.text
		if value == "" {
			continue
		}
		var pattern strings.Builder
		for i := 0; i < len(value); i++ {
			if form.encoded && value[i] == '%' && i+2 < len(value) {
				pattern.WriteString("(?i:" + regexp.QuoteMeta(value[i:i+3]) + ")")
				i += 2
			} else {
				pattern.WriteString(regexp.QuoteMeta(value[i : i+1]))
			}
		}
		patterns = append(patterns, pattern.String())
	}
	if len(patterns) > 0 {
		s = regexp.MustCompile(strings.Join(patterns, "|")).ReplaceAllString(s, "[redacted]")
	}

	return s
}

// cleanError preserves APIError and transport causes while hiding secret text.
func (p *Provider) cleanError(err error) error {
	if p.secretFree(err) {
		return err
	}
	var apiErr *dnsprovider.APIError
	if errors.As(err, &apiErr) {
		copyErr := *apiErr
		copyErr.Messages = make([]string, len(apiErr.Messages))
		for i, msg := range apiErr.Messages {
			copyErr.Messages[i] = p.redact(msg)
		}
		return &copyErr
	}
	if uerr, ok := err.(*url.Error); ok {
		copyErr := *uerr
		copyErr.URL = p.redact(copyErr.URL)
		copyErr.Op = p.redact(copyErr.Op)
		copyErr.Err = p.cleanError(copyErr.Err)
		return &copyErr
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		causes := multi.Unwrap()
		safe := make([]error, len(causes))
		for i, cause := range causes {
			safe[i] = p.cleanError(cause)
		}
		return &redactedError{text: p.redact(err.Error()), cause: errors.Join(safe...), original: err}
	}
	if cause := errors.Unwrap(err); cause != nil {
		return &redactedError{text: p.redact(err.Error()), cause: p.cleanError(cause), original: err}
	}
	if text := p.redact(err.Error()); text != err.Error() {
		return &redactedError{text: text, original: err}
	}
	return err
}

// Inspect every exposed cause, including wrappers that hide their cause text.
func (p *Provider) secretFree(err error) bool {
	if err == nil {
		return true
	}
	if p.redact(err.Error()) != err.Error() {
		return false
	}
	if uerr, ok := err.(*url.Error); ok && (p.redact(uerr.URL) != uerr.URL || p.redact(uerr.Op) != uerr.Op) {
		return false
	}
	if api, ok := err.(*dnsprovider.APIError); ok {
		for _, message := range api.Messages {
			if p.redact(message) != message {
				return false
			}
		}
	}
	if multi, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range multi.Unwrap() {
			if !p.secretFree(cause) {
				return false
			}
		}
		return true
	}
	return p.secretFree(errors.Unwrap(err))
}

type redactedError struct {
	text     string
	cause    error
	original error
}

func (e *redactedError) Unwrap() error        { return e.cause }
func (e *redactedError) Error() string        { return e.text }
func (e *redactedError) Is(target error) bool { return errors.Is(e.original, target) }
func (p *Provider) apiError(status int, body map[string]json.RawMessage) error {
	var message string
	_ = json.Unmarshal(body["message"], &message)
	var code int
	_ = json.Unmarshal(body["code"], &code)
	var kind error
	switch code {
	case 107002, 100005:
		kind = dnsprovider.ErrUnauthorized
	}
	if kind == nil {
		lower := strings.ToLower(message)
		if strings.Contains(lower, "rate limit") || strings.Contains(lower, "quota exceeded") || strings.Contains(lower, "too many requests") {
			kind = dnsprovider.ErrRateLimited
		}
	}
	return &dnsprovider.APIError{Provider: "internetbs", StatusCode: status, Messages: []string{p.redact(message)}, Kind: kind}
}
