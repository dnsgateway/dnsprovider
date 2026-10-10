// Package ovhcloud implements DNS Zone services in the OVHcloud API, with
// application/consumer credentials and signed requests.
//
// Request signing follows the official API guide and the official Go
// client, github.com/ovh/go-ovh (BSD 3-Clause License, Copyright (c)
// 2015-2025, OVH SAS); no code is copied from it.
package ovhcloud

import (
	"context"
	"crypto/sha1" //nolint:gosec // the OVHcloud signature protocol is SHA-1.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/rest"
)

// Endpoint identifiers and Factory fields.
const (
	// EndpointEU is the default European API.
	EndpointEU = "ovh-eu"
	// EndpointCA is the Canadian API.
	EndpointCA = "ovh-ca"
	// EndpointUS is the United States API.
	EndpointUS = "ovh-us"

	// DefaultRequestTimeout bounds requests when no client is supplied.
	DefaultRequestTimeout = 30 * time.Second

	FieldApplicationKey    = "application_key"
	FieldApplicationSecret = "application_secret"
	FieldConsumerKey       = "consumer_key"
	FieldEndpoint          = "endpoint"
)

// endpoints are the regional APIs, as the official Go client names them.
var endpoints = map[string]string{
	EndpointEU: "https://eu.api.ovh.com/1.0",
	EndpointCA: "https://ca.api.ovh.com/1.0",
	EndpointUS: "https://api.us.ovhcloud.com/1.0",
}

// Config holds the application and consumer credentials and the regional
// API. Endpoint is one of EndpointEU (the default), EndpointCA and
// EndpointUS.
type Config struct {
	ApplicationKey    string
	ApplicationSecret string
	ConsumerKey       string
	Endpoint          string
}

// Provider manages DNS Zone services of one OVHcloud account.
type Provider struct {
	creds   credentials
	baseURL string
	client  *http.Client
	log     *slog.Logger
	clock   *clock
}

// credentials are the application and consumer keys that sign requests.
type credentials struct {
	appKey, appSecret, consumerKey string
}

// sign adds the authentication headers for a request with this body at
// the API's time ts: the signature covers the method, the absolute URL
// with its encoded query, the exact body and ts.
func (c credentials) sign(r *http.Request, body []byte, ts int64) {
	stamp := strconv.FormatInt(ts, 10)
	sum := sha1.Sum([]byte(c.appSecret + "+" + c.consumerKey + "+" + r.Method + "+" + r.URL.String() + "+" + string(body) + "+" + stamp)) //nolint:gosec // protocol

	r.Header.Set("X-Ovh-Application", c.appKey)
	r.Header.Set("X-Ovh-Consumer", c.consumerKey)
	r.Header.Set("X-Ovh-Timestamp", stamp)
	r.Header.Set("X-Ovh-Signature", "$1$"+hex.EncodeToString(sum[:]))
}

// redact removes every credential from s.
func (c credentials) redact(s string) string {
	for _, secret := range []string{c.appSecret, c.consumerKey, c.appKey} {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}

	return s
}

// clock is the lazily read difference between the local and the API's
// clock, shared by every request of a Provider.
type clock struct {
	// sem admits one time lookup at a time, abandoned on cancellation.
	sem   chan struct{}
	mu    sync.Mutex
	known bool
	delta time.Duration
	// lookup counts the time lookups; it names the offset a request was
	// signed with, so callers refused for the same offset drop it once.
	lookup uint64
}

// now is the API's current time, in Unix seconds.
func (c *clock) now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return time.Now().Add(-c.delta).Unix()
}

// state reports whether the offset is known, and its lookup.
func (c *clock) state() (bool, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.known, c.lookup
}

// invalidate drops the offset of lookup, unless a later lookup replaced
// it already.
func (c *clock) invalidate(lookup uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lookup == lookup {
		c.known = false
	}
}

// errClockRejected is the Kind of an answer refusing the request's
// timestamp (QUERY_TIME_OUT).
var errClockRejected = fmt.Errorf("%w (request time out of the API's window)", dnsprovider.ErrUnauthorized)

func credential(name, value string) error {
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("ovhcloud: a valid %s is required", name)
	}

	return nil
}

// New validates configuration without contacting the service.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	for _, c := range []struct{ name, value string }{
		{"application key", cfg.ApplicationKey},
		{"application secret", cfg.ApplicationSecret},
		{"consumer key", cfg.ConsumerKey},
	} {
		if err := credential(c.name, c.value); err != nil {
			return nil, err
		}
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = EndpointEU
	}

	base, ok := endpoints[endpoint]
	if !ok {
		return nil, fmt.Errorf("ovhcloud: unknown endpoint %q; use %s, %s or %s", endpoint, EndpointEU, EndpointCA, EndpointUS)
	}

	o := dnsprovider.NewOptions(opts...)
	if o.BaseURL != "" {
		base = strings.TrimRight(o.BaseURL, "/")
	}

	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultRequestTimeout}
	}

	return &Provider{
		creds:   credentials{appKey: cfg.ApplicationKey, appSecret: cfg.ApplicationSecret, consumerKey: cfg.ConsumerKey},
		baseURL: base, client: client, log: o.Logger, clock: &clock{sem: make(chan struct{}, 1)},
	}, nil
}

// Factory describes the secret credentials and the regional endpoint.
func Factory() dnsprovider.Factory {
	return fields.Factory("ovhcloud", []dnsprovider.Field{
		{Name: FieldApplicationKey, Label: "Application key", Secret: true},
		{Name: FieldApplicationSecret, Label: "Application secret", Secret: true},
		{Name: FieldConsumerKey, Label: "Consumer key", Secret: true},
		{Name: FieldEndpoint, Label: "API endpoint (ovh-eu, ovh-ca or ovh-us)"},
	}, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{
			ApplicationKey: m[FieldApplicationKey], ApplicationSecret: m[FieldApplicationSecret],
			ConsumerKey: m[FieldConsumerKey], Endpoint: m[FieldEndpoint],
		}, opts...)
	})
}

// syncClock reads the API's clock unless it is known, through the
// configured client and endpoint, and returns the lookup the offset
// comes from. A failed or canceled lookup leaves it unknown, so no
// authenticated request goes out, and the next call tries again.
func (p *Provider) syncClock(ctx context.Context) (uint64, error) {
	c := p.clock

	if known, lookup := c.state(); known {
		return lookup, nil
	}

	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return 0, fmt.Errorf("ovhcloud: clock synchronization: %w", ctx.Err())
	}
	defer func() { <-c.sem }()

	if known, lookup := c.state(); known {
		return lookup, nil
	}

	var serverTime int64
	if err := p.restClient(nil).Do(ctx, http.MethodGet, "/auth/time", nil, nil, &serverTime); err != nil {
		return 0, fmt.Errorf("ovhcloud: clock synchronization failed; no authenticated request was sent: %w", err)
	}

	if serverTime <= 0 {
		return 0, errors.New("ovhcloud: clock synchronization failed: malformed time")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.delta, c.known = time.Since(time.Unix(serverTime, 0)), true
	c.lookup++

	return c.lookup, nil
}

// sign adds the authentication headers to one try of a request, at the
// API's current time.
func (p *Provider) sign(r *http.Request) {
	var body []byte
	if r.GetBody != nil {
		if rc, err := r.GetBody(); err == nil {
			body, _ = io.ReadAll(rc)
			_ = rc.Close()
		}
	}

	p.creds.sign(r, body, p.clock.now())
}

// restClient is the client for the API with auth, nil for the public
// time lookup. An Auth signs every try again, so a retry carries a
// fresh timestamp.
func (p *Provider) restClient(auth func(*http.Request)) *rest.Client {
	return &rest.Client{Provider: "ovhcloud", BaseURL: p.baseURL, HTTP: p.client, Log: p.log, Auth: auth, Decode: p.apiError}
}

// do sends one authenticated call once the clock is known. When the API
// refuses its timestamp (QUERY_TIME_OUT), the clock has drifted since
// the lookup: the offset is dropped and read again, and the call is
// sent once more. The API refuses such a request before running it, so
// even a POST is not repeated; a second refusal is returned.
func (p *Provider) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	lookup, err := p.syncClock(ctx)
	if err != nil {
		return err
	}

	api := p.restClient(p.sign)

	err = api.Do(ctx, method, path, q, body, out)
	if !errors.Is(err, errClockRejected) {
		return err
	}

	p.clock.invalidate(lookup)

	if _, syncErr := p.syncClock(ctx); syncErr != nil {
		return errors.Join(err, syncErr)
	}

	return api.Do(ctx, method, path, q, body, out)
}

func (p *Provider) apiError(res *http.Response, body []byte) error {
	var payload struct {
		Class     string            `json:"class"`
		Message   string            `json:"message"`
		ErrorCode string            `json:"errorCode"`
		Details   map[string]string `json:"details"`
	}

	e := &dnsprovider.APIError{Provider: "ovhcloud", StatusCode: res.StatusCode, RetryAfter: rest.RetryAfter(res.Header.Get("Retry-After"), time.Now())}
	if err := json.Unmarshal(body, &payload); err != nil {
		if text := strings.TrimSpace(string(body)); text != "" {
			e.Messages = []string{p.creds.redact("malformed error response: " + truncate(text))}
		}

		return e
	}

	var parts []string

	for _, s := range []string{payload.Class, payload.ErrorCode} {
		if s != "" {
			parts = append(parts, s)
		}
	}

	msg := strings.Join(parts, " ")
	if payload.Message != "" {
		msg = strings.TrimPrefix(msg+": "+payload.Message, ": ")
	}

	for _, k := range []string{"unauthorizedActionsByAuthentication", "unauthorizedActionsByIAM"} {
		if v := payload.Details[k]; v != "" {
			msg += " (missing permissions: " + v + ")"
		}
	}

	if id := res.Header.Get("X-Ovh-Queryid"); id != "" {
		msg += " (query " + id + ")"
	}

	if msg != "" {
		e.Messages = []string{p.creds.redact(msg)}
	}

	e.Kind = errorKind(res.StatusCode, payload.Class, payload.ErrorCode)

	return e
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}

	return s
}

// errorKind maps the API's error code or class to a sentinel. Only
// QUERY_TIME_OUT is a clock error: the signature covers the timestamp
// sent, so INVALID_SIGNATURE means a wrong secret, URL or body, which a
// new time lookup cannot fix.
func errorKind(status int, class, code string) error {
	switch code {
	case "QUERY_TIME_OUT":
		return errClockRejected
	case "INVALID_CREDENTIAL", "INVALID_SIGNATURE", "INVALID_KEY", "NOT_CREDENTIAL", "NOT_GRANTED_CALL":
		return dnsprovider.ErrUnauthorized
	}

	switch {
	case strings.Contains(class, "Unauthorized"), strings.Contains(class, "Forbidden"):
		return dnsprovider.ErrUnauthorized
	case strings.Contains(class, "NotFound"):
		return dnsprovider.ErrNotFound
	case strings.Contains(class, "Conflict"), strings.Contains(class, "AlreadyExists"), status == http.StatusConflict:
		return dnsprovider.ErrConflict
	case strings.Contains(class, "TooManyRequests"):
		return dnsprovider.ErrRateLimited
	}

	return nil
}

// Account verifies the credentials with the authenticated account
// endpoint, GET /me, which works without Zones. The Tenant is the
// account's NIC handle and organization name, when it has one.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var me struct {
		Nichandle string `json:"nichandle"`
		Org       string `json:"organisation"` //nolint:misspell // the API's field name
	}

	if err := p.do(ctx, http.MethodGet, "/me", nil, nil, &me); err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	if me.Nichandle == "" {
		return dnsprovider.AccountInfo{}, errors.New("ovhcloud: malformed account response")
	}

	return dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: me.Nichandle, Name: me.Org}}, nil
}
