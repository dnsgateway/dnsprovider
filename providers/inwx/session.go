package inwx

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP, as INWX uses it, is HMAC-SHA1.
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// cookieName is the name of the DomRobot session cookie.
const cookieName = "domrobot"

// keptCodes bounds the TOTP codes a session keeps to redact.
const keptCodes = 8

// session is the DomRobot session a Provider holds, shared by its
// goroutines.
type session struct {
	// sem admits one login at a time, abandoned on cancellation.
	sem chan struct{}

	mu     sync.Mutex
	cookie string // the domrobot cookie value; empty when no session is held
	// opened counts the sessions opened; it names the session a call was
	// sent with, so callers refused for the same session drop it once.
	opened uint64
	codes  []string // the latest TOTP codes sent, redacted from errors
}

// held is the session's cookie and number; an empty cookie when none is
// held.
func (s *session) held() (string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.cookie, s.opened
}

// drop forgets the session numbered opened, unless a later one replaced
// it already.
func (s *session) drop(opened uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.opened == opened {
		s.cookie = ""
	}
}

// sent records a TOTP code, to redact it.
func (s *session) sent(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.codes = append(s.codes, code)
	if len(s.codes) > keptCodes {
		s.codes = s.codes[len(s.codes)-keptCodes:]
	}
}

// secrets is what the Provider's errors never show: the static
// credentials, the TOTP codes sent and the cookie.
func (p *Provider) secretsWith(cookie string) []string {
	s := p.session

	s.mu.Lock()
	defer s.mu.Unlock()

	out := append([]string{}, p.secrets...)
	out = append(out, s.codes...)

	if cookie != "" {
		out = append(out, cookie)
	}

	return out
}

// api is the client for calls with the session cookie, or with none for
// an empty cookie. It is built per call, so that each one redacts the
// cookie it carries along with the other secrets.
func (p *Provider) api(cookie string) *rest.Client {
	c := &rest.Client{
		Provider: "inwx", BaseURL: p.base, HTTP: p.client, Log: p.log, Limit: p.limit,
		Secrets: p.secretsWith(cookie), Decode: httpError,
		// Every call is a POST, which rest.Client never retries.
		Attempts: 1,
	}
	if cookie != "" {
		c.Auth = func(r *http.Request) { r.Header.Set("Cookie", cookieName+"="+cookie) }
	}

	return c
}

// open returns the held session, or else logs in. Logging in is
// serialized, so concurrent first calls log in once.
func (p *Provider) open(ctx context.Context) (string, uint64, error) {
	s := p.session
	if cookie, opened := s.held(); cookie != "" {
		return cookie, opened, nil
	}

	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return "", 0, fmt.Errorf("inwx: log in: %w", ctx.Err())
	}
	defer func() { <-s.sem }()

	if cookie, opened := s.held(); cookie != "" {
		return cookie, opened, nil
	}

	cookie, err := p.login(ctx)
	if err != nil {
		return "", 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cookie = cookie
	s.opened++

	return s.cookie, s.opened, nil
}

// login sends account.login and, for an account with two-factor
// authentication, account.unlock with a TOTP code computed now. It
// returns the session cookie, which the login answer sets.
func (p *Provider) login(ctx context.Context) (string, error) {
	catcher := &cookieCatcher{next: p.client.Transport}
	if catcher.next == nil {
		catcher.next = http.DefaultTransport
	}

	hc := *p.client
	hc.Transport = catcher

	c := p.api("")
	c.HTTP = &hc

	env, err := p.rpc(ctx, c, "account.login", map[string]any{"user": p.username, "pass": p.password})
	if err != nil {
		return "", loginRefused(err)
	}

	cookie := catcher.value()
	if cookie == "" {
		return "", errors.New("inwx: log in: the answer set no domrobot session cookie")
	}

	var answer struct {
		TFA json.RawMessage `json:"tfa"`
	}
	if len(env.ResData) > 0 {
		_ = json.Unmarshal(env.ResData, &answer)
	}

	if !twoFactor(answer.TFA) {
		return cookie, nil
	}

	if p.totpKey == nil {
		p.logout(ctx, cookie)

		return "", fmt.Errorf("inwx: log in: the account has two-factor authentication, which needs shared_secret: %w", dnsprovider.ErrUnauthorized)
	}

	code := totp(p.totpKey, time.Now())
	p.session.sent(code)

	if _, err := p.rpc(ctx, p.api(cookie), "account.unlock", map[string]any{"tan": code}); err != nil {
		p.logout(ctx, cookie)

		return "", fmt.Errorf("inwx: unlock the session with a TOTP code of shared_secret: %w", loginRefused(err))
	}

	return cookie, nil
}

// loginRefused is a refusal of account.login or account.unlock as
// ErrUnauthorized, with INWX's code, message and reason kept: whatever
// the code, the credentials did not open a session. 2502 (session
// limit) stays ErrRateLimited, and an error that is not a refusal is
// returned as it is.
func loginRefused(err error) error {
	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 0 || errors.Is(apiErr.Kind, dnsprovider.ErrRateLimited) {
		return err
	}

	refused := *apiErr
	refused.Kind = dnsprovider.ErrUnauthorized

	return &refused
}

// twoFactor reports whether a login answer's tfa field says the account
// has two-factor authentication: the documentation gives "0" for none
// and a method name such as "GOOGLE-AUTH" otherwise; a number or a bool
// is read the same way.
func twoFactor(tfa json.RawMessage) bool {
	var v any
	if len(tfa) == 0 || json.Unmarshal(tfa, &v) != nil {
		return false
	}

	switch t := v.(type) {
	case string:
		return t != "" && t != "0"
	case float64:
		return t != 0
	case bool:
		return t
	}

	return false
}

// totp is the RFC 6238 code of key at t: HMAC-SHA1 over 30-second
// steps, six digits.
func totp(key []byte, t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30)) //nolint:gosec // Unix time is positive.

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", code%1_000_000)
}

// cookieCatcher keeps the domrobot cookie an answer sets: rest.Client
// hands back no headers of a successful answer.
type cookieCatcher struct {
	next http.RoundTripper

	mu     sync.Mutex
	cookie string
}

func (c *cookieCatcher) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := c.next.RoundTrip(r)
	if err != nil {
		return res, err
	}

	for _, ck := range res.Cookies() {
		if ck.Name == cookieName && ck.Value != "" {
			c.mu.Lock()
			c.cookie = ck.Value
			c.mu.Unlock()
		}
	}

	return res, nil
}

func (c *cookieCatcher) value() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.cookie
}

// call is one DomRobot call through a client carrying the session.
type call func(c *rest.Client) (envelope, error)

// send makes a call with the session, logging in if none is held. When
// INWX refuses the held session with an authentication code, it has
// expired or was ended: it is dropped, a new one opened and the call
// sent once more. INWX refuses such a call before running it, so even a
// write is not repeated; a second refusal is returned.
func (p *Provider) send(ctx context.Context, do call) (envelope, error) {
	cookie, opened, err := p.open(ctx)
	if err != nil {
		return envelope{}, err
	}

	env, err := do(p.api(cookie))
	if !sessionRefused(err) {
		return env, err
	}

	p.session.drop(opened)

	if cookie, _, err = p.open(ctx); err != nil {
		return envelope{}, err
	}

	return do(p.api(cookie))
}

// sessionRefused reports whether err is a refusal of the session: an
// authentication or authorization code. INWX documents no code for an
// expired session; these are the ones it answers a call it does not
// authenticate with.
func sessionRefused(err error) bool {
	var apiErr *dnsprovider.APIError

	return errors.As(err, &apiErr) && apiErr.StatusCode == 0 && errors.Is(apiErr.Kind, dnsprovider.ErrUnauthorized)
}

// logout ends a session, best effort, as after a login whose unlock
// failed.
func (p *Provider) logout(ctx context.Context, cookie string) {
	if _, err := p.rpc(ctx, p.api(cookie), "account.logout", nil); err != nil && p.log != nil {
		p.log.DebugContext(ctx, "logout failed", "provider", "inwx", "err", err)
	}
}

// Close logs the Provider's session out, if it holds one, and forgets
// it; a later call logs in again. A login in progress when Close is
// called is waited for and its session closed too, and closing one INWX
// already ended succeeds. Close is not part of dnsprovider.Provider:
// call it on the *Provider when done.
func (p *Provider) Close(ctx context.Context) error {
	s := p.session

	// Holding sem waits out a login in progress, so that its session is
	// the one closed.
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("inwx: log out: %w", ctx.Err())
	}
	defer func() { <-s.sem }()

	s.mu.Lock()
	cookie := s.cookie
	s.cookie = ""
	s.mu.Unlock()

	if cookie == "" {
		return nil
	}

	_, err := p.rpc(ctx, p.api(cookie), "account.logout", nil)
	if sessionRefused(err) {
		return nil
	}

	return err
}

// Account implements dnsprovider.Provider: it logs in, or reuses the
// session, and reads account.info to prove access, which an Account
// without domains or Zones answers too. The Tenant is the customer ID
// (the account ID when INWX gives none); INWX sets no account-wide
// nameservers.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var info struct {
		CustomerID wireInt `json:"customerId"`
		CustomerNo wireInt `json:"customerNo"`
		AccountID  wireInt `json:"accountId"`
	}

	if err := p.read(ctx, "account.info", nil, &info); err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	id := info.CustomerID
	if id == 0 {
		id = info.AccountID
	}

	if id == 0 {
		return dnsprovider.AccountInfo{}, errors.New("inwx: account.info: the answer has no customer or account ID")
	}

	t := dnsprovider.Tenant{ID: id.String()}
	if info.CustomerNo != 0 {
		t.Name = strconv.FormatInt(int64(info.CustomerNo), 10)
	}

	return dnsprovider.AccountInfo{Tenant: t}, nil
}
