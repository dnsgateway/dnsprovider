package netim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// session is the Netim session a Provider holds, shared by its
// goroutines.
type session struct {
	// sem admits one session opening at a time, abandoned on
	// cancellation.
	sem chan struct{}

	mu    sync.Mutex
	token string // the access token; empty when no session is held
	// opened counts the sessions opened; it names the session a call was
	// sent with, so callers refused for the same session drop it once.
	opened uint64
}

// held is the session's token and number; an empty token when none is
// held.
func (s *session) held() (string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.token, s.opened
}

// drop forgets the session numbered opened, unless a later one replaced
// it already.
func (s *session) drop(opened uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.opened == opened {
		s.token = ""
	}
}

// preferences ask for synchronous processing, no notification mail and
// English messages.
var preferences = map[string]any{"preferences": map[string]any{"lang": "EN", "sync": 1, "notif": 0}}

// open returns the held session, or else opens one with the Basic
// credentials. Opening is serialized, so concurrent first calls open one
// session.
func (p *Provider) open(ctx context.Context) (string, uint64, error) {
	s := p.session
	if token, opened := s.held(); token != "" {
		return token, opened, nil
	}

	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return "", 0, fmt.Errorf("netim: open session: %w", ctx.Err())
	}
	defer func() { <-s.sem }()

	if token, opened := s.held(); token != "" {
		return token, opened, nil
	}

	api := p.api("")
	api.Auth = func(r *http.Request) {
		r.Header.Set("Authorization", "Basic "+p.basic)
		r.Header.Set("Accept-Language", "EN")
	}

	var answer struct {
		Token string `json:"access_token"`
	}
	if err := api.Do(ctx, http.MethodPost, "/session/", nil, preferences, &answer); err != nil {
		return "", 0, err
	}

	if strings.TrimSpace(answer.Token) == "" {
		return "", 0, errors.New("netim: open session: the answer has no access token")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.token = answer.Token
	s.opened++

	return s.token, s.opened, nil
}

// api is the client for calls with the session token, or with no auth
// for an empty token. It is built per call, so that each one redacts the
// token it carries along with the static secrets.
func (p *Provider) api(token string) *rest.Client {
	c := &rest.Client{
		Provider: "netim", BaseURL: p.base, HTTP: p.client, Log: p.log, Limit: p.limit,
		Secrets: p.secrets, Decode: p.apiError,
	}
	if token != "" {
		c.Secrets = append([]string{token}, p.secrets...)
		c.Auth = func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
	}

	return c
}

// read sends a call that changes nothing (rest.Client.Do).
func (p *Provider) read(ctx context.Context, method, path string, body, out any) error {
	return p.send(ctx, func(c *rest.Client, ctx context.Context, method, path string, body, out any) error {
		return c.Do(ctx, method, path, nil, body, out)
	}, method, path, body, out)
}

type sender func(c *rest.Client, ctx context.Context, method, path string, body, out any) error

// send makes a call with the session, opening one if none is held. When
// Netim refuses the held session (401), it has expired or was revoked:
// it is dropped, a new one opened and the call sent once more. Netim
// refuses such a call before running it, so even a write is not
// repeated; a second refusal is returned.
func (p *Provider) send(ctx context.Context, call sender, method, path string, body, out any) error {
	token, opened, err := p.open(ctx)
	if err != nil {
		return err
	}

	err = call(p.api(token), ctx, method, path, body, out)
	if !unauthorized(err) {
		return err
	}

	p.session.drop(opened)

	if token, _, err = p.open(ctx); err != nil {
		return err
	}

	return call(p.api(token), ctx, method, path, body, out)
}

// unauthorized reports whether err is Netim's 401 answer.
func unauthorized(err error) bool {
	var apiErr *dnsprovider.APIError

	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

// Close ends the Provider's Netim session, if it holds one, and forgets
// it; a later call opens a new session. A session being opened when Close
// is called is waited for and closed too, and so is one Netim already
// ended. Close is not part of dnsprovider.Provider: call it on the
// *Provider when done, as Netim allows a reseller few sessions at once.
func (p *Provider) Close(ctx context.Context) error {
	s := p.session

	// Holding sem waits out an opening in progress, so that its session
	// is the one closed.
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("netim: close session: %w", ctx.Err())
	}
	defer func() { <-s.sem }()

	s.mu.Lock()
	token := s.token
	s.token = ""
	s.mu.Unlock()

	if token == "" {
		return nil
	}

	err := p.api(token).Do(ctx, http.MethodDelete, "/session/", nil, nil, nil)
	if unauthorized(err) {
		return nil
	}

	return err
}

// apiError is a non-2xx answer as an APIError with Netim's message. Its
// kind comes from the status alone: Netim documents no error codes.
func (p *Provider) apiError(res *http.Response, body []byte) error {
	e := &dnsprovider.APIError{Provider: "netim", StatusCode: res.StatusCode}

	var answer struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &answer) == nil && answer.Message != "" {
		e.Messages = []string{answer.Message}
	}

	return e
}
