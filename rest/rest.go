// Package rest is the HTTP plumbing the plain net/http adapters share:
// auth, JSON encoding and decoding, error decoding into
// dnsprovider.APIError, retries and a client-side rate limiter.
package rest

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

// Retry defaults, for a Client field left zero.
const (
	DefaultAttempts = 3
	DefaultBackoff  = 250 * time.Millisecond
	DefaultMaxWait  = 10 * time.Second
	// DefaultMaxBody bounds an answer Do reads, for a Client whose
	// MaxBody is zero.
	DefaultMaxBody = 64 << 20
)

// Client sends one Account's requests to a Provider's API.
type Client struct {
	// Provider is the Provider type, for errors, e.g. "godaddy".
	Provider string
	// BaseURL is the API endpoint each path is appended to.
	BaseURL string
	// HTTP sends the requests, with the adapter's request timeout.
	HTTP *http.Client
	// Auth puts the Account's credentials on a request; nil adds none.
	Auth func(*http.Request)
	// Secrets are the Account's credentials. No error Do returns or logs
	// shows one, as written or URL-escaped; see Redact.
	Secrets []string
	// Limit is the Provider's published rate limit, per Account, such as
	// AccountPerMinute or a *rate.Limiter; nil sends without waiting.
	Limit Limiter
	// Decode turns a non-2xx answer into an error, normally a
	// *dnsprovider.APIError; nil gives an APIError with the status alone.
	Decode func(res *http.Response, body []byte) error

	// MaxBody bounds an answer Do reads; a larger 2xx answer is an
	// error. Zero is DefaultMaxBody.
	MaxBody int64

	// Log receives a debug line for each retry; nil logs nothing.
	Log *slog.Logger

	// Attempts bounds the tries of a retried call; zero is DefaultAttempts.
	Attempts int
	// Backoff is the wait before the first retry when the Provider does
	// not say how long to wait; it doubles on each retry. Zero is
	// DefaultBackoff.
	Backoff time.Duration
	// MaxWait is the longest wait for a retry: the backoff stops growing
	// there, and a Provider that asks for longer gets its error returned
	// at once. Zero is DefaultMaxWait.
	MaxWait time.Duration
}

// Do sends a request to BaseURL+path with the query q. A url.Values body
// is sent as a form, any other non-nil body as JSON. Any 2xx is success:
// its answer is decoded as JSON into out, or handed back as is when out is
// a *[]byte, or dropped when out is nil.
//
// A GET, PUT or DELETE answered 429 or 5xx is tried again, after the wait
// the Provider asked for (Retry-After) or else a doubling backoff. A POST
// is never tried again: a lost answer would create twice. A retried DELETE
// answered 404 succeeds: an earlier try deleted it and its answer was lost.
//
// No Secret shows in the error, nor in any cause errors.As finds in it.
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	return c.RedactError(c.do(ctx, method, path, q, body, out))
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var (
		data        []byte
		contentType string
	)

	switch b := body.(type) {
	case nil:
	case url.Values:
		data, contentType = []byte(b.Encode()), "application/x-www-form-urlencoded"
	default:
		var err error
		if data, err = json.Marshal(body); err != nil {
			return fmt.Errorf("%s: encode %s: %w", c.Provider, path, err)
		}

		contentType = "application/json"
	}

	raw, isRaw := out.(*[]byte)

	accept := "application/json"
	if isRaw {
		accept = ""
	}

	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	attempts := cmp.Or(c.Attempts, DefaultAttempts)
	backoff := cmp.Or(c.Backoff, DefaultBackoff)

	for try := 1; ; try++ {
		answer, err := c.send(ctx, method, u, contentType, accept, data)
		if err == nil {
			if isRaw {
				*raw = answer

				return nil
			}

			if out == nil {
				return nil
			}

			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("%s: decode %s: %w", c.Provider, path, err)
			}

			return nil
		}

		if try > 1 && method == http.MethodDelete && isStatus(err, http.StatusNotFound) {
			// An earlier try may have deleted it and lost the answer.
			return nil
		}

		wait, ok := c.retryWait(method, err, backoff)
		if !ok || try >= attempts {
			return err
		}

		if c.Log != nil {
			c.Log.DebugContext(ctx, "retry", "provider", c.Provider, "method", method, "path", c.Redact(path), "try", try, "wait", wait, "err", c.RedactError(err))
		}

		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()

			return fmt.Errorf("%s: %w", c.Provider, ctx.Err())
		case <-t.C:
		}

		// Capped, the doubling cannot overflow.
		backoff = min(backoff*2, cmp.Or(c.MaxWait, DefaultMaxWait))
	}
}

// send makes one try of a request and reads its answer. A non-2xx answer
// is the error Decode makes of it.
func (c *Client) send(ctx context.Context, method, u, contentType, accept string, data []byte) ([]byte, error) {
	if c.Limit != nil {
		if err := c.Limit.Wait(ctx); err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%s: %w", c.Provider, ctx.Err())
			}

			// A limiter refuses at once a wait past the deadline; a
			// *rate.Limiter says so without context.DeadlineExceeded.
			if _, has := ctx.Deadline(); has && !errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("%s: %w: %w", c.Provider, context.DeadlineExceeded, err)
			}

			return nil, fmt.Errorf("%s: %w", c.Provider, err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Provider, err)
	}

	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if c.Auth != nil {
		c.Auth(req)
	}

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Provider, err)
	}
	defer func() { _ = res.Body.Close() }()

	limit := c.MaxBody
	if limit <= 0 {
		limit = DefaultMaxBody
	}

	// One byte past the limit tells a cut-off answer from one that fits.
	answer, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Provider, err)
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, c.decode(res, answer[:min(int64(len(answer)), limit)])
	}

	if int64(len(answer)) > limit {
		return nil, fmt.Errorf("%s: the answer is over %d bytes", c.Provider, limit)
	}

	return answer, nil
}

// retryWait is how long to wait before trying a failed call again: what
// the Provider asked for, or else the backoff cut to MaxWait. ok is false
// when it is not tried again: a POST, an error that is not a 429 or 5xx
// answer, or a Provider asking for a wait past MaxWait.
func (c *Client) retryWait(method string, err error, backoff time.Duration) (wait time.Duration, ok bool) {
	switch method {
	case http.MethodGet, http.MethodPut, http.MethodDelete:
	default:
		return 0, false
	}

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || (apiErr.StatusCode != http.StatusTooManyRequests && apiErr.StatusCode < 500) {
		return 0, false
	}

	maxWait := cmp.Or(c.MaxWait, DefaultMaxWait)
	if apiErr.RetryAfter > 0 {
		return apiErr.RetryAfter, apiErr.RetryAfter <= maxWait
	}

	return min(backoff, maxWait), true
}

// isStatus reports whether err is an APIError with the HTTP status code.
func isStatus(err error, code int) bool {
	var apiErr *dnsprovider.APIError

	return errors.As(err, &apiErr) && apiErr.StatusCode == code
}

// decode turns a non-2xx answer into an error with Decode. An APIError
// that does not say how long to wait gets the Retry-After header's wait.
func (c *Client) decode(res *http.Response, body []byte) error {
	var err error = &dnsprovider.APIError{Provider: c.Provider, StatusCode: res.StatusCode}
	if c.Decode != nil {
		err = c.Decode(res, body)
	}

	var apiErr *dnsprovider.APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter == 0 {
		apiErr.RetryAfter = RetryAfter(res.Header.Get("Retry-After"), time.Now())
	}

	return err
}

// RetryAfter is the wait a Retry-After header asks for at now, in seconds
// or as an HTTP date; zero when it asks for none or cannot be read. A wait
// past what a Duration holds is the longest Duration.
func RetryAfter(h string, now time.Time) time.Duration {
	if h == "" {
		return 0
	}

	if s, err := strconv.ParseInt(h, 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		switch {
		case s <= 0:
			return 0
		case s > math.MaxInt64/int64(time.Second):
			return math.MaxInt64
		default:
			return time.Duration(s) * time.Second
		}
	}

	if t, err := http.ParseTime(h); err == nil {
		return max(t.Sub(now).Round(time.Second), 0)
	}

	return 0
}
