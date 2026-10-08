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
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dnsgateway/dnsprovider"

	"golang.org/x/time/rate"
)

// Retry defaults, for a Client field left zero.
const (
	DefaultAttempts = 3
	DefaultBackoff  = 250 * time.Millisecond
	DefaultMaxWait  = 10 * time.Second
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
	// Limit is the Provider's published rate limit, per Account; nil
	// sends without waiting.
	Limit *rate.Limiter
	// Decode turns a non-2xx answer into an error, normally a
	// *dnsprovider.APIError; nil gives an APIError with the status alone.
	Decode func(res *http.Response, body []byte) error

	// Attempts bounds the tries of a retried call; zero is DefaultAttempts.
	Attempts int
	// Backoff is the wait before the first retry when the Provider does
	// not say how long to wait; it doubles on each retry. Zero is
	// DefaultBackoff.
	Backoff time.Duration
	// MaxWait is the longest wait for a retry; a Provider that asks for
	// longer gets its error returned at once. Zero is DefaultMaxWait.
	MaxWait time.Duration
}

// Do sends a request to BaseURL+path with the query q. A non-nil body is
// sent as JSON. Any 2xx is success, and its answer is decoded as JSON into
// out unless out is nil.
//
// A GET, PUT or DELETE answered 429 or 5xx is tried again, after the wait
// the Provider asked for (Retry-After) or else a doubling backoff. A POST
// is never tried again: a lost answer would create twice.
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var data []byte

	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return fmt.Errorf("%s: encode %s: %w", c.Provider, path, err)
		}
	}

	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	attempts := cmp.Or(c.Attempts, DefaultAttempts)
	backoff := cmp.Or(c.Backoff, DefaultBackoff)

	for try := 1; ; try++ {
		answer, err := c.send(ctx, method, u, body != nil, data)
		if err == nil {
			if out == nil {
				return nil
			}

			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("%s: decode %s: %w", c.Provider, path, err)
			}

			return nil
		}

		wait, ok := c.retryWait(method, err, backoff)
		if !ok || try >= attempts {
			return err
		}

		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()

			return fmt.Errorf("%s: %w", c.Provider, ctx.Err())
		case <-t.C:
		}

		backoff *= 2
	}
}

// send makes one try of a request and reads its answer. A non-2xx answer
// is the error Decode makes of it.
func (c *Client) send(ctx context.Context, method, u string, hasBody bool, data []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Provider, err)
	}

	req.Header.Set("Accept", "application/json")

	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.Auth != nil {
		c.Auth(req)
	}

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Provider, err)
	}
	defer func() { _ = res.Body.Close() }()

	answer, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Provider, err)
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, c.decode(res, answer)
	}

	return answer, nil
}

// retryWait is how long to wait before trying a failed call again; ok is
// false when it is not tried again: a POST, an error that is not a 429 or
// 5xx answer, or a wait past MaxWait.
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

	wait = cmp.Or(apiErr.RetryAfter, backoff)

	return wait, wait <= cmp.Or(c.MaxWait, DefaultMaxWait)
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
		apiErr.RetryAfter = retryAfter(res.Header.Get("Retry-After"), time.Now())
	}

	return err
}

// retryAfter is the wait a Retry-After header asks for, in seconds or as
// an HTTP date; zero when it asks for none or cannot be read.
func retryAfter(h string, now time.Time) time.Duration {
	if h == "" {
		return 0
	}

	if s, err := strconv.Atoi(h); err == nil {
		return max(time.Duration(s)*time.Second, 0)
	}

	if t, err := http.ParseTime(h); err == nil {
		return max(t.Sub(now).Round(time.Second), 0)
	}

	return 0
}
