// Package rest is the HTTP plumbing the plain net/http adapters share:
// auth, JSON encoding and decoding, error decoding into
// dnsprovider.APIError, retries and a client-side rate limiter.
package rest

import (
	"bytes"
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
}

// Do sends a request to BaseURL+path with the query q. A non-nil body is
// sent as JSON. Any 2xx is success, and its answer is decoded as JSON into
// out unless out is nil.
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

	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: %w", c.Provider, err)
	}

	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.Auth != nil {
		c.Auth(req)
	}

	res, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", c.Provider, err)
	}
	defer func() { _ = res.Body.Close() }()

	answer, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("%s: %w", c.Provider, err)
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return c.decode(res, answer)
	}

	if out == nil {
		return nil
	}

	if err := json.Unmarshal(answer, out); err != nil {
		return fmt.Errorf("%s: decode %s: %w", c.Provider, path, err)
	}

	return nil
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
