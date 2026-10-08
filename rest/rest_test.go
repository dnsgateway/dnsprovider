package rest_test

// Seam: rest.Client.Do against an httptest server.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// newClient is a Client of srv that authenticates with a bearer token.
func newClient(t *testing.T, h http.Handler) *rest.Client {
	t.Helper()

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	return &rest.Client{
		Provider: "test",
		BaseURL:  srv.URL,
		HTTP:     srv.Client(),
		Auth:     func(r *http.Request) { r.Header.Set("Authorization", "Bearer t0k3n") },
	}
}

func TestDoSendsAuthenticatedJSONAndDecodesAny2xx(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer t0k3n" {
			t.Errorf("Authorization = %q, want the token", got)
		}

		if r.Method != http.MethodPut || r.URL.Path != "/v1/things/a b" || r.URL.Query().Get("x") != "1" {
			t.Errorf("request %s %s, want PUT /v1/things/a b?x=1", r.Method, r.URL)
		}

		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in["name"] != "www" {
			t.Errorf("body = %v (%v), want name www", in, err)
		}

		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"42"}`))
	}))

	var out struct {
		ID string `json:"id"`
	}

	err := c.Do(context.Background(), http.MethodPut, "/v1/things/a%20b", url.Values{"x": {"1"}}, map[string]string{"name": "www"}, &out)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if out.ID != "42" {
		t.Errorf("out.ID = %q, want 42", out.ID)
	}
}

func TestDoDecodesAnErrorAnswerWithTheProvidersDecoder(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`bad name`))
	}))

	c.Decode = func(res *http.Response, body []byte) error {
		return &dnsprovider.APIError{Provider: "test", StatusCode: res.StatusCode, Messages: []string{string(body)}}
	}

	var out map[string]any

	err := c.Do(context.Background(), http.MethodPost, "/things", nil, nil, &out)

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 422 || len(apiErr.Messages) != 1 || apiErr.Messages[0] != "bad name" {
		t.Fatalf("err = %v, want the decoder's APIError with HTTP 422 and its body", err)
	}
}

func TestDoWithoutADecoderGivesTheStatusAndRetryAfter(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))

	err := c.Do(context.Background(), http.MethodPost, "/things", nil, nil, nil)

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || apiErr.Provider != "test" || apiErr.StatusCode != 429 {
		t.Fatalf("err = %v, want an APIError of test with HTTP 429", err)
	}

	if !errors.Is(err, dnsprovider.ErrRateLimited) {
		t.Errorf("err = %v, want ErrRateLimited", err)
	}

	if apiErr.RetryAfter != 2*time.Minute {
		t.Errorf("RetryAfter = %v, want the header's 2m0s", apiErr.RetryAfter)
	}
}
