package rest_test

// Seam: rest.Client.Do against an httptest server.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
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

// flaky answers each status in turn, with its Retry-After header if
// retryAfter is set, then 200 with {}; it counts the requests and keeps
// each body.
type flaky struct {
	statuses   []int
	retryAfter string

	calls  atomic.Int32
	bodies []string
}

func (f *flaky) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := int(f.calls.Add(1))

	b, _ := io.ReadAll(r.Body)
	f.bodies = append(f.bodies, string(b))

	if n <= len(f.statuses) {
		if f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}

		w.WriteHeader(f.statuses[n-1])

		return
	}

	_, _ = w.Write([]byte(`{}`))
}

// quick makes a Client's retries wait no time.
func quick(c *rest.Client) *rest.Client {
	c.Backoff = time.Nanosecond

	return c
}

func TestIdempotentCallsRetry429And5xx(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		for _, status := range []int{429, 500, 502, 503} {
			t.Run(method+" "+strconv.Itoa(status), func(t *testing.T) {
				f := &flaky{statuses: []int{status, status}}
				c := quick(newClient(t, f))

				body := map[string]string{"name": "www"}
				if err := c.Do(context.Background(), method, "/things", nil, body, nil); err != nil {
					t.Fatalf("Do: %v, want success on the third try", err)
				}

				if got := f.calls.Load(); got != 3 {
					t.Errorf("sent %d requests, want 3", got)
				}

				if f.bodies[2] != f.bodies[0] || f.bodies[0] == "" {
					t.Errorf("bodies = %q, want the same body on every try", f.bodies)
				}
			})
		}
	}
}

func TestAPOSTIsNeverRetried(t *testing.T) {
	for _, status := range []int{429, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f := &flaky{statuses: []int{status}}
			c := quick(newClient(t, f))

			err := c.Do(context.Background(), http.MethodPost, "/things", nil, map[string]string{"name": "www"}, nil)

			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != status {
				t.Errorf("err = %v, want the HTTP %d answer", err, status)
			}

			if got := f.calls.Load(); got != 1 {
				t.Errorf("sent %d requests, want 1: a lost answer would create twice", got)
			}
		})
	}
}

func TestOtherErrorsAreNotRetried(t *testing.T) {
	f := &flaky{statuses: []int{http.StatusNotFound}}
	c := quick(newClient(t, f))

	if err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil, nil); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}

	if got := f.calls.Load(); got != 1 {
		t.Errorf("sent %d requests, want 1", got)
	}
}

func TestRetriesGiveUpWithTheLastError(t *testing.T) {
	f := &flaky{statuses: []int{503, 503, 503, 503, 503}}
	c := quick(newClient(t, f))
	c.Attempts = 4

	err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil, nil)

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 503 {
		t.Errorf("err = %v, want the HTTP 503 answer", err)
	}

	if got := f.calls.Load(); got != 4 {
		t.Errorf("sent %d requests, want 4", got)
	}
}

func TestA429WaitsWhatRetryAfterAsks(t *testing.T) {
	f := &flaky{statuses: []int{429}, retryAfter: "1"}
	c := quick(newClient(t, f))

	start := time.Now()
	if err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if waited := time.Since(start); waited < time.Second {
		t.Errorf("retried after %v, want Retry-After's 1s", waited)
	}
}

func TestARetryAfterPastMaxWaitIsReportedNotWaited(t *testing.T) {
	f := &flaky{statuses: []int{429}, retryAfter: "60"}
	c := quick(newClient(t, f))
	c.MaxWait = 10 * time.Second

	err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil, nil)

	var apiErr *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrRateLimited) || !errors.As(err, &apiErr) || apiErr.RetryAfter != time.Minute {
		t.Errorf("err = %v, want ErrRateLimited asking for 1m0s", err)
	}

	if got := f.calls.Load(); got != 1 {
		t.Errorf("sent %d requests, want 1", got)
	}
}

func TestAWaitEndsWithTheContext(t *testing.T) {
	f := &flaky{statuses: []int{503}, retryAfter: "5"}
	c := newClient(t, f)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.Do(ctx, http.MethodGet, "/things", nil, nil, nil)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the context's deadline", err)
	}

	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("Do returned after %v, want it to stop with the context", waited)
	}
}

func TestARetryIsLogged(t *testing.T) {
	var logs strings.Builder

	f := &flaky{statuses: []int{503}}
	c := quick(newClient(t, f))
	c.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if !strings.Contains(logs.String(), "retry") || !strings.Contains(logs.String(), "/things") {
		t.Errorf("logs = %q, want the retry of /things", logs.String())
	}
}

func TestRetryAfterMayBeAnHTTPDate(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", time.Now().Add(2*time.Minute).UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusTooManyRequests)
	}))

	err := c.Do(context.Background(), http.MethodPost, "/things", nil, nil, nil)

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || apiErr.RetryAfter < 118*time.Second || apiErr.RetryAfter > 2*time.Minute {
		t.Errorf("err = %v, want RetryAfter about 2m0s", err)
	}
}

func TestARetriedDeleteThatFindsItGoneSucceeds(t *testing.T) {
	f := &flaky{statuses: []int{503, http.StatusNotFound}}
	c := quick(newClient(t, f))

	if err := c.Do(context.Background(), http.MethodDelete, "/things/1", nil, nil, nil); err != nil {
		t.Errorf("Do: %v, want success: the first try may have deleted it", err)
	}

	if got := f.calls.Load(); got != 2 {
		t.Errorf("sent %d requests, want 2", got)
	}
}

func TestOnlyARetriedDeleteTakesA404AsDone(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		statuses []int
	}{
		{"first delete", http.MethodDelete, []int{http.StatusNotFound}},
		{"retried get", http.MethodGet, []int{503, http.StatusNotFound}},
		{"retried put", http.MethodPut, []int{503, http.StatusNotFound}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := quick(newClient(t, &flaky{statuses: tc.statuses}))

			if err := c.Do(context.Background(), tc.method, "/things/1", nil, nil, nil); !errors.Is(err, dnsprovider.ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestTheBackoffIsCappedAtMaxWait(t *testing.T) {
	f := &flaky{statuses: []int{503, 503}}
	c := newClient(t, f)
	c.Backoff = time.Hour
	c.MaxWait = time.Millisecond

	start := time.Now()
	if err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil, nil); err != nil {
		t.Fatalf("Do: %v, want retries that wait MaxWait", err)
	}

	if got := f.calls.Load(); got != 3 {
		t.Errorf("sent %d requests, want 3", got)
	}

	if waited := time.Since(start); waited > time.Second {
		t.Errorf("Do took %v, want each wait cut to MaxWait", waited)
	}
}
