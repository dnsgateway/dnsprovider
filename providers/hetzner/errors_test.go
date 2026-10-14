package hetzner_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/hetzner"
)

func TestNativeErrorsAndCredentialRedaction(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		kind   error
	}{
		{401, "unauthorized", dnsprovider.ErrUnauthorized},
		{403, "token_readonly", dnsprovider.ErrUnauthorized},
		{404, "not_found", dnsprovider.ErrNotFound},
		{409, "uniqueness_error", dnsprovider.ErrConflict},
		{423, "protected", dnsprovider.ErrConflict},
		{429, "rate_limit_exceeded", dnsprovider.ErrRateLimited},
	} {
		t.Run(tc.code, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": tc.code, "message": "test-secret denied"}})
			}))
			defer s.Close()
			p, _ := hetzner.New(hetzner.Config{Token: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
			_, err := p.Account(context.Background())
			var api *dnsprovider.APIError
			if !errors.Is(err, tc.kind) || !errors.As(err, &api) || api.StatusCode != tc.status || strings.Contains(err.Error(), "test-secret") {
				t.Fatalf("error=%v", err)
			}
			if tc.status == 429 && api.RetryAfter != time.Minute {
				t.Fatalf("retry=%v", api.RetryAfter)
			}
		})
	}
}

func TestFailedActionMapsNativePermissionError(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if strings.HasSuffix(r.URL.Path, "/rrsets") {
				_, _ = w.Write([]byte(`{"rrsets":[],"meta":{"pagination":{"page":1,"next_page":null}}}`))
			} else {
				_, _ = w.Write([]byte(`{"zone":{"id":1,"name":"example.com","ttl":300,"mode":"primary","status":"ok"}}`))
			}
			return
		}
		_, _ = w.Write([]byte(`{"action":{"id":99,"status":"error","error":{"code":"forbidden","message":"secret action denied"}}}`))
	}))
	defer s.Close()
	p, _ := hetzner.New(hetzner.Config{Token: "secret"}, dnsprovider.WithBaseURL(s.URL))
	_, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.1", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("action=%v", err)
	}
}

func TestMalformedAcknowledgementAndReadbackDoNotResubmit(t *testing.T) {
	for _, answer := range []string{`{}`, `{"action":{"status":"success"}}`, `not json`} {
		t.Run(answer, func(t *testing.T) {
			writes := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if strings.HasSuffix(r.URL.Path, "/rrsets") {
						_, _ = w.Write([]byte(`{"rrsets":[],"meta":{"pagination":{"page":1,"next_page":null}}}`))
					} else {
						_, _ = w.Write([]byte(`{"zone":{"id":1,"name":"example.com","ttl":300,"mode":"primary"}}`))
					}
					return
				}
				writes++
				_, _ = w.Write([]byte(answer))
			}))
			defer s.Close()
			p, _ := hetzner.New(hetzner.Config{Token: "secret"}, dnsprovider.WithBaseURL(s.URL))
			_, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.1", TTL: 300})
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) || writes != 1 {
				t.Fatalf("malformed=%v writes=%d", err, writes)
			}
		})
	}
	f := newFixture(t)
	f.readFail = true
	_, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.1", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) || len(f.writes) != 1 {
		t.Fatalf("readback=%v writes=%v", err, f.writes)
	}
}

func TestAWriteWithoutAnAnswerIsUnconfirmedAndARefusedOneIsNot(t *testing.T) {
	for _, tc := range []struct {
		name        string
		answer      func(w http.ResponseWriter)
		unconfirmed bool
	}{
		{"5xx", func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }, true},
		{"lost", func(w http.ResponseWriter) {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		}, true},
		{"4xx", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":{"code":"invalid_input","message":"rejected"}}`))
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					if strings.HasSuffix(r.URL.Path, "/rrsets") {
						_, _ = w.Write([]byte(`{"rrsets":[],"meta":{"pagination":{"page":1,"next_page":null}}}`))
					} else {
						_, _ = w.Write([]byte(`{"zone":{"id":1,"name":"example.com","ttl":300,"mode":"primary"}}`))
					}
					return
				}
				writes++
				tc.answer(w)
			}))
			defer s.Close()
			p, _ := hetzner.New(hetzner.Config{Token: "secret"}, dnsprovider.WithBaseURL(s.URL))
			_, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.1", TTL: 300})
			if err == nil || errors.Is(err, dnsprovider.ErrUnconfirmed) != tc.unconfirmed || writes != 1 {
				t.Fatalf("write=%v writes=%d, want unconfirmed: %v", err, writes, tc.unconfirmed)
			}
		})
	}
}

func TestClientTimeoutAndCanceledContext(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	client := s.Client()
	client.Timeout = 20 * time.Millisecond
	p, _ := hetzner.New(hetzner.Config{Token: "secret"}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(client))
	started := time.Now()
	_, err := p.Account(context.Background())
	if err == nil || time.Since(started) > time.Second || client.Timeout != 20*time.Millisecond {
		t.Fatalf("timeout=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = p.Account(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}
