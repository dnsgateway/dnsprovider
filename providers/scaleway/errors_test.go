package scaleway_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/scaleway"
)

func TestAPIErrorKindsRetryAfterAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		status int
		kind   error
	}{
		{http.StatusUnauthorized, dnsprovider.ErrUnauthorized},
		{http.StatusForbidden, dnsprovider.ErrUnauthorized},
		{http.StatusNotFound, dnsprovider.ErrNotFound},
		{http.StatusConflict, dnsprovider.ErrConflict},
		{http.StatusTooManyRequests, dnsprovider.ErrRateLimited},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"type":"denied","message":"invalid secret credential"}`))
			}))
			defer srv.Close()
			p, _ := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, dnsprovider.WithBaseURL(srv.URL))
			_, err := p.Account(context.Background())
			var api *dnsprovider.APIError
			if !errors.Is(err, tc.kind) || !errors.As(err, &api) || api.RetryAfter != time.Minute || strings.Contains(err.Error(), "secret") || requests != 1 {
				t.Fatalf("mapped %v, requests %d", err, requests)
			}
		})
	}
}

func TestTTLBoundsAndUnsupportedTypesRejectBeforeWrites(t *testing.T) {
	f, p := newFixture(t)
	ttl := dnsprovider.TTLRangeOf(p)
	if ttl.Min != 60 || ttl.Max != 2592000 || ttl.Auto {
		t.Fatalf("TTL range %+v", ttl)
	}
	for _, r := range []dnsprovider.Record{
		{Type: "A", Name: "new", Value: "192.0.2.9", TTL: 1},
		{Type: "A", Name: "new", Value: "192.0.2.9", TTL: 59},
		{Type: "A", Name: "new", Value: "192.0.2.9", TTL: 2592001},
		{Type: "URI", Name: "new", Value: `10 1 "https://example.com"`, TTL: 600},
	} {
		if _, err := p.CreateRecord(context.Background(), testZone, r); err == nil {
			t.Fatalf("invalid record accepted %+v", r)
		}
	}
	if f.writes != 0 {
		t.Fatalf("invalid requests wrote %d batches", f.writes)
	}
}
