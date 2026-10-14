package vultr_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

func TestErrorsKeepTheirClassificationAndRedactTheKey(t *testing.T) {
	for _, tc := range []struct {
		status int
		msg    string
		kind   error
	}{
		{http.StatusUnauthorized, "Invalid API token.", dnsprovider.ErrUnauthorized},
		{http.StatusUnauthorized, "Unauthorized IP address: 198.51.100.7", dnsprovider.ErrUnauthorized},
		{http.StatusForbidden, "Forbidden", dnsprovider.ErrUnauthorized},
		{http.StatusNotFound, "Domain not found.", dnsprovider.ErrNotFound},
		{http.StatusTooManyRequests, "Rate limit reached - please try your request again later.", dnsprovider.ErrRateLimited},
		{http.StatusBadRequest, "Invalid domain.", nil},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"error":"%s (key %s)","status":%d}`, tc.msg, apiKey, tc.status)
			})
			_, err := p.GetZone(context.Background(), "example.com")
			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || strings.Contains(err.Error(), apiKey) || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("error: %v", err)
			}
			if tc.kind != nil && !errors.Is(err, tc.kind) {
				t.Fatalf("classification: %v", err)
			}
			if tc.kind == nil && (errors.Is(err, dnsprovider.ErrUnauthorized) || errors.Is(err, dnsprovider.ErrNotFound)) {
				t.Fatalf("validation failure misclassified: %v", err)
			}
		})
	}
}

func TestRateLimitsReportRetryAfterWithoutWaitingPastTheSharedBound(t *testing.T) {
	calls := 0
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"Rate limit reached - please try your request again later.","status":429}`)
	})
	_, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{})
	var apiErr *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrRateLimited) || !errors.As(err, &apiErr) || apiErr.RetryAfter != time.Hour || calls != 1 {
		t.Fatalf("rate limit: %v calls=%d", err, calls)
	}
}

func TestIdempotentReadsRetryAfterShortWaits(t *testing.T) {
	calls := 0
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, `{"domains":[],%s}`, meta(0, "", ""))
	})
	if _, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err != nil || calls != 2 {
		t.Fatalf("retry: %v calls=%d", err, calls)
	}
}

func TestDeniedDNSPermissionLeavesRecordsAsTheyWere(t *testing.T) {
	for _, msg := range []string{"Forbidden", "Unauthorized IP address: 198.51.100.7"} {
		t.Run(msg, func(t *testing.T) {
			s := newRecords(t)
			id := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
			p := provider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					status := http.StatusForbidden
					if msg != "Forbidden" {
						status = http.StatusUnauthorized
					}
					s.fail(w, status, msg)
					return
				}
				s.handler(w, r)
			})
			ctx := context.Background()
			_, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300})
			if !errors.Is(err, dnsprovider.ErrUnauthorized) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("denied create: %v", err)
			}
			before := dnsprovider.Record{ID: id, Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
			after := before
			after.Value = "192.0.2.2"
			if _, err := p.UpdateRecord(ctx, exampleZone, before, after); !errors.Is(err, dnsprovider.ErrUnauthorized) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("denied update: %v", err)
			}
			if err := p.DeleteRecord(ctx, exampleZone, before); !errors.Is(err, dnsprovider.ErrUnauthorized) {
				t.Fatalf("denied delete: %v", err)
			}
			if len(s.writes) != 0 || len(s.records) != 1 {
				t.Fatalf("writes: %v", s.writes)
			}
		})
	}
}

func TestCancellationIsRespected(t *testing.T) {
	p := provider(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("a canceled call reached the API") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.ListZones(ctx, dnsprovider.ZoneFilter{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Zones: %v", err)
	}
	if _, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300}); !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateRecord: %v", err)
	}
}
