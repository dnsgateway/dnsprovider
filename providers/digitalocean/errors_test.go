package digitalocean_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

func TestErrorsKeepTheirClassificationAndRedactTheToken(t *testing.T) {
	for _, tc := range []struct {
		status int
		id     string
		kind   error
	}{
		{http.StatusUnauthorized, "unauthorized", dnsprovider.ErrUnauthorized},
		{http.StatusForbidden, "Forbidden", dnsprovider.ErrUnauthorized},
		{http.StatusNotFound, "not_found", dnsprovider.ErrNotFound},
		{http.StatusConflict, "conflict", dnsprovider.ErrConflict},
		{http.StatusTooManyRequests, "too_many_requests", dnsprovider.ErrRateLimited},
		{http.StatusUnprocessableEntity, "unprocessable_entity", nil},
	} {
		t.Run(tc.id, func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"id":%q,"message":"rejected dop_v1_secret","request_id":"4d9d8375"}`, tc.id)
			})
			_, err := p.Zone(context.Background(), "example.com")
			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || strings.Contains(err.Error(), "dop_v1_secret") || !strings.Contains(err.Error(), tc.id) {
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

func TestQuotaErrorsWaitForRateLimitReset(t *testing.T) {
	calls := 0
	reset := time.Now().Add(time.Hour).Unix()
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Ratelimit-Limit", "5000")
		w.Header().Set("Ratelimit-Remaining", "0")
		w.Header().Set("Ratelimit-Reset", strconv.FormatInt(reset, 10))
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"id":"too_many_requests","message":"API rate limit exceeded."}`)
	})
	_, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
	var apiErr *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrRateLimited) || !errors.As(err, &apiErr) || apiErr.RetryAfter < 59*time.Minute || apiErr.RetryAfter > time.Hour {
		t.Fatalf("quota: %v", err)
	}
	if calls != 1 {
		t.Fatalf("a wait past the shared bound was retried: %d calls", calls)
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
		fmt.Fprint(w, `{"domains":[],"links":{},"meta":{"total":0}}`)
	})
	if _, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{}); err != nil || calls != 2 {
		t.Fatalf("retry: %v calls=%d", err, calls)
	}
}

func TestDeniedDNSWriteScopeLeavesRecordsAsTheyWere(t *testing.T) {
	s := newRecords(t)
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			s.fail(w, http.StatusForbidden, "Forbidden", "You are not authorized to perform this operation")
			return
		}
		s.handler(w, r)
	})
	_, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || strings.Contains(err.Error(), "unconfirmed") || len(s.writes) != 0 {
		t.Fatalf("denied create: %v", err)
	}
}

func TestCancellationIsRespected(t *testing.T) {
	p := provider(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("a canceled call reached the API") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Zones(ctx, dnsprovider.ZoneFilter{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Zones: %v", err)
	}
	if _, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300}); !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateRecord: %v", err)
	}
}
