package dnsimple_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/dnsimple"
)

func TestProviderErrorsRetainClassificationAndRedactTokens(t *testing.T) {
	for _, tc := range []struct {
		status int
		kind   error
	}{
		{http.StatusUnauthorized, dnsprovider.ErrUnauthorized},
		{http.StatusForbidden, dnsprovider.ErrUnauthorized},
		{http.StatusNotFound, dnsprovider.ErrNotFound},
		{http.StatusConflict, dnsprovider.ErrConflict},
		{http.StatusPaymentRequired, dnsprovider.ErrUnauthorized},
		{http.StatusPreconditionFailed, dnsprovider.ErrUnauthorized},
		{http.StatusTooManyRequests, dnsprovider.ErrRateLimited},
		{http.StatusBadRequest, nil},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, `{"message":"failed secret","errors":{"regions":["plan does not support secret"]}}`)
			})
			_, err := p.Zone(context.Background(), "example.com")
			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error: %v", err)
			}
			if tc.kind != nil && !errors.Is(err, tc.kind) {
				t.Fatalf("classification: %v", err)
			}
			if tc.status == http.StatusTooManyRequests && apiErr.RetryAfter != time.Minute {
				t.Fatalf("retry: %v", apiErr.RetryAfter)
			}
		})
	}
}

func TestAccountReadPermissionIsNotConfusedWithEmptyAccount(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/whoami":
			fmt.Fprint(w, `{"data":{"account":{"id":12},"user":null}}`)
		case "/accounts":
			fmt.Fprint(w, `{"data":[{"id":12}]}`)
		default:
			http.Error(w, `{"message":"Permission Denied. Required Scope: zones:*:read"}`, http.StatusForbidden)
		}
	})
	_, err := p.Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("permission: %v", err)
	}
}

func TestCancellationIsRespected(t *testing.T) {
	p := provider(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("canceled call reached API") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.Zones(ctx, dnsprovider.ZoneFilter{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

func TestCreateIsNeverAutomaticallyRetried(t *testing.T) {
	writes := 0
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"data":[],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
			return
		}
		writes++
		http.Error(w, `{"message":"uncertain response"}`, http.StatusInternalServerError)
	})
	_, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 60})
	if err == nil || writes != 1 {
		t.Fatalf("create: %v writes=%d", err, writes)
	}
}

func TestSuppliedHTTPClientTimeoutIsRespected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Millisecond
	p, err := dnsimple.New(dnsimple.Config{Token: "secret", AccountID: "12"}, dnsprovider.WithBaseURL(server.URL), dnsprovider.WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Zones(context.Background(), dnsprovider.ZoneFilter{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("client timeout: %v", err)
	}
}
