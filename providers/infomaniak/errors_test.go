package infomaniak_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

func TestStatusesMapToTheModuleErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		file   string
		want   error
	}{
		{http.StatusUnauthorized, "not_authorized.json", dnsprovider.ErrUnauthorized},
		{http.StatusForbidden, "not_authorized.json", dnsprovider.ErrUnauthorized},
		{http.StatusNotFound, "object_not_found.json", dnsprovider.ErrNotFound},
	} {
		f := newFake(t)
		f.script("GET /2/zones/example.ch", tc.status, fixture(t, tc.file))

		if _, err := f.provider().GetZone(context.Background(), "example.ch"); !errors.Is(err, tc.want) {
			t.Errorf("%d: GetZone = %v, want %v", tc.status, err, tc.want)
		}
	}
}

func TestRateLimitingIsErrRateLimitedWithItsWait(t *testing.T) {
	f := newFake(t)
	f.script("GET /2/domains/domains", http.StatusTooManyRequests, fixture(t, "too_many_requests.json"), "Retry-After", "30")

	_, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{})

	var api *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrRateLimited) || !errors.As(err, &api) || api.RetryAfter != 30*time.Second {
		t.Fatalf("ListZones = %v, want ErrRateLimited with a 30s wait", err)
	}
}

// leaks reports whether the token shows in s, as it is or URL-escaped.
func leaks(s string) bool {
	return strings.Contains(s, token) || strings.Contains(s, url.QueryEscape(token)) || strings.Contains(s, url.PathEscape(token))
}

func TestTheTokenShowsInNoErrorOrLog(t *testing.T) {
	echo := fmt.Sprintf(`{"result":"error","error":{"code":"internal","description":"refused Bearer %s","errors":[{"code":"x","description":"%s"}]}}`, token, token)

	f := newFake(t)

	var logs bytes.Buffer
	p := f.provider(dnsprovider.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))

	// A read answered 503 is retried, and logged, before it fails.
	for range 3 {
		f.script("GET /2/domains/domains", http.StatusServiceUnavailable, echo)
	}

	_, err := p.Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Account = %v, want a 503 APIError", err)
	}

	if logs.Len() == 0 {
		t.Fatal("the retries logged nothing")
	}

	if leaks(fmt.Sprint(err, api.Messages, logs.String())) {
		t.Fatalf("the token shows in %v / %s", err, logs.String())
	}

	// An error result in an answer of success is redacted too.
	f.script("GET /2/zones/example.ch", http.StatusOK, echo)

	_, err = p.GetZone(context.Background(), "example.ch")
	if !errors.As(err, &api) || api.StatusCode != 0 || leaks(fmt.Sprint(err, api.Messages)) {
		t.Fatalf("GetZone = %v, want a redacted refusal", err)
	}
}
