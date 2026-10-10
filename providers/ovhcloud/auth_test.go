package ovhcloud_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/ovhcloud"
)

func TestSignsExactURLQueryAndBody(t *testing.T) {
	f := newFake(t)
	f.prefix = "/1.0"
	f.addZone("example.com", wireRecord{FieldType: "A", SubDomain: "www", Target: "192.0.2.1", TTL: 300})
	p := f.provider(t)

	// The fake answers 400 INVALID_SIGNATURE unless the signature covers
	// the URL with its prefix and encoded query, and the exact body.
	if _, err := p.Records(context.Background(), dnsprovider.Zone{ID: "example.com", Name: "example.com"}, dnsprovider.RecordFilter{Type: "a"}); err != nil {
		t.Fatalf("Records = %v", err)
	}

	if _, err := p.CreateRecord(context.Background(), dnsprovider.Zone{ID: "example.com", Name: "example.com"}, dnsprovider.Record{Type: "TXT", Name: "txt", Value: `"a \"quoted\" é"`, TTL: 600}); err != nil {
		t.Fatalf("CreateRecord = %v", err)
	}

	if !containsPrefix(f.requests, "GET /domain/zone/example.com/record?fieldType=A") {
		t.Errorf("type filter not pushed down as an encoded query: %v", f.requests)
	}
}

func containsPrefix(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}

	return false
}

func TestClockSyncIsLazySharedAndCorrectsSkew(t *testing.T) {
	f := newFake(t)
	f.skew = -2 * time.Hour
	p := f.provider(t)

	if f.timeCalls != 0 {
		t.Fatal("construction read the time")
	}

	var wg sync.WaitGroup

	errs := make(chan error, 8)

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, err := p.Account(context.Background())
			errs <- err
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("Account with a skewed server clock = %v", err)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.timeCalls != 1 {
		t.Errorf("time API called %d times, want once", f.timeCalls)
	}

	for _, ts := range f.timestamps {
		if d := time.Now().Add(f.skew).Unix() - ts; d < -5 || d > 5 {
			t.Errorf("timestamp %d is not the server's time", ts)
		}
	}
}

func TestClockDriftIsResyncedOnQueryTimeOut(t *testing.T) {
	f := newFake(t)
	f.skew = -2 * time.Hour
	p := f.provider(t)

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The API's clock moves after the offset was cached.
	f.mu.Lock()
	f.skew = time.Hour
	f.mu.Unlock()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatalf("Account after the clock moved = %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if f.timeCalls != 2 || len(f.signatures) != 3 {
		t.Fatalf("time lookups %d, authenticated tries %d; want one re-sync and one retry", f.timeCalls, len(f.signatures))
	}
}

func TestQueryTimeOutIsRetriedOnceAndSharesOneResync(t *testing.T) {
	f := newFake(t)

	const callers = 8

	var (
		tries   atomic.Int32
		barrier = make(chan struct{})
	)

	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			// After the first call, the next callers' first tries are
			// all answered together: they used the same offset.
			switch n := tries.Add(1); {
			case n > 2 && n < 2+callers:
				<-barrier
			case n == 2+callers:
				close(barrier)
			}

			f.writeJSON(w, http.StatusBadRequest, map[string]string{"errorCode": "QUERY_TIME_OUT", "httpCode": "400 Bad Request", "message": "Query out of time"})

			return
		}

		f.serve(w, r)
	})

	timeCalls := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()

		return f.timeCalls
	}

	p := f.provider(t)
	if _, err := p.Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) || !strings.Contains(err.Error(), "QUERY_TIME_OUT") {
		t.Fatalf("persistent time error = %v", err)
	}

	if tries.Load() != 2 || timeCalls() != 2 {
		t.Fatalf("tries %d, time lookups %d; want one retry after one re-sync", tries.Load(), timeCalls())
	}

	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, _ = p.Account(context.Background())
		}()
	}

	wg.Wait()

	if tries.Load() != 2+2*callers || timeCalls() != 3 {
		t.Fatalf("tries %d, time lookups %d; want each caller retried once after one shared re-sync", tries.Load(), timeCalls())
	}
}

func TestRetriesAreSignedAgain(t *testing.T) {
	f := newFake(t)

	var (
		once  sync.Once
		first string
	)

	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			retry := false

			once.Do(func() { retry, first = true, r.Header.Get("X-Ovh-Timestamp") })

			if retry {
				w.Header().Set("Retry-After", "1")
				f.apiError(w, http.StatusServiceUnavailable, "Server::ServiceUnavailable", "busy")

				return
			}
		}

		f.serve(w, r)
	})

	p := f.provider(t)
	if _, err := p.Account(context.Background()); err != nil {
		t.Fatalf("Account after Retry-After = %v", err)
	}

	// The retry, a second later, passed the fake's signature check with
	// its own, later timestamp.
	if len(f.timestamps) != 1 || first == "" || strconv.FormatInt(f.timestamps[0], 10) == first {
		t.Fatalf("retry timestamps: first %s, then %v", first, f.timestamps)
	}
}

func newWithKeys(f *fake, key, secret, consumer string) (*ovhcloud.Provider, error) {
	return ovhcloud.New(ovhcloud.Config{ApplicationKey: key, ApplicationSecret: secret, ConsumerKey: consumer}, dnsprovider.WithBaseURL(f.srv.URL), dnsprovider.WithHTTPClient(f.srv.Client()))
}

func TestFailedOrCanceledTimeLookupSendsNothingAuthenticated(t *testing.T) {
	f := newFake(t)
	f.timeStatus = http.StatusServiceUnavailable
	p := f.provider(t)

	if _, err := p.Account(context.Background()); err == nil {
		t.Fatal("Account succeeded without a clock")
	}

	if len(f.requests) != 0 || len(f.signatures) != 0 {
		t.Fatalf("authenticated requests without a clock: %v", f.requests)
	}

	f.mu.Lock()
	f.timeStatus = 0
	f.timeHold = make(chan struct{})
	f.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		_, err := p.Account(ctx)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled time lookup = %v", err)
	}

	if len(f.signatures) != 0 {
		t.Fatal("authenticated request after a canceled time lookup")
	}

	f.mu.Lock()
	close(f.timeHold)
	f.timeHold = nil
	f.mu.Unlock()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatalf("Account after the clock recovered = %v", err)
	}
}

func TestAccountIsAuthenticatedNotTheTimeAPI(t *testing.T) {
	f := newFake(t)
	f.meStatus = http.StatusForbidden
	p := f.provider(t)

	_, err := p.Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || !errors.As(err, &api) || api.StatusCode != http.StatusForbidden {
		t.Fatalf("denied Account = %v", err)
	}

	if strings.Contains(err.Error(), consumerKey) || strings.Contains(err.Error(), appSecret) {
		t.Fatalf("credential in error: %v", err)
	}

	if f.timeCalls != 1 || !containsPrefix(f.requests, "GET /me") {
		t.Fatalf("Account did not verify /me: %v", f.requests)
	}

	// No Zones: Account still succeeds once access is granted.
	f.meStatus = 0
	if a, err := p.Account(context.Background()); err != nil || a.Tenant.ID == "" {
		t.Fatalf("Account without Zones = %+v, %v", a, err)
	}
}

func TestInvalidCredentialsAreUnauthorized(t *testing.T) {
	f := newFake(t)

	p, err := newWithKeys(f, "other-app", appSecret, consumerKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p.Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) || !strings.Contains(err.Error(), "INVALID_CREDENTIAL") {
		t.Fatalf("invalid credential = %v", err)
	}

	p, _ = newWithKeys(f, appKey, "wrong-secret", consumerKey)
	if _, err := p.Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) || strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("invalid signature = %v", err)
	}
}
