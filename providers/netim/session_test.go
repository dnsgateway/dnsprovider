package netim_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/netim"
)

func TestAccountReturnsTheResellerAsTenantWithNoDomains(t *testing.T) {
	f := newFake(t)
	f.serveFile("POST /domains/", "ds_list_empty.json") // an empty array

	a, err := f.provider().Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if a.Tenant.ID != resellerID || a.Nameservers != nil {
		t.Fatalf("Account = %+v, want the reseller as Tenant", a)
	}

	if f.count("GET /session/") != 1 {
		t.Fatal("Account did not read the session to prove access")
	}
}

func TestAccountRefusesBadCredentials(t *testing.T) {
	f := newFake(t)

	p, err := netim.New(netim.Config{ID: resellerID, Secret: "wrong"}, dnsprovider.WithBaseURL(f.srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || !errors.As(err, &api) || api.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Account = %v, want ErrUnauthorized", err)
	}

	if n := f.count("POST /session/"); n != 1 {
		t.Fatalf("tried to open %d sessions, want 1", n)
	}
}

func TestConcurrentFirstCallsOpenOneSession(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if _, err := p.Account(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}

	wg.Wait()

	if opened, _, _ := f.stats(); opened != 1 {
		t.Fatalf("opened %d sessions, want 1", opened)
	}
}

func TestAnExpiredSessionIsReopenedAndTheCallResentOnce(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.expire()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatalf("Account after expiry: %v", err)
	}

	if opened, _, _ := f.stats(); opened != 2 {
		t.Fatalf("opened %d sessions, want 2", opened)
	}

	if n := f.count("GET /session/"); n != 3 {
		t.Fatalf("sent GET /session/ %d times, want 3 (one, then a 401 and its resend)", n)
	}
}

func TestA401OnTheResendIsUnauthorized(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The held session is refused, and so is the fresh one.
	f.script("GET /session/", http.StatusUnauthorized, fixture(t, "error_401.json"))
	f.script("GET /session/", http.StatusUnauthorized, fixture(t, "error_401.json"))

	_, err := p.Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("Account = %v, want ErrUnauthorized", err)
	}

	if n := f.count("GET /session/"); n != 3 {
		t.Fatalf("sent GET /session/ %d times, want 3: no second resend", n)
	}
}

func TestCloseEndsTheSessionAndALaterCallOpensANewOne(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("Close without a session: %v", err)
	}

	if n := f.count("DELETE /session/"); n != 0 {
		t.Fatalf("Close without a session sent %d requests", n)
	}

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	if opened, closed, live := f.stats(); opened != 1 || closed != 1 || live != 0 {
		t.Fatalf("opened %d, closed %d, live %d sessions, want 1, 1, 0", opened, closed, live)
	}

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	if opened, _, _ := f.stats(); opened != 2 {
		t.Fatalf("opened %d sessions, want 2", opened)
	}
}

func TestClosingAnExpiredSessionSucceeds(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.expire()

	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("Close of an expired session = %v", err)
	}
}

// gate holds each session opening in the transport until released.
type gate struct {
	next    http.RoundTripper
	arrived chan struct{}
	release chan struct{}
}

func (g *gate) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && r.URL.Path == "/session/" {
		g.arrived <- struct{}{}
		<-g.release
	}

	return g.next.RoundTrip(r)
}

func TestCloseAlsoClosesASessionBeingOpened(t *testing.T) {
	f := newFake(t)
	g := &gate{next: f.srv.Client().Transport, arrived: make(chan struct{}, 1), release: make(chan struct{})}
	p := f.provider(dnsprovider.WithHTTPClient(&http.Client{Transport: g}))

	called := make(chan struct{})

	go func() {
		defer close(called)

		_, _ = p.Account(context.Background())
	}()

	<-g.arrived

	closed := make(chan error, 1)

	go func() { closed <- p.Close(context.Background()) }()

	// Close waits for the opening to end; a Close that does not returns
	// while it is still held.
	var err error
	select {
	case err = <-closed:
		close(g.release)
	case <-time.After(100 * time.Millisecond):
		close(g.release)

		err = <-closed
	}

	<-called

	if err != nil {
		t.Fatalf("Close = %v", err)
	}

	if _, n, _ := f.stats(); n != 1 {
		t.Fatalf("Close closed %d sessions, want the one opened alongside it", n)
	}
}

func TestASessionLimitRefusalIsRateLimited(t *testing.T) {
	f := newFake(t)
	f.script("POST /session/", http.StatusTooManyRequests, fixture(t, "session_open_limit.json"))

	_, err := f.provider().Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrRateLimited) {
		t.Fatalf("Account = %v, want ErrRateLimited", err)
	}
}
