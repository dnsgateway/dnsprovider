package inwx_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/inwx"
)

// The fake's TOTP is RFC 6238's: its SHA-1 test vector at 59 seconds is
// 94287082, of which six digits are kept.
func TestTheFakeComputesRFC6238Codes(t *testing.T) {
	if got := totp([]byte("12345678901234567890"), 59/30); got != "287082" {
		t.Fatalf("totp = %s, want 287082", got)
	}
}

func TestAccountLogsInAndReturnsTheCustomerAsTenant(t *testing.T) {
	f := newFake(t)
	f.zones = nil // an empty Account

	a, err := f.provider().Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if a.Tenant.ID != "100001" || a.Nameservers != nil {
		t.Fatalf("Account = %+v, want customer 100001 as Tenant", a)
	}

	if got := f.methodsCalled(); !slices.Equal(got, []string{"account.login", "account.info"}) {
		t.Fatalf("calls = %v, want a login and account.info", got)
	}

	if p := f.params("account.login"); p["user"] != username || p["pass"] != password {
		t.Fatalf("login params = %v", p)
	}
}

func TestAccountRefusesBadCredentials(t *testing.T) {
	f := newFake(t)

	_, err := f.providerWith(inwx.Config{Username: username, Password: "wrong"}).Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || !errors.As(err, &api) || !strings.Contains(err.Error(), "2200") {
		t.Fatalf("Account = %v, want ErrUnauthorized with code 2200", err)
	}

	if n := f.count("account.login"); n != 1 {
		t.Fatalf("logged in %d times, want 1", n)
	}
}

func TestCallsReuseTheSession(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	for range 3 {
		if _, err := p.Account(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	if logins, _, _ := f.stats(); logins != 1 {
		t.Fatalf("logged in %d times, want 1", logins)
	}
}

func TestConcurrentFirstCallsLogInOnce(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := p.Account(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}

	wg.Wait()

	if logins, _, _ := f.stats(); logins != 1 {
		t.Fatalf("logged in %d times, want 1", logins)
	}
}

func TestATwoFactorAccountIsUnlockedWithATOTPCode(t *testing.T) {
	f := newFake(t)
	f.enableTFA()

	if _, err := f.provider().Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	if got := f.methodsCalled(); !slices.Equal(got, []string{"account.login", "account.unlock", "account.info"}) {
		t.Fatalf("calls = %v, want login, unlock and account.info", got)
	}
}

func TestATwoFactorAccountWithoutASharedSecretIsUnauthorized(t *testing.T) {
	f := newFake(t)
	f.enableTFA()

	_, err := f.providerWith(inwx.Config{Username: username, Password: password}).Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || !strings.Contains(err.Error(), "shared_secret") {
		t.Fatalf("Account = %v, want ErrUnauthorized naming shared_secret", err)
	}

	if n := f.count("account.unlock"); n != 0 {
		t.Fatalf("sent %d unlocks without a shared secret", n)
	}

	if n := f.count("account.info"); n != 0 {
		t.Fatal("sent a call with a locked session")
	}
}

func TestAWrongSharedSecretIsUnauthorized(t *testing.T) {
	f := newFake(t)
	f.enableTFA()

	_, err := f.providerWith(inwx.Config{Username: username, Password: password, SharedSecret: "GEZDGNBVGY3TQOJQ"}).Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("Account = %v, want ErrUnauthorized", err)
	}
}

func TestAnUnlockRefusedWithAnotherCodeIsUnauthorized(t *testing.T) {
	f := newFake(t)
	f.enableTFA()
	f.scriptCode("account.unlock", 2003, "tan missing")

	_, err := f.provider().Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || !errors.As(err, &api) || !strings.Contains(err.Error(), "tan missing") {
		t.Fatalf("Account = %v, want ErrUnauthorized with the refusal", err)
	}
}

func TestALoginAnswerWithTFAAsANumberZeroNeedsNoUnlock(t *testing.T) {
	f := newFake(t)
	f.handle("account.login", func(r *request) string {
		f.login(r)

		return `{"code":1000,"msg":"Command completed successfully","resData":{"customerId":100001,"tfa":0}}`
	})

	if _, err := f.provider().Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	if n := f.count("account.unlock"); n != 0 {
		t.Fatalf("sent %d unlocks", n)
	}
}

func TestAnExpiredSessionIsReopenedAndTheCallResentOnce(t *testing.T) {
	f := newFake(t)
	f.enableTFA()

	p := f.provider()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.expire()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatalf("Account after expiry: %v", err)
	}

	if logins, _, _ := f.stats(); logins != 2 {
		t.Fatalf("logged in %d times, want 2", logins)
	}

	if n := f.count("account.info"); n != 3 {
		t.Fatalf("sent account.info %d times, want 3 (one, then a refusal and its resend)", n)
	}
}

func TestARefusalOfTheFreshSessionIsUnauthorized(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The held session is refused, and so is the fresh one.
	f.scriptCode("account.info", 2200, "")
	f.scriptCode("account.info", 2200, "")

	_, err := p.Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("Account = %v, want ErrUnauthorized", err)
	}

	if n := f.count("account.info"); n != 3 {
		t.Fatalf("sent account.info %d times, want 3: no second resend", n)
	}
}

func TestCloseLogsOutAndALaterCallLogsInAgain(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("Close without a session: %v", err)
	}

	if n := f.count("account.logout"); n != 0 {
		t.Fatalf("Close without a session sent %d logouts", n)
	}

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	if logins, logouts, live := f.stats(); logins != 1 || logouts != 1 || live != 0 {
		t.Fatalf("logins %d, logouts %d, live %d, want 1, 1, 0", logins, logouts, live)
	}

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	if logins, _, _ := f.stats(); logins != 2 {
		t.Fatalf("logged in %d times, want 2", logins)
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

func TestASessionLimitRefusalIsRateLimited(t *testing.T) {
	f := newFake(t)
	f.maxSessions = 1
	f.sessions["someone-else"] = true

	_, err := f.provider().Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrRateLimited) {
		t.Fatalf("Account = %v, want ErrRateLimited", err)
	}

	if errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("Account = %v, want ErrRateLimited alone", err)
	}
}

func TestARefusalAtLoginIsUnauthorizedWithItsDetails(t *testing.T) {
	for _, code := range []int{2003, 2303, 2400, 2501} {
		f := newFake(t)
		f.scriptCode("account.login", code, "account locked")

		_, err := f.provider().Account(context.Background())

		var api *dnsprovider.APIError
		if !errors.Is(err, dnsprovider.ErrUnauthorized) || !errors.As(err, &api) || !strings.Contains(err.Error(), "account locked") {
			t.Fatalf("Account after a %d at login = %v, want ErrUnauthorized with the refusal", code, err)
		}

		if errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("Account after a %d at login = %v, want ErrUnauthorized alone", code, err)
		}
	}
}

func TestASuppliedClientWithoutAJarWorksAndAJarIsNotUsed(t *testing.T) {
	f := newFake(t)

	if _, err := f.provider(dnsprovider.WithHTTPClient(&http.Client{Transport: f.srv.Client().Transport})).Account(context.Background()); err != nil {
		t.Fatalf("a client without a jar: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	p := f.provider(dnsprovider.WithHTTPClient(&http.Client{Transport: f.srv.Client().Transport, Jar: jar}))
	if _, err := p.Account(context.Background()); err != nil {
		t.Fatalf("a client with a jar: %v", err)
	}

	if got := jar.Cookies(mustURL(t, f.srv.URL+"/jsonrpc/")); len(got) != 0 {
		t.Fatalf("the session cookie went into the client's jar: %v", got)
	}
}
