package inwx_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// leaks reports which credential shows in s: the password, the shared
// secret, a TOTP code the fake took or a session cookie.
func (f *fake) leaks(s string) []string {
	f.mu.Lock()
	secrets := append([]string{password, sharedSecret, "fakecookie01", "fakecookie02"}, f.tans...)
	f.mu.Unlock()

	var found []string

	for _, c := range secrets {
		if strings.Contains(s, c) {
			found = append(found, c)
		}
	}

	return found
}

// echo is an answer refusing with every credential in its message and
// reason. The fake fills in the cookie and the TOTP code.
var echo = fmt.Sprintf(`{"code":2005,"msg":"refused %s %s","reason":"cookie {cookie} code {tan}","reasonCode":"{tan}"}`, password, sharedSecret)

func TestNoCredentialShowsInRefusalsOrLogs(t *testing.T) {
	f := newFake(t)
	f.enableTFA()

	var logs bytes.Buffer
	p := f.provider(dnsprovider.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))

	f.script("account.info", http.StatusOK, echo)

	_, err := p.Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.As(err, &api) {
		t.Fatalf("Account = %v, want an APIError", err)
	}

	if f.count("account.unlock") != 1 {
		t.Fatal("the session was not unlocked")
	}

	if found := f.leaks(fmt.Sprint(err, api.Messages, logs.String())); found != nil {
		t.Fatalf("credentials %q show in %v / %s", found, err, logs.String())
	}
}

func TestNoCredentialShowsInANon200Answer(t *testing.T) {
	f := newFake(t)
	f.enableTFA()
	f.script("account.info", http.StatusInternalServerError, echo)

	_, err := f.provider().Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusInternalServerError {
		t.Fatalf("Account = %v, want a 500 APIError", err)
	}

	if found := f.leaks(fmt.Sprint(err, api.Messages)); found != nil {
		t.Fatalf("credentials %q show in %v", found, err)
	}
}

func TestNoCredentialShowsInARefusedLoginOrUnlock(t *testing.T) {
	for _, method := range []string{"account.login", "account.unlock"} {
		f := newFake(t)
		f.enableTFA()
		f.script(method, http.StatusOK, echo)

		_, err := f.provider().Account(context.Background())
		if err == nil {
			t.Fatalf("%s refused: Account succeeded", method)
		}

		if found := f.leaks(err.Error()); found != nil {
			t.Fatalf("%s refused: credentials %q show in %v", method, found, err)
		}
	}
}

// echoTransport fails every request carrying a session cookie with an
// error holding the cookie and the request body.
type echoTransport struct{ next http.RoundTripper }

func (e echoTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if c := r.Header.Get("Cookie"); c != "" {
		return nil, fmt.Errorf("transport failed with %s", c)
	}

	return e.next.RoundTrip(r)
}

func TestNoCookieShowsInATransportError(t *testing.T) {
	f := newFake(t)

	_, err := f.provider(dnsprovider.WithHTTPClient(&http.Client{Transport: echoTransport{f.srv.Client().Transport}})).Account(context.Background())
	if err == nil {
		t.Fatal("Account succeeded")
	}

	if !strings.Contains(err.Error(), "transport failed") {
		t.Fatalf("Account = %v, want the transport error", err)
	}

	if found := f.leaks(err.Error()); found != nil {
		t.Fatalf("credentials %q show in %v", found, err)
	}
}
