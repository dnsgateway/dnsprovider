package netim_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/netim"
)

// leaks reports which credential shows in s.
func leaks(s string) []string {
	basic := base64.StdEncoding.EncodeToString([]byte(resellerID + ":" + secret))

	var found []string

	for _, c := range []string{secret, basic, "00000000000000000000000000fake01", "00000000000000000000000000fake02"} {
		if strings.Contains(s, c) {
			found = append(found, c)
		}
	}

	return found
}

func TestNoCredentialShowsInErrorsOrLogs(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte(resellerID + ":" + secret))
	echo := fmt.Sprintf(`{"message":"refused %s, Basic %s, Bearer 00000000000000000000000000fake01"}`, secret, basic)

	f := newFake(t)

	var logs bytes.Buffer
	p := f.provider(dnsprovider.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))

	// A read answered 503 is retried, and logged, before it fails.
	for range 3 {
		f.script("GET /session/", http.StatusServiceUnavailable, echo)
	}

	_, err := p.Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Account = %v, want a 503 APIError", err)
	}

	if logs.Len() == 0 {
		t.Fatal("the retries logged nothing")
	}

	if found := leaks(fmt.Sprint(err, api.Messages, logs.String())); found != nil {
		t.Fatalf("credentials %q show in %v / %s", found, err, logs.String())
	}
}

func TestNoCredentialShowsInARefusedSessionOpening(t *testing.T) {
	basic := base64.StdEncoding.EncodeToString([]byte(resellerID + ":" + secret))

	f := newFake(t)
	f.script("POST /session/", http.StatusBadRequest, fmt.Sprintf(`{"message":"bad %s %s"}`, secret, basic))

	_, err := f.provider().Account(context.Background())
	if err == nil {
		t.Fatal("Account succeeded")
	}

	if found := leaks(err.Error()); found != nil {
		t.Fatalf("credentials %q show in %v", found, err)
	}
}

// echoTransport fails every request with an error holding its
// Authorization header.
type echoTransport struct{ next http.RoundTripper }

func (e echoTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return nil, fmt.Errorf("transport failed with %s", r.Header.Get("Authorization"))
	}

	return e.next.RoundTrip(r)
}

func TestNoSessionTokenShowsInATransportError(t *testing.T) {
	f := newFake(t)

	p, err := netim.New(netim.Config{ID: resellerID, Secret: secret}, dnsprovider.WithBaseURL(f.srv.URL), dnsprovider.WithHTTPClient(&http.Client{Transport: echoTransport{f.srv.Client().Transport}}))
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.Account(context.Background())
	if err == nil {
		t.Fatal("Account succeeded")
	}

	if found := leaks(err.Error()); found != nil {
		t.Fatalf("credentials %q show in %v", found, err)
	}
}
