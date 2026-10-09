package gandi_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestConstructorsValidateLocallyAndPreserveOptions(t *testing.T) {
	calls := 0
	client := &http.Client{Timeout: 13 * time.Second, Transport: transportFunc(func(r *http.Request) (*http.Response, error) { calls++; return nil, r.Context().Err() })}
	opts := []dnsprovider.Option{dnsprovider.WithHTTPClient(client), dnsprovider.WithBaseURL("http://override.invalid")}
	typed, err := gandi.New(gandi.Config{Token: "pat_test"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := gandi.Factory().New(map[string]string{"token": "pat_test"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || client.Timeout != 13*time.Second {
		t.Fatal("constructor contacted network or changed timeout")
	}
	for _, p := range []dnsprovider.Provider{typed, mapped} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := p.Account(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation = %v", err)
		}
	}
	for _, m := range []map[string]string{nil, {"token": ""}, {"token": "pat_test", "unknown": "secret"}, {"token": "secret\n"}} {
		p, err := gandi.Factory().New(m)
		if err == nil || p != nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid fields: %v, %v", p, err)
		}
	}
	fields := gandi.Factory().Fields
	if len(fields) != 1 || fields[0].Name != "token" || !fields[0].Secret {
		t.Fatalf("Fields = %+v", fields)
	}
	limits := dnsprovider.TTLRangeOf(typed)
	if limits.Min != 300 || limits.Max != 2592000 || limits.Auto {
		t.Fatalf("TTL = %+v", limits)
	}
}

func TestUnsupportedWritesMakeNoMutation(t *testing.T) {
	f, p := newService(t)
	for _, r := range []dnsprovider.Record{
		{Name: "@", Type: "URI", Value: `10 1 "https://example.org"`, TTL: 300},
		{Name: "@", Type: "A", Value: "not-an-address", TTL: 300},
		{Name: "@", Type: "A", Value: "192.0.2.1", TTL: 299},
		{Name: "outside.net.", Type: "A", Value: "192.0.2.1", TTL: 300},
	} {
		if _, err := p.CreateRecord(context.Background(), testZone, r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
}
