package digitalocean_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/digitalocean"
)

func TestConstructionValidatesLocallyWithoutContactingAPI(t *testing.T) {
	for _, token := range []string{"", "  ", "dop_v1_secret\r\n"} {
		if _, err := digitalocean.New(digitalocean.Config{Token: token}); err == nil || (token != "" && strings.Contains(err.Error(), "secret")) {
			t.Fatalf("invalid token %q accepted or exposed: %v", token, err)
		}
	}
	f := digitalocean.Factory()
	if !reflect.DeepEqual(f.Fields, []dnsprovider.Field{{Name: "token", Label: "API token", Secret: true}}) {
		t.Fatalf("fields: %+v", f.Fields)
	}
	if len(f.Capabilities) != 0 {
		t.Fatalf("capabilities: %v", f.Capabilities)
	}
	opts := []dnsprovider.Option{dnsprovider.WithHTTPClient(nonet.Client(t))}
	if _, err := digitalocean.New(digitalocean.Config{Token: "dop_v1_secret"}, opts...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.New(map[string]string{"token": "dop_v1_secret"}, opts...); err != nil {
		t.Fatalf("factory construction: %v", err)
	}
	if _, err := f.New(map[string]string{}); err == nil {
		t.Fatal("missing token accepted")
	}
	if _, err := f.New(map[string]string{"token": "dop_v1_secret", "tokn": "dop_v1_secret"}); err == nil || strings.Contains(err.Error(), "dop_v1_secret") {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestTypedAndFactoryConstructorsHaveEquivalentPublicBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dop_v1_secret" {
			t.Error("configured token missing")
		}
		if r.URL.Path != "/v2/account" {
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
		fmt.Fprint(w, accountFixture)
	}))
	defer server.Close()
	opts := []dnsprovider.Option{dnsprovider.WithBaseURL(server.URL + "/v2"), dnsprovider.WithHTTPClient(server.Client())}
	typed, err := digitalocean.New(digitalocean.Config{Token: "dop_v1_secret"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	fromFields, err := digitalocean.Factory().New(map[string]string{"token": "dop_v1_secret"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]dnsprovider.Provider{"typed": typed, "factory": fromFields} {
		t.Run(name, func(t *testing.T) {
			got, err := p.Account(context.Background())
			if err != nil || !reflect.DeepEqual(got, wantAccount) {
				t.Fatalf("Account: %+v %v", got, err)
			}
		})
	}
}

func TestSuppliedHTTPClientTimeoutIsRespected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	client := server.Client()
	client.Timeout = 10 * time.Millisecond
	p, err := digitalocean.New(digitalocean.Config{Token: "dop_v1_secret"}, dnsprovider.WithBaseURL(server.URL), dnsprovider.WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("client timeout: %v", err)
	}
}
