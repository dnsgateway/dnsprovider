package vultr_test

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
	"github.com/dnsgateway/dnsprovider/providers/vultr"
)

const apiKey = "EXAMPLEKEYVULTRSECRET0123456789AB"

func TestConstructionValidatesLocallyWithoutContactingAPI(t *testing.T) {
	for _, key := range []string{"", "  ", apiKey + "\r\n", apiKey + " X"} {
		_, err := vultr.New(vultr.Config{APIKey: key})
		if err == nil || strings.Contains(err.Error(), apiKey) {
			t.Fatalf("invalid API key %q accepted or exposed: %v", key, err)
		}
	}
	f := vultr.Factory()
	if !reflect.DeepEqual(f.Fields, []dnsprovider.Field{{Name: "api_key", Label: "API key", Secret: true}}) {
		t.Fatalf("fields: %+v", f.Fields)
	}
	if len(f.Capabilities) != 0 {
		t.Fatalf("capabilities: %v", f.Capabilities)
	}
	opts := []dnsprovider.Option{dnsprovider.WithHTTPClient(nonet.Client(t))}
	if _, err := vultr.New(vultr.Config{APIKey: apiKey}, opts...); err != nil {
		t.Fatal(err)
	}
	if _, err := f.New(map[string]string{"api_key": apiKey}, opts...); err != nil {
		t.Fatalf("factory construction: %v", err)
	}
	if _, err := f.New(map[string]string{}); err == nil {
		t.Fatal("missing API key accepted")
	}
	if _, err := f.New(map[string]string{"api_key": apiKey, "apikey": apiKey}); err == nil || strings.Contains(err.Error(), apiKey) {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestTypedAndFactoryConstructorsHaveEquivalentPublicBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+apiKey {
			t.Error("configured API key missing")
		}
		if r.URL.Path != "/v2/account" {
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
		fmt.Fprint(w, accountFixture)
	}))
	defer server.Close()
	opts := []dnsprovider.Option{dnsprovider.WithBaseURL(server.URL + "/v2/"), dnsprovider.WithHTTPClient(server.Client())}
	typed, err := vultr.New(vultr.Config{APIKey: apiKey}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	fromFields, err := vultr.Factory().New(map[string]string{"api_key": apiKey}, opts...)
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
	p, err := vultr.New(vultr.Config{APIKey: apiKey}, dnsprovider.WithBaseURL(server.URL), dnsprovider.WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("client timeout: %v", err)
	}
}
