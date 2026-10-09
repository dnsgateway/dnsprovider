package dnsimple_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/dnsimple"
)

func TestConstructionValidatesLocallyWithoutContactingAPI(t *testing.T) {
	for _, id := range []string{"", "0", "-1", "1/other", " 12", "01", "18446744073709551616"} {
		if _, err := dnsimple.New(dnsimple.Config{Token: "secret", AccountID: id}); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("invalid AccountID accepted or secret exposed: %q, %v", id, err)
		}
	}
	if _, err := dnsimple.New(dnsimple.Config{AccountID: "12"}); err == nil {
		t.Fatal("missing token accepted")
	}
	f := dnsimple.Factory()
	if !reflect.DeepEqual(f.Fields, []dnsprovider.Field{{Name: "token", Label: "API token", Secret: true}, {Name: "account_id", Label: "Account ID"}}) {
		t.Fatalf("fields: %+v", f.Fields)
	}
	opts := []dnsprovider.Option{dnsprovider.WithHTTPClient(nonet.Client(t))}
	_, err := dnsimple.New(dnsimple.Config{Token: "secret", AccountID: "12"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.New(map[string]string{"token": "secret", "account_id": "12"}, opts...)
	if err != nil {
		t.Fatalf("factory construction: %v", err)
	}
	if _, err := f.New(map[string]string{"token": "secret", "account_id": "12", "typo": "secret"}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestTypedAndFactoryConstructorsHaveEquivalentPublicBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("configured token missing")
		}
		switch r.URL.Path {
		case "/whoami":
			fmt.Fprint(w, `{"data":{"account":{"id":12},"user":null}}`)
		case "/accounts":
			fmt.Fprint(w, `{"data":[{"id":12,"name":"chosen"}]}`)
		case "/12/zones":
			fmt.Fprint(w, `{"data":[],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
		default:
			t.Errorf("unexpected Account scope: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	opts := []dnsprovider.Option{dnsprovider.WithBaseURL(server.URL), dnsprovider.WithHTTPClient(server.Client())}
	typed, err := dnsimple.New(dnsimple.Config{Token: "secret", AccountID: "12"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	fromFields, err := dnsimple.Factory().New(map[string]string{"token": "secret", "account_id": "12"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	want := dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: "12", Name: "chosen"}}
	for name, p := range map[string]dnsprovider.Provider{"typed": typed, "factory": fromFields} {
		t.Run(name, func(t *testing.T) {
			got, err := p.Account(context.Background())
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("Account: %+v %v", got, err)
			}
		})
	}
}
