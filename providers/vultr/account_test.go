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

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/vultr"
)

// accountFixture is a GET /v2/account answer, as the official client's
// tests and the API reference show it.
const accountFixture = `{"account":{"balance":-5519.11,"pending_charges":57.03,"last_payment_date":"2014-07-18 15:31:01","last_payment_amount":-1.00,"name":"Test Tester","email":"example@vultr.com","acls":["subscriptions","billing","support","provisioning"]}}`

// wantAccount has no Tenant ID: Vultr's Account answer carries none.
var wantAccount = dnsprovider.AccountInfo{
	Tenant:      dnsprovider.Tenant{Name: "Test Tester"},
	Nameservers: []string{"ns1.vultr.com", "ns2.vultr.com"},
}

// provider builds the adapter against a local server speaking API v2 under
// /v2, as the production endpoint does.
func provider(t *testing.T, h http.HandlerFunc) *vultr.Provider {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+apiKey {
			t.Error("Bearer API key missing")
		}
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}))
	t.Cleanup(s.Close)
	p, err := vultr.New(vultr.Config{APIKey: apiKey}, dnsprovider.WithBaseURL(s.URL+"/v2"), dnsprovider.WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccountVerifiesTheKeyWithoutReadingZones(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v2/account" {
			t.Errorf("Account sent %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, accountFixture)
	})
	got, err := p.Account(context.Background())
	if err != nil || !reflect.DeepEqual(got, wantAccount) {
		t.Fatalf("Account: %+v %v", got, err)
	}
}

func TestAccountWithoutNameUsesTheEmail(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"account":{"balance":0,"pending_charges":0,"name":"","email":"dns@example.com","acls":["dns"]}}`)
	})
	got, err := p.Account(context.Background())
	if err != nil || got.Tenant != (dnsprovider.Tenant{Name: "dns@example.com"}) {
		t.Fatalf("Account: %+v %v", got, err)
	}
}

func TestAccountDistinguishesDeniedKeysFromMalformedAnswers(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		kind   error
		msg    string
	}{
		{http.StatusUnauthorized, `{"error":"Invalid API token.","status":401}`, dnsprovider.ErrUnauthorized, "Invalid API token."},
		// An API key's access control refuses calls from other addresses.
		{http.StatusUnauthorized, `{"error":"Unauthorized IP address: 198.51.100.7","status":401}`, dnsprovider.ErrUnauthorized, "Unauthorized IP address"},
		{http.StatusForbidden, `{"error":"Forbidden","status":403}`, dnsprovider.ErrUnauthorized, "Forbidden"},
		{http.StatusOK, `{}`, nil, ""},
		{http.StatusOK, `{"account":null}`, nil, ""},
		{http.StatusOK, `not json`, nil, ""},
	} {
		t.Run(fmt.Sprint(tc.status, tc.body), func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			_, err := p.Account(context.Background())
			if err == nil || (tc.kind != nil && !errors.Is(err, tc.kind)) || errors.Is(err, dnsprovider.ErrNotFound) || strings.Contains(err.Error(), apiKey) {
				t.Fatalf("Account: %v", err)
			}
			if tc.kind == nil && errors.Is(err, dnsprovider.ErrUnauthorized) {
				t.Fatalf("malformed answer classified as denied: %v", err)
			}
			if !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("the service's message is lost: %v", err)
			}
		})
	}
}
