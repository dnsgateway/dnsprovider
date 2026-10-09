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

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/digitalocean"
)

// accountFixture is the documented GET /v2/account answer.
const accountFixture = `{"account":{"droplet_limit":25,"floating_ip_limit":5,"email":"sammy@example.com","name":"Sammy the Shark","uuid":"b6fr89dbf6d9156cace5f3c78dc9851d957381ef","email_verified":true,"status":"active","status_message":" ","team":{"uuid":"5df3e3004a17e242b7c20ca6c9fc25b701a47ece","name":"My Team"}}}`

var wantAccount = dnsprovider.AccountInfo{
	Tenant:      dnsprovider.Tenant{ID: "5df3e3004a17e242b7c20ca6c9fc25b701a47ece", Name: "My Team"},
	Nameservers: []string{"ns1.digitalocean.com", "ns2.digitalocean.com", "ns3.digitalocean.com"},
}

// provider builds the adapter against a local server speaking API v2 under
// /v2, as the production endpoint does.
func provider(t *testing.T, h http.HandlerFunc) *digitalocean.Provider {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dop_v1_secret" {
			t.Error("Bearer token missing")
		}
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}))
	t.Cleanup(s.Close)
	p, err := digitalocean.New(digitalocean.Config{Token: "dop_v1_secret"}, dnsprovider.WithBaseURL(s.URL+"/v2"), dnsprovider.WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccountVerifiesTokenWithoutReadingZones(t *testing.T) {
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

func TestAccountWithoutTeamUsesTheAuthenticatedAccount(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"account":{"email":"sammy@example.com","name":"","uuid":"b6fr89dbf6d9156cace5f3c78dc9851d957381ef","status":"active"}}`)
	})
	got, err := p.Account(context.Background())
	if err != nil || got.Tenant != (dnsprovider.Tenant{ID: "b6fr89dbf6d9156cace5f3c78dc9851d957381ef", Name: "sammy@example.com"}) {
		t.Fatalf("Account: %+v %v", got, err)
	}
}

func TestAccountDistinguishesDeniedScopesFromMalformedAnswers(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		kind   error
	}{
		{http.StatusUnauthorized, `{"id":"unauthorized","message":"Unable to authenticate you."}`, dnsprovider.ErrUnauthorized},
		{http.StatusForbidden, `{"id":"Forbidden","message":"You are not authorized to perform this operation"}`, dnsprovider.ErrUnauthorized},
		{http.StatusOK, `{}`, nil},
		{http.StatusOK, `{"account":{"uuid":""}}`, nil},
	} {
		t.Run(fmt.Sprint(tc.status, tc.body), func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			_, err := p.Account(context.Background())
			if err == nil || (tc.kind != nil && !errors.Is(err, tc.kind)) || errors.Is(err, dnsprovider.ErrNotFound) || strings.Contains(err.Error(), "dop_v1_secret") {
				t.Fatalf("Account: %v", err)
			}
			if tc.kind == nil && errors.Is(err, dnsprovider.ErrUnauthorized) {
				t.Fatalf("malformed answer classified as denied: %v", err)
			}
		})
	}
}
