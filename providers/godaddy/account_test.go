package godaddy_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/godaddy"
)

func account(t *testing.T, p dnsprovider.Provider) (dnsprovider.AccountInfo, error) {
	t.Helper()

	return p.Account(context.Background())
}

func TestAccountReadsActiveDomainsUntilOneNamesTheAccountsNameserverPair(t *testing.T) {
	api := &gdAPI{pageSize: 1, domains: []map[string]any{
		domain("elsewhere.example", "cruz.ns.cloudflare.com", "dee.ns.cloudflare.com"),
		domain("a.example", "NS44.DOMAINCONTROL.COM.", "ns43.domaincontrol.com"),
		domain("b.example", "ns43.domaincontrol.com", "ns44.domaincontrol.com"),
	}}

	info, err := account(t, newProvider(t, api))
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	want := dnsprovider.AccountInfo{Nameservers: []string{"ns43.domaincontrol.com", "ns44.domaincontrol.com"}}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("Account = %+v, want %+v", info, want)
	}

	reqs := api.Requests()
	if len(reqs) != 2 {
		t.Errorf("Account sent %v, want two pages: it stops at the first GoDaddy-hosted domain", reqs)
	}

	for _, u := range reqs {
		if u.Path != "/v1/domains" || u.Query().Get("statuses") != "ACTIVE" {
			t.Errorf("Account sent %s, want GET /v1/domains of ACTIVE domains", u)
		}
	}
}

func TestAccountWithoutGoDaddyNameserversHasNone(t *testing.T) {
	for name, domains := range map[string][]map[string]any{
		"no domains":          nil,
		"delegated elsewhere": {domain("elsewhere.example", "cruz.ns.cloudflare.com", "dee.ns.cloudflare.com")},
	} {
		t.Run(name, func(t *testing.T) {
			info, err := account(t, newProvider(t, &gdAPI{domains: domains}))
			if err != nil {
				t.Fatalf("Account: %v", err)
			}

			if info.Nameservers != nil {
				t.Errorf("Nameservers = %v, want none", info.Nameservers)
			}
		})
	}
}

func TestAccountWithABadKeyIsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusUnauthorized, "UNABLE_TO_AUTHENTICATE", "Unable to authenticate")
	}))
	t.Cleanup(srv.Close)

	p, err := godaddy.New(testConfig, dnsprovider.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := account(t, p); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("Account err = %v, want ErrUnauthorized", err)
	}
}
