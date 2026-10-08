package cloudflare_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

// cfTenants scripts the token and the Cloudflare accounts it reaches on
// top of api.
type cfTenants struct {
	// tokenStatus is the token's status; "active" when empty.
	tokenStatus string
	accounts    []map[string]any
}

func cfAccount(id, name string) map[string]any {
	return map[string]any{
		"id":         id,
		"name":       name,
		"type":       "standard",
		"created_on": "2024-01-02T03:04:05.000000Z",
		"settings":   map[string]any{"enforce_twofactor": false},
	}
}

// newProviderIn builds the Provider scoped to the Tenant tenantID, empty
// for none, on api answering for tenants too.
func newProviderIn(t *testing.T, api *cfAPI, tenants cfTenants, tenantID string) *cloudflare.Provider {
	t.Helper()

	next := api.intercept
	api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet {
			switch path := strings.TrimPrefix(r.URL.Path, "/client/v4/"); {
			case path == "user/tokens/verify":
				status := tenants.tokenStatus
				if status == "" {
					status = "active"
				}

				writeResult(w, map[string]any{"id": "tok1", "status": status})

				return true
			case path == "accounts":
				api.page(w, r, tenants.accounts)

				return true
			case strings.HasPrefix(path, "accounts/"):
				for _, a := range tenants.accounts {
					if a["id"] == strings.TrimPrefix(path, "accounts/") {
						writeResult(w, a)

						return true
					}
				}

				writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")

				return true
			}
		}

		return next != nil && next(w, r)
	}

	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)

	p, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: tenantID}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return p
}

var acme = cfTenants{accounts: []map[string]any{cfAccount("acc1", "Acme Ltd"), cfAccount("acc2", "Side project")}}

func TestAccountVerifiesTheTokenAndNamesTheTenant(t *testing.T) {
	api := &cfAPI{}

	info, err := newProviderIn(t, api, acme, "acc1").Account(context.Background())
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	if want := (dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: "acc1", Name: "Acme Ltd"}}); !reflect.DeepEqual(info, want) {
		t.Errorf("Account = %+v, want %+v", info, want)
	}

	if got, want := strings.Join(api.Requests(), " "), "/client/v4/user/tokens/verify?page= /client/v4/accounts/acc1?page="; got != want {
		t.Errorf("requests = %s, want %s", got, want)
	}
}

func TestAccountBeforeATenantIsSetVerifiesTheTokenAlone(t *testing.T) {
	api := &cfAPI{}

	info, err := newProviderIn(t, api, acme, "").Account(context.Background())
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	if !reflect.DeepEqual(info, dnsprovider.AccountInfo{}) {
		t.Errorf("Account = %+v, want no Tenant", info)
	}

	if got, want := strings.Join(api.Requests(), " "), "/client/v4/user/tokens/verify?page="; got != want {
		t.Errorf("requests = %s, want %s", got, want)
	}
}

func TestAccountWithABadTokenIsUnauthorized(t *testing.T) {
	invalid := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
		writeErrors(w, http.StatusUnauthorized, 1000, "Invalid API Token")
	}}

	if _, err := newProviderIn(t, invalid, acme, "acc1").Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("invalid token: err = %v, want ErrUnauthorized", err)
	}

	for _, status := range []string{"disabled", "expired"} {
		tenants := acme
		tenants.tokenStatus = status

		if _, err := newProviderIn(t, &cfAPI{}, tenants, "acc1").Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
			t.Errorf("%s token: err = %v, want ErrUnauthorized", status, err)
		}
	}
}

func TestAccountOfATenantTheTokenCannotReachIsUnauthorized(t *testing.T) {
	if _, err := newProviderIn(t, &cfAPI{}, acme, "other").Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}
