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
	// owner is the Cloudflare account that owns an account-owned token,
	// which reaches that account alone; empty for a user's token.
	owner string
	// listForbidden answers the account list 403, as for a token
	// without Account Settings Read, such as a DNS-only one.
	listForbidden bool
	accounts      []map[string]any
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

	verified := func(w http.ResponseWriter) {
		status := tenants.tokenStatus
		if status == "" {
			status = "active"
		}

		writeResult(w, map[string]any{"id": "tok1", "status": status})
	}

	// Each verify endpoint knows only its own kind of token.
	invalid := func(w http.ResponseWriter) {
		writeErrors(w, http.StatusUnauthorized, 1000, "Invalid API Token")
	}

	next := api.intercept
	api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet {
			return next != nil && next(w, r)
		}

		path := strings.TrimPrefix(r.URL.Path, "/client/v4/")
		switch {
		case path == "user/tokens/verify":
			if tenants.owner != "" {
				invalid(w)
			} else {
				verified(w)
			}
		case strings.HasPrefix(path, "accounts/") && strings.HasSuffix(path, "/tokens/verify"):
			if id := strings.TrimSuffix(strings.TrimPrefix(path, "accounts/"), "/tokens/verify"); tenants.owner == "" || id != tenants.owner {
				invalid(w)
			} else {
				verified(w)
			}
		case path == "accounts":
			if tenants.listForbidden {
				writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")

				break
			}

			reached := tenants.accounts
			if tenants.owner != "" {
				reached = nil
				for _, a := range tenants.accounts {
					if a["id"] == tenants.owner {
						reached = append(reached, a)
					}
				}
			}

			api.page(w, r, reached)
		case strings.HasPrefix(path, "accounts/"):
			// Reading one account needs Account Settings Read.
			writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")
		default:
			return next != nil && next(w, r)
		}

		return true
	}

	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)

	p, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: tenantID}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return p
}

var acme = cfTenants{accounts: []map[string]any{cfAccount(acc1, "Acme Ltd"), cfAccount(acc2, "Side project")}}

// accountOf returns what Account reports and the requests it sent.
func accountOf(t *testing.T, tenants cfTenants, tenantID string) (dnsprovider.AccountInfo, error, string) {
	t.Helper()

	api := &cfAPI{}
	info, err := newProviderIn(t, api, tenants, tenantID).Account(context.Background())

	return info, err, strings.Join(api.Requests(), " ")
}

func TestAccountOfAUserTokenVerifiesItAndNamesTheTenant(t *testing.T) {
	info, err, reqs := accountOf(t, acme, acc1)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	if want := (dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: acc1, Name: "Acme Ltd"}}); !reflect.DeepEqual(info, want) {
		t.Errorf("Account = %+v, want %+v", info, want)
	}

	want := "/client/v4/accounts/" + acc1 + "/tokens/verify?page= /client/v4/user/tokens/verify?page= /client/v4/accounts?page=1"
	if reqs != want {
		t.Errorf("requests = %s, want %s", reqs, want)
	}
}

func TestAccountOfAnAccountOwnedTokenVerifiesItWithinTheTenant(t *testing.T) {
	tenants := acme
	tenants.owner = acc2

	info, err, reqs := accountOf(t, tenants, acc2)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	if want := (dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: acc2, Name: "Side project"}}); !reflect.DeepEqual(info, want) {
		t.Errorf("Account = %+v, want %+v", info, want)
	}

	if want := "/client/v4/accounts/" + acc2 + "/tokens/verify?page= /client/v4/accounts?page=1"; reqs != want {
		t.Errorf("requests = %s, want %s", reqs, want)
	}
}

func TestAccountOfATokenThatCannotReadAccountsIsTheTenantIDAlone(t *testing.T) {
	for name, owner := range map[string]string{"user token": "", "account-owned token": acc1} {
		t.Run(name, func(t *testing.T) {
			tenants := acme
			tenants.owner = owner
			tenants.listForbidden = true

			info, err, _ := accountOf(t, tenants, acc1)
			if err != nil {
				t.Fatalf("Account: %v", err)
			}

			if want := (dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: acc1}}); !reflect.DeepEqual(info, want) {
				t.Errorf("Account = %+v, want %+v", info, want)
			}
		})
	}
}

func TestAccountBeforeATenantIsSetVerifiesTheTokenAlone(t *testing.T) {
	info, err, reqs := accountOf(t, acme, "")
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	if !reflect.DeepEqual(info, dnsprovider.AccountInfo{}) {
		t.Errorf("Account = %+v, want no Tenant", info)
	}

	if want := "/client/v4/user/tokens/verify?page="; reqs != want {
		t.Errorf("requests = %s, want %s", reqs, want)
	}
}

func TestAccountWithABadTokenIsUnauthorized(t *testing.T) {
	for _, tenantID := range []string{"", acc1} {
		invalid := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
			writeErrors(w, http.StatusUnauthorized, 1000, "Invalid API Token")
		}}

		if _, err := newProviderIn(t, invalid, acme, tenantID).Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
			t.Errorf("invalid token, Tenant %q: err = %v, want ErrUnauthorized", tenantID, err)
		}
	}

	for _, owner := range []string{"", acc1} {
		for _, status := range []string{"disabled", "expired"} {
			tenants := acme
			tenants.owner = owner
			tenants.tokenStatus = status

			if _, err, _ := accountOf(t, tenants, acc1); !errors.Is(err, dnsprovider.ErrUnauthorized) {
				t.Errorf("%s token owned by %q: err = %v, want ErrUnauthorized", status, owner, err)
			}
		}
	}
}

func TestAccountOfATenantTheTokenCannotReachIsUnauthorized(t *testing.T) {
	for name, owner := range map[string]string{"user token": "", "account-owned token": acc2} {
		t.Run(name, func(t *testing.T) {
			tenants := acme
			tenants.owner = owner

			if _, err, _ := accountOf(t, tenants, accOther); !errors.Is(err, dnsprovider.ErrUnauthorized) {
				t.Errorf("err = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestTenantsListsEveryAccountTheTokenReachesBeforeATenantIsSet(t *testing.T) {
	api := &cfAPI{pageSize: 1}
	p := newProviderIn(t, api, acme, "")

	if !dnsprovider.CanListTenants(p) {
		t.Fatal("Cloudflare does not list Tenants")
	}

	tenants, err := p.Tenants(context.Background())
	if err != nil {
		t.Fatalf("Tenants: %v", err)
	}

	want := []dnsprovider.Tenant{{ID: acc1, Name: "Acme Ltd"}, {ID: acc2, Name: "Side project"}}
	if !reflect.DeepEqual(tenants, want) {
		t.Errorf("Tenants = %+v, want %+v", tenants, want)
	}

	if got, want := strings.Join(api.Requests(), " "), "/client/v4/accounts?page=1 /client/v4/accounts?page=2"; got != want {
		t.Errorf("requests = %s, want %s", got, want)
	}
}

func TestTenantsWithABadTokenIsUnauthorized(t *testing.T) {
	api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
		writeErrors(w, http.StatusUnauthorized, 1000, "Invalid API Token")
	}}

	if _, err := newProviderIn(t, api, acme, "").Tenants(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("err = %v, want ErrUnauthorized", err)
	}
}

func TestZonesAreTheTenantsAlone(t *testing.T) {
	api := &cfAPI{pageSize: 1, zones: []map[string]any{cfZone("z1", "example.com"), cfZone("z2", "example.net")}}

	var scopes []string

	api.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/client/v4/zones" {
			scopes = append(scopes, r.URL.Query().Get("account.id"))
		}

		return false
	}

	if _, err := newProviderIn(t, api, acme, acc1).Zones(context.Background(), dnsprovider.ZoneFilter{}); err != nil {
		t.Fatalf("Zones: %v", err)
	}

	if want := []string{acc1, acc1}; !reflect.DeepEqual(scopes, want) {
		t.Errorf("zone lists scoped to account.id %q, want %q", scopes, want)
	}
}

func TestZonesNeedATenant(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}}

	if _, err := newProviderIn(t, api, acme, "").Zones(context.Background(), dnsprovider.ZoneFilter{}); !errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Errorf("err = %v, want ErrNoTenant", err)
	}

	if got := api.Requests(); len(got) != 0 {
		t.Errorf("Zones sent %v without a Tenant, want nothing", got)
	}
}

func TestZoneCallsNeedATenant(t *testing.T) {
	zone := dnsprovider.Zone{ID: "z1", Name: "example.com"}
	api := &cfAPI{
		zones:   []map[string]any{cfZone("z1", "example.com")},
		records: map[string][]map[string]any{"z1": {}},
	}
	p := newProviderIn(t, api, acme, "")
	ctx := context.Background()

	if _, err := p.Zone(ctx, zone.Name); !errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Errorf("Zone: err = %v, want ErrNoTenant", err)
	}

	_, err := p.Records(ctx, zone)
	if !errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Errorf("Records: err = %v, want ErrNoTenant", err)
	}

	cs := dnsprovider.Changeset{Zone: zone, Changes: []dnsprovider.Change{{
		Kind:  dnsprovider.ChangeAdd,
		After: dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300},
	}}}
	if _, err := p.Apply(ctx, cs); !errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Errorf("Apply: err = %v, want ErrNoTenant", err)
	}

	if _, err := p.ZoneStatus(ctx, zone); !errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Errorf("ZoneStatus: err = %v, want ErrNoTenant", err)
	}

	if got := api.Requests(); len(got) != 0 {
		t.Errorf("sent %v without a Tenant, want nothing", got)
	}
}
