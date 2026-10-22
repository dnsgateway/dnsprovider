package infomaniak_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/infomaniak"
)

func TestAccountProvesTheTokenWithOneDomainOfTheList(t *testing.T) {
	f := newFake(t)

	info, err := f.provider().Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if info.Tenant != (dnsprovider.Tenant{}) || info.Nameservers != nil {
		t.Fatalf("Account = %+v, want no Tenant and no nameservers", info)
	}

	q := f.queries("GET /2/domains/domains")
	if len(q) != 1 || q[0].Get("per_page") != "1" || q[0].Has("account_id") {
		t.Fatalf("queries = %v, want one per_page=1 without account_id", q)
	}
}

func TestAccountSucceedsOnAnEmptyAccount(t *testing.T) {
	f := newFake(t)
	f.script("GET /2/domains/domains", http.StatusOK, `{"result":"success","data":[]}`)

	if _, err := f.provider().Account(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAccountIsScopedByTheAccountIDAndReturnsItAsTheTenant(t *testing.T) {
	f := newFake(t)

	info, err := f.providerFor(infomaniak.Config{Token: token, AccountID: accountID}).Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if info.Tenant.ID != accountID {
		t.Fatalf("Tenant = %+v, want ID %s", info.Tenant, accountID)
	}

	if q := f.queries("GET /2/domains/domains"); len(q) != 1 || q[0].Get("account_id") != accountID {
		t.Fatalf("queries = %v, want account_id=%s", q, accountID)
	}
}

func TestAccountRefusesABadTokenOrAMissingScopeAsUnauthorized(t *testing.T) {
	f := newFake(t)

	p, err := infomaniak.New(infomaniak.Config{Token: "wrong"}, dnsprovider.WithBaseURL(f.srv.URL), dnsprovider.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := p.Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("Account with a bad token = %v, want ErrUnauthorized", err)
	}

	f.script("GET /2/domains/domains", http.StatusForbidden, `{"result":"error","error":{"code":"access_denied","description":"SYNTHETIC: missing scope"}}`)

	if _, err := f.provider().Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("Account without the scope = %v, want ErrUnauthorized", err)
	}
}

func TestAccountTreatsAnErrorResultInASuccessAsARefusal(t *testing.T) {
	f := newFake(t)
	f.script("GET /2/domains/domains", http.StatusOK, `{"result":"error","error":{"code":"not_authorized","description":"SYNTHETIC: refused"}}`)

	_, err := f.provider().Account(context.Background())

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || api.StatusCode != 0 || len(api.Messages) == 0 || api.Messages[0] != "not_authorized: SYNTHETIC: refused" {
		t.Fatalf("Account = %v, want an APIError of status 0 with its code", err)
	}
}
