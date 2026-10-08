package namecheap_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestAccountChecksTheKeyWithGetBalancesAndNamesBasicDNS(t *testing.T) {
	api := &ncAPI{}

	info, err := newProvider(t, api).Account(context.Background())
	if err != nil {
		t.Fatalf("Account: %v", err)
	}

	want := dnsprovider.AccountInfo{
		Tenant:      dnsprovider.Tenant{ID: "apiuser", Name: "apiuser"},
		Nameservers: []string{"dns1.registrar-servers.com", "dns2.registrar-servers.com"},
	}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("Account = %+v, want %+v", info, want)
	}

	if got := api.Commands(); !slices.Equal(got, []string{"namecheap.users.getBalances"}) {
		t.Errorf("Account sent %v, want one getBalances", got)
	}
}

func TestAccountWithABadKeyIsUnauthorized(t *testing.T) {
	api := &ncAPI{fail: func(string) []ncError { return []ncError{{1011102, "Parameter APIKey is invalid"}} }}

	if _, err := newProvider(t, api).Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("Account err = %v, want ErrUnauthorized", err)
	}
}
