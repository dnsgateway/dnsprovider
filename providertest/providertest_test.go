package providertest_test

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

func TestReaddedZoneStartsClean(t *testing.T) {
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}

	fake := providertest.New().AddZone(z).SetSerial("z1", 7)
	fake.SetZoneStatus("z1", dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On})
	fake.RemoveZone("z1")
	fake.AddZone(z)

	p, err := fake.Factory().New(map[string]string{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}

	rs, err := p.Records(ctx, z)
	if err != nil {
		t.Fatal(err)
	}

	if rs.Serial != 0 {
		t.Errorf("serial = %d after re-adding the Zone, want 0", rs.Serial)
	}

	st, err := p.ZoneStatus(ctx, z)
	if err != nil {
		t.Fatal(err)
	}

	if st != (dnsprovider.ZoneStatus{}) {
		t.Errorf("Zone Status = %+v after re-adding the Zone, want none", st)
	}
}

func TestFactoryRecordsTheFieldsItBuildsFrom(t *testing.T) {
	fake := providertest.New()

	r := dnsprovider.Registry{"fake": fake.Factory()}

	if _, err := r.New("fake", map[string]string{"token": "t1"}); err != nil {
		t.Fatal(err)
	}

	calls := fake.Calls()
	if len(calls) != 1 || calls[0].Op != providertest.OpNew || !maps.Equal(calls[0].Fields, map[string]string{"token": "t1"}) {
		t.Fatalf("calls = %+v, want one New with token t1", calls)
	}

	if f := fake.Factory().Fields; len(f) != 1 || f[0].Name != "token" || !f[0].Secret {
		t.Errorf("Fields = %+v, want one secret token", f)
	}
}

func TestFactoryReturnsTheScriptedFailure(t *testing.T) {
	boom := errors.New("boom")
	fake := providertest.New()
	fake.Fail(providertest.OpNew, boom)

	if _, err := fake.Factory().New(map[string]string{"token": "t"}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestFactoryRefusesMissingAndUnknownFields(t *testing.T) {
	for name, fields := range map[string]map[string]string{
		"no token":      {},
		"empty token":   {"token": ""},
		"unknown field": {"token": "t", "secret": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := providertest.New().Factory().New(fields); err == nil {
				t.Fatalf("Factory built a Provider from %v", fields)
			}
		})
	}
}

func TestAccountIsTheScriptedAccountInfo(t *testing.T) {
	fake := providertest.New()
	want := dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: "t1", Name: "Acme"}, Nameservers: []string{"ns1.example.net"}}
	fake.SetAccount(want)

	p, err := fake.Factory().New(map[string]string{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}

	got, err := p.Account(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Account = %+v, %v; want %+v", got, err, want)
	}

	boom := errors.New("boom")
	fake.Fail(providertest.OpAccount, boom)

	if _, err := p.Account(context.Background()); !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}

func TestTenantsAreListedOnlyOnceScripted(t *testing.T) {
	fake := providertest.New()

	p, err := fake.Factory().New(map[string]string{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}

	if dnsprovider.CanListTenants(p) {
		t.Error("an unscripted fake lists Tenants")
	}

	want := []dnsprovider.Tenant{{ID: "t1", Name: "Acme"}, {ID: "t2", Name: "Side"}}
	fake.SetTenants(want...)

	p, err = fake.Factory().New(map[string]string{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}

	l, ok := p.(dnsprovider.TenantLister)
	if !ok {
		t.Fatal("a fake with scripted Tenants does not list them")
	}

	got, err := l.Tenants(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("Tenants = %+v, %v; want %+v", got, err, want)
	}

	if calls := fake.Calls(); calls[len(calls)-1].Op != providertest.OpTenants {
		t.Errorf("last call = %+v, want Tenants", calls[len(calls)-1])
	}
}

func TestOptionalInterfacesAreScriptedIndependently(t *testing.T) {
	fake := providertest.New()

	p, err := fake.Factory().New(map[string]string{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}

	if r := dnsprovider.TTLRangeOf(p); r != dnsprovider.DefaultTTLRange {
		t.Errorf("unscripted TTL range = %+v, want the default", r)
	}

	if types := dnsprovider.ProxiableTypesOf(p); types != nil {
		t.Errorf("unscripted proxiable types = %v, want none", types)
	}

	fake.SetTTLRange(60, 3600)
	fake.SetAutoTTL(true)
	fake.SetProxiableTypes("A")
	fake.SetTenants(dnsprovider.Tenant{ID: "t1"})

	p, err = fake.Factory().New(map[string]string{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}

	if r, want := dnsprovider.TTLRangeOf(p), (dnsprovider.TTLRange{Min: 60, Max: 3600, Auto: true}); r != want {
		t.Errorf("TTL range = %+v, want %+v", r, want)
	}

	if types := dnsprovider.ProxiableTypesOf(p); !reflect.DeepEqual(types, []string{"A"}) {
		t.Errorf("proxiable types = %v, want [A]", types)
	}

	if !dnsprovider.CanListTenants(p) {
		t.Error("a fake with scripted options and Tenants does not list Tenants")
	}
}
