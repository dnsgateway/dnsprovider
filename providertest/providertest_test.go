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

	st, err := dnsprovider.ZoneStatusOf(ctx, p, z)
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

func newFake(t *testing.T, fake *providertest.Provider) dnsprovider.Provider {
	t.Helper()

	p, err := fake.Factory().New(map[string]string{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func TestZonesAreFilteredAndRecordTheFilter(t *testing.T) {
	fake := providertest.New().
		AddZone(dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingActive}).
		AddZone(dnsprovider.Zone{ID: "z2", Name: "other.org", State: dnsprovider.HostingPending})
	p := newFake(t, fake)

	f := dnsprovider.ZoneFilter{Contains: "AMPLE"}

	zones, err := p.Zones(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.Zone{{ID: "z1", Name: "example.com", State: dnsprovider.HostingActive}}
	if !reflect.DeepEqual(zones, want) {
		t.Errorf("Zones = %+v, want %+v", zones, want)
	}

	if calls := fake.Calls(); calls[len(calls)-1].Op != providertest.OpZones || calls[len(calls)-1].ZoneFilter != f {
		t.Errorf("last call = %+v, want Zones with the filter", calls[len(calls)-1])
	}
}

func TestSetHostingStateChangesAScriptedZone(t *testing.T) {
	fake := providertest.New().AddZone(dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingPending})
	fake.SetHostingState("z1", dnsprovider.HostingActive)

	zones, err := newFake(t, fake).Zones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if len(zones) != 1 || zones[0].State != dnsprovider.HostingActive {
		t.Errorf("Zones = %+v, want example.com Active", zones)
	}
}

func TestZoneReadsOneScriptedZoneByName(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingMoved, Nameservers: []string{"ns1.example.net"}}
	fake := providertest.New().AddZone(z).AddZone(dnsprovider.Zone{ID: "z2", Name: "shop.example.com"})
	p := newFake(t, fake)

	got, err := p.Zone(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, z) {
		t.Errorf("Zone = %+v, want %+v", got, z)
	}

	if _, err := p.Zone(context.Background(), "example"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Zone(example) error = %v, want ErrNotFound", err)
	}

	if calls := fake.Calls(); calls[len(calls)-1].Op != providertest.OpZone || calls[len(calls)-1].Zone.Name != "example" {
		t.Errorf("last call = %+v, want Zone with the name asked for", calls[len(calls)-1])
	}
}

func TestZoneStatusIsReadOnlyOnceScripted(t *testing.T) {
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}
	fake := providertest.New().AddZone(z)

	if _, ok := newFake(t, fake).(dnsprovider.ZoneStatusReader); ok {
		t.Error("an unscripted fake reads Zone Status")
	}

	want := dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.Off}
	fake.SetZoneStatus("z1", want)

	got, err := dnsprovider.ZoneStatusOf(ctx, newFake(t, fake), z)
	if err != nil || got != want {
		t.Errorf("Zone Status = %+v, %v; want %+v", got, err, want)
	}

	if calls := fake.Calls(); calls[len(calls)-1].Op != providertest.OpZoneStatus {
		t.Errorf("last call = %+v, want ZoneStatus", calls[len(calls)-1])
	}

	fake.SetTenants(dnsprovider.Tenant{ID: "t1"})
	p := newFake(t, fake)

	if _, ok := p.(dnsprovider.ZoneStatusReader); !ok || !dnsprovider.CanListTenants(p) {
		t.Error("a fake with scripted Zone Status and Tenants does not do both")
	}
}

func TestSetHostingStateHoldsForAZoneAddedLaterUntilItIsRemoved(t *testing.T) {
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingPending}

	fake := providertest.New().SetHostingState("z1", dnsprovider.HostingMoved).AddZone(z)
	p := newFake(t, fake)

	if got, err := p.Zone(ctx, "example.com"); err != nil || got.State != dnsprovider.HostingMoved {
		t.Errorf("Zone = %+v, %v; want example.com Moved", got, err)
	}

	fake.RemoveZone("z1")
	fake.AddZone(z)

	if got, err := p.Zone(ctx, "example.com"); err != nil || got.State != dnsprovider.HostingPending {
		t.Errorf("re-added Zone = %+v, %v; want example.com Pending, as added", got, err)
	}
}
