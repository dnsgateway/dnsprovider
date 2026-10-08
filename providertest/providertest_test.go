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

	rs, err := p.Records(ctx, z, dnsprovider.RecordFilter{})
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

func TestZoneMatchesNamesAsTheAdaptersDo(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "Example.COM."}
	p := newFake(t, providertest.New().AddZone(z))

	for _, name := range []string{"example.com", "EXAMPLE.com."} {
		if got, err := p.Zone(context.Background(), name); err != nil || got.ID != "z1" {
			t.Errorf("Zone(%s) = %+v, %v; want z1", name, got, err)
		}
	}
}

func TestRecordsAreFilteredAndRecordTheFilter(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}
	a := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	aaaa := dnsprovider.Record{ID: "r2", Type: "AAAA", Name: "www.example.com", Value: "2001:db8::1", TTL: 300}
	mx := dnsprovider.Record{ID: "r3", Type: "MX", Name: "example.com", Value: "10 mail.example.com", TTL: 3600}
	fake := providertest.New().AddZone(z, a, aaaa, mx).SetSerial("z1", 7)
	p := newFake(t, fake)

	cases := []struct {
		filter dnsprovider.RecordFilter
		want   []dnsprovider.Record
	}{
		{dnsprovider.RecordFilter{}, []dnsprovider.Record{a, aaaa, mx}},
		{dnsprovider.RecordFilter{Type: "mx"}, []dnsprovider.Record{mx}},
		{dnsprovider.RecordFilter{Contains: "WWW."}, []dnsprovider.Record{a, aaaa}},
		{dnsprovider.RecordFilter{Type: "AAAA", Contains: "www"}, []dnsprovider.Record{aaaa}},
		{dnsprovider.RecordFilter{Type: "TXT"}, []dnsprovider.Record{}},
	}

	for _, c := range cases {
		rs, err := p.Records(context.Background(), z, c.filter)
		if err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(rs.Records, c.want) || rs.Serial != 7 {
			t.Errorf("Records(%+v) = %+v serial %d, want %+v serial 7", c.filter, rs.Records, rs.Serial, c.want)
		}

		if calls := fake.Calls(); calls[len(calls)-1].Op != providertest.OpRecords || calls[len(calls)-1].RecordFilter != c.filter {
			t.Errorf("last call = %+v, want Records with the filter %+v", calls[len(calls)-1], c.filter)
		}
	}
}

func TestBatcherIsImplementedOnlyOnceScriptedWithAnyOtherOption(t *testing.T) {
	for _, tenants := range []bool{false, true} {
		for _, status := range []bool{false, true} {
			for _, batcher := range []bool{false, true} {
				fake := providertest.New()
				if tenants {
					fake.SetTenants(dnsprovider.Tenant{ID: "t1"})
				}

				if status {
					fake.SetZoneStatus("z1", dnsprovider.ZoneStatus{})
				}

				fake.SetBatcher(batcher)

				p := newFake(t, fake)

				_, isBatcher := p.(dnsprovider.Batcher)
				_, readsStatus := p.(dnsprovider.ZoneStatusReader)

				if isBatcher != batcher || dnsprovider.CanListTenants(p) != tenants || readsStatus != status {
					t.Errorf("tenants %v, status %v, batcher %v: built a Provider listing Tenants %v, reading Zone Status %v, batching %v",
						tenants, status, batcher, dnsprovider.CanListTenants(p), readsStatus, isBatcher)
				}
			}
		}
	}
}

func TestBatcherMakesEachChangeAndReportsTheBumpedSerial(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}
	www := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	fake := providertest.New().AddZone(z, www).SetSerial("z1", 9)
	fake.SetBatcher(true)
	fake.FailChanges(func(c dnsprovider.Change) error {
		if c.Kind == dnsprovider.ChangeDelete {
			return errors.New("refused")
		}

		return nil
	})

	b, ok := newFake(t, fake).(dnsprovider.Batcher)
	if !ok {
		t.Fatal("the fake is no Batcher")
	}

	// The addition takes the place of the Record the modification moves.
	moved := www
	moved.Value = "192.0.2.2"
	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: www}
	modify := dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: www, After: moved}
	del := dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: www}

	res, err := b.ApplyChangeset(context.Background(), dnsprovider.Changeset{Zone: z, Changes: []dnsprovider.Change{add, modify, del}})
	if err != nil {
		t.Fatal(err)
	}

	if res.Serial != 10 {
		t.Errorf("serial = %d, want 10", res.Serial)
	}

	if r := res.Results[0]; r.Err != nil || r.Record.ID == "" || r.Record.Value != "192.0.2.1" {
		t.Errorf("addition = %+v, want it stored with an ID", r)
	}

	if r := res.Results[1]; r.Err != nil || r.Record.ID != "r1" || r.Record.Value != "192.0.2.2" {
		t.Errorf("modification = %+v, want r1 changed", r)
	}

	if r := res.Results[2]; r.Err == nil {
		t.Errorf("deletion = %+v, want the scripted failure", r)
	}

	calls := fake.Calls()
	if last := calls[len(calls)-1]; last.Op != providertest.OpApply || len(last.Changeset.Changes) != 3 {
		t.Errorf("last call = %+v, want the Changeset recorded as OpApply", last)
	}
}

func TestCRUDRefusesDuplicatesAndRecordsMissingByID(t *testing.T) {
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}
	www := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	p := newFake(t, providertest.New().AddZone(z, www))

	dup := www
	dup.ID, dup.Name, dup.TTL = "", "WWW.example.com", 600

	if _, err := p.CreateRecord(ctx, z, dup); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Errorf("CreateRecord of a duplicate: err = %v, want ErrConflict", err)
	}

	gone := www
	gone.ID = "r9"

	if _, err := p.UpdateRecord(ctx, z, gone, www); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("UpdateRecord of a missing ID: err = %v, want ErrNotFound", err)
	}

	if err := p.DeleteRecord(ctx, z, gone); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("DeleteRecord of a missing ID: err = %v, want ErrNotFound", err)
	}

	if err := p.DeleteRecord(ctx, z, www); err != nil {
		t.Errorf("DeleteRecord: %v", err)
	}
}

func TestBatcherFailsAChangeOfNoKnownKindAlone(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}
	fake := providertest.New().AddZone(z)
	fake.SetBatcher(true)

	add := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	cs := dnsprovider.Changeset{Zone: z, Changes: []dnsprovider.Change{{After: add}, {Kind: dnsprovider.ChangeAdd, After: add}}}

	res, err := dnsprovider.Apply(context.Background(), newFake(t, fake), cs)
	if err != nil {
		t.Fatal(err)
	}

	if r := res.Results[0]; r.Err == nil || !reflect.DeepEqual(r.Change, cs.Changes[0]) {
		t.Errorf("change of no kind = %+v, want it failed", r)
	}

	if r := res.Results[1]; r.Err != nil {
		t.Errorf("addition = %+v, want it made", r)
	}
}

func TestZoneUpdaterIsImplementedOnlyOnceScriptedWithAnyOtherOption(t *testing.T) {
	for set := range 16 {
		tenants, status, batcher, updater := set&1 != 0, set&2 != 0, set&4 != 0, set&8 != 0

		fake := providertest.New()
		if tenants {
			fake.SetTenants(dnsprovider.Tenant{ID: "t1"})
		}

		if status {
			fake.SetZoneStatus("z1", dnsprovider.ZoneStatus{})
		}

		fake.SetBatcher(batcher)
		fake.SetZoneUpdater(updater)

		p := newFake(t, fake)

		_, isBatcher := p.(dnsprovider.Batcher)
		_, readsStatus := p.(dnsprovider.ZoneStatusReader)

		if dnsprovider.CanUpdateZone(p) != updater || isBatcher != batcher || dnsprovider.CanListTenants(p) != tenants || readsStatus != status {
			t.Errorf("tenants %v, status %v, batcher %v, updater %v: built a Provider listing Tenants %v, reading Zone Status %v, batching %v, updating Zones %v",
				tenants, status, batcher, updater, dnsprovider.CanListTenants(p), readsStatus, isBatcher, dnsprovider.CanUpdateZone(p))
		}
	}
}

func TestUpdateZoneChangesTheSettingsItIsGivenAndRecordsTheUpdate(t *testing.T) {
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}

	fake := providertest.New().AddZone(z)
	fake.SetZoneStatus("z1", dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.Off})
	fake.SetZoneUpdater(true)

	p := newFake(t, fake)
	on := true
	u := dnsprovider.ZoneUpdate{HSTS: &on}

	got, err := p.(dnsprovider.ZoneUpdater).UpdateZone(ctx, z, u)
	if err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}

	want := dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.On}
	if got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}

	calls := fake.Calls()
	if c := calls[len(calls)-1]; c.Op != providertest.OpUpdateZone || c.Zone.ID != z.ID || c.ZoneUpdate != u {
		t.Errorf("last call = %+v, want UpdateZone of %v with %+v", c, z, u)
	}

	if st, err := dnsprovider.ZoneStatusOf(ctx, p, z); err != nil || st != want {
		t.Errorf("Zone Status after UpdateZone = %+v, %v; want %+v", st, err, want)
	}
}

func TestUpdateZoneFailsAsScriptedAndForAZoneNotScripted(t *testing.T) {
	ctx := context.Background()
	fake := providertest.New().AddZone(dnsprovider.Zone{ID: "z1", Name: "example.com"})
	fake.SetZoneUpdater(true)

	up := newFake(t, fake).(dnsprovider.ZoneUpdater)
	off := false

	if _, err := up.UpdateZone(ctx, dnsprovider.Zone{ID: "z2", Name: "example.org"}, dnsprovider.ZoneUpdate{HSTS: &off}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("UpdateZone of a Zone not scripted: error = %v, want ErrNotFound", err)
	}

	fake.Fail(providertest.OpUpdateZone, dnsprovider.ErrUnauthorized)

	if _, err := up.UpdateZone(ctx, dnsprovider.Zone{ID: "z1", Name: "example.com"}, dnsprovider.ZoneUpdate{HSTS: &off}); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("UpdateZone error = %v, want the scripted ErrUnauthorized", err)
	}
}

func TestUpdateZoneLeavesDNSSECPendingAsCloudflareSignsOrUnsignsOverTime(t *testing.T) {
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}

	for _, on := range []bool{true, false} {
		fake := providertest.New().AddZone(z)
		fake.SetZoneStatus("z1", dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Off, HSTS: dnsprovider.On})
		fake.SetZoneUpdater(true)

		p := newFake(t, fake)

		got, err := p.(dnsprovider.ZoneUpdater).UpdateZone(ctx, z, dnsprovider.ZoneUpdate{DNSSEC: &on})
		if err != nil {
			t.Fatalf("UpdateZone: %v", err)
		}

		want := dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.On}
		if got != want {
			t.Errorf("DNSSEC %v: UpdateZone = %+v, want %+v", on, got, want)
		}

		if st, err := dnsprovider.ZoneStatusOf(ctx, p, z); err != nil || st != want {
			t.Errorf("DNSSEC %v: Zone Status after UpdateZone = %+v, %v; want %+v", on, st, err, want)
		}
	}
}
