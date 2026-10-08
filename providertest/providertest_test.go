package providertest_test

import (
	"context"
	"errors"
	"maps"
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
