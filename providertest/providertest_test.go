package providertest_test

import (
	"context"
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

	p, err := fake.New("token")
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
