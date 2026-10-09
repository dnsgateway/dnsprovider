package dnsprovider_test

import (
	"context"
	"errors"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestMatchZoneMatchesNamesHoldingTheTextIgnoringCase(t *testing.T) {
	cases := []struct {
		contains, name string
		want           bool
	}{
		{"", "example.com", true},
		{"ample", "example.com", true},
		{"AMPLE", "Example.COM", true},
		{"example.org", "example.com", false},
		{"shop.", "shop.example.com", true},
		// A trailing dot ends the name, as in an absolute name.
		{"Example.COM.", "example.com", true},
		{"example.com.", "shop.example.com", true},
		{"example.com.", "example.community", false},
		{"example.com", "example.com.", true},
	}

	for _, c := range cases {
		z := dnsprovider.Zone{ID: "z1", Name: c.name}
		if got := dnsprovider.MatchZone(dnsprovider.ZoneFilter{Contains: c.contains}, z); got != c.want {
			t.Errorf("MatchZone(%q, %q) = %v, want %v", c.contains, c.name, got, c.want)
		}
	}
}

// statusReader is a Provider that reads Zone Status.
type statusReader struct {
	dnsprovider.Provider
	status dnsprovider.ZoneStatus
	err    error
}

func (r statusReader) ZoneStatus(context.Context, dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	return r.status, r.err
}

func TestZoneStatusOfAProviderWithoutAReaderIsUnknown(t *testing.T) {
	got, err := dnsprovider.ZoneStatusOf(context.Background(), oneTenant{}, dnsprovider.Zone{ID: "z1", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Unknown, HSTS: dnsprovider.Unknown}); got != want {
		t.Errorf("ZoneStatusOf = %+v, want %+v", got, want)
	}
}

func TestZoneStatusOfAReaderIsWhatItReads(t *testing.T) {
	p := statusReader{status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.Off}}

	got, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{ID: "z1", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if got != p.status {
		t.Errorf("ZoneStatusOf = %+v, want %+v", got, p.status)
	}

	p.err = dnsprovider.ErrUnauthorized
	if _, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{ID: "z1"}); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("ZoneStatusOf error = %v, want ErrUnauthorized", err)
	}
}

// zoneUpdater is a Provider that changes Zone settings.
type zoneUpdater struct{ dnsprovider.Provider }

func (zoneUpdater) UpdateZone(context.Context, dnsprovider.Zone, dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	return dnsprovider.ZoneStatus{}, nil
}

func TestCanUpdateZoneOnlyForAZoneUpdater(t *testing.T) {
	if dnsprovider.CanUpdateZone(oneTenant{}) {
		t.Error("a Provider without a ZoneUpdater updates Zones")
	}

	if !dnsprovider.CanUpdateZone(zoneUpdater{}) {
		t.Error("a ZoneUpdater does not update Zones")
	}
}

// zoneCreator is a Provider that Onboards zone names.
type zoneCreator struct{ oneTenant }

func (zoneCreator) CreateZone(context.Context, string) (dnsprovider.Zone, error) {
	return dnsprovider.Zone{}, nil
}

func TestCanCreateZoneOnlyForAZoneCreator(t *testing.T) {
	if dnsprovider.CanCreateZone(oneTenant{}) {
		t.Error("a Provider without a ZoneCreator creates Zones")
	}

	if !dnsprovider.CanCreateZone(zoneCreator{}) {
		t.Error("a ZoneCreator does not create Zones")
	}
}

// zoneDeleter is a Provider that Offboards Zones.
type zoneDeleter struct{ oneTenant }

func (zoneDeleter) DeleteZone(context.Context, dnsprovider.Zone) error {
	return nil
}

func TestCanDeleteZoneOnlyForAZoneDeleter(t *testing.T) {
	if dnsprovider.CanDeleteZone(oneTenant{}) {
		t.Error("a Provider without a ZoneDeleter deletes Zones")
	}

	if !dnsprovider.CanDeleteZone(zoneDeleter{}) {
		t.Error("a ZoneDeleter does not delete Zones")
	}
}

func TestAFactoryCanWhatItDeclares(t *testing.T) {
	f := dnsprovider.Factory{Capabilities: []dnsprovider.Capability{dnsprovider.CapZoneCreator}}

	if !f.Can(dnsprovider.CapZoneCreator) {
		t.Error("a Factory declaring ZoneCreator cannot create Zones")
	}

	if f.Can(dnsprovider.CapZoneUpdater) || (dnsprovider.Factory{}).Can(dnsprovider.CapZoneCreator) {
		t.Error("a Factory can what it does not declare")
	}
}
