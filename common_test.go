package dnsprovider_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// oneTenant is a Provider whose credentials act within one Tenant alone.
type oneTenant struct{ dnsprovider.Provider }

func (oneTenant) Traits() dnsprovider.Traits { return dnsprovider.Traits{} }

func TestZoneMethodsAloneDoNotDeclareSupport(t *testing.T) {
	if dnsprovider.Can(oneTenant{}, dnsprovider.CapZoneCreator) || dnsprovider.Can(oneTenant{}, dnsprovider.CapZoneUpdater) || dnsprovider.Can(oneTenant{}, dnsprovider.CapZoneDeleter) {
		t.Fatal("Zone methods alone must not declare supported operations")
	}
}

// manyTenants is a Provider whose credentials can reach several Tenants.
type manyTenants struct{ dnsprovider.Provider }

func (manyTenants) Tenants(context.Context) ([]dnsprovider.Tenant, error) {
	return []dnsprovider.Tenant{{ID: "acc1", Name: "Acme Ltd"}}, nil
}

func TestCanListTenantsOnlyForATenantLister(t *testing.T) {
	if dnsprovider.CanListTenants(oneTenant{}) {
		t.Error("a Provider without Tenants lists them")
	}

	if !dnsprovider.CanListTenants(manyTenants{}) {
		t.Error("a TenantLister does not list Tenants")
	}
}

// registrar is a Provider that registers domains and can replace the DS
// records the registry publishes for them.
type registrar struct{ dnsprovider.Provider }

func (registrar) ListDelegationSigners(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	return nil, dnsprovider.ErrNotFound
}

func (registrar) SetDelegationSigners(context.Context, dnsprovider.Zone, []dnsprovider.SigningKey) error {
	return dnsprovider.ErrUnsupported
}

func (registrar) DeleteDelegationSigners(context.Context, dnsprovider.Zone) error {
	return dnsprovider.ErrNotFound
}

func TestCanRegisterDSOnlyForADSRegistrar(t *testing.T) {
	if dnsprovider.CanRegisterDS(oneTenant{}) {
		t.Error("a Provider that cannot write DS records registers them")
	}

	if !dnsprovider.CanRegisterDS(registrar{}) {
		t.Error("a DSRegistrar does not register DS records")
	}
}

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

// zoneUpdater is a Provider that changes Zone settings.
type zoneUpdater struct{ dnsprovider.Provider }

func (zoneUpdater) Traits() dnsprovider.Traits {
	return dnsprovider.Traits{Capabilities: []dnsprovider.Capability{dnsprovider.CapZoneUpdater}}
}

func (zoneUpdater) UpdateZone(context.Context, dnsprovider.Zone, dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	return dnsprovider.ZoneStatus{}, nil
}

func TestCanUpdateZoneOnlyForAZoneUpdater(t *testing.T) {
	if dnsprovider.Can(oneTenant{}, dnsprovider.CapZoneUpdater) {
		t.Error("a Provider without a ZoneUpdater updates Zones")
	}

	if !dnsprovider.Can(zoneUpdater{}, dnsprovider.CapZoneUpdater) {
		t.Error("a ZoneUpdater does not update Zones")
	}
}

// zoneCreator is a Provider that Onboards zone names.
type zoneCreator struct{ oneTenant }

func (zoneCreator) Traits() dnsprovider.Traits {
	return dnsprovider.Traits{Capabilities: []dnsprovider.Capability{dnsprovider.CapZoneCreator}}
}

func (zoneCreator) CreateZone(context.Context, string) (dnsprovider.Zone, error) {
	return dnsprovider.Zone{}, nil
}

func TestCanCreateZoneOnlyForAZoneCreator(t *testing.T) {
	if dnsprovider.Can(oneTenant{}, dnsprovider.CapZoneCreator) {
		t.Error("a Provider without a ZoneCreator creates Zones")
	}

	if !dnsprovider.Can(zoneCreator{}, dnsprovider.CapZoneCreator) {
		t.Error("a ZoneCreator does not create Zones")
	}
}

// zoneDeleter is a Provider that Offboards Zones.
type zoneDeleter struct{ oneTenant }

func (zoneDeleter) Traits() dnsprovider.Traits {
	return dnsprovider.Traits{Capabilities: []dnsprovider.Capability{dnsprovider.CapZoneDeleter}}
}

func (zoneDeleter) DeleteZone(context.Context, dnsprovider.Zone) error {
	return nil
}

func TestCanDeleteZoneOnlyForAZoneDeleter(t *testing.T) {
	if dnsprovider.Can(oneTenant{}, dnsprovider.CapZoneDeleter) {
		t.Error("a Provider without a ZoneDeleter deletes Zones")
	}

	if !dnsprovider.Can(zoneDeleter{}, dnsprovider.CapZoneDeleter) {
		t.Error("a ZoneDeleter does not delete Zones")
	}
}

func TestAFactoryCanWhatItDeclares(t *testing.T) {
	f := dnsprovider.Factory{Traits: dnsprovider.Traits{Capabilities: []dnsprovider.Capability{dnsprovider.CapZoneCreator}}}

	if !f.Can(dnsprovider.CapZoneCreator) {
		t.Error("a Factory declaring ZoneCreator cannot create Zones")
	}

	if f.Can(dnsprovider.CapZoneUpdater) || (dnsprovider.Factory{}).Can(dnsprovider.CapZoneCreator) {
		t.Error("a Factory can what it does not declare")
	}
}

func TestTraitsCloneSharesNoSlice(t *testing.T) {
	orig := dnsprovider.Traits{
		Capabilities: []dnsprovider.Capability{dnsprovider.CapZoneCreator},
		Extras:       []dnsprovider.ExtraSpec{dnsprovider.ProxiedExtra("A")},
	}
	c := orig.Clone()
	c.Capabilities[0] = dnsprovider.CapZoneDeleter
	c.Extras[0].Key = "changed"
	c.Extras[0].Types[0] = "AAAA"

	if orig.Capabilities[0] != dnsprovider.CapZoneCreator || orig.Extras[0].Key != dnsprovider.ExtraProxied || orig.Extras[0].Types[0] != "A" {
		t.Fatalf("mutating a clone changed the original: %+v", orig)
	}
}

func TestUnimplementedZoneWritesAreNotImplemented(t *testing.T) {
	var u dnsprovider.UnimplementedZoneWrites
	ctx := context.Background()

	if z, err := u.CreateZone(ctx, "example.com"); !errors.Is(err, dnsprovider.ErrNotImplemented) || !reflect.DeepEqual(z, dnsprovider.Zone{}) {
		t.Errorf("CreateZone = %+v, %v", z, err)
	}

	if st, err := u.UpdateZone(ctx, dnsprovider.Zone{}, dnsprovider.ZoneUpdate{}); !errors.Is(err, dnsprovider.ErrNotImplemented) || st != (dnsprovider.ZoneStatus{}) {
		t.Errorf("UpdateZone = %+v, %v", st, err)
	}

	if err := u.DeleteZone(ctx, dnsprovider.Zone{}); !errors.Is(err, dnsprovider.ErrNotImplemented) {
		t.Errorf("DeleteZone = %v", err)
	}
}
