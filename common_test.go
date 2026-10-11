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

func (oneTenant) Capabilities() []dnsprovider.Capability { return nil }

func TestZoneMethodsAloneDoNotDeclareSupport(t *testing.T) {
	if dnsprovider.CanCreateZone(oneTenant{}) || dnsprovider.CanUpdateZone(oneTenant{}) || dnsprovider.CanDeleteZone(oneTenant{}) {
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

func (registrar) DelegationSigners(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	return nil, dnsprovider.ErrNotFound
}

func (registrar) SetDelegationSigners(context.Context, dnsprovider.Zone, []dnsprovider.SigningKey) error {
	return dnsprovider.ErrUnsupported
}

func TestCanRegisterDSOnlyForADSRegistrar(t *testing.T) {
	if dnsprovider.CanRegisterDS(oneTenant{}) {
		t.Error("a Provider that cannot write DS records registers them")
	}

	if !dnsprovider.CanRegisterDS(registrar{}) {
		t.Error("a DSRegistrar does not register DS records")
	}
}

// keyHost is a Provider whose API returns the keys it signs a Zone with,
// or err when set.
type keyHost struct {
	dnsprovider.Provider
	err error
}

func (h keyHost) SigningKeys(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	if h.err != nil {
		return nil, h.err
	}

	return []dnsprovider.SigningKey{{
		DNSKEY: "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
		KeyTag: 2371,
		DS:     []string{"2371 13 2 1F987CC6583E92DF0890718C42A2BC8C04E5A60A1D3E1FC1D0C7826A4F47B4C1"},
	}}, nil
}

func TestCanReadKeysOnlyForAKeyReader(t *testing.T) {
	if dnsprovider.CanReadKeys(oneTenant{}) {
		t.Error("a Provider whose API returns no keys reads them")
	}

	if !dnsprovider.CanReadKeys(keyHost{}) {
		t.Error("a KeyReader does not read keys")
	}
}

func TestSigningKeysOfAProviderWithoutAReaderAreNone(t *testing.T) {
	got, err := dnsprovider.SigningKeysOf(context.Background(), oneTenant{}, dnsprovider.Zone{ID: "z1", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if got != nil {
		t.Errorf("SigningKeysOf = %+v, want none", got)
	}
}

func TestSigningKeysOfAReaderAreWhatItReads(t *testing.T) {
	got, err := dnsprovider.SigningKeysOf(context.Background(), keyHost{}, dnsprovider.Zone{ID: "z1", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.SigningKey{{
		DNSKEY: "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
		KeyTag: 2371,
		DS:     []string{"2371 13 2 1F987CC6583E92DF0890718C42A2BC8C04E5A60A1D3E1FC1D0C7826A4F47B4C1"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SigningKeysOf = %+v, want %+v", got, want)
	}

	if _, err := dnsprovider.SigningKeysOf(context.Background(), keyHost{err: dnsprovider.ErrUnauthorized}, dnsprovider.Zone{ID: "z1"}); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("SigningKeysOf error = %v, want ErrUnauthorized", err)
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

func (zoneUpdater) Capabilities() []dnsprovider.Capability {
	return []dnsprovider.Capability{dnsprovider.CapZoneUpdater}
}

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

func (zoneCreator) Capabilities() []dnsprovider.Capability {
	return []dnsprovider.Capability{dnsprovider.CapZoneCreator}
}

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

func (zoneDeleter) Capabilities() []dnsprovider.Capability {
	return []dnsprovider.Capability{dnsprovider.CapZoneDeleter}
}

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
