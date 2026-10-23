package providers_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers"
)

func TestRegisteredProvidersDeclareTraitsIndependently(t *testing.T) {
	for typ, factory := range providers.Registry() {
		t.Run(typ, func(t *testing.T) {
			p, err := factory.New(validFields[typ])
			if err != nil {
				t.Fatal(err)
			}
			want := map[string][]dnsprovider.Capability{
				"cloudflare": {dnsprovider.CapZoneCreator, dnsprovider.CapZoneUpdater, dnsprovider.CapZoneDeleter, dnsprovider.CapTenantLister},
				"gandi":      {dnsprovider.CapBatcher, dnsprovider.CapDSRegistrar},
				"godaddy":    {dnsprovider.CapBatcher},
				"hetzner":    {dnsprovider.CapBatcher},
				"infomaniak": {dnsprovider.CapZoneUpdater, dnsprovider.CapDSRegistrar},
				"internetbs": {dnsprovider.CapDSRegistrar},
				"inwx":       {dnsprovider.CapZoneCreator, dnsprovider.CapZoneUpdater, dnsprovider.CapZoneDeleter, dnsprovider.CapDSRegistrar},
				"namecheap":  {dnsprovider.CapBatcher},
				"netim":      {dnsprovider.CapDSRegistrar},
				"ovhcloud":   {dnsprovider.CapBatcher},
				"porkbun":    {dnsprovider.CapDSRegistrar},
				"scaleway":   {dnsprovider.CapBatcher},
			}[typ]
			if got := p.Traits().Capabilities; !slices.Equal(got, want) {
				t.Fatalf("Capabilities = %v, want %v", got, want)
			}
			fresh := providers.Registry()[typ].Traits
			mutate := func(tr dnsprovider.Traits) {
				if len(tr.Capabilities) > 0 {
					tr.Capabilities[0] = "changed"
				}
				for i := range tr.Extras {
					tr.Extras[i].Key = "changed"
					if len(tr.Extras[i].Types) > 0 {
						tr.Extras[i].Types[0] = "changed"
					}
				}
			}
			mutate(p.Traits())
			mutate(factory.Traits)
			if !reflect.DeepEqual(p.Traits(), fresh) || !reflect.DeepEqual(providers.Registry()[typ].Traits, fresh) {
				t.Fatal("mutating declared Traits changed the Provider or another Factory")
			}
		})
	}
}

func TestUndeclaredOperationsReturnNotImplementedWithoutNetworkTraffic(t *testing.T) {
	for typ, factory := range providers.Registry() {
		t.Run(typ, func(t *testing.T) {
			var requests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			t.Cleanup(s.Close)
			p, err := factory.New(validFields[typ], dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
			if err != nil {
				t.Fatal(err)
			}
			on := true
			zone := dnsprovider.Zone{ID: "z1", Name: "example.com"}
			for _, ctx := range []context.Context{context.Background(), canceledContext()} {
				if !dnsprovider.Can(p, dnsprovider.CapZoneCreator) {
					z, err := p.CreateZone(ctx, "example.com")
					if !errors.Is(err, dnsprovider.ErrNotImplemented) || !reflect.DeepEqual(z, dnsprovider.Zone{}) {
						t.Fatalf("unsupported CreateZone = %+v, %v", z, err)
					}
				}
				if !dnsprovider.Can(p, dnsprovider.CapZoneUpdater) {
					st, err := p.UpdateZone(ctx, zone, dnsprovider.ZoneUpdate{DNSSEC: &on})
					if !errors.Is(err, dnsprovider.ErrNotImplemented) || st != (dnsprovider.ZoneStatus{}) {
						t.Fatalf("unsupported UpdateZone = %+v, %v", st, err)
					}
				}
				if !dnsprovider.Can(p, dnsprovider.CapZoneDeleter) {
					if err := p.DeleteZone(ctx, zone); !errors.Is(err, dnsprovider.ErrNotImplemented) {
						t.Fatalf("unsupported DeleteZone = %v", err)
					}
				}
				if !dnsprovider.Can(p, dnsprovider.CapBatcher) {
					res, err := p.ApplyChangeset(ctx, dnsprovider.Changeset{Zone: zone})
					if !errors.Is(err, dnsprovider.ErrNotImplemented) || res.Results != nil {
						t.Fatalf("unsupported ApplyChangeset = %+v, %v", res, err)
					}
				}
				if !dnsprovider.Can(p, dnsprovider.CapTenantLister) {
					if ts, err := p.ListTenants(ctx); !errors.Is(err, dnsprovider.ErrNotImplemented) || ts != nil {
						t.Fatalf("unsupported ListTenants = %+v, %v", ts, err)
					}
				}
				if !dnsprovider.Can(p, dnsprovider.CapDSRegistrar) {
					keys, err := p.ListDelegationSigners(ctx, zone)
					if !errors.Is(err, dnsprovider.ErrNotImplemented) || keys != nil {
						t.Fatalf("unsupported ListDelegationSigners = %+v, %v", keys, err)
					}
					if err := p.SetDelegationSigners(ctx, zone, []dnsprovider.SigningKey{{KeyTag: 1}}); !errors.Is(err, dnsprovider.ErrNotImplemented) {
						t.Fatalf("unsupported SetDelegationSigners = %v", err)
					}
					if err := p.DeleteDelegationSigners(ctx, zone); !errors.Is(err, dnsprovider.ErrNotImplemented) {
						t.Fatalf("unsupported DeleteDelegationSigners = %v", err)
					}
				}
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("undeclared operations issued %d HTTP requests", got)
			}
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestDSRegistrarsRefuseSettingNoKeysWithoutNetworkTraffic(t *testing.T) {
	registrars := 0
	for typ, factory := range providers.Registry() {
		var requests atomic.Int32
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		p, err := factory.New(validFields[typ], dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
		if err != nil {
			s.Close()
			t.Fatalf("%s: %v", typ, err)
		}
		if dnsprovider.Can(p, dnsprovider.CapDSRegistrar) {
			registrars++
			for _, keys := range [][]dnsprovider.SigningKey{nil, {}} {
				if err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{ID: "z1", Name: "example.com"}, keys); !errors.Is(err, dnsprovider.ErrNoSigningKeys) {
					t.Errorf("%s: SetDelegationSigners(%#v) = %v, want ErrNoSigningKeys", typ, keys, err)
				}
			}
			if got := requests.Load(); got != 0 {
				t.Errorf("%s: SetDelegationSigners of no keys issued %d HTTP requests", typ, got)
			}
		}
		s.Close()
	}
	if registrars != 6 {
		t.Errorf("found %d DS registrars, want porkbun, gandi, internetbs, netim, infomaniak and inwx", registrars)
	}
}

func TestProvidersWithoutZonePropertiesReportThemUnsupportedWithoutNetworkTraffic(t *testing.T) {
	for typ, factory := range providers.Registry() {
		if typ == "cloudflare" || typ == "infomaniak" || typ == "inwx" {
			continue
		}
		t.Run(typ, func(t *testing.T) {
			var requests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			t.Cleanup(s.Close)
			p, err := factory.New(validFields[typ], dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
			if err != nil {
				t.Fatal(err)
			}
			zone := dnsprovider.Zone{ID: "z1", Name: "example.com"}
			got, err := p.ZoneDetails(context.Background(), zone, dnsprovider.ZoneDetailRequest{SigningKeys: true})
			if err != nil || !reflect.DeepEqual(got.Zone, zone) || got.Status != (dnsprovider.ZoneStatus{}) || got.SigningKeys != nil {
				t.Fatalf("ZoneDetails = %+v, %v", got, err)
			}
			unsupported := dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported}
			if got.Properties != (dnsprovider.ZoneDetailProperties{DNSSEC: unsupported, HSTS: unsupported, MinTLS: unsupported, SigningKeys: unsupported}) {
				t.Errorf("Properties = %+v, want every one unsupported", got.Properties)
			}
			if n := requests.Load(); n != 0 {
				t.Errorf("ZoneDetails issued %d HTTP requests", n)
			}
		})
	}
}
