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
			var want []dnsprovider.Capability
			if typ == "cloudflare" {
				want = []dnsprovider.Capability{dnsprovider.CapZoneCreator, dnsprovider.CapZoneUpdater, dnsprovider.CapZoneDeleter}
			}
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

func TestUnsupportedZoneWritesReturnNotImplementedWithoutNetworkTraffic(t *testing.T) {
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
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("unsupported writes issued %d HTTP requests", got)
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
		if r, ok := p.(dnsprovider.DSRegistrar); ok {
			registrars++
			for _, keys := range [][]dnsprovider.SigningKey{nil, {}} {
				if err := r.SetDelegationSigners(context.Background(), dnsprovider.Zone{ID: "z1", Name: "example.com"}, keys); !errors.Is(err, dnsprovider.ErrNoSigningKeys) {
					t.Errorf("%s: SetDelegationSigners(%#v) = %v, want ErrNoSigningKeys", typ, keys, err)
				}
			}
			if got := requests.Load(); got != 0 {
				t.Errorf("%s: SetDelegationSigners of no keys issued %d HTTP requests", typ, got)
			}
		}
		s.Close()
	}
	if registrars != 3 {
		t.Errorf("found %d DSRegistrars, want porkbun, gandi and internetbs", registrars)
	}
}

func TestProvidersWithoutZonePropertiesReportThemUnsupportedWithoutNetworkTraffic(t *testing.T) {
	for typ, factory := range providers.Registry() {
		if typ == "cloudflare" {
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
