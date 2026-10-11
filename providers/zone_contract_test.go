package providers_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers"
)

func TestRegisteredProvidersDeclareSupportedZoneWritesIndependently(t *testing.T) {
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
			assertCapabilities := func() {
				t.Helper()
				if got := p.Capabilities(); !slices.Equal(got, want) {
					t.Fatalf("Capabilities = %v, want %v", got, want)
				}
				if got := providers.Registry()[typ].Capabilities; !slices.Equal(got, want) {
					t.Fatalf("Factory capabilities = %v, want %v", got, want)
				}
				for _, c := range []dnsprovider.Capability{dnsprovider.CapZoneCreator, dnsprovider.CapZoneUpdater, dnsprovider.CapZoneDeleter} {
					if factory.Can(c) != slices.Contains(want, c) {
						t.Fatalf("Factory.Can(%v) disagrees with supported writes", c)
					}
				}
			}
			assertCapabilities()
			got := p.Capabilities()
			if len(got) > 0 {
				got[0] = dnsprovider.Capability("changed")
			}
			assertCapabilities()
			if len(factory.Capabilities) > 0 {
				factory.Capabilities[0] = dnsprovider.Capability("changed")
			}
			if !slices.Equal(p.Capabilities(), want) || !slices.Equal(providers.Registry()[typ].Capabilities, want) {
				t.Fatal("mutating Factory capabilities changed the Provider or another Factory")
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
				if !dnsprovider.CanCreateZone(p) {
					z, err := p.CreateZone(ctx, "example.com")
					if !errors.Is(err, dnsprovider.ErrNotImplemented) || !reflect.DeepEqual(z, dnsprovider.Zone{}) {
						t.Fatalf("unsupported CreateZone = %+v, %v", z, err)
					}
				}
				if !dnsprovider.CanUpdateZone(p) {
					st, err := p.UpdateZone(ctx, zone, dnsprovider.ZoneUpdate{DNSSEC: &on})
					if !errors.Is(err, dnsprovider.ErrNotImplemented) || st != (dnsprovider.ZoneStatus{}) {
						t.Fatalf("unsupported UpdateZone = %+v, %v", st, err)
					}
				}
				if !dnsprovider.CanDeleteZone(p) {
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

// The aliases remain available on concrete adapters during migration, although
// the required Provider interface deliberately exposes only canonical reads.
type legacyZoneReader interface {
	Zone(context.Context, string) (dnsprovider.Zone, error)
	Zones(context.Context, dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error)
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestCanonicalAndDeprecatedZoneReadsPreserveCancellation(t *testing.T) {
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
			aliases, ok := p.(legacyZoneReader)
			if !ok {
				t.Fatal("concrete adapter lacks migration aliases")
			}
			ctx := canceledContext()
			for name, read := range map[string]func() error{
				"GetZone":   func() error { _, err := p.GetZone(ctx, "Example.Com."); return err },
				"Zone":      func() error { _, err := aliases.Zone(ctx, "Example.Com."); return err },
				"ListZones": func() error { _, err := p.ListZones(ctx, dnsprovider.ZoneFilter{Contains: "example.com."}); return err },
				"Zones": func() error {
					_, err := aliases.Zones(ctx, dnsprovider.ZoneFilter{Contains: "example.com."})
					return err
				},
			} {
				if err := read(); !errors.Is(err, context.Canceled) {
					t.Errorf("%s with canceled context = %v, want context.Canceled", name, err)
				}
			}
			if got := requests.Load(); got != 0 {
				t.Fatalf("canceled reads issued %d HTTP requests", got)
			}
		})
	}
}

func TestDeprecatedZoneReadsPreserveCanonicalResultsAndTypedErrors(t *testing.T) {
	// The Cloudflare zone-list fixture includes a loose filter match and
	// assigned nameservers, so forwarding must retain exact local filtering
	// and returned metadata as well as not-found classification.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true,"result":[{"id":"z1","name":"example.com","status":"pending","name_servers":["ns1.example.net"]},{"id":"z2","name":"example.community","status":"active"}],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer s.Close()
	p, err := providers.Registry().New("cloudflare", validFields["cloudflare"], dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	aliases := p.(legacyZoneReader)
	ctx := context.Background()
	filter := dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."}
	set, err := p.ListZones(ctx, filter)
	if err != nil || set.Partial || len(set.Zones) != 1 {
		t.Fatalf("ListZones = %+v, %v; want one Zone in a Full View", set, err)
	}
	oldSet, err := aliases.Zones(ctx, filter)
	if err != nil || !reflect.DeepEqual(oldSet, set) {
		t.Fatalf("Zones = %+v, %v; want canonical %+v", oldSet, err, set)
	}
	want := dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingPending, Nameservers: []string{"ns1.example.net"}}
	for _, read := range []func(context.Context, string) (dnsprovider.Zone, error){p.GetZone, aliases.Zone} {
		got, err := read(ctx, "Example.Com.")
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("exact-name read = %+v, %v; want %+v", got, err, want)
		}
		if _, err := read(ctx, "absent.example"); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("missing Zone = %v, want ErrNotFound", err)
		}
	}
}
