package providers_test

import (
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers"
)

func TestRegistryHasOneFactoryPerProvider(t *testing.T) {
	r := providers.Registry()

	if got, want := r.Types(), []string{"cloudflare", "cloudns", "godaddy", "namecheap"}; !slices.Equal(got, want) {
		t.Fatalf("Types() = %v, want %v", got, want)
	}

	for typ, f := range r {
		t.Run(typ, func(t *testing.T) {
			var names []string

			secret := false

			for _, fd := range f.Fields {
				if fd.Name == "" || fd.Label == "" {
					t.Errorf("field %+v has no name or label", fd)
				}

				if slices.Contains(names, fd.Name) {
					t.Errorf("field %q is named twice", fd.Name)
				}

				names = append(names, fd.Name)
				secret = secret || fd.Secret
			}

			if !secret {
				t.Error("no field is Secret")
			}

			if _, err := r.New(typ, nil); err == nil {
				t.Error("built a Provider without its required fields")
			}
		})
	}
}

// validFields are fields each Provider type builds from, without a call.
var validFields = map[string]map[string]string{
	"cloudflare": {"token": "t", "tenant_id": "0123456789abcdef0123456789abcdef"},
	"godaddy":    {"key": "k", "secret": "s"},
	"cloudns":    {"password": "s", "auth_id": "123"},
	"namecheap":  {"user": "u", "key": "k", "client_ip": "192.0.2.1"},
}

func TestEachFactoryDeclaresTheZoneWritesItsProvidersImplement(t *testing.T) {
	r := providers.Registry()

	for typ, f := range r {
		p, err := r.New(typ, validFields[typ])
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}

		if f.Can(dnsprovider.CapZoneCreator) != dnsprovider.CanCreateZone(p) {
			t.Errorf("%s: Factory declares ZoneCreator %v, its Provider implements it %v", typ, f.Can(dnsprovider.CapZoneCreator), dnsprovider.CanCreateZone(p))
		}

		if f.Can(dnsprovider.CapZoneUpdater) != dnsprovider.CanUpdateZone(p) {
			t.Errorf("%s: Factory declares ZoneUpdater %v, its Provider implements it %v", typ, f.Can(dnsprovider.CapZoneUpdater), dnsprovider.CanUpdateZone(p))
		}

		if f.Can(dnsprovider.CapZoneDeleter) != dnsprovider.CanDeleteZone(p) {
			t.Errorf("%s: Factory declares ZoneDeleter %v, its Provider implements it %v", typ, f.Can(dnsprovider.CapZoneDeleter), dnsprovider.CanDeleteZone(p))
		}
	}
}
