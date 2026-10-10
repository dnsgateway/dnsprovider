package providers_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers"
)

func TestRegistryHasOneFactoryPerProvider(t *testing.T) {
	r := providers.Registry()

	if got, want := r.Types(), []string{"cloudflare", "cloudns", "digitalocean", "dnsimple", "gandi", "godaddy", "hetzner", "internetbs", "namecheap", "ovhcloud", "porkbun", "scaleway", "vultr"}; !slices.Equal(got, want) {
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

				if fd.Default != "" && len(fd.Choices) > 0 && !slices.Contains(fd.Choices, fd.Default) {
					t.Errorf("field %q defaults to a value not among its choices", fd.Name)
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
	"cloudflare":   {"token": "t", "tenant_id": "0123456789abcdef0123456789abcdef"},
	"dnsimple":     {"token": "t", "account_id": "12"},
	"digitalocean": {"token": "t"},
	"godaddy":      {"key": "k", "secret": "s"},
	"internetbs":   {"key": "k", "password": "s"},
	"gandi":        {"token": "t"},
	"hetzner":      {"token": "t"},
	"ovhcloud":     {"application_key": "a", "application_secret": "s", "consumer_key": "c"},
	"porkbun":      {"key": "k", "secret": "s"},
	"cloudns":      {"password": "s", "auth_id": "123"},
	"namecheap":    {"user": "u", "key": "k", "client_ip": "192.0.2.1"},
	"vultr":        {"api_key": "k"},
	"scaleway":     {"secret_key": "s", "project_id": "11111111-1111-4111-8111-111111111111"},
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

func TestRegistryReturnsIndependentFactories(t *testing.T) {
	first := providers.Registry()
	f, ok := first["internetbs"]
	if !ok {
		t.Fatal("Internet.bs is absent from Registry")
	}
	f.Fields[0].Label = "changed"
	first["internetbs"] = f
	delete(first, "cloudflare")

	second := providers.Registry()
	if _, ok := second["cloudflare"]; !ok {
		t.Error("changing one Registry removed another Registry entry")
	}
	if got := second["internetbs"].Fields[0].Label; got == "changed" {
		t.Error("changing one Factory mutated another Registry's fields")
	}
}

func TestHetznerRegistryFactoriesAreIndependent(t *testing.T) {
	first := providers.Registry()
	f, ok := first["hetzner"]
	if !ok {
		t.Fatal("Hetzner is absent from Registry")
	}
	if len(f.Fields) != 1 || f.Fields[0].Name != "token" || !f.Fields[0].Secret {
		t.Fatalf("Hetzner credential fields = %+v", f.Fields)
	}
	f.Fields[0].Label = "changed"
	first["hetzner"] = f
	delete(first, "hetzner")
	second := providers.Registry()
	if got, ok := second["hetzner"]; !ok || got.Fields[0].Label == "changed" {
		t.Fatal("changing one Registry mutated another Hetzner Factory")
	}
}

func TestOVHcloudRegistryFactoriesAreIndependent(t *testing.T) {
	first := providers.Registry()
	f, ok := first["ovhcloud"]
	if !ok {
		t.Fatal("OVHcloud is absent from Registry")
	}
	if len(f.Fields) != 4 || !f.Fields[0].Secret || !f.Fields[1].Secret || !f.Fields[2].Secret || f.Fields[3].Name != "endpoint" || f.Fields[3].Secret {
		t.Fatalf("OVHcloud fields = %+v", f.Fields)
	}
	f.Fields[0].Label = "changed"
	delete(first, "ovhcloud")
	second := providers.Registry()
	if got, ok := second["ovhcloud"]; !ok || got.Fields[0].Label == "changed" {
		t.Fatal("changing one Registry mutated another OVHcloud Factory")
	}
	if _, err := second.New("ovhcloud", map[string]string{"application_key": "a", "application_secret": "s", "consumer_key": "c", "endpoint": "ovh-ca"}); err != nil {
		t.Fatal(err)
	}
}

func TestEachFactoryDeclaresTheTTLRangeOfItsProviders(t *testing.T) {
	r := providers.Registry()

	for typ, f := range r {
		p, err := r.New(typ, validFields[typ])
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}

		if got, want := f.TTLRange(), dnsprovider.TTLRangeOf(p); got != want {
			t.Errorf("%s: Factory declares TTL range %+v, its Provider takes %+v", typ, got, want)
		}
	}
}

func TestFactoryTTLRangesNeedNoProvider(t *testing.T) {
	r := providers.Registry()

	for typ, want := range map[string]dnsprovider.TTLRange{
		"cloudflare": {Min: 60, Max: 86400, Auto: true},
		"godaddy":    {Min: 600, Max: 86400},
		"vultr":      {Min: 30, Max: 86400},
	} {
		if got := r[typ].TTLRange(); got != want {
			t.Errorf("%s: Factory TTL range = %+v, want %+v", typ, got, want)
		}
	}
}

func TestEachFactoryDeclaresTheProxiableTypesOfItsProviders(t *testing.T) {
	r := providers.Registry()

	for typ, f := range r {
		p, err := r.New(typ, validFields[typ])
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}

		if got, want := f.ProxiableTypes(), dnsprovider.ProxiableTypesOf(p); !slices.Equal(got, want) {
			t.Errorf("%s: Factory declares proxiable types %v, its Provider proxies %v", typ, got, want)
		}
	}
}

func TestEachFactoryDeclaresWellFormedExtras(t *testing.T) {
	kinds := []dnsprovider.ExtraKind{dnsprovider.ExtraBool, dnsprovider.ExtraString, dnsprovider.ExtraJSON}

	for typ, f := range providers.Registry() {
		var keys []string

		for _, s := range f.Extras {
			if s.Key == "" || s.Label == "" || !slices.Contains(kinds, s.Kind) {
				t.Errorf("%s: extra %+v has no key, no label or an unknown kind", typ, s)
			}

			if slices.Contains(keys, s.Key) {
				t.Errorf("%s: extra %q is declared twice", typ, s.Key)
			}

			keys = append(keys, s.Key)

			for _, rt := range s.Types {
				if rt != strings.ToUpper(rt) {
					t.Errorf("%s: extra %q names type %q, not upper case", typ, s.Key, rt)
				}
			}
		}
	}
}

func TestFactoriesDeclareTheRecordExtrasTheirProvidersRead(t *testing.T) {
	const (
		b = dnsprovider.ExtraBool
		s = dnsprovider.ExtraString
		j = dnsprovider.ExtraJSON
	)

	want := map[string][]dnsprovider.ExtraSpec{
		"cloudflare": {
			{Key: "proxied", Label: "Proxied", Kind: b, Writable: true, Types: []string{"A", "AAAA", "CNAME"}},
			{Key: "comment", Label: "Comment", Kind: s},
			{Key: "tags", Label: "Tags", Kind: j},
		},
		"cloudns": {{Key: "*", Label: "Record metadata", Kind: s}},
		"dnsimple": {
			{Key: "system_record", Label: "System record", Kind: b},
			{Key: "regions", Label: "Regions", Kind: j},
			{Key: "parent_id", Label: "Parent record ID", Kind: s},
		},
		"hetzner": {
			{Key: "comment", Label: "Comment", Kind: s},
			{Key: "protected", Label: "Change protection", Kind: b},
			{Key: "labels", Label: "Labels", Kind: j},
		},
		"internetbs": {
			{Key: "internetbs:wire_value", Label: "Wire value", Kind: s, Types: []string{"CNAME", "NS", "MX"}},
			{Key: "*", Label: "Record metadata", Kind: j},
		},
		"porkbun": {{Key: "notes", Label: "Notes", Kind: s, Writable: true}},
	}

	for typ, f := range providers.Registry() {
		if got := f.Extras; !reflect.DeepEqual(got, want[typ]) {
			t.Errorf("%s: Extras = %+v, want %+v", typ, got, want[typ])
		}
	}
}
