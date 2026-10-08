package providers_test

import (
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider/providers"
)

func TestRegistryHasOneFactoryPerProvider(t *testing.T) {
	r := providers.Registry()

	if got, want := r.Types(), []string{"cloudflare", "godaddy", "namecheap"}; !slices.Equal(got, want) {
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
