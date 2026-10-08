// Package livetest reads a real Provider Account, for the adapters'
// optional live tests.
package livetest

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

// Env is the environment variable holding a Provider's field, such as
// DNSPROVIDER_CLOUDFLARE_TOKEN for Cloudflare's "token".
func Env(typ, field string) string {
	return "DNSPROVIDER_" + strings.ToUpper(typ) + "_" + strings.ToUpper(field)
}

// Run builds a Provider from its Factory's fields, read from the
// environment (see Env), and reads its Account without writing to it. It
// skips the test unless every secret field is set. A Provider that lists
// Tenants has them listed, and its Zones read only when its Tenant is set
// too: Zones failing with dnsprovider.ErrNoTenant ends the test there.
// DNSPROVIDER_<TYPE>_BASE_URL may point it at another endpoint, such as a
// sandbox.
func Run(t *testing.T, typ string, f dnsprovider.Factory) {
	t.Helper()

	fields := map[string]string{}

	for _, fd := range f.Fields {
		v := os.Getenv(Env(typ, fd.Name))
		if v == "" && fd.Secret {
			t.Skipf("%s is not set", Env(typ, fd.Name))
		}

		if v != "" {
			fields[fd.Name] = v
		}
	}

	var opts []dnsprovider.Option
	if u := os.Getenv(Env(typ, "base_url")); u != "" {
		opts = append(opts, dnsprovider.WithBaseURL(u))
	}

	p, err := f.New(fields, opts...)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := p.Account(ctx); err != nil {
		t.Fatalf("Account: %v", err)
	}

	tenants := dnsprovider.CanListTenants(p)
	if tenants {
		if _, err := p.(dnsprovider.TenantLister).Tenants(ctx); err != nil {
			t.Fatalf("Tenants: %v", err)
		}
	}

	zones, err := p.Zones(ctx, dnsprovider.ZoneFilter{})
	if tenants && errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Logf("Zones not read: %v", err)

		return
	}

	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	for _, z := range zones {
		if z.ID == "" || z.Name == "" {
			t.Errorf("Zone %+v has no ID or Name", z)
		}
	}

	if len(zones) == 0 {
		return
	}

	if _, err := p.Records(ctx, zones[0]); err != nil {
		t.Fatalf("Records(%s): %v", zones[0].Name, err)
	}
}
