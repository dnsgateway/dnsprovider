// Package livetest reads a real Provider Account, for the adapters'
// optional live tests.
package livetest

import (
	"context"
	"os"
	"slices"
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

// closer is a Provider that holds a session to end when done.
type closer interface {
	Close(ctx context.Context) error
}

// Run builds a Provider from its Factory's fields, read from the
// environment (see Env), and reads its Account, its Zones, the first of
// them by name and its Records, unfiltered and then filtered by the
// first Record's type and name, without writing to the Account. It skips
// the test unless every secret field is set. A Provider that lists
// Tenants has them listed too. Every read must be a Full View, not a
// Partial View: the Providers here do not report one.
// DNSPROVIDER_<TYPE>_BASE_URL may point it at another endpoint, such as a
// sandbox. A Provider with a Close(ctx) method, such as Netim's, which
// holds a session, is closed when the test ends.
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

	if c, ok := p.(closer); ok {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			if err := c.Close(ctx); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if _, err := p.Account(ctx); err != nil {
		t.Fatalf("Account: %v", err)
	}

	if dnsprovider.Can(p, dnsprovider.CapTenantLister) {
		if _, err := p.ListTenants(ctx); err != nil {
			t.Fatalf("Tenants: %v", err)
		}
	}

	zs, err := p.ListZones(ctx, dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	if zs.Partial {
		t.Error("Zones is a Partial View, want a Full View")
	}

	zones := zs.Zones

	for _, z := range zones {
		if z.ID == "" || z.Name == "" {
			t.Errorf("Zone %+v has no ID or Name", z)
		}
	}

	if len(zones) == 0 {
		return
	}

	z, err := p.GetZone(ctx, zones[0].Name)
	if err != nil {
		t.Fatalf("Zone(%s): %v", zones[0].Name, err)
	}

	if z.ID != zones[0].ID || z.State != zones[0].State {
		t.Errorf("Zone(%s) = %+v, want %+v as Zones listed it", zones[0].Name, z, zones[0])
	}

	rs, err := p.ListRecords(ctx, zones[0], dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("ListRecords(%s): %v", zones[0].Name, err)
	}

	if rs.Partial {
		t.Errorf("ListRecords(%s) is a Partial View, want a Full View", zones[0].Name)
	}

	if len(rs.Records) == 0 {
		return
	}

	// A filtered read holds just the Records of the whole read that the
	// filter matches, whatever the Provider's API filtered itself. A type
	// no Provider holds finds none rather than failing.
	first := rs.Records[0]
	for _, rf := range []dnsprovider.RecordFilter{
		{Type: first.Type, Contains: first.Name},
		{Type: first.Type},
		{Contains: first.Name},
		{Type: "NOSUCHTYPE"},
	} {
		filtered, err := p.ListRecords(ctx, zones[0], rf)
		if err != nil {
			t.Fatalf("ListRecords(%s, %+v): %v", zones[0].Name, rf, err)
		}

		var want []string
		for _, r := range rs.Records {
			if dnsprovider.MatchRecord(rf, r) {
				want = append(want, r.ID)
			}
		}

		if got := recordIDs(filtered.Records); !slices.Equal(got, sorted(want)) {
			t.Errorf("ListRecords(%s, %+v) = %v, want %v from the whole read", zones[0].Name, rf, got, sorted(want))
		}
	}
}

// recordIDs returns the Records' IDs, sorted.
func recordIDs(records []dnsprovider.Record) []string {
	ids := make([]string, 0, len(records))
	for _, r := range records {
		ids = append(ids, r.ID)
	}

	return sorted(ids)
}

func sorted(s []string) []string {
	s = append([]string{}, s...)
	slices.Sort(s)

	return s
}
