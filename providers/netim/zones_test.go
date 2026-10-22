package netim_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestListZonesReturnsEveryDomainAsAFullView(t *testing.T) {
	f := newFake(t)

	set, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if set.Partial {
		t.Error("ListZones is a Partial View, want a Full View")
	}

	var got []string

	for _, z := range set.Zones {
		if z.ID != z.Name || z.State != dnsprovider.HostingUnknown {
			t.Errorf("Zone %+v: want its name as ID and an Unknown Hosting State", z)
		}

		got = append(got, z.Name)
	}

	if want := []string{"example.com", "example.net", "example.org"}; !slices.Equal(got, want) {
		t.Fatalf("Zones = %v, want %v", got, want)
	}
}

func TestListZonesFiltersExactlyIgnoringCaseAndATrailingDot(t *testing.T) {
	f := newFake(t)
	f.script("POST /domains/", http.StatusOK, `[{"domain":"Example.COM"},{"domain":"shop.example.com."},{"domain":"example.community"}]`)

	set, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE.com."})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, z := range set.Zones {
		got = append(got, z.Name)
	}

	if want := []string{"example.com", "shop.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("Zones = %v, want %v", got, want)
	}
}

func TestGetZoneFindsADomainWithItsNameservers(t *testing.T) {
	f := newFake(t)

	z, err := f.provider().GetZone(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Zone{ID: "example.com", Name: "example.com", State: dnsprovider.HostingUnknown, Nameservers: []string{"ns1-ote.netim.net", "ns2-ote.netim.net"}}
	if z.ID != want.ID || z.Name != want.Name || z.State != want.State || !slices.Equal(z.Nameservers, want.Nameservers) {
		t.Fatalf("GetZone = %+v, want %+v", z, want)
	}
}

func TestGetZoneReadsEveryNameserverForm(t *testing.T) {
	for name, info := range map[string]string{
		"strings": `{"domain":"example.com","ns":["NS1.example.net.","ns2.example.net"]}`,
		"objects": `{"domain":"example.com","ns":[{"name":"NS1.example.net.","IPv4":""},{"name":"ns2.example.net"}]}`,
		"map":     `{"domain":"example.com","ns":{"1":{"name":"NS1.example.net."},"2":{"name":"ns2.example.net"}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.script("GET /domain/example.com/info/", http.StatusOK, info)

			z, err := f.provider().GetZone(context.Background(), "example.com")
			if err != nil {
				t.Fatal(err)
			}

			if want := []string{"ns1.example.net", "ns2.example.net"}; !slices.Equal(z.Nameservers, want) {
				t.Fatalf("Nameservers = %v, want %v", z.Nameservers, want)
			}
		})
	}
}

func TestGetZoneIsNotFoundOnlyWhenTheAccountHasNoSuchDomain(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if _, err := p.GetZone(context.Background(), "example.info"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone of a domain not held = %v, want ErrNotFound", err)
	}

	if n := f.count("GET /domain/example.info/info/"); n != 0 {
		t.Fatalf("read the info of a domain not held %d times", n)
	}

	f.script("POST /domains/", http.StatusBadRequest, fixture(t, "error_400.json"))

	if _, err := p.GetZone(context.Background(), "example.com"); err == nil || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone with a failed domain list = %v, want an error other than ErrNotFound", err)
	}

	f.script("GET /domain/example.com/info/", http.StatusMethodNotAllowed, fixture(t, "error_405.json"))

	var api *dnsprovider.APIError
	if _, err := p.GetZone(context.Background(), "example.com"); !errors.As(err, &api) || api.StatusCode != http.StatusMethodNotAllowed || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone with a failed info read = %v, want the 405 APIError", err)
	}
}

func TestAMalformedDomainListIsAnError(t *testing.T) {
	for _, body := range []string{`{`, `{}`, `null`, `[{"domain":""}]`, `[null]`} {
		t.Run(body, func(t *testing.T) {
			f := newFake(t)
			f.script("POST /domains/", http.StatusOK, body)

			if set, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
				t.Fatalf("ListZones = %+v, want an error", set)
			}
		})
	}
}
