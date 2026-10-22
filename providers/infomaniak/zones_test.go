package infomaniak_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/infomaniak"
)

func zoneNames(zs []dnsprovider.Zone) []string {
	var out []string
	for _, z := range zs {
		out = append(out, z.Name)
	}

	return out
}

func TestListZonesReadsEveryPageAsAFullView(t *testing.T) {
	f := newFake(t)
	f.perPage = 2

	set, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if set.Partial {
		t.Error("ListZones is a Partial View, want a Full View")
	}

	for _, z := range set.Zones {
		if z.ID != z.Name || z.State != dnsprovider.HostingUnknown {
			t.Errorf("Zone %+v: want its name as ID and an Unknown Hosting State", z)
		}
	}

	if got, want := zoneNames(set.Zones), []string{"example.ch", "external-dns.com", "example.org"}; !slices.Equal(got, want) {
		t.Fatalf("Zones = %v, want %v", got, want)
	}

	if q := f.queries("GET /2/domains/domains"); len(q) != 2 || q[0].Get("page") != "1" || q[1].Get("page") != "2" {
		t.Fatalf("queries = %v, want pages 1 and 2", q)
	}
}

func TestListZonesFiltersExactlyIgnoringCaseAndATrailingDot(t *testing.T) {
	f := newFake(t)
	f.script("GET /2/domains/domains", http.StatusOK,
		`{"result":"success","data":[{"name":"Example.CH"},{"name":"shop.example.ch."},{"name":"example.chat"}],"total":3,"page":1,"pages":1,"items_per_page":100}`)

	set, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE.ch."})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := zoneNames(set.Zones), []string{"example.ch", "shop.example.ch"}; !slices.Equal(got, want) {
		t.Fatalf("Zones = %v, want %v", got, want)
	}

	for _, z := range set.Zones {
		if z.ID != z.Name {
			t.Errorf("Zone ID %q is not its lower-case name", z.ID)
		}
	}
}

func TestListZonesScopesEveryPageToTheAccountID(t *testing.T) {
	f := newFake(t)
	f.perPage = 2

	set, err := f.providerFor(infomaniak.Config{Token: token, AccountID: "777"}).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if len(set.Zones) != 0 {
		t.Fatalf("Zones = %v, want none in another Account", zoneNames(set.Zones))
	}

	for _, q := range f.queries("GET /2/domains/domains") {
		if q.Get("account_id") != "777" {
			t.Fatalf("query %v has no account_id", q)
		}
	}
}

func TestListZonesFailsOnARepeatedShortOrMalformedPage(t *testing.T) {
	page := func(data string, page, pages, perPage, total int) string {
		return `{"result":"success","data":[` + data + `],"total":` + strconv.Itoa(total) + `,"page":` + strconv.Itoa(page) +
			`,"pages":` + strconv.Itoa(pages) + `,"items_per_page":` + strconv.Itoa(perPage) + `}`
	}

	a, b := `{"name":"a.example"}`, `{"name":"b.example"}`

	for name, replies := range map[string][]string{
		"repeated page":  {page(a+","+b, 1, 2, 2, 4), page(a+","+b, 1, 2, 2, 4)},
		"same items":     {page(a+","+b, 1, 2, 2, 4), page(a+","+b, 2, 2, 2, 4)},
		"short page":     {page(a, 1, 2, 2, 3)},
		"total mismatch": {page(a+","+b, 1, 1, 2, 5)},
		"no data":        {`{"result":"success","total":0,"page":1,"pages":1,"items_per_page":2}`},
		"nameless":       {page(`{"name":""}`, 1, 1, 2, 1)},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			for _, r := range replies {
				f.script("GET /2/domains/domains", http.StatusOK, r)
			}

			if set, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
				t.Fatalf("ListZones = %v, want an error", zoneNames(set.Zones))
			}
		})
	}
}

func TestListZonesTakesAnEmptyAccount(t *testing.T) {
	for _, pages := range []string{"0", "1"} {
		f := newFake(t)
		f.script("GET /2/domains/domains", http.StatusOK, `{"result":"success","data":[],"total":0,"page":1,"pages":`+pages+`,"items_per_page":100}`)

		set, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{})
		if err != nil || len(set.Zones) != 0 {
			t.Fatalf("pages %s: ListZones = %+v, %v; want no Zone", pages, set, err)
		}
	}
}

func TestGetZoneReadsTheZoneWithItsNameservers(t *testing.T) {
	f := newFake(t)

	z, err := f.provider().GetZone(context.Background(), "Example.CH.")
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Zone{ID: "example.ch", Name: "example.ch", State: dnsprovider.HostingUnknown, Nameservers: []string{"ns11.infomaniak.ch", "ns12.infomaniak.ch"}}
	if z.ID != want.ID || z.Name != want.Name || z.State != want.State || !slices.Equal(z.Nameservers, want.Nameservers) {
		t.Fatalf("GetZone = %+v, want %+v", z, want)
	}

	if n := len(f.queries("GET /2/domains/domains")); n != 0 {
		t.Fatalf("GetZone read the domain list %d times", n)
	}
}

func TestGetZoneIsScopedToTheAccountID(t *testing.T) {
	f := newFake(t)

	if _, err := f.providerFor(infomaniak.Config{Token: token, AccountID: "777"}).GetZone(context.Background(), "example.ch"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone in another Account = %v, want ErrNotFound", err)
	}

	z, err := f.providerFor(infomaniak.Config{Token: token, AccountID: accountID}).GetZone(context.Background(), "example.ch")
	if err != nil || z.Name != "example.ch" {
		t.Fatalf("GetZone in its Account = %+v, %v; want example.ch", z, err)
	}

	for _, q := range f.queries("GET /2/domains/domains") {
		if q.Get("account_id") == "" {
			t.Fatalf("query %v has no account_id", q)
		}
	}
}

func TestListZonesPushesContainsDownAsSearch(t *testing.T) {
	f := newFake(t)

	set, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE."})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := zoneNames(set.Zones), []string{"example.ch", "example.org"}; !slices.Equal(got, want) {
		t.Fatalf("Zones = %v, want %v", got, want)
	}

	if q := f.queries("GET /2/domains/domains"); len(q) != 1 || q[0].Get("search") != "example" {
		t.Fatalf("queries = %v, want search=example", q)
	}
}

func TestGetZoneOfARegisteredDomainWithoutAZoneIsNotServed(t *testing.T) {
	f := newFake(t)

	_, err := f.provider().GetZone(context.Background(), "external-dns.com")
	if !errors.Is(err, dnsprovider.ErrNotServed) || !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone = %v, want ErrNotServed", err)
	}
}

func TestGetZoneOfAnUnknownNameIsNotFound(t *testing.T) {
	for _, file := range []string{"zone_does_not_exists.json", "object_not_found.json"} {
		f := newFake(t)
		f.script("GET /2/zones/unknown.example", http.StatusNotFound, fixture(t, file))

		_, err := f.provider().GetZone(context.Background(), "unknown.example")
		if !errors.Is(err, dnsprovider.ErrNotFound) || errors.Is(err, dnsprovider.ErrNotServed) {
			t.Fatalf("%s: GetZone = %v, want ErrNotFound alone", file, err)
		}
	}
}

func TestGetZoneReturnsOtherFailuresAsTheyAre(t *testing.T) {
	f := newFake(t)
	f.script("GET /2/zones/example.ch", http.StatusUnprocessableEntity, fixture(t, "validation_failed.json"))

	_, err := f.provider().GetZone(context.Background(), "example.ch")

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusUnprocessableEntity || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone = %v, want the 422 APIError", err)
	}

	if want := []string{"validation_failed: Validation failed", "validation_rule_record_dns_ttl: validation.record_dns_ttl"}; !slices.Equal(api.Messages, want) {
		t.Fatalf("Messages = %q, want %q", api.Messages, want)
	}

	if n := len(f.queries("GET /2/domains/domains")); n != 0 {
		t.Fatalf("GetZone read the domain list %d times", n)
	}
}

func TestGetZoneRefusesAnAnswerForAnotherZone(t *testing.T) {
	f := newFake(t)
	f.script("GET /2/zones/example.ch", http.StatusOK, `{"result":"success","data":{"id":1,"fqdn":"other.example","nameservers":[]}}`)

	if z, err := f.provider().GetZone(context.Background(), "example.ch"); err == nil {
		t.Fatalf("GetZone = %+v, want an error", z)
	}
}
