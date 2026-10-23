package inwx_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

var allZones = []dnsprovider.Zone{
	{ID: "1001", Name: "example.com", State: dnsprovider.HostingUnknown},
	{ID: "1002", Name: "example.org", State: dnsprovider.HostingUnknown},
	{ID: "1003", Name: "slave.example.net", State: dnsprovider.HostingUnknown},
}

func TestListZonesReadsEveryPage(t *testing.T) {
	f := newFake(t)
	f.pageCap = 2

	zs, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(zs, dnsprovider.ZoneSet{Zones: allZones}) {
		t.Fatalf("ListZones = %+v, want %+v as a Full View", zs, allZones)
	}

	if n := f.count("nameserver.list"); n != 2 {
		t.Fatalf("read %d pages, want 2", n)
	}

	if p := f.params("nameserver.list"); number(p["page"], 0) != 2 {
		t.Fatalf("the last page read was %v, want 2", p["page"])
	}
}

func TestListZonesFiltersExactly(t *testing.T) {
	f := newFake(t)

	for _, tc := range []struct {
		contains string
		want     []string
	}{
		{"ORG", []string{"example.org"}},
		{"example.net.", []string{"slave.example.net"}},
		{"example.co", []string{"example.com"}},
		{"nothing", nil},
	} {
		zs, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: tc.contains})
		if err != nil {
			t.Fatal(err)
		}

		var got []string
		for _, z := range zs.Zones {
			got = append(got, z.Name)
		}

		if !slices.Equal(got, tc.want) {
			t.Errorf("ListZones(%q) = %v, want %v", tc.contains, got, tc.want)
		}
	}
}

func TestListZonesOfAnEmptyAccountIsEmpty(t *testing.T) {
	f := newFake(t)
	f.zones = nil

	zs, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil || len(zs.Zones) != 0 || zs.Partial {
		t.Fatalf("ListZones = %+v, %v, want no Zones", zs, err)
	}
}

func TestListZonesTakesACountAsAString(t *testing.T) {
	f := newFake(t)
	f.handle("nameserver.list", func(r *request) string {
		var a map[string]any
		_ = json.Unmarshal([]byte(f.list(r)), &a)
		res := a["resData"].(map[string]any)
		res["count"] = "3"

		data, _ := json.Marshal(a)

		return string(data)
	})

	zs, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil || len(zs.Zones) != 3 {
		t.Fatalf("ListZones = %+v, %v, want 3 Zones", zs, err)
	}
}

// pages answers nameserver.list with the given pages of zone indexes,
// and count.
func (f *fake) pages(count int, pages ...[]int) handler {
	return func(r *request) string {
		page := number(r.params["page"], 1)

		domains := []any{}

		if page <= len(pages) {
			for _, i := range pages[page-1] {
				z := f.zones[i]
				domains = append(domains, map[string]any{"roId": z.fields["roId"], "domain": z.name(), "type": z.fields["type"]})
			}
		}

		return answer(1000, map[string]any{"count": count, "domains": domains})
	}
}

func TestListZonesRefusesARepeatedOrShortPage(t *testing.T) {
	for name, tc := range map[string]struct {
		count int
		pages [][]int
		same  bool
	}{
		"repeated":         {3, [][]int{{0, 1}, {0, 1}}, true},
		"empty before end": {3, [][]int{{0, 1}, {}}, false},
		"short":            {5, [][]int{{0, 1}, {2}, {0, 1}}, false},
		"over the count":   {1, [][]int{{0, 1}}, false},
	} {
		f := newFake(t)
		f.handle("nameserver.list", f.pages(tc.count, tc.pages...))

		_, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{})
		if err == nil {
			t.Fatalf("%s: ListZones succeeded", name)
		}

		if tc.same && !errors.Is(err, rest.ErrSamePage) {
			t.Fatalf("%s: ListZones = %v, want ErrSamePage", name, err)
		}
	}
}

func TestListZonesFailsOnAFailedPage(t *testing.T) {
	f := newFake(t)
	f.pageCap = 2
	f.handle("nameserver.list", func(r *request) string {
		if number(r.params["page"], 1) == 2 {
			return refusal(2400, "")
		}

		return f.list(r)
	})

	if _, err := f.provider().ListZones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
		t.Fatal("ListZones succeeded with a failed page")
	}
}

func TestGetZoneIgnoresCaseAndATrailingDotAndReportsTheApexNameservers(t *testing.T) {
	f := newFake(t)

	z, err := f.provider().GetZone(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Zone{ID: "1001", Name: "example.com", State: dnsprovider.HostingUnknown, Nameservers: []string{"ns.inwx.de", "ns2.inwx.de"}}
	if !reflect.DeepEqual(z, want) {
		t.Fatalf("GetZone = %+v, want %+v", z, want)
	}

	if p := f.params("nameserver.info"); p["domain"] != "example.com" || p["type"] != "NS" {
		t.Fatalf("nameserver.info params = %v, want example.com filtered to NS", p)
	}
}

func TestGetZoneOfARegisteredDomainWithoutAZoneIsNotServed(t *testing.T) {
	f := newFake(t)

	_, err := f.provider().GetZone(context.Background(), "example.net")
	if !errors.Is(err, dnsprovider.ErrNotServed) || !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone = %v, want ErrNotServed", err)
	}
}

func TestGetZoneOfAnUnknownNameIsNotFound(t *testing.T) {
	f := newFake(t)

	_, err := f.provider().GetZone(context.Background(), "unknown.example")
	if !errors.Is(err, dnsprovider.ErrNotFound) || errors.Is(err, dnsprovider.ErrNotServed) {
		t.Fatalf("GetZone = %v, want ErrNotFound alone", err)
	}

	if n := f.count("domain.info"); n != 1 {
		t.Fatalf("read domain.info %d times, want 1", n)
	}
}

func TestGetZoneNeverTakesAFailedRegistrationReadForAbsence(t *testing.T) {
	f := newFake(t)
	f.scriptCode("domain.info", 2400, "")

	_, err := f.provider().GetZone(context.Background(), "unknown.example")
	if err == nil || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone = %v, want the domain.info failure", err)
	}
}

func TestGetZoneReturnsOtherFailuresWithoutReadingTheRegistration(t *testing.T) {
	f := newFake(t)
	f.scriptCode("nameserver.info", 2400, "")

	_, err := f.provider().GetZone(context.Background(), "example.com")
	if err == nil || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone = %v, want the nameserver.info failure", err)
	}

	if n := f.count("domain.info"); n != 0 {
		t.Fatalf("read domain.info %d times, want 0", n)
	}
}

func TestGetZoneOfABlankNameSendsNothing(t *testing.T) {
	f := newFake(t)

	if _, err := f.provider().GetZone(context.Background(), " . "); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone = %v, want ErrNotFound", err)
	}

	if got := f.methodsCalled(); len(got) != 0 {
		t.Fatalf("sent %v", got)
	}
}
