package ovhcloud_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

var testZone = dnsprovider.Zone{ID: "example.com", Name: "example.com"}

func discoveryFake(t *testing.T) *fake {
	t.Helper()

	f := newFake(t)
	f.addZone("example.com",
		wireRecord{ID: 11, FieldType: "A", SubDomain: "", Target: "192.0.2.1", TTL: 0},
		wireRecord{ID: 12, FieldType: "MX", SubDomain: "*.sub", Target: "10 mail", TTL: 600},
		wireRecord{ID: 13, FieldType: "TXT", SubDomain: "", Target: "v=spf1 include:mx.ovh.com ~all", TTL: 300},
		wireRecord{ID: 14, FieldType: "TXT", SubDomain: "multi", Target: `"one" "two"`, TTL: 300},
		wireRecord{ID: 15, FieldType: "SRV", SubDomain: "_sip._tcp", Target: "10 5 5060 sip.example.net.", TTL: 300},
		wireRecord{ID: 16, FieldType: "CAA", SubDomain: "", Target: `0 issue "letsencrypt.org"`, TTL: 300},
		wireRecord{ID: 17, FieldType: "CNAME", SubDomain: "WWW", Target: "example.com.", TTL: 300},
		wireRecord{ID: 18, FieldType: "SPF", SubDomain: "", Target: `"v=spf1 -all"`, TTL: 300},
		wireRecord{ID: 19, FieldType: "AAAA", SubDomain: "v6", Target: "2001:DB8::1", TTL: 300},
	)
	f.addZone("example.community")
	f.addZone("shop.example.net")

	return f
}

func TestZoneDiscoveryAndExactLookupAgree(t *testing.T) {
	f := discoveryFake(t)
	p := f.provider(t)

	allSet, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
	all := allSet.Zones

	if err != nil || len(all) != 3 {
		t.Fatalf("Zones = %+v, %v", all, err)
	}

	if allSet.Partial {
		t.Error("Zones is a Partial View, want a full view")
	}

	filteredSet, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."})
	filtered := filteredSet.Zones

	if err != nil || len(filtered) != 1 || filtered[0].Name != "example.com" {
		t.Fatalf("filtered Zones = %+v, %v", filtered, err)
	}

	z, err := p.Zone(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}

	if z.ID != filtered[0].ID || z.Name != "example.com" || z.State != dnsprovider.HostingUnknown || z.State != filtered[0].State {
		t.Fatalf("Zone = %+v, discovery %+v", z, filtered[0])
	}

	if !slices.Equal(z.Nameservers, []string{"dns200.anycast.me", "ns200.anycast.me"}) || !slices.Equal(z.Nameservers, filtered[0].Nameservers) {
		t.Fatalf("nameservers = %v / %v", z.Nameservers, filtered[0].Nameservers)
	}

	if _, err := p.Zone(context.Background(), "absent.example"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("absent Zone = %v", err)
	}

	f.fail["GET /domain/zone/example.com"] = []int{http.StatusForbidden}
	if _, err := p.Zone(context.Background(), "example.com"); !errors.Is(err, dnsprovider.ErrUnauthorized) || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("denied Zone = %v", err)
	}
}

func TestZoneListingRejectsRepeatedOrMalformedNames(t *testing.T) {
	for _, body := range []string{`["example.com","EXAMPLE.com."]`, `{"zones":[]}`, `[""]`, `null`} {
		t.Run(body, func(t *testing.T) {
			f := newFake(t)
			f.addZone("example.com")
			f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/zone" {
					_, _ = w.Write([]byte(body))

					return
				}

				f.serve(w, r)
			})

			if _, err := f.provider(t).Zones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
				t.Fatal("malformed listing accepted")
			}
		})
	}
}

func TestRecordsExpandIDsIntoRecords(t *testing.T) {
	f := discoveryFake(t)
	p := f.provider(t)

	rs, err := p.Records(context.Background(), testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if rs.Partial {
		t.Error("Records is a Partial View, want a full view")
	}

	if rs.Serial != 2026101001 || len(rs.Records) != 9 {
		t.Fatalf("Records = %+v", rs)
	}

	want := map[string]dnsprovider.Record{
		"11": {ID: "11", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
		"12": {ID: "12", Type: "MX", Name: "*.sub.example.com", Value: "10 mail.example.com.", TTL: 600},
		"13": {ID: "13", Type: "TXT", Name: "example.com", Value: `"v=spf1 include:mx.ovh.com ~all"`, TTL: 300},
		"14": {ID: "14", Type: "TXT", Name: "multi.example.com", Value: `"one" "two"`, TTL: 300},
		"15": {ID: "15", Type: "SRV", Name: "_sip._tcp.example.com", Value: "10 5 5060 sip.example.net.", TTL: 300},
		"16": {ID: "16", Type: "CAA", Name: "example.com", Value: `0 issue "letsencrypt.org"`, TTL: 300},
		"17": {ID: "17", Type: "CNAME", Name: "www.example.com", Value: "example.com.", TTL: 300},
		"18": {ID: "18", Type: "SPF", Name: "example.com", Value: `"v=spf1 -all"`, TTL: 300},
		"19": {ID: "19", Type: "AAAA", Name: "v6.example.com", Value: "2001:db8::1", TTL: 300},
	}

	for _, r := range rs.Records {
		w, ok := want[r.ID]
		if !ok || r.ID != w.ID || r.Type != w.Type || r.Name != w.Name || r.Value != w.Value || r.TTL != w.TTL {
			t.Errorf("Record %+v, want %+v", r, w)
		}
	}

	if got := countPrefix(f.requests, "GET /domain/zone/example.com/record/"); got != 9 {
		t.Errorf("per-record reads = %d", got)
	}
}

func countPrefix(list []string, prefix string) int {
	n := 0

	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}

	return n
}

func TestRecordFiltersKeepSharedSemantics(t *testing.T) {
	f := discoveryFake(t)
	p := f.provider(t)

	for _, tc := range []struct {
		filter dnsprovider.RecordFilter
		want   []string
	}{
		{dnsprovider.RecordFilter{Type: "mx", Contains: "SUB.EXAMPLE.COM."}, []string{"12"}},
		{dnsprovider.RecordFilter{Type: "txt"}, []string{"13", "14"}},
		{dnsprovider.RecordFilter{Contains: "www"}, []string{"17"}},
		{dnsprovider.RecordFilter{Contains: "example.com."}, []string{"11", "12", "13", "14", "15", "16", "17", "18", "19"}},
		{dnsprovider.RecordFilter{Contains: "multi.example.co"}, []string{"14"}},
		{dnsprovider.RecordFilter{Contains: "ulti"}, []string{"14"}},
		{dnsprovider.RecordFilter{Type: "NOSUCHTYPE"}, nil},
		{dnsprovider.RecordFilter{Type: "URI"}, nil},
	} {
		rs, err := p.Records(context.Background(), testZone, tc.filter)
		if err != nil {
			t.Fatalf("%+v: %v", tc.filter, err)
		}

		var got []string
		for _, r := range rs.Records {
			got = append(got, r.ID)
		}

		slices.Sort(got)

		if !slices.Equal(got, tc.want) {
			t.Errorf("%+v = %v, want %v", tc.filter, got, tc.want)
		}
	}

	for _, r := range f.requests {
		if strings.Contains(r, "subDomain=") || strings.Contains(r, "fieldType=NOSUCHTYPE") || strings.Contains(r, "fieldType=URI") {
			t.Errorf("filter pushdown changes semantics: %s", r)
		}
	}
}

func TestRecordReadsRejectMalformedOrRepeatedAnswers(t *testing.T) {
	for name, tc := range map[string]struct{ path, body string }{
		"repeated ids":    {"/domain/zone/example.com/record", `[11,11]`},
		"not an array":    {"/domain/zone/example.com/record", `{"ids":[11]}`},
		"other record":    {"/domain/zone/example.com/record/11", `{"id":12,"fieldType":"A","subDomain":"","target":"192.0.2.1","ttl":0,"zone":"example.com"}`},
		"other zone":      {"/domain/zone/example.com/record/11", `{"id":11,"fieldType":"A","subDomain":"","target":"192.0.2.1","ttl":0,"zone":"example.net"}`},
		"no type":         {"/domain/zone/example.com/record/11", `{"id":11,"subDomain":"","target":"192.0.2.1","ttl":0,"zone":"example.com"}`},
		"no default ttl":  {"/domain/zone/example.com/soa", `{"serial":1,"ttl":0}`},
		"malformed json":  {"/domain/zone/example.com/record/11", `{`},
		"missing target":  {"/domain/zone/example.com/record/11", `{"id":11,"fieldType":"A","subDomain":"","ttl":0,"zone":"example.com"}`},
		"vanished record": {"/domain/zone/example.com/record/11", ``},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.addZone("example.com", wireRecord{ID: 11, FieldType: "A", Target: "192.0.2.1"})
			f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.path {
					if tc.body == "" {
						f.apiError(w, http.StatusNotFound, "Client::NotFound", "gone")

						return
					}

					_, _ = w.Write([]byte(tc.body))

					return
				}

				f.serve(w, r)
			})

			if rs, err := f.provider(t).Records(context.Background(), testZone, dnsprovider.RecordFilter{}); err == nil {
				t.Fatalf("accepted %+v", rs)
			}
		})
	}
}

func TestRecordsOfAbsentZoneAreNotFound(t *testing.T) {
	f := discoveryFake(t)

	_, err := f.provider(t).Records(context.Background(), dnsprovider.Zone{Name: "absent.example"}, dnsprovider.RecordFilter{})
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("Records = %v", err)
	}
}
