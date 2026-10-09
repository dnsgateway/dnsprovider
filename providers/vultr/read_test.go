package vultr_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

func domainJSON(name string) string {
	return fmt.Sprintf(`{"domain":%q,"date_created":"2020-10-10T01:56:20+00:00","dns_sec":"disabled"}`, name)
}

// meta is a list answer's pagination metadata: next is an opaque cursor,
// empty on the last page.
func meta(total int, next, prev string) string {
	return fmt.Sprintf(`"meta":{"total":%d,"links":{"next":%q,"prev":%q}}`, total, next, prev)
}

func TestZonesFollowCursorsThroughConfiguredEndpointAndFilterExactly(t *testing.T) {
	var pages []string
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/domains":
			q := r.URL.Query()
			pages = append(pages, q.Get("cursor")+"/"+q.Get("per_page"))
			if q.Get("cursor") == "" {
				fmt.Fprintf(w, `{"domains":[%s,%s],%s}`, domainJSON("Example.COM"), domainJSON("example.community"), meta(3, "bmV4dF9fZXhhbXBsZS5jb21tdW5pdHk=", ""))
			} else {
				fmt.Fprintf(w, `{"domains":[%s],%s}`, domainJSON("shop.example.com"), meta(3, "", "cHJldl9fc2hvcC5leGFtcGxlLmNvbQ=="))
			}
		case "/v2/domains/example.com":
			fmt.Fprintf(w, `{"domain":%s}`, domainJSON("example.com"))
		case "/v2/domains/missing.com":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"Domain not found.","status":404}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	all, err := p.Zones(ctx, dnsprovider.ZoneFilter{})
	if err != nil || len(all) != 3 || !reflect.DeepEqual(pages, []string{"/500", "bmV4dF9fZXhhbXBsZS5jb21tdW5pdHk=/500"}) {
		t.Fatalf("Zones: %+v %v pages=%v", all, err, pages)
	}
	zs, err := p.Zones(ctx, dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."})
	want := []dnsprovider.Zone{
		{ID: "example.com", Name: "example.com", State: dnsprovider.HostingUnknown},
		{ID: "shop.example.com", Name: "shop.example.com", State: dnsprovider.HostingUnknown},
	}
	if err != nil || !reflect.DeepEqual(zs, want) {
		t.Fatalf("filtered Zones: %+v %v", zs, err)
	}
	z, err := p.Zone(ctx, "EXAMPLE.COM.")
	if err != nil || !reflect.DeepEqual(z, want[0]) {
		t.Fatalf("Zone: %+v %v", z, err)
	}
	if _, err := p.Zone(ctx, "missing.com"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("missing Zone: %v", err)
	}
}

func TestEmptyAccountListsNoZones(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"domains":[],%s}`, meta(0, "", ""))
	})
	zs, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil || len(zs) != 0 {
		t.Fatalf("Zones: %+v %v", zs, err)
	}
}

func TestDeniedDNSPermissionIsNotAnEmptyAccountOrMissingZone(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"Forbidden","status":403}`)
	})
	if _, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{}); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("denied Zones: %v", err)
	}
	_, err := p.Zone(context.Background(), "example.com")
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("denied Zone: %v", err)
	}
}

func TestZoneRejectsAnAnswerForAnotherDomain(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"domain":%s}`, domainJSON("other.com"))
	})
	if z, err := p.Zone(context.Background(), "example.com"); err == nil {
		t.Fatalf("Zone: %+v", z)
	}
}

func TestPaginationRefusesRepeatedOrInconsistentPages(t *testing.T) {
	d := domainJSON("example.com")
	for name, tc := range map[string]struct {
		body func(cursor string) string
		want error
	}{
		"repeated cursor": {func(string) string {
			return fmt.Sprintf(`{"domains":[%s],%s}`, d, meta(9, "c2FtZQ==", ""))
		}, rest.ErrSamePage},
		"cursor cycle": {func(c string) string {
			next := map[string]string{"": "YQ==", "YQ==": "Yg==", "Yg==": "YQ=="}[c]
			return fmt.Sprintf(`{"domains":[%s],%s}`, domainJSON("x"+c+".com"), meta(9, next, ""))
		}, rest.ErrSamePage},
		"empty intermediate page": {func(string) string {
			return fmt.Sprintf(`{"domains":[],%s}`, meta(2, "bmV4dA==", ""))
		}, nil},
		"short of total": {func(string) string { return fmt.Sprintf(`{"domains":[%s],%s}`, d, meta(2, "", "")) }, nil},
		"over total": {func(string) string {
			return fmt.Sprintf(`{"domains":[%s,%s],%s}`, d, domainJSON("b.com"), meta(1, "", ""))
		}, nil},
		"missing meta": {func(string) string { return fmt.Sprintf(`{"domains":[%s]}`, d) }, nil},
		"missing list": {func(string) string { return fmt.Sprintf(`{%s}`, meta(0, "", "")) }, nil},
		"null list":    {func(string) string { return fmt.Sprintf(`{"domains":null,%s}`, meta(0, "", "")) }, nil},
		"nameless":     {func(string) string { return fmt.Sprintf(`{"domains":[{"domain":""}],%s}`, meta(1, "", "")) }, nil},
		"not json":     {func(string) string { return `<html>` }, nil},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			p := provider(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls > 5 {
					t.Error("pagination does not end")
					w.WriteHeader(http.StatusTeapot)
					return
				}
				fmt.Fprint(w, tc.body(r.URL.Query().Get("cursor")))
			})
			_, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("Zones: %v", err)
			}
		})
	}
}

func TestCursorsThatLookLikeURLsStayOnTheConfiguredEndpoint(t *testing.T) {
	var cursors []string
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		c := r.URL.Query().Get("cursor")
		cursors = append(cursors, c)
		if c == "" {
			fmt.Fprintf(w, `{"domains":[%s],%s}`, domainJSON("a.com"), meta(2, "https://attacker.example/v2/domains?x=1", ""))
			return
		}
		fmt.Fprintf(w, `{"domains":[%s],%s}`, domainJSON("b.com"), meta(2, "", ""))
	})
	zs, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil || len(zs) != 2 || cursors[1] != "https://attacker.example/v2/domains?x=1" {
		t.Fatalf("Zones: %+v %v %v", zs, err, cursors)
	}
}

// recordsFixture are Records of every type Vultr holds, as
// GET /v2/domains/example.com/records answers them: names relative, ""
// the apex; host names without their trailing dot; TXT data in quotes;
// SRV data "weight port target" with the priority apart.
const recordsFixture = `[
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b60","type":"A","name":"","data":"192.0.2.10","priority":0,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b61","type":"A","name":"www","data":"192.0.2.11","priority":0,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b62","type":"AAAA","name":"*","data":"2001:db8::1","priority":0,"ttl":3600},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b63","type":"CNAME","name":"alias","data":"example.com","priority":0,"ttl":3600},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b64","type":"NS","name":"","data":"ns1.vultr.com","priority":0,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b65","type":"MX","name":"","data":"mail.example.net","priority":0,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b66","type":"MX","name":"null","data":".","priority":0,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b67","type":"SRV","name":"_sip._tcp","data":"5 5060 sip.example.net","priority":10,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b68","type":"TXT","name":"","data":"\"v=spf1 include:_spf.example.net -all\"","priority":0,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b69","type":"CAA","name":"","data":"0 issue \"letsencrypt.org\"","priority":0,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b6a","type":"CAA","name":"","data":"128 iodef mailto:security@example.com","priority":0,"ttl":300},
{"id":"cb676a46-66fd-4dfb-b839-443f2e6c0b6b","type":"SSHFP","name":"host","data":"4 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789","priority":0,"ttl":300}
]`

var wantRecords = []dnsprovider.Record{
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b60", Type: "A", Name: "example.com", Value: "192.0.2.10", TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b61", Type: "A", Name: "www.example.com", Value: "192.0.2.11", TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b62", Type: "AAAA", Name: "*.example.com", Value: "2001:db8::1", TTL: 3600},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b63", Type: "CNAME", Name: "alias.example.com", Value: "example.com.", TTL: 3600},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b64", Type: "NS", Name: "example.com", Value: "ns1.vultr.com.", TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b65", Type: "MX", Name: "example.com", Value: "0 mail.example.net.", TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b66", Type: "MX", Name: "null.example.com", Value: "0 .", TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b67", Type: "SRV", Name: "_sip._tcp.example.com", Value: "10 5 5060 sip.example.net.", TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b68", Type: "TXT", Name: "example.com", Value: "v=spf1 include:_spf.example.net -all", TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b69", Type: "CAA", Name: "example.com", Value: `0 issue "letsencrypt.org"`, TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b6a", Type: "CAA", Name: "example.com", Value: `128 iodef "mailto:security@example.com"`, TTL: 300},
	{ID: "cb676a46-66fd-4dfb-b839-443f2e6c0b6b", Type: "SSHFP", Name: "host.example.com", Value: "4 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789", TTL: 300},
}

func TestRecordsConvertStructuredFields(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/domains/example.com/records" {
			t.Errorf("unexpected request %s", r.URL)
		}
		fmt.Fprintf(w, `{"records":%s,%s}`, recordsFixture, meta(12, "", ""))
	})
	set, err := p.Records(context.Background(), exampleZone, dnsprovider.RecordFilter{})
	if err != nil || !reflect.DeepEqual(set.Records, wantRecords) || set.Serial != 0 {
		t.Fatalf("Records: %+v %v", set, err)
	}
}

func TestRecordsExhaustPagesAndFilterExactly(t *testing.T) {
	s := newRecords(t)
	for i := range 1100 {
		s.add(map[string]any{"type": "A", "name": fmt.Sprintf("h%d", i), "data": "192.0.2.1", "ttl": 300})
	}
	s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.2", "ttl": 60})
	s.add(map[string]any{"type": "A", "name": "www.example", "data": "192.0.2.3", "ttl": 60})
	s.add(map[string]any{"type": "TXT", "name": "WWW", "data": `"x"`, "ttl": 60})
	s.add(map[string]any{"type": "A", "name": "WWW", "data": "192.0.2.4", "ttl": 60})
	var lists int
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		lists++
		s.handler(w, r)
	})
	ctx := context.Background()
	set, err := p.Records(ctx, exampleZone, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 1104 || lists != 3 {
		t.Fatalf("Records: %d %v lists=%d", len(set.Records), err, lists)
	}
	set, err = p.Records(ctx, exampleZone, dnsprovider.RecordFilter{Type: "a", Contains: "WWW.EXAMPLE.COM."})
	if err != nil || len(set.Records) != 2 || set.Records[0].Value != "192.0.2.2" || set.Records[1].Value != "192.0.2.4" {
		t.Fatalf("filtered Records: %+v %v", set.Records, err)
	}
	set, err = p.Records(ctx, exampleZone, dnsprovider.RecordFilter{Type: "URI"})
	if err != nil || len(set.Records) != 0 {
		t.Fatalf("unsupported type: %+v %v", set, err)
	}
}

func TestRecordsOfAZoneNamedOnlyByID(t *testing.T) {
	s := newRecords(t)
	s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
	p := provider(t, s.handler)
	set, err := p.Records(context.Background(), dnsprovider.Zone{ID: "Example.com."}, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 1 || set.Records[0].Name != "www.example.com" {
		t.Fatalf("Records: %+v %v", set, err)
	}
}

func TestRecordsOfMissingZoneAndMalformedRecordsFail(t *testing.T) {
	s := newRecords(t)
	p := provider(t, s.handler)
	if _, err := p.Records(context.Background(), dnsprovider.Zone{Name: "missing.com"}, dnsprovider.RecordFilter{}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	for _, row := range []string{
		`{"id":"","type":"A","name":"www","data":"192.0.2.1","priority":0,"ttl":60}`,
		`{"id":"x","type":"A","data":"192.0.2.1","priority":0,"ttl":60}`,
		`{"id":"x","type":"A","name":"www","priority":0,"ttl":60}`,
		`{"id":"x","type":"A","name":"www","data":"192.0.2.1","priority":0}`,
		`{"id":"x","type":"A","name":"www","data":"192.0.2.1","priority":0,"ttl":-1}`,
		`{"id":"x","type":"MX","name":"","data":"mail.example.net","ttl":60}`,
		`{"id":"x","type":"MX","name":"","data":"mail.example.net","priority":70000,"ttl":60}`,
		`{"id":"x","type":"SRV","name":"_sip._tcp","data":"5 sip.example.net","priority":1,"ttl":60}`,
		`{"id":"x","type":"CAA","name":"","data":"0 issue","priority":0,"ttl":60}`,
		`{"id":"x","type":"CNAME","name":"www","data":"","priority":0,"ttl":60}`,
	} {
		t.Run(row, func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(w, `{"records":[%s],%s}`, row, meta(1, "", ""))
			})
			if _, err := p.Records(context.Background(), exampleZone, dnsprovider.RecordFilter{}); err == nil {
				t.Fatal("malformed Record accepted")
			}
		})
	}
}

func TestCAAValuesRoundTripDecimalEscapesAndControlCharacters(t *testing.T) {
	for data, want := range map[string]string{
		"0 iodef \"mailto:a\x01b@example.com\"":   `0 iodef "mailto:a\001b@example.com"`,
		`0 issue "ca.example.net; account=\"1\""`: `0 issue "ca.example.net; account=\"1\""`,
		"0 issue \"letsencrypt.org\"":             `0 issue "letsencrypt.org"`,
		`0 issue ;`:                               `0 issue ";"`,
		`0 iodef "mailto:\\back@example.com"`:     `0 iodef "mailto:\\back@example.com"`,
	} {
		t.Run(data, func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
				row, _ := json.Marshal(map[string]any{"id": "x", "type": "CAA", "name": "", "data": data, "priority": 0, "ttl": 300})
				fmt.Fprintf(w, `{"records":[%s],%s}`, row, meta(1, "", ""))
			})
			set, err := p.Records(context.Background(), exampleZone, dnsprovider.RecordFilter{})
			if err != nil || len(set.Records) != 1 || set.Records[0].Value != want {
				t.Fatalf("Records: %+v %v", set, err)
			}
		})
	}
}
