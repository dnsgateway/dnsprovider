package digitalocean_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

const zoneFile = `$ORIGIN example.com.
$TTL 1800
example.com. IN SOA ns1.digitalocean.com. hostmaster.example.com. 1415982609 10800 3600 604800 1800
example.com. 1800 IN NS ns1.digitalocean.com.
example.com. 1800 IN NS ns2.digitalocean.com.
example.com. 1800 IN NS ns3.digitalocean.com.
example.com. 1800 IN A 1.2.3.4
`

func domainJSON(name string) string {
	return fmt.Sprintf(`{"name":%q,"ttl":1800,"zone_file":%q}`, name, strings.ReplaceAll(zoneFile, "example.com", name))
}

// next is a production next-page link, as DigitalOcean answers it.
func next(path string, page int) string {
	return fmt.Sprintf(`"links":{"pages":{"first":"https://api.digitalocean.com/v2%[1]s?page=1","next":"https://api.digitalocean.com/v2%[1]s?page=%[2]d","last":"https://api.digitalocean.com/v2%[1]s?page=%[2]d"}}`, path, page)
}

func TestZonesFollowNextLinksThroughConfiguredEndpointAndFilterExactly(t *testing.T) {
	var pages []string
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/domains":
			pages = append(pages, r.URL.Query().Get("page")+"/"+r.URL.Query().Get("per_page"))
			if r.URL.Query().Get("page") == "1" {
				fmt.Fprintf(w, `{"domains":[%s,%s],%s,"meta":{"total":3}}`, domainJSON("Example.COM"), domainJSON("example.community"), next("/domains", 2))
			} else {
				fmt.Fprintf(w, `{"domains":[%s],"links":{"pages":{"first":"https://api.digitalocean.com/v2/domains?page=1","prev":"https://api.digitalocean.com/v2/domains?page=1"}},"meta":{"total":3}}`, domainJSON("shop.example.com"))
			}
		case "/v2/domains/example.com":
			fmt.Fprintf(w, `{"domain":%s}`, domainJSON("example.com"))
		case "/v2/domains/missing.com":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"id":"not_found","message":"The resource you were accessing could not be found.","request_id":"4d9d8375-3c56-4925-a3e7-eb137fed17e9"}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	allSet, err := p.Zones(ctx, dnsprovider.ZoneFilter{})
	all := allSet.Zones

	if err != nil || len(all) != 3 || !reflect.DeepEqual(pages, []string{"1/200", "2/200"}) {
		t.Fatalf("Zones: %+v %v pages=%v", all, err, pages)
	}

	if allSet.Partial {
		t.Error("Zones is a Partial View, want a full view")
	}

	set, err := p.Zones(ctx, dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."})
	zs := set.Zones

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
		fmt.Fprint(w, `{"domains":[],"links":{},"meta":{"total":0}}`)
	})
	set, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
	zs := set.Zones

	if err != nil || len(zs) != 0 {
		t.Fatalf("Zones: %+v %v", zs, err)
	}
}

func TestZoneDeniedScopeIsNotAMissingZone(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"id":"Forbidden","message":"You are not authorized to perform this operation"}`)
	})
	_, err := p.Zone(context.Background(), "example.com")
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("denied: %v", err)
	}
}

func TestPaginationRefusesUntrustedRepeatedOrInconsistentPages(t *testing.T) {
	d := domainJSON("example.com")
	for name, tc := range map[string]struct {
		body func(page string) string
		want error
	}{
		"foreign host": {func(string) string {
			return fmt.Sprintf(`{"domains":[%s],"links":{"pages":{"next":"https://attacker.example/v2/domains?page=2"}},"meta":{"total":2}}`, d)
		}, nil},
		"other list": {func(string) string {
			return fmt.Sprintf(`{"domains":[%s],"links":{"pages":{"next":"https://api.digitalocean.com/v2/droplets?page=2"}},"meta":{"total":2}}`, d)
		}, nil},
		"skipped page": {func(string) string {
			return fmt.Sprintf(`{"domains":[%s],%s,"meta":{"total":2}}`, d, next("/domains", 3))
		}, nil},
		"same page": {func(page string) string {
			return fmt.Sprintf(`{"domains":[%s],"links":{"pages":{"next":"https://api.digitalocean.com/v2/domains?page=%s"}},"meta":{"total":2}}`, d, page)
		}, rest.ErrSamePage},
		"repeated contents": {func(page string) string {
			n := map[string]int{"1": 2, "2": 3, "3": 4}[page]
			return fmt.Sprintf(`{"domains":[%s],%s,"meta":{"total":9}}`, d, next("/domains", n))
		}, rest.ErrSamePage},
		"empty intermediate page": {func(string) string {
			return fmt.Sprintf(`{"domains":[],%s,"meta":{"total":2}}`, next("/domains", 2))
		}, nil},
		"short of total": {func(string) string { return fmt.Sprintf(`{"domains":[%s],"links":{},"meta":{"total":2}}`, d) }, nil},
		"missing list":   {func(string) string { return `{"links":{},"meta":{"total":0}}` }, nil},
		"null list":      {func(string) string { return `{"domains":null}` }, nil},
		"nameless":       {func(string) string { return `{"domains":[{"name":""}],"links":{},"meta":{"total":1}}` }, nil},
	} {
		t.Run(name, func(t *testing.T) {
			var hosts []string
			p := provider(t, func(w http.ResponseWriter, r *http.Request) {
				hosts = append(hosts, r.Host)
				fmt.Fprint(w, tc.body(r.URL.Query().Get("page")))
			})
			_, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("Zones: %v", err)
			}
			if tc.want == nil && len(hosts) != 1 {
				t.Fatalf("followed a refused next page: %d requests", len(hosts))
			}
		})
	}
}

// recordsFixture are realistic Domain Records of every supported type,
// as GET /v2/domains/example.com/records answers them.
const recordsFixture = `[
{"id":28448429,"type":"NS","name":"@","data":"ns1.digitalocean.com","priority":null,"port":null,"ttl":1800,"weight":null,"flags":null,"tag":null},
{"id":28448432,"type":"A","name":"@","data":"1.2.3.4","priority":null,"port":null,"ttl":1800,"weight":null,"flags":null,"tag":null},
{"id":28448433,"type":"A","name":"www","data":"162.10.66.0","priority":null,"port":null,"ttl":1800,"weight":null,"flags":null,"tag":null},
{"id":28448434,"type":"AAAA","name":"*","data":"2001:db8::1","priority":null,"port":null,"ttl":3600,"weight":null,"flags":null,"tag":null},
{"id":28448435,"type":"CNAME","name":"alias","data":"@","priority":null,"port":null,"ttl":43200,"weight":null,"flags":null,"tag":null},
{"id":28448436,"type":"MX","name":"@","data":"mail.example.net","priority":10,"port":null,"ttl":14400,"weight":null,"flags":null,"tag":null},
{"id":28448437,"type":"SRV","name":"_sip._tcp","data":"sip.example.net","priority":0,"port":5060,"ttl":1800,"weight":5,"flags":null,"tag":null},
{"id":28448438,"type":"TXT","name":"@","data":"v=spf1 include:_spf.example.net -all","priority":null,"port":null,"ttl":3600,"weight":null,"flags":null,"tag":null},
{"id":28448439,"type":"CAA","name":"@","data":"letsencrypt.org","priority":null,"port":null,"ttl":3600,"weight":null,"flags":0,"tag":"issue"},
{"id":28448440,"type":"CAA","name":"@","data":"mailto:security@example.com","priority":null,"port":null,"ttl":3600,"weight":null,"flags":128,"tag":"iodef"},
{"id":28448441,"type":"SOA","name":"@","data":"1800","priority":null,"port":null,"ttl":1800,"weight":null,"flags":null,"tag":null}
]`

var wantRecords = []dnsprovider.Record{
	{ID: "28448429", Type: "NS", Name: "example.com", Value: "ns1.digitalocean.com.", TTL: 1800},
	{ID: "28448432", Type: "A", Name: "example.com", Value: "1.2.3.4", TTL: 1800},
	{ID: "28448433", Type: "A", Name: "www.example.com", Value: "162.10.66.0", TTL: 1800},
	{ID: "28448434", Type: "AAAA", Name: "*.example.com", Value: "2001:db8::1", TTL: 3600},
	{ID: "28448435", Type: "CNAME", Name: "alias.example.com", Value: "example.com.", TTL: 43200},
	{ID: "28448436", Type: "MX", Name: "example.com", Value: "10 mail.example.net.", TTL: 14400},
	{ID: "28448437", Type: "SRV", Name: "_sip._tcp.example.com", Value: "0 5 5060 sip.example.net.", TTL: 1800},
	{ID: "28448438", Type: "TXT", Name: "example.com", Value: "v=spf1 include:_spf.example.net -all", TTL: 3600},
	{ID: "28448439", Type: "CAA", Name: "example.com", Value: `0 issue "letsencrypt.org"`, TTL: 3600},
	{ID: "28448440", Type: "CAA", Name: "example.com", Value: `128 iodef "mailto:security@example.com"`, TTL: 3600},
	{ID: "28448441", Type: "SOA", Name: "example.com", Value: "1800", TTL: 1800},
}

func TestRecordsConvertStructuredFieldsAndReportSerial(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/domains/example.com":
			fmt.Fprintf(w, `{"domain":%s}`, domainJSON("example.com"))
		case "/v2/domains/example.com/records":
			fmt.Fprintf(w, `{"domain_records":%s,"links":{},"meta":{"total":11}}`, recordsFixture)
		default:
			t.Errorf("unexpected request %s", r.URL)
		}
	})
	set, err := p.Records(context.Background(), dnsprovider.Zone{ID: "example.com", Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil || !reflect.DeepEqual(set.Records, wantRecords) || set.Serial != 1415982609 {
		t.Fatalf("Records: %+v %v", set, err)
	}

	if set.Partial {
		t.Error("Records is a Partial View, want a full view")
	}
}

func TestRecordsExhaustPagesAndFilterExactly(t *testing.T) {
	var queries []string
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/domains/example.com" {
			fmt.Fprint(w, `{"domain":{"name":"example.com","ttl":1800,"zone_file":null}}`)
			return
		}
		if r.URL.Path != "/v2/domains/example.com/records" {
			t.Errorf("unexpected request %s", r.URL)
		}
		queries = append(queries, r.URL.Query().Encode())
		rows := map[string]string{
			"1": `{"id":1,"type":"A","name":"www","data":"192.0.2.1","ttl":60}`,
			"2": `{"id":2,"type":"A","name":"www.example","data":"192.0.2.2","ttl":60}`,
			"3": `{"id":3,"type":"A","name":"WWW","data":"192.0.2.3","ttl":60}`,
		}
		page := r.URL.Query().Get("page")
		link := `"links":{}`
		if page != "3" {
			link = next("/domains/example.com/records", int(page[0]-'0')+1)
		}
		fmt.Fprintf(w, `{"domain_records":[%s],%s,"meta":{"total":3}}`, rows[page], link)
	})
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "example.com", Name: "example.com"}
	set, err := p.Records(ctx, z, dnsprovider.RecordFilter{Type: "a", Contains: "WWW.EXAMPLE.COM."})
	if err != nil || len(set.Records) != 2 || set.Records[0].ID != "1" || set.Records[1].ID != "3" || set.Serial != 0 {
		t.Fatalf("Records: %+v %v", set, err)
	}
	if !strings.Contains(queries[0], "type=A") || len(queries) != 3 {
		t.Fatalf("queries: %v", queries)
	}
	queries = nil
	set, err = p.Records(ctx, z, dnsprovider.RecordFilter{Type: "URI"})
	if err != nil || len(set.Records) != 0 || len(queries) != 0 {
		t.Fatalf("unsupported type: %+v %v %v", set, err, queries)
	}
}

func TestRecordsOfMissingZoneAndMalformedRecordsFail(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"id":"not_found","message":"The resource you were accessing could not be found."}`)
	})
	if _, err := p.Records(context.Background(), dnsprovider.Zone{Name: "missing.com"}, dnsprovider.RecordFilter{}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	for _, row := range []string{
		`{"id":0,"type":"A","name":"www","data":"192.0.2.1","ttl":60}`,
		`{"id":1,"type":"A","data":"192.0.2.1","ttl":60}`,
		`{"id":1,"type":"A","name":"www","ttl":60}`,
		`{"id":1,"type":"A","name":"www","data":"192.0.2.1"}`,
		`{"id":1,"type":"MX","name":"@","data":"mail.example.net","ttl":60,"priority":null}`,
		`{"id":1,"type":"SRV","name":"_sip._tcp","data":"sip.example.net","ttl":60,"priority":1,"weight":1}`,
		`{"id":1,"type":"CAA","name":"@","data":"letsencrypt.org","ttl":60,"flags":0,"tag":null}`,
	} {
		t.Run(row, func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/domains/example.com" {
					fmt.Fprintf(w, `{"domain":%s}`, domainJSON("example.com"))
					return
				}
				fmt.Fprintf(w, `{"domain_records":[%s],"links":{},"meta":{"total":1}}`, row)
			})
			if _, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{}); err == nil {
				t.Fatal("malformed Record accepted")
			}
		})
	}
}
