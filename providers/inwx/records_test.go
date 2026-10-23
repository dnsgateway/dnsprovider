package inwx_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

var exampleCom = dnsprovider.Zone{ID: "1001", Name: "example.com"}

// exampleComRecords are the Records of nameserver_info_example_com.json
// as a consumer sees them.
var exampleComRecords = []dnsprovider.Record{
	{ID: "5001", Type: "SOA", Name: "example.com", Value: "ns.inwx.de hostmaster.inwx.de 2026102201 10800 3600 604800 3600", TTL: 86400},
	{ID: "5002", Type: "NS", Name: "example.com", Value: "ns.inwx.de.", TTL: 86400},
	{ID: "5003", Type: "NS", Name: "example.com", Value: "ns2.inwx.de.", TTL: 86400},
	{ID: "5004", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
	{ID: "5005", Type: "AAAA", Name: "www.example.com", Value: "2001:db8::1", TTL: 3600},
	{ID: "5006", Type: "CNAME", Name: "alias.example.com", Value: "www.example.com.", TTL: 300},
	{ID: "5007", Type: "MX", Name: "example.com", Value: "10 mail.example.net.", TTL: 3600},
	{ID: "5008", Type: "SRV", Name: "_sip._tcp.example.com", Value: "10 0 5060 sip.example.net.", TTL: 3600},
	{ID: "5009", Type: "TXT", Name: "example.com", Value: `v=spf1 include:example.net "quoted" -all`, TTL: 3600},
	{ID: "5010", Type: "CAA", Name: "example.com", Value: `0 issue "letsencrypt.org"`, TTL: 3600},
	{ID: "5011", Type: "URI", Name: "_ftp._tcp.example.com", Value: `10 1 "ftp://ftp.example.com/public"`, TTL: 3600},
	{ID: "5012", Type: "URL", Name: "redirect.example.com", Value: "https://www.example.org", TTL: 3600},
	{ID: "5013", Type: "A", Name: "*.example.com", Value: "192.0.2.2", TTL: 3600},
	{ID: "5014", Type: "TXT", Name: "txt.example.com", Value: `  two  spaces, a back\slash and "quotes"  `, TTL: 600},
	{ID: "5015", Type: "ALIAS", Name: "example.com", Value: "lb.example.net", TTL: 3600},
	{ID: "5016", Type: "MX", Name: "null.example.com", Value: "0 .", TTL: 3600},
	{ID: "5017", Type: "TLSA", Name: "_443._tcp.www.example.com", Value: "3 1 1 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", TTL: 3600},
}

func TestListRecordsReturnsEveryRecordInTheSharedForm(t *testing.T) {
	f := newFake(t)

	rs, err := f.provider().ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if rs.Serial != 2026102201 || rs.Partial {
		t.Fatalf("Serial = %d, Partial = %v, want 2026102201 and a Full View", rs.Serial, rs.Partial)
	}

	if len(rs.Records) != len(exampleComRecords) {
		t.Fatalf("ListRecords = %d Records, want %d: %+v", len(rs.Records), len(exampleComRecords), rs.Records)
	}

	for i, want := range exampleComRecords {
		if !reflect.DeepEqual(rs.Records[i], want) {
			t.Errorf("Record %d = %+v, want %+v", i, rs.Records[i], want)
		}
	}

	if p := f.params("nameserver.info"); p["domain"] != "example.com" || p["type"] != nil || p["name"] != nil {
		t.Fatalf("nameserver.info params = %v, want the zone unfiltered", p)
	}
}

func TestListRecordsKeepsTheWritableValuesValid(t *testing.T) {
	f := newFake(t)

	rs, err := f.provider().ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range rs.Records {
		if dnsprovider.Editable(r.Type) {
			if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
				t.Errorf("%s %s: %v", r.Type, r.Name, err)
			}
		}
	}
}

func TestListRecordsPushesASingleTypeDownAndFiltersExactly(t *testing.T) {
	f := newFake(t)

	rs, err := f.provider().ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{Type: "mx", Contains: "NULL."})
	if err != nil {
		t.Fatal(err)
	}

	if got := ids(rs.Records); !slices.Equal(got, []string{"5016"}) {
		t.Fatalf("ListRecords = %v, want the null MX alone", got)
	}

	if p := f.params("nameserver.info"); p["type"] != "MX" {
		t.Fatalf("nameserver.info params = %v, want type MX pushed down", p)
	}
}

func TestListRecordsFiltersByNameLocally(t *testing.T) {
	f := newFake(t)

	rs, err := f.provider().ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{Contains: "www."})
	if err != nil {
		t.Fatal(err)
	}

	if got := ids(rs.Records); !slices.Equal(got, []string{"5005", "5017"}) {
		t.Fatalf("ListRecords = %v, want www and the TLSA under it", got)
	}
}

func TestListRecordsOfATypeINWXDoesNotKnowFindsNone(t *testing.T) {
	f := newFake(t)

	rs, err := f.provider().ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{Type: "NOSUCHTYPE"})
	if err != nil || len(rs.Records) != 0 {
		t.Fatalf("ListRecords = %+v, %v, want none", rs, err)
	}

	if p := f.params("nameserver.info"); p["type"] != nil {
		t.Fatalf("nameserver.info params = %v, want no type pushed down", p)
	}
}

func TestListRecordsOfAZoneKnownByItsIDAloneReadsItByRoID(t *testing.T) {
	f := newFake(t)

	rs, err := f.provider().ListRecords(context.Background(), dnsprovider.Zone{ID: "1002"}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if got := ids(rs.Records); !slices.Equal(got, []string{"6001", "6002", "6003", "6004"}) {
		t.Fatalf("ListRecords = %v, want example.org's", got)
	}

	if p := f.params("nameserver.info"); number(p["roId"], 0) != 1002 || p["domain"] != nil {
		t.Fatalf("nameserver.info params = %v, want roId 1002", p)
	}
}

func TestListRecordsOfARegisteredDomainWithoutAZoneIsNotServed(t *testing.T) {
	f := newFake(t)

	_, err := f.provider().ListRecords(context.Background(), dnsprovider.Zone{Name: "example.net"}, dnsprovider.RecordFilter{})
	if !errors.Is(err, dnsprovider.ErrNotServed) {
		t.Fatalf("ListRecords = %v, want ErrNotServed", err)
	}
}

func TestListRecordsOfAZoneWithoutNameOrIDSendsNothing(t *testing.T) {
	f := newFake(t)

	if _, err := f.provider().ListRecords(context.Background(), dnsprovider.Zone{}, dnsprovider.RecordFilter{}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("ListRecords = %v, want ErrNotFound", err)
	}

	if got := f.methodsCalled(); len(got) != 0 {
		t.Fatalf("sent %v", got)
	}
}

func TestListRecordsRefusesATruncatedList(t *testing.T) {
	f := newFake(t)
	f.handle("nameserver.info", func(*request) string {
		return answer(1000, map[string]any{
			"roId": 1001, "domain": "example.com", "SOAserial": "1", "count": 2,
			"record": []any{map[string]any{"id": "5004", "name": "example.com", "type": "A", "content": "192.0.2.1", "ttl": 3600, "prio": 0}},
		})
	})

	if _, err := f.provider().ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{}); err == nil {
		t.Fatal("ListRecords returned a truncated list")
	}
}

func TestListRecordsRefusesAMalformedRecord(t *testing.T) {
	for _, rec := range []map[string]any{
		{"name": "example.com", "type": "A", "content": "192.0.2.1", "ttl": 3600},
		{"id": "1", "name": "example.com", "content": "192.0.2.1", "ttl": 3600},
		{"id": "1", "name": "example.com", "type": "SRV", "content": "5060 sip.example.net", "ttl": 3600, "prio": 10},
	} {
		f := newFake(t)
		f.handle("nameserver.info", func(*request) string {
			return answer(1000, map[string]any{"roId": 1001, "domain": "example.com", "SOAserial": "1", "count": 1, "record": []any{rec}})
		})

		if _, err := f.provider().ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{}); err == nil {
			t.Fatalf("ListRecords took %v", rec)
		}
	}
}

func ids(records []dnsprovider.Record) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.ID)
	}

	return out
}
