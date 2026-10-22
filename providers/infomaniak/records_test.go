package infomaniak_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

var exampleCH = dnsprovider.Zone{ID: "example.ch", Name: "example.ch"}

func TestListRecordsReadsEveryPageInPresentationForm(t *testing.T) {
	f := newFake(t)

	set, err := f.provider().ListRecords(context.Background(), exampleCH, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.Record{
		{ID: "22429078", Type: "NS", Name: "example.ch", Value: "ns11.infomaniak.ch.", TTL: 3600},
		{ID: "22585703", Type: "A", Name: "test.example.ch", Value: "192.0.2.1", TTL: 3600},
		{ID: "22592559", Type: "AAAA", Name: "test.example.ch", Value: "2001:db8::3", TTL: 300},
		{ID: "22592561", Type: "CAA", Name: "example.ch", Value: `0 issue "sectigo.com"`, TTL: 3600},
		{ID: "22592587", Type: "CNAME", Name: "test2.example.ch", Value: "test.example.test.", TTL: 3600},
		{ID: "22592804", Type: "DS", Name: "test.example.ch", Value: "2371 15 1 23711321F987CC6583E92DF0890718C42", TTL: 3600},
		{ID: "22592805", Type: "MX", Name: "mail.example.ch", Value: "10 mail.example.test.", TTL: 3600},
		{ID: "22592829", Type: "NS", Name: "test6.example.ch", Value: "test.example.test.", TTL: 3600},
		{ID: "22592951", Type: "SRV", Name: "_imap._tcp.example.ch", Value: "10 0 8000 test.example.test.", TTL: 3600},
		{ID: "22592952", Type: "SSHFP", Name: "test.example.ch", Value: "4 2 A9759105BF5A6BDE1555CF2D30E2049B3E63DC81C899DC5C1DEC28CD02A9E88F", TTL: 3600},
		{ID: "22592953", Type: "TXT", Name: "_dmarc.example.ch", Value: "v=DMARC1; p=reject; aspf=s; adkim=s; rua=mailto:security@example.test; ruf=mailto:security@example.test;", TTL: 3600},
		{ID: "22592990", Type: "TLSA", Name: "test.example.ch", Value: "0 0 1 2B8C10F47DE35F59C834305E5DFDB6C549DA57A79DF470728B3A67CAB99256C1", TTL: 3600},
		{ID: "22600001", Type: "A", Name: "*.example.ch", Value: "192.0.2.9", TTL: 300},
		{ID: "22600002", Type: "TXT", Name: "long.example.ch", Value: "first chunk second chunk", TTL: 300},
		{ID: "22600003", Type: "MX", Name: "example.ch", Value: "0 .", TTL: 3600},
		{ID: "22600004", Type: "CNAME", Name: "www.example.ch", Value: "example.ch.", TTL: 3600},
	}

	if !reflect.DeepEqual(set.Records, want) {
		t.Fatalf("Records =\n%+v\nwant\n%+v", set.Records, want)
	}

	if set.Serial != 0 || set.Partial {
		t.Fatalf("Serial %d, Partial %v; want 0 and a Full View", set.Serial, set.Partial)
	}

	if q := f.queries("GET /2/zones/example.ch/records"); len(q) != 4 || q[3].Get("page") != "4" {
		t.Fatalf("queries = %v, want 4 pages", q)
	}
}

func TestListRecordsPushesTheTypeDownAndFiltersExactly(t *testing.T) {
	f := newFake(t)

	set, err := f.provider().ListRecords(context.Background(), exampleCH, dnsprovider.RecordFilter{Type: "mx", Contains: "MAIL.example.ch."})
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.Record{{ID: "22592805", Type: "MX", Name: "mail.example.ch", Value: "10 mail.example.test.", TTL: 3600}}
	if !reflect.DeepEqual(set.Records, want) {
		t.Fatalf("Records = %+v, want %+v", set.Records, want)
	}

	if q := f.queries("GET /2/zones/example.ch/records"); len(q) != 1 || q[0]["filter[types][]"][0] != "MX" {
		t.Fatalf("queries = %v, want filter[types][]=MX", q)
	}
}

func TestListRecordsOfATypeInfomaniakDoesNotHoldFindsNone(t *testing.T) {
	f := newFake(t)

	set, err := f.provider().ListRecords(context.Background(), exampleCH, dnsprovider.RecordFilter{Type: "URI"})
	if err != nil || len(set.Records) != 0 {
		t.Fatalf("ListRecords = %+v, %v; want no Record", set, err)
	}

	for _, q := range f.queries("GET /2/zones/example.ch/records") {
		if q.Has("filter[types][]") {
			t.Fatalf("query %v pushes down a type Infomaniak does not hold", q)
		}
	}
}

func TestListRecordsReadsTXTAsLiteralTextAndCAAInPresentationForm(t *testing.T) {
	f := newFake(t)
	f.script("GET /2/zones/example.ch/records", http.StatusOK, `{"result":"success","data":[
		{"id":1,"source":"a","type":"TXT","ttl":60,"target":"\"quoted\""},
		{"id":2,"source":"b","type":"TXT","ttl":60,"target":"say \"hi\""},
		{"id":3,"source":"c","type":"TXT","ttl":60,"target":"\"unterminated"},
		{"id":4,"source":".","type":"CAA","ttl":60,"target":"0 issuewild letsencrypt.org"},
		{"id":5,"source":"d","type":"MX","ttl":60,"target":"20  mx.example.test."},
		{"id":6,"source":"e","type":"SRV","ttl":60,"target":"1 2 3 ."}
	],"total":6,"page":1,"pages":1,"items_per_page":100}`)

	set, err := f.provider().ListRecords(context.Background(), exampleCH, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, r := range set.Records {
		got = append(got, r.Value)
	}

	want := []string{"quoted", `say "hi"`, `"unterminated`, `0 issuewild "letsencrypt.org"`, "20 mx.example.test.", "1 2 3 ."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Values = %q, want %q", got, want)
	}
}

func TestListRecordsOfARegisteredDomainWithoutAZoneIsNotServed(t *testing.T) {
	f := newFake(t)

	_, err := f.provider().ListRecords(context.Background(), dnsprovider.Zone{ID: "external-dns.com", Name: "external-dns.com"}, dnsprovider.RecordFilter{})
	if !errors.Is(err, dnsprovider.ErrNotServed) {
		t.Fatalf("ListRecords = %v, want ErrNotServed", err)
	}

	_, err = f.provider().ListRecords(context.Background(), dnsprovider.Zone{ID: "unknown.example", Name: "unknown.example"}, dnsprovider.RecordFilter{})
	if !errors.Is(err, dnsprovider.ErrNotFound) || errors.Is(err, dnsprovider.ErrNotServed) {
		t.Fatalf("ListRecords of an unknown Zone = %v, want ErrNotFound alone", err)
	}
}

func TestListRecordsFailsOnAShortOrRepeatedPage(t *testing.T) {
	page1 := `{"result":"success","data":[{"id":1,"source":"a","type":"A","ttl":60,"target":"192.0.2.1"},{"id":2,"source":"b","type":"A","ttl":60,"target":"192.0.2.2"}],"total":4,"page":1,"pages":2,"items_per_page":2}`
	repeat := `{"result":"success","data":[{"id":1,"source":"a","type":"A","ttl":60,"target":"192.0.2.1"},{"id":2,"source":"b","type":"A","ttl":60,"target":"192.0.2.2"}],"total":4,"page":2,"pages":2,"items_per_page":2}`
	short := `{"result":"success","data":[{"id":1,"source":"a","type":"A","ttl":60,"target":"192.0.2.1"}],"total":3,"page":1,"pages":2,"items_per_page":2}`

	for name, replies := range map[string][]string{"repeated": {page1, repeat}, "short": {short}} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			for _, r := range replies {
				f.script("GET /2/zones/example.ch/records", http.StatusOK, r)
			}

			if set, err := f.provider().ListRecords(context.Background(), exampleCH, dnsprovider.RecordFilter{}); err == nil {
				t.Fatalf("ListRecords = %+v, want an error", set)
			}
		})
	}
}

func TestListRecordsRefusesAMalformedRecord(t *testing.T) {
	for _, rec := range []string{
		`{"source":"a","type":"A","ttl":60,"target":"192.0.2.1"}`,
		`{"id":1,"source":"a","ttl":60,"target":"192.0.2.1"}`,
		`{"id":1,"source":"a","type":"A","ttl":60}`,
		`{"id":1,"type":"A","ttl":60,"target":"192.0.2.1"}`,
		`{"id":1,"source":"a","type":"A","target":"192.0.2.1"}`,
	} {
		f := newFake(t)
		f.script("GET /2/zones/example.ch/records", http.StatusOK, `{"result":"success","data":[`+rec+`],"total":1,"page":1,"pages":1,"items_per_page":100}`)

		if set, err := f.provider().ListRecords(context.Background(), exampleCH, dnsprovider.RecordFilter{}); err == nil {
			t.Fatalf("%s: ListRecords = %+v, want an error", rec, set)
		}
	}
}
