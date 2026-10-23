package inwx_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// updateFake is a recordFake that also takes nameserver.updateRecord.
func updateFake(t *testing.T) *fake {
	t.Helper()

	f := recordFake(t)
	f.handle("nameserver.updateRecord", f.updateRecord)

	return f
}

// updateRecord changes the fields the call sends of the record of its
// id, in whichever zone holds it.
func (f *fake) updateRecord(r *request) string {
	for _, z := range f.zones {
		for _, rec := range z.records {
			if fmt.Sprint(rec["id"]) != fmt.Sprint(r.params["id"]) {
				continue
			}

			for _, k := range []string{"name", "type", "content", "ttl", "prio"} {
				if v, ok := r.params[k]; ok {
					rec[k] = v
				}
			}

			return fixture(f.t, "ok.json")
		}
	}

	return refusal(2303, "")
}

func TestUpdateRecordSendsOneUpdateByIDAndReturnsTheRecordReadBack(t *testing.T) {
	f := updateFake(t)
	before := exampleComRecords[3] // A example.com 192.0.2.1

	after := before
	after.Value, after.TTL = "192.0.2.99", 600

	got, err := f.provider().UpdateRecord(context.Background(), exampleCom, before, after)
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Record{ID: "5004", Type: "A", Name: "example.com", Value: "192.0.2.99", TTL: 600}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UpdateRecord = %+v, want %+v", got, want)
	}

	if w := f.writesSent(); !slices.Equal(w, []string{"nameserver.updateRecord"}) {
		t.Fatalf("writes = %v, want one updateRecord", w)
	}

	p := f.params("nameserver.updateRecord")
	if p["id"] != "5004" || p["name"] != "example.com" || p["type"] != "A" || p["content"] != "192.0.2.99" || p["ttl"] != float64(600) || p["prio"] != float64(0) {
		t.Fatalf("updateRecord params = %v", p)
	}
}

func TestUpdateRecordMovesToAnotherNameAndTypeWithOneUpdate(t *testing.T) {
	f := updateFake(t)
	before := exampleComRecords[4] // AAAA www 2001:db8::1
	after := dnsprovider.Record{Type: "MX", Name: "mail", Value: "5 mx.example.net.", TTL: 900}

	got, err := f.provider().UpdateRecord(context.Background(), exampleCom, before, after)
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Record{ID: "5005", Type: "MX", Name: "mail.example.com", Value: "5 mx.example.net.", TTL: 900}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UpdateRecord = %+v, want %+v", got, want)
	}

	if w := f.writesSent(); !slices.Equal(w, []string{"nameserver.updateRecord"}) {
		t.Fatalf("writes = %v, want one updateRecord and no create or delete", w)
	}

	p := f.params("nameserver.updateRecord")
	if p["id"] != "5005" || p["name"] != "mail.example.com" || p["type"] != "MX" || p["content"] != "mx.example.net" || p["prio"] != float64(5) {
		t.Fatalf("updateRecord params = %v", p)
	}

	rs, err := f.provider().ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{Type: "AAAA"})
	if err != nil {
		t.Fatal(err)
	}

	if len(rs.Records) != 0 {
		t.Fatalf("the Zone still holds %+v", rs.Records)
	}
}

func TestUpdateRecordOfAnIDTheZoneDoesNotHoldIsErrNotFoundWithoutAWrite(t *testing.T) {
	for name, before := range map[string]dnsprovider.Record{
		"another zone's": {ID: "6002", Type: "NS", Name: "example.com", Value: "ns.inwx.de.", TTL: 86400},
		"a deleted":      {ID: "4999", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
	} {
		f := updateFake(t)

		_, err := f.provider().UpdateRecord(context.Background(), exampleCom, before, newRecord)
		if !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("%s ID: UpdateRecord = %v, want ErrNotFound", name, err)
		}

		if w := f.writesSent(); len(w) != 0 {
			t.Fatalf("%s ID: writes = %v, want none", name, w)
		}
	}
}

func TestUpdateRecordToADuplicateOfAnotherRecordIsErrConflictWithoutAWrite(t *testing.T) {
	f := updateFake(t)

	// The Zone holds A *.example.com 192.0.2.2 as Record 5013.
	after := dnsprovider.Record{Type: "A", Name: "*", Value: "192.0.2.2", TTL: 600}

	_, err := f.provider().UpdateRecord(context.Background(), exampleCom, exampleComRecords[3], after)
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("UpdateRecord = %v, want ErrConflict", err)
	}

	if w := f.writesSent(); len(w) != 0 {
		t.Fatalf("writes = %v, want none", w)
	}
}

func TestUpdateRecordOfTheTTLAloneIsNotAConflictWithItself(t *testing.T) {
	f := updateFake(t)
	before := exampleComRecords[3]

	after := before
	after.TTL = 7200

	got, err := f.provider().UpdateRecord(context.Background(), exampleCom, before, after)
	if err != nil || !reflect.DeepEqual(got, after) {
		t.Fatalf("UpdateRecord = %+v, %v, want %+v", got, err, after)
	}
}

func TestUpdateRecordRefusesLocallyWithoutARequest(t *testing.T) {
	ctx := context.Background()
	f := updateFake(t)
	p := f.provider()
	before := exampleComRecords[3]

	for _, after := range []dnsprovider.Record{
		{Type: "A", Name: "www.example.org.", Value: "192.0.2.1", TTL: 3600},
		{Type: "A", Name: "www", Value: "not an address", TTL: 3600},
		{Type: "MX", Name: "@", Value: "mail.example.net", TTL: 3600},
		{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 299},
		{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 86401},
		{Type: "A", Name: "www", Value: "192.0.2.1", TTL: dnsprovider.TTLAuto},
		{Type: "TLSA", Name: "_443._tcp", Value: "3 1 1 00", TTL: 3600},
		{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 3600, Extras: map[string]string{dnsprovider.ExtraProxied: "true"}},
	} {
		if _, err := p.UpdateRecord(ctx, exampleCom, before, after); err == nil {
			t.Errorf("UpdateRecord to %+v succeeded", after)
		}
	}

	for _, b := range []dnsprovider.Record{
		{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
		{ID: "abc", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
		exampleComRecords[0],  // SOA
		exampleComRecords[11], // URL
	} {
		if _, err := p.UpdateRecord(ctx, exampleCom, b, newRecord); err == nil {
			t.Errorf("UpdateRecord of %+v succeeded", b)
		}
	}

	if _, err := p.UpdateRecord(ctx, dnsprovider.Zone{ID: "1001"}, before, newRecord); err == nil {
		t.Error("UpdateRecord in a Zone without a name succeeded")
	}

	if n := len(f.methodsCalled()); n != 0 {
		t.Errorf("sent %d requests, want none: %v", n, f.methodsCalled())
	}
}

func TestUpdateRecordWhoseOutcomeIsUnknownIsUnconfirmedAndNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"a lost answer", lost, ""},
		{"HTTP 502", http.StatusBadGateway, "<html>bad gateway</html>"},
		{"HTTP 404", http.StatusNotFound, "<html>not found</html>"},
		{"an undecodable answer", http.StatusOK, "not json"},
		{"code 1001", http.StatusOK, answer(1001, nil)},
		{"code 2400", http.StatusOK, refusal(2400, "SYNTHETIC: internal error")},
		{"code 2502", http.StatusOK, refusal(2502, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := updateFake(t)
			f.script("nameserver.updateRecord", tc.status, tc.body)

			_, err := f.provider().UpdateRecord(context.Background(), exampleCom, exampleComRecords[3], newRecord)
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("UpdateRecord = %v, want ErrUnconfirmed", err)
			}

			if n := f.count("nameserver.updateRecord"); n != 1 {
				t.Fatalf("sent updateRecord %d times, want once", n)
			}
		})
	}
}

func TestUpdateRecordWhoseReadBackDoesNotShowItIsUnconfirmed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		handle func(f *fake) handler
	}{
		{"a success that changed nothing", func(f *fake) handler {
			return func(*request) string { return fixture(f.t, "ok.json") }
		}},
		{"a record stored with another TTL", func(f *fake) handler {
			return func(r *request) string {
				r.params["ttl"] = float64(3600)

				return f.updateRecord(r)
			}
		}},
		{"a failed read-back", func(f *fake) handler {
			return func(r *request) string {
				// The handler runs with f.mu held.
				f.once["nameserver.info"] = append(f.once["nameserver.info"], reply{http.StatusOK, refusal(2400, "")})

				return f.updateRecord(r)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := updateFake(t)
			f.handle("nameserver.updateRecord", tc.handle(f))

			_, err := f.provider().UpdateRecord(context.Background(), exampleCom, exampleComRecords[3], newRecord)
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("UpdateRecord = %v, want ErrUnconfirmed", err)
			}

			if n := f.count("nameserver.updateRecord"); n != 1 {
				t.Fatalf("sent updateRecord %d times, want once", n)
			}
		})
	}
}

func TestUpdateRecordRefusedByINWXIsAPlainAPIErrorCarryingItsCode(t *testing.T) {
	for _, code := range []int{2003, 2005, 2306} {
		f := updateFake(t)
		f.scriptCode("nameserver.updateRecord", code, "SYNTHETIC: refused")

		_, err := f.provider().UpdateRecord(context.Background(), exampleCom, exampleComRecords[3], newRecord)

		var api *dnsprovider.APIError
		if !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnconfirmed) ||
			!strings.Contains(err.Error(), fmt.Sprint(code)) || !strings.Contains(err.Error(), "SYNTHETIC: refused") {
			t.Errorf("code %d: %v, want a plain APIError with the code and reason", code, err)
		}

		if n := f.count("nameserver.updateRecord"); n != 1 {
			t.Errorf("code %d: sent updateRecord %d times, want once", code, n)
		}
	}
}

func TestApplyUpdatesGoThroughUpdateRecord(t *testing.T) {
	f := updateFake(t)
	before := exampleComRecords[4] // AAAA www

	after := before
	after.ID, after.Value = "", "2001:db8::2"

	res, err := dnsprovider.Apply(context.Background(), f.provider(), dnsprovider.Changeset{Zone: exampleCom, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeModify, Before: before, After: after},
	}})
	if err != nil {
		t.Fatal(err)
	}

	if r := res.Results[0]; r.Err != nil || r.Record.ID != "5005" || r.Record.Value != "2001:db8::2" {
		t.Fatalf("modify = %+v", r)
	}

	if w := f.writesSent(); !slices.Equal(w, []string{"nameserver.updateRecord"}) {
		t.Fatalf("writes = %v, want one updateRecord", w)
	}
}
