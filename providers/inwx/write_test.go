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

// recordFake is a fake that also takes nameserver.createRecord and
// nameserver.deleteRecord, keeping record IDs unique across the account.
func recordFake(t *testing.T) *fake {
	t.Helper()

	f := newFake(t)
	f.handle("nameserver.createRecord", f.createRecord)
	f.handle("nameserver.deleteRecord", f.deleteRecord)

	return f
}

// createRecord adds a record to the zone of the call's domain, with the
// next ID of the account, and answers that ID.
func (f *fake) createRecord(r *request) string {
	z := f.zone(r.params)
	if z == nil {
		return refusal(2303, "")
	}

	for _, p := range []string{"type", "content", "name"} {
		if _, ok := r.params[p].(string); !ok {
			return refusal(2003, "SYNTHETIC: "+p+" missing")
		}
	}

	next := 0

	for _, zone := range f.zones {
		for _, rec := range zone.records {
			next = max(next, number(rec["id"], 0))
		}
	}

	id := fmt.Sprint(next + 1)
	z.records = append(z.records, map[string]any{
		"id": id, "name": r.params["name"], "type": r.params["type"], "content": r.params["content"],
		"ttl": r.params["ttl"], "prio": r.params["prio"],
	})

	return answer(1000, map[string]any{"id": id})
}

// deleteRecord removes the record of the call's id from whichever zone
// holds it.
func (f *fake) deleteRecord(r *request) string {
	for _, z := range f.zones {
		for i, rec := range z.records {
			if fmt.Sprint(rec["id"]) == fmt.Sprint(r.params["id"]) {
				z.records = slices.Delete(z.records, i, i+1)

				return fixture(f.t, "ok.json")
			}
		}
	}

	return refusal(2303, "")
}

// writesSent is the record writes the fake received, by method.
func (f *fake) writesSent() []string {
	var out []string

	for _, m := range f.methodsCalled() {
		if strings.HasPrefix(m, "nameserver.") && m != "nameserver.info" && m != "nameserver.list" {
			out = append(out, m)
		}
	}

	return out
}

func TestCreateRecordSendsOneCreateAndReturnsTheRecordReadBackByItsID(t *testing.T) {
	f := recordFake(t)

	got, err := f.provider().CreateRecord(context.Background(), exampleCom, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.10", TTL: 600})
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Record{ID: "7003", Type: "A", Name: "new.example.com", Value: "192.0.2.10", TTL: 600}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CreateRecord = %+v, want %+v", got, want)
	}

	if w := f.writesSent(); !slices.Equal(w, []string{"nameserver.createRecord"}) {
		t.Fatalf("writes = %v, want one createRecord", w)
	}

	p := f.params("nameserver.createRecord")
	if p["domain"] != "example.com" || p["name"] != "new.example.com" || p["type"] != "A" || p["content"] != "192.0.2.10" || p["ttl"] != float64(600) || p["prio"] != float64(0) {
		t.Fatalf("createRecord params = %v", p)
	}

	if p := f.params("nameserver.info"); p["recordId"] != "7003" {
		t.Fatalf("the read-back was not by the new ID: %v", p)
	}
}

func TestCreateRecordSendsEachWriteTypeInINWXsForm(t *testing.T) {
	for _, tc := range []struct {
		in      dnsprovider.Record
		name    string
		content string
		prio    float64
		value   string // the Value returned
	}{
		{dnsprovider.Record{Type: "AAAA", Name: "v6", Value: "2001:db8::10"}, "v6.example.com", "2001:db8::10", 0, "2001:db8::10"},
		{dnsprovider.Record{Type: "CNAME", Name: "c", Value: "target.example.net."}, "c.example.com", "target.example.net", 0, "target.example.net."},
		{dnsprovider.Record{Type: "CNAME", Name: "c2", Value: "target.example.net"}, "c2.example.com", "target.example.net", 0, "target.example.net."},
		{dnsprovider.Record{Type: "MX", Name: "@", Value: "20 mx2.example.net."}, "example.com", "mx2.example.net", 20, "20 mx2.example.net."},
		{dnsprovider.Record{Type: "MX", Name: "nomail", Value: "0 ."}, "nomail.example.com", ".", 0, "0 ."},
		{dnsprovider.Record{Type: "TXT", Name: "t", Value: ` a "quoted" back\slash `}, "t.example.com", ` a "quoted" back\slash `, 0, ` a "quoted" back\slash `},
		{dnsprovider.Record{Type: "NS", Name: "sub", Value: "ns1.example.net."}, "sub.example.com", "ns1.example.net", 0, "ns1.example.net."},
		{dnsprovider.Record{Type: "SRV", Name: "_xmpp._tcp", Value: "5 10 5222 xmpp.example.net."}, "_xmpp._tcp.example.com", "10 5222 xmpp.example.net", 5, "5 10 5222 xmpp.example.net."},
		{dnsprovider.Record{Type: "CAA", Name: "", Value: `0 issuewild "ca.example.net"`}, "example.com", `0 issuewild "ca.example.net"`, 0, `0 issuewild "ca.example.net"`},
		{dnsprovider.Record{Type: "URI", Name: "_http._tcp", Value: `10 1 "https://example.com/"`}, "_http._tcp.example.com", `1 "https://example.com/"`, 10, `10 1 "https://example.com/"`},
		{dnsprovider.Record{Type: "a", Name: "*.wild.example.com.", Value: "192.0.2.20"}, "*.wild.example.com", "192.0.2.20", 0, "192.0.2.20"},
	} {
		t.Run(tc.in.Type+" "+tc.name, func(t *testing.T) {
			f := recordFake(t)

			tc.in.TTL = 3600

			got, err := f.provider().CreateRecord(context.Background(), exampleCom, tc.in)
			if err != nil {
				t.Fatal(err)
			}

			p := f.params("nameserver.createRecord")
			if p["name"] != tc.name || p["content"] != tc.content || p["prio"] != tc.prio || p["ttl"] != float64(3600) {
				t.Fatalf("createRecord params = %v, want name %q, content %q, prio %v", p, tc.name, tc.content, tc.prio)
			}

			want := dnsprovider.Record{ID: "7003", Type: strings.ToUpper(tc.in.Type), Name: tc.name, Value: tc.value, TTL: 3600}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("CreateRecord = %+v, want %+v", got, want)
			}
		})
	}
}

func TestCreateRecordOfARecordTheZoneHoldsIsErrConflictWithoutAWrite(t *testing.T) {
	f := recordFake(t)

	// The Zone holds MX 10 mail.example.net at the apex.
	_, err := f.provider().CreateRecord(context.Background(), exampleCom, dnsprovider.Record{Type: "MX", Name: "@", Value: "10 mail.example.net", TTL: 600})
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("CreateRecord = %v, want ErrConflict", err)
	}

	if w := f.writesSent(); len(w) != 0 {
		t.Fatalf("writes = %v, want none", w)
	}
}

// newRecord is a Record the Zone does not hold.
var newRecord = dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.10", TTL: 600}

func TestCreateRecordRefusedAsExistingIsErrConflict(t *testing.T) {
	f := recordFake(t)
	f.scriptCode("nameserver.createRecord", 2302, "")

	_, err := f.provider().CreateRecord(context.Background(), exampleCom, newRecord)

	var api *dnsprovider.APIError
	if !errors.Is(err, dnsprovider.ErrConflict) || !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("CreateRecord = %v, want an ErrConflict APIError", err)
	}
}

func TestRecordWritesRefuseLocallyWithoutARequest(t *testing.T) {
	ctx := context.Background()
	f := recordFake(t)
	p := f.provider()

	for _, r := range []dnsprovider.Record{
		{Type: "A", Name: "www.example.org.", Value: "192.0.2.1", TTL: 3600},
		{Type: "A", Name: "www", Value: "not an address", TTL: 3600},
		{Type: "MX", Name: "@", Value: "mail.example.net", TTL: 3600},
		{Type: "URI", Name: "_http._tcp", Value: "10 1 https://example.com/", TTL: 3600},
		{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 299},
		{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 86401},
		{Type: "A", Name: "www", Value: "192.0.2.1", TTL: dnsprovider.TTLAuto},
		{Type: "TLSA", Name: "_443._tcp", Value: "3 1 1 00", TTL: 3600},
		{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 3600, Extras: map[string]string{dnsprovider.ExtraProxied: "true"}},
	} {
		if _, err := p.CreateRecord(ctx, exampleCom, r); err == nil {
			t.Errorf("CreateRecord(%+v) succeeded", r)
		}
	}

	if _, err := p.CreateRecord(ctx, dnsprovider.Zone{ID: "1001"}, newRecord); err == nil {
		t.Error("CreateRecord in a Zone without a name succeeded")
	}

	for _, r := range []dnsprovider.Record{
		{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
		{ID: "abc", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
		{ID: "5001", Type: "SOA", Name: "example.com", TTL: 86400},
	} {
		if err := p.DeleteRecord(ctx, exampleCom, r); err == nil {
			t.Errorf("DeleteRecord(%+v) succeeded", r)
		}
	}

	if n := len(f.methodsCalled()); n != 0 {
		t.Errorf("sent %d requests, want none: %v", n, f.methodsCalled())
	}
}

func TestRecordWritesWhoseOutcomeIsUnknownAreUnconfirmedAndNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"a lost answer", lost, ""},
		{"HTTP 502", http.StatusBadGateway, "<html>bad gateway</html>"},
		{"HTTP 404", http.StatusNotFound, "<html>not found</html>"},
		{"HTTP 429", http.StatusTooManyRequests, ""},
		{"an undecodable answer", http.StatusOK, "not json"},
		{"an answer without a code", http.StatusOK, `{"msg":"no code"}`},
		{"code 1001", http.StatusOK, answer(1001, map[string]any{"id": "7003"})},
		{"code 2400", http.StatusOK, refusal(2400, "SYNTHETIC: internal error")},
		{"code 2500", http.StatusOK, refusal(2500, "")},
		{"code 2502", http.StatusOK, refusal(2502, "")},
	} {
		t.Run("create after "+tc.name, func(t *testing.T) {
			f := recordFake(t)
			f.script("nameserver.createRecord", tc.status, tc.body)

			_, err := f.provider().CreateRecord(context.Background(), exampleCom, newRecord)
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("CreateRecord = %v, want ErrUnconfirmed", err)
			}

			if n := f.count("nameserver.createRecord"); n != 1 {
				t.Fatalf("sent createRecord %d times, want once", n)
			}
		})

		t.Run("delete after "+tc.name, func(t *testing.T) {
			f := recordFake(t)
			f.script("nameserver.deleteRecord", tc.status, tc.body)

			err := f.provider().DeleteRecord(context.Background(), exampleCom, exampleComRecords[3])
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("DeleteRecord = %v, want ErrUnconfirmed", err)
			}

			if n := f.count("nameserver.deleteRecord"); n != 1 {
				t.Fatalf("sent deleteRecord %d times, want once", n)
			}
		})
	}
}

func TestCreateRecordWhoseAnswerOrReadBackDoesNotShowItIsUnconfirmed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		handle func(f *fake) handler
	}{
		{"an answer without an id", func(*fake) handler {
			return func(*request) string { return answer(1000, map[string]any{}) }
		}},
		{"an id the zone does not hold", func(*fake) handler {
			return func(*request) string { return answer(1000, map[string]any{"id": 9999}) }
		}},
		{"a record stored with another TTL", func(f *fake) handler {
			return func(r *request) string {
				r.params["ttl"] = float64(3600)

				return f.createRecord(r)
			}
		}},
		{"a failed read-back", func(f *fake) handler {
			return func(r *request) string {
				// The handler runs with f.mu held.
				f.once["nameserver.info"] = append(f.once["nameserver.info"], reply{http.StatusOK, refusal(2400, "")})

				return f.createRecord(r)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := recordFake(t)
			f.handle("nameserver.createRecord", tc.handle(f))

			_, err := f.provider().CreateRecord(context.Background(), exampleCom, newRecord)
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("CreateRecord = %v, want ErrUnconfirmed", err)
			}

			if n := f.count("nameserver.createRecord"); n != 1 {
				t.Fatalf("sent createRecord %d times, want once", n)
			}
		})
	}
}

func TestRecordWritesRefusedByINWXArePlainAPIErrorsCarryingItsCode(t *testing.T) {
	ctx := context.Background()

	for _, code := range []int{2003, 2005, 2306} {
		f := recordFake(t)
		f.scriptCode("nameserver.createRecord", code, "SYNTHETIC: refused")
		f.scriptCode("nameserver.deleteRecord", code, "SYNTHETIC: refused")
		p := f.provider()

		_, cerr := p.CreateRecord(ctx, exampleCom, newRecord)
		derr := p.DeleteRecord(ctx, exampleCom, exampleComRecords[3])

		for _, err := range []error{cerr, derr} {
			var api *dnsprovider.APIError
			if !errors.As(err, &api) || api.StatusCode != 0 || errors.Is(err, dnsprovider.ErrUnconfirmed) ||
				!strings.Contains(err.Error(), fmt.Sprint(code)) || !strings.Contains(err.Error(), "SYNTHETIC: refused") {
				t.Errorf("code %d: %v, want a plain APIError with the code and reason", code, err)
			}
		}

		if c, d := f.count("nameserver.createRecord"), f.count("nameserver.deleteRecord"); c != 1 || d != 1 {
			t.Errorf("code %d: sent createRecord %d and deleteRecord %d times, want once each", code, c, d)
		}
	}
}

func TestARecordWriteRefusedForItsSessionIsSentOnceMoreWithANewOne(t *testing.T) {
	f := recordFake(t)
	f.scriptCode("nameserver.createRecord", 2200, "")

	got, err := f.provider().CreateRecord(context.Background(), exampleCom, newRecord)
	if err != nil || got.ID != "7003" {
		t.Fatalf("CreateRecord = %+v, %v", got, err)
	}

	if logins, _, _ := f.stats(); logins != 2 || f.count("nameserver.createRecord") != 2 {
		t.Fatalf("logins %d, createRecord sent %d times, want 2 each", logins, f.count("nameserver.createRecord"))
	}
}

func TestDeleteRecordDeletesByIDAfterConfirmingItIsTheZones(t *testing.T) {
	f := recordFake(t)
	p := f.provider()

	if err := p.DeleteRecord(context.Background(), exampleCom, exampleComRecords[3]); err != nil {
		t.Fatal(err)
	}

	if w := f.writesSent(); !slices.Equal(w, []string{"nameserver.deleteRecord"}) {
		t.Fatalf("writes = %v, want one deleteRecord", w)
	}

	if params := f.params("nameserver.deleteRecord"); params["id"] != "5004" {
		t.Fatalf("deleteRecord params = %v, want id 5004", params)
	}

	rs, err := p.ListRecords(context.Background(), exampleCom, dnsprovider.RecordFilter{Type: "A"})
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range rs.Records {
		if r.ID == "5004" {
			t.Fatal("the Zone still holds the Record")
		}
	}
}

func TestDeleteRecordOfAnIDTheZoneDoesNotHoldIsErrNotFoundWithoutAWrite(t *testing.T) {
	for name, r := range map[string]dnsprovider.Record{
		"another zone's": {ID: "6002", Type: "NS", Name: "example.com", Value: "ns.inwx.de.", TTL: 86400},
		"a deleted":      {ID: "4999", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
	} {
		f := recordFake(t)

		if err := f.provider().DeleteRecord(context.Background(), exampleCom, r); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("%s ID: DeleteRecord = %v, want ErrNotFound", name, err)
		}

		if w := f.writesSent(); len(w) != 0 {
			t.Fatalf("%s ID: writes = %v, want none", name, w)
		}
	}
}

func TestDeleteRecordRefusedAsAbsentIsErrNotFound(t *testing.T) {
	f := recordFake(t)
	f.scriptCode("nameserver.deleteRecord", 2303, "")

	err := f.provider().DeleteRecord(context.Background(), exampleCom, exampleComRecords[3])
	if !errors.Is(err, dnsprovider.ErrNotFound) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("DeleteRecord = %v, want ErrNotFound", err)
	}
}

func TestApplyOverCRUDReturnsPerChangeResults(t *testing.T) {
	f := recordFake(t)
	held := exampleComRecords[4] // AAAA www

	changes := []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: newRecord},
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "CAA", Name: "@", Value: exampleComRecords[9].Value, TTL: 300}},
		{Kind: dnsprovider.ChangeDelete, Before: held},
	}

	res, err := dnsprovider.Apply(context.Background(), f.provider(), dnsprovider.Changeset{Zone: exampleCom, Changes: changes})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Results) != 3 {
		t.Fatalf("Apply returned %d results, want 3", len(res.Results))
	}

	if r := res.Results[0]; r.Err != nil || r.Record.ID != "7003" {
		t.Errorf("add = %+v, want Record 7003", r)
	}

	if r := res.Results[1]; !errors.Is(r.Err, dnsprovider.ErrConflict) {
		t.Errorf("duplicate add = %+v, want ErrConflict", r)
	}

	if r := res.Results[2]; r.Err != nil {
		t.Errorf("delete = %+v", r)
	}

	if w := f.writesSent(); !slices.Equal(w, []string{"nameserver.deleteRecord", "nameserver.createRecord"}) {
		t.Fatalf("writes = %v, want the delete then the create", w)
	}
}

func TestApplyWithAStaleChangesetSendsNoWrite(t *testing.T) {
	f := recordFake(t)

	stale := exampleComRecords[4]
	stale.Value = "2001:db8::99"

	_, err := dnsprovider.Apply(context.Background(), f.provider(), dnsprovider.Changeset{Zone: exampleCom, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: newRecord},
		{Kind: dnsprovider.ChangeDelete, Before: stale},
	}})
	if !errors.Is(err, dnsprovider.ErrStale) {
		t.Fatalf("Apply = %v, want ErrStale", err)
	}

	if w := f.writesSent(); len(w) != 0 {
		t.Fatalf("writes = %v, want none", w)
	}
}
