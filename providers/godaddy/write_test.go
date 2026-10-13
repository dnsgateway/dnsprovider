package godaddy_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// wwwAPI holds example.com with an A RRset of two values at www.
func wwwAPI() *gdAPI {
	return &gdAPI{records: map[string][]map[string]any{"example.com": {
		{"recordId": "r1", "type": "A", "name": "www", "data": "192.0.2.1", "ttl": 600},
		{"recordId": "r2", "type": "A", "name": "www", "data": "192.0.2.2", "ttl": 600},
		{"recordId": "r3", "type": "TXT", "name": "@", "data": "v=spf1 -all", "ttl": 3600},
	}}}
}

func records(t *testing.T, p dnsprovider.Provider) []dnsprovider.Record {
	t.Helper()

	set, err := p.ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	return set.Records
}

func byValue(rs []dnsprovider.Record, v string) dnsprovider.Record {
	for _, r := range rs {
		if r.Value == v {
			return r
		}
	}

	return dnsprovider.Record{}
}

func TestAddingToAnExistingRRsetPostsOnlyTheNewRecord(t *testing.T) {
	api := wwwAPI()
	p := newProvider(t, api)

	got, err := p.CreateRecord(context.Background(), example, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.3", TTL: 600})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	if want := []string{"POST /dns-records"}; !slices.Equal(api.WriteLines(), want) {
		t.Fatalf("writes = %v, want %v", api.WriteLines(), want)
	}

	if body := api.Writes()[0].Body; !reflect.DeepEqual(body, map[string]any{"type": "A", "name": "www", "data": "192.0.2.3", "ttl": 600.0}) {
		t.Errorf("POST body = %v", body)
	}

	if got.ID == "" || got.Name != "www.example.com" || got.Value != "192.0.2.3" {
		t.Errorf("CreateRecord = %+v, want it as read back with its recordId", got)
	}

	if n := len(records(t, p)); n != 4 {
		t.Errorf("%d Records, want the siblings kept", n)
	}
}

func TestDeletingTheLastValueDeletesItsRecordByID(t *testing.T) {
	api := wwwAPI()
	p := newProvider(t, api)

	if err := p.DeleteRecord(context.Background(), example, byValue(records(t, p), "v=spf1 -all")); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	if want := []string{"DELETE /dns-records/r3"}; !slices.Equal(api.WriteLines(), want) {
		t.Fatalf("writes = %v, want %v", api.WriteLines(), want)
	}
}

func TestAModificationPostsTheNewRecordBeforeDeletingTheOld(t *testing.T) {
	api := wwwAPI()
	p := newProvider(t, api)

	before := byValue(records(t, p), "192.0.2.1")
	after := before
	after.ID, after.Value = "", "192.0.2.9"

	if _, err := p.UpdateRecord(context.Background(), example, before, after); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	if want := []string{"POST /dns-records", "DELETE /dns-records/r1"}; !slices.Equal(api.WriteLines(), want) {
		t.Fatalf("writes = %v, want %v", api.WriteLines(), want)
	}
}

func TestASharedTTLChangePutsEveryKeptRecord(t *testing.T) {
	api := wwwAPI()
	p := newProvider(t, api)

	rs := records(t, p)

	var changes []dnsprovider.Change

	for _, v := range []string{"192.0.2.1", "192.0.2.2"} {
		before := byValue(rs, v)
		after := before
		after.TTL = 3600
		changes = append(changes, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: before, After: after})
	}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: example, Changes: changes})
	if err != nil || res.Results[0].Err != nil || res.Results[1].Err != nil {
		t.Fatalf("Apply = %+v, %v", res, err)
	}

	if want := []string{"PUT /dns-records/r1", "PUT /dns-records/r2"}; !slices.Equal(api.WriteLines(), want) {
		t.Fatalf("writes = %v, want %v", api.WriteLines(), want)
	}

	for _, r := range res.Results {
		if r.Record.TTL != 3600 || r.Record.ID == "" {
			t.Errorf("Record = %+v, want TTL 3600 and its recordId", r.Record)
		}
	}
}

func TestApplySplitsThePriorityAndSRVAndCAAFieldsOutOfTheValue(t *testing.T) {
	api := &gdAPI{records: map[string][]map[string]any{"example.com": {}}}
	p := newProvider(t, api)

	mx := dnsprovider.Record{Type: "MX", Name: "example.com", Value: "10 mail.example.com", TTL: 600}
	srv := dnsprovider.Record{Type: "SRV", Name: "_sip._tcp.example.com", Value: "10 5 5060 sip.example.com", TTL: 600}
	caa := dnsprovider.Record{Type: "CAA", Name: "example.com", Value: `0 issue "letsencrypt.org"`, TTL: 600}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: example, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: mx},
		{Kind: dnsprovider.ChangeAdd, After: srv},
		{Kind: dnsprovider.ChangeAdd, After: caa},
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for i, r := range res.Results {
		if r.Err != nil {
			t.Errorf("result %d: %v", i, r.Err)
		}
	}

	var bodies []map[string]any
	for _, w := range api.Writes() {
		bodies = append(bodies, w.Body)
	}

	want := []map[string]any{
		{"type": "MX", "name": "@", "data": "mail.example.com", "priority": 10.0, "ttl": 600.0},
		{"type": "SRV", "name": "@", "data": "sip.example.com", "priority": 10.0, "weight": 5.0, "port": 5060.0, "service": "_sip", "protocol": "_tcp", "ttl": 600.0},
		{"type": "CAA", "name": "@", "data": "letsencrypt.org", "flag": 0.0, "tag": "issue", "ttl": 600.0},
	}
	if !reflect.DeepEqual(bodies, want) {
		t.Errorf("POST bodies =\n%v\nwant\n%v", bodies, want)
	}

	// The records read back as they were written.
	if got := noIDs(records(t, p)); !reflect.DeepEqual(got, []dnsprovider.Record{mx, srv, caa}) {
		t.Errorf("Records = %v", got)
	}
}

func TestMissingBeforeAndDuplicateAdditionsWriteNothing(t *testing.T) {
	api := wwwAPI()
	p := newProvider(t, api)

	if _, err := p.CreateRecord(context.Background(), example, dnsprovider.Record{Type: "A", Name: "WWW.example.com.", Value: "192.0.2.1", TTL: 3600}); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Errorf("duplicate = %v, want ErrConflict", err)
	}

	gone := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.99", TTL: 600}
	if err := p.DeleteRecord(context.Background(), example, gone); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("delete of a missing Record = %v, want ErrNotFound", err)
	}

	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", w)
	}
}

func TestConcurrentChangesetsOnOneRRsetKeepEachOthersValues(t *testing.T) {
	add := func(v string) dnsprovider.Change {
		return dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "_acme-challenge.example.com", Value: v, TTL: 600}}
	}

	for _, tc := range []struct {
		name      string
		existing  []map[string]any
		changes   func(existing []dnsprovider.Record) [][]dnsprovider.Change
		snapshots int
		want      []string
	}{
		{
			// Both DNS-01 values of a certificate for example.com and
			// *.example.com.
			name: "two additions",
			changes: func([]dnsprovider.Record) [][]dnsprovider.Change {
				return [][]dnsprovider.Change{{add("a")}, {add("b")}}
			},
			snapshots: 2,
			want:      []string{"a", "b"},
		},
		{
			name:     "an addition and a deletion of the last value",
			existing: []map[string]any{{"recordId": "old", "type": "TXT", "name": "_acme-challenge", "data": "old", "ttl": 600}},
			changes: func(existing []dnsprovider.Record) [][]dnsprovider.Change {
				return [][]dnsprovider.Change{{add("new")}, {{Kind: dnsprovider.ChangeDelete, Before: existing[0]}}}
			},
			// Apply re-reads before a deletion.
			snapshots: 3,
			want:      []string{"new"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &gdAPI{records: map[string][]map[string]any{"example.com": tc.existing}}
			p := newProvider(t, api)
			changesets := tc.changes(records(t, p))
			api.holdWritesUntil(tc.snapshots)

			var wg sync.WaitGroup

			results := make([]dnsprovider.ApplyResult, len(changesets))
			errs := make([]error, len(changesets))

			for i, changes := range changesets {
				wg.Add(1)

				go func() {
					defer wg.Done()

					results[i], errs[i] = dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: example, Changes: changes})
				}()
			}

			wg.Wait()

			for i := range changesets {
				if errs[i] != nil || results[i].Results[0].Err != nil {
					t.Errorf("Apply %d = %+v, %v", i, results[i], errs[i])
				}
			}

			var got []string
			for _, r := range records(t, p) {
				got = append(got, r.Value)
			}

			slices.Sort(got)

			if !slices.Equal(got, tc.want) {
				t.Errorf("stored %v, want %v; writes = %v", got, tc.want, api.WriteLines())
			}
		})
	}
}

func TestReadBackIgnoresRecordsAnotherWriterAdded(t *testing.T) {
	api := wwwAPI()
	api.onWrite = func(api *gdAPI) {
		api.records["example.com"] = append(api.records["example.com"], map[string]any{"recordId": "x", "type": "A", "name": "www", "data": "192.0.2.77", "ttl": 600})
	}

	if _, err := newProvider(t, api).CreateRecord(context.Background(), example, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.3", TTL: 600}); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
}

func TestReadBackMissingAnAddedRecordIsAConflict(t *testing.T) {
	api := wwwAPI()
	api.acknowledgeOnly = true

	_, err := newProvider(t, api).CreateRecord(context.Background(), example, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.3", TTL: 600})
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("lost write = %v, want ErrConflict", err)
	}
}

func TestARecordAnotherWriterDeletedFirstIsGoneAsPlanned(t *testing.T) {
	api := wwwAPI()
	p := newProvider(t, api)
	r := byValue(records(t, p), "192.0.2.1")

	api.onWrite = func(api *gdAPI) {
		api.records["example.com"] = slices.DeleteFunc(api.records["example.com"], func(rec map[string]any) bool { return rec["recordId"] == "r1" })
	}

	if err := p.DeleteRecord(context.Background(), example, r); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
}

func TestADuplicatePostIsAConflictNeverRepeated(t *testing.T) {
	api := wwwAPI()
	// Another writer adds the same record after the Changeset read.
	api.onWrite = func(api *gdAPI) {
		api.records["example.com"] = append(api.records["example.com"], map[string]any{"recordId": "x", "type": "A", "name": "www", "data": "192.0.2.3", "ttl": 600})
	}

	_, err := newProvider(t, api).CreateRecord(context.Background(), example, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.3", TTL: 600})
	if !errors.Is(err, dnsprovider.ErrConflict) || len(api.Writes()) != 1 {
		t.Fatalf("duplicate POST = %v, writes %v; want ErrConflict from one POST", err, api.WriteLines())
	}
}

func TestAFailedPostLeavesTheSourceOfAMove(t *testing.T) {
	api := wwwAPI()
	api.reject = func(method string, _ map[string]any) string {
		if method == http.MethodPost {
			return "Service unavailable"
		}

		return ""
	}
	p := newProvider(t, api)

	before := byValue(records(t, p), "192.0.2.1")
	after := before
	after.ID, after.Name = "", "api.example.com"

	_, err := p.UpdateRecord(context.Background(), example, before, after)
	if err == nil || !strings.Contains(err.Error(), "partial side effects") {
		t.Fatalf("UpdateRecord = %v, want a partial-side-effects error", err)
	}

	if byValue(records(t, p), "192.0.2.1").ID != "r1" || slices.Contains(api.WriteLines(), "DELETE /dns-records/r1") {
		t.Errorf("writes = %v, want the source kept", api.WriteLines())
	}
}

func TestApplyRefusesTheSOAAndTypesGoDaddyDoesNotTake(t *testing.T) {
	api := &gdAPI{records: map[string][]map[string]any{"example.com": {
		{"recordId": "soa", "type": "SOA", "name": "@", "data": "ns1.domaincontrol.com. dns.jomax.net. 1 28800 7200 604800 600", "ttl": 3600},
	}}}
	p := newProvider(t, api)

	soa := records(t, p)[0]
	if err := p.DeleteRecord(context.Background(), example, soa); err == nil {
		t.Error("deleted the SOA")
	}

	if _, err := p.CreateRecord(context.Background(), example, dnsprovider.Record{Type: "URI", Name: "_x._tcp", Value: `10 1 "https://example.com/"`, TTL: 600}); err == nil {
		t.Error("created a URI record")
	}

	if w := api.Writes(); len(w) != 0 {
		t.Errorf("writes = %v, want none", w)
	}
}
