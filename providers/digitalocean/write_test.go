package digitalocean_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestCreateRoundTripsStructuredRecords(t *testing.T) {
	for _, tc := range []struct {
		typ, name, value, want string
		sent                   map[string]any
	}{
		{"A", "example.com", "192.0.2.1", "", map[string]any{"name": "@", "data": "192.0.2.1"}},
		{"AAAA", "*.example.com", "2001:db8::1", "", map[string]any{"name": "*", "data": "2001:db8::1"}},
		{"CNAME", "www.example.com", "target.example.net", "target.example.net.", map[string]any{"name": "www", "data": "target.example.net."}},
		{"NS", "sub.example.com", "ns1.example.net.", "", map[string]any{"name": "sub", "data": "ns1.example.net."}},
		{"MX", "example.com", "10 mail.example.net.", "", map[string]any{"data": "mail.example.net.", "priority": 10.0, "weight": nil}},
		{"SRV", "_sip._tcp.example.com", " 0\t5 5060 sip.example.net. ", "0 5 5060 sip.example.net.", map[string]any{"name": "_sip._tcp", "data": "sip.example.net.", "priority": 0.0, "weight": 5.0, "port": 5060.0}},
		{"TXT", "example.com", `v=spf1 -all "quoted".`, "", map[string]any{"data": `v=spf1 -all "quoted".`, "priority": nil}},
		{"CAA", "example.com", `0 issue "letsencrypt.org"`, "", map[string]any{"data": "letsencrypt.org.", "flags": 0.0, "tag": "issue"}},
		{"CAA", "example.com", `128 iodef "mailto:security@example.com"`, "", map[string]any{"data": "mailto:security@example.com", "flags": 128.0, "tag": "iodef"}},
	} {
		t.Run(tc.typ+" "+tc.value, func(t *testing.T) {
			s := newRecords(t)
			p := provider(t, s.handler)
			want := tc.want
			if want == "" {
				want = tc.value
			}
			r, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: tc.typ, Name: tc.name, Value: tc.value, TTL: 300})
			if err != nil || r.ID != "28448501" || r.Value != want || r.Name != tc.name || r.TTL != 300 || r.Type != tc.typ {
				t.Fatalf("create: %+v %v", r, err)
			}
			body := s.bodies[0]
			for k, v := range tc.sent {
				if !reflect.DeepEqual(body[k], v) {
					t.Errorf("sent %s = %#v, want %#v (body %v)", k, body[k], v, body)
				}
			}
			set, err := p.Records(context.Background(), exampleZone, dnsprovider.RecordFilter{Type: tc.typ})
			if err != nil || len(set.Records) != 1 || !reflect.DeepEqual(set.Records[0], r) {
				t.Fatalf("read back: %+v %v", set, err)
			}
		})
	}
}

func TestUnsupportedWritesAreRejectedLocally(t *testing.T) {
	s := newRecords(t)
	p := provider(t, s.handler)
	for _, r := range []dnsprovider.Record{
		{Type: "URI", Name: "example.com", Value: `10 1 "https://example.com/"`, TTL: 300},
		{Type: "CAA", Name: "example.com", Value: `0 tbs "unknown"`, TTL: 300},
		{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 10},
		{Type: "A", Name: "other.org.", Value: "192.0.2.1", TTL: 300},
		{Type: "SOA", Name: "example.com", Value: "1800", TTL: 300},
	} {
		if _, err := p.CreateRecord(context.Background(), exampleZone, r); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	if len(s.writes) != 0 {
		t.Fatalf("writes: %v", s.writes)
	}
}

func TestCreateRejectsDuplicatesRegardlessOfTTL(t *testing.T) {
	s := newRecords(t)
	s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 1800})
	p := provider(t, s.handler)
	_, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "a", Name: "WWW.Example.com.", Value: "192.0.2.1", TTL: 60})
	if !errors.Is(err, dnsprovider.ErrConflict) || len(s.writes) != 0 {
		t.Fatalf("duplicate: %v writes=%v", err, s.writes)
	}
}

func TestCreateIsNeverAutomaticallyRetried(t *testing.T) {
	s := newRecords(t)
	posts := 0
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"id":"server_error","message":"Unexpected server-side error"}`)
			return
		}
		s.handler(w, r)
	})
	_, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300})
	if err == nil || posts != 1 || !strings.Contains(err.Error(), "unconfirmed") {
		t.Fatalf("create: %v posts=%d", err, posts)
	}
}

func TestEmptyAcknowledgementsAreReadBackWithoutRepeatingTheWrite(t *testing.T) {
	s := newRecords(t)
	s.emptyAnswers = true
	p := provider(t, s.handler)
	ctx := context.Background()
	created, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "MX", Name: "example.com", Value: "10 mail.example.net.", TTL: 300})
	if err != nil || created.ID != "28448501" || created.Value != "10 mail.example.net." {
		t.Fatalf("create: %+v %v", created, err)
	}
	after := created
	after.Value = "20 mail.example.net."
	updated, err := p.UpdateRecord(ctx, exampleZone, created, after)
	if err != nil || updated.ID != created.ID || updated.Value != "20 mail.example.net." {
		t.Fatalf("update: %+v %v", updated, err)
	}
	if !reflect.DeepEqual(s.writes, []string{"POST 28448501", "PUT 28448501"}) {
		t.Fatalf("writes: %v", s.writes)
	}
}

func TestFailedReadBackAfterAcknowledgedUpdateReportsCompletedWrite(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
	s.emptyAnswers = true
	written := false
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if written && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/"+strconv.Itoa(id)) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		written = written || r.Method == http.MethodPut
		s.handler(w, r)
	})
	before := dnsprovider.Record{ID: strconv.Itoa(id), Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	after := before
	after.Value = "192.0.2.2"
	_, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err == nil || !strings.Contains(err.Error(), "acknowledged") || len(s.writes) != 1 {
		t.Fatalf("update: %v writes=%v", err, s.writes)
	}
}

func TestMalformedAcknowledgementsAreReadBackWithoutRepeatingTheWrite(t *testing.T) {
	for _, answer := range []string{`{"domain_record":{"id":`, `{"domain_record":{"id":28448501}}`} {
		t.Run(answer, func(t *testing.T) {
			s := newRecords(t)
			s.emptyAnswers = true
			p := provider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost || r.Method == http.MethodPut {
					s.handler(w, r)
					fmt.Fprint(w, answer)
					return
				}
				s.handler(w, r)
			})
			ctx := context.Background()
			created, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300})
			if err != nil || created.ID != "28448501" || created.Value != "192.0.2.1" {
				t.Fatalf("create: %+v %v", created, err)
			}
			after := created
			after.TTL = 600
			updated, err := p.UpdateRecord(ctx, exampleZone, created, after)
			if err != nil || !reflect.DeepEqual(updated, after) {
				t.Fatalf("update: %+v %v", updated, err)
			}
			if !reflect.DeepEqual(s.writes, []string{"POST 28448501", "PUT 28448501"}) {
				t.Fatalf("writes: %v", s.writes)
			}
		})
	}
}

func TestMalformedAcknowledgementWithFailedReadBackReportsPossiblyCompletedWrite(t *testing.T) {
	s := newRecords(t)
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"domain_record":{"id":28448501}}`)
			return
		}
		s.handler(w, r)
	})
	_, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300})
	if err == nil || !strings.Contains(err.Error(), "acknowledged") {
		t.Fatalf("malformed create: %v", err)
	}
}

func TestUpdateEditsInPlaceAndPreservesSiblings(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "SRV", "name": "_sip._tcp", "data": "sip.example.net", "ttl": 1800, "priority": 0, "weight": 5, "port": 5060})
	sibling := s.add(map[string]any{"type": "SRV", "name": "_sip._tcp", "data": "sip2.example.net", "ttl": 1800, "priority": 10, "weight": 5, "port": 5060})
	p := provider(t, s.handler)
	before := dnsprovider.Record{ID: strconv.Itoa(id), Type: "SRV", Name: "_sip._tcp.example.com", Value: "0 5 5060 sip.example.net.", TTL: 1800}
	after := before
	after.Name = "_sips._tcp.example.com"
	after.Value = "1 2 5061 sips.example.net."
	after.TTL = 600
	got, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err != nil || !reflect.DeepEqual(got, after) {
		t.Fatalf("update: %+v %v", got, err)
	}
	if !reflect.DeepEqual(s.writes, []string{"PUT " + before.ID}) || s.records[sibling]["data"] != "sip2.example.net" {
		t.Fatalf("writes %v, sibling %v", s.writes, s.records[sibling])
	}
}

func TestTypeMoveReplacesTheRecordAndDropsOldTypeFields(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "MX", "name": "@", "data": "mail.example.net", "ttl": 300, "priority": 10})
	p := provider(t, s.handler)
	before := dnsprovider.Record{ID: strconv.Itoa(id), Type: "MX", Name: "example.com", Value: "10 mail.example.net.", TTL: 300}
	after := dnsprovider.Record{ID: before.ID, Type: "TXT", Name: "moved.example.com", Value: "hello", TTL: 300}
	got, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err != nil || got.ID == before.ID || got.Type != "TXT" || got.Name != "moved.example.com" {
		t.Fatalf("move: %+v %v", got, err)
	}
	newID, _ := strconv.Atoi(got.ID)
	if _, ok := s.records[id]; ok || s.records[newID]["priority"] != nil {
		t.Fatalf("state: %v", s.records)
	}
	if !reflect.DeepEqual(s.writes, []string{"POST " + got.ID, "DELETE " + before.ID}) {
		t.Fatalf("writes: %v", s.writes)
	}
}

func TestTypeMoveReportsBothRecordsWhenOriginalDeletionFails(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
	p := provider(t, s.handler)
	s.failDelete = true
	before := dnsprovider.Record{ID: strconv.Itoa(id), Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	after := dnsprovider.Record{Type: "AAAA", Name: "www.example.com", Value: "2001:db8::1", TTL: 300}
	got, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err == nil || got.ID == "" || !strings.Contains(err.Error(), got.ID) || !strings.Contains(err.Error(), before.ID) {
		t.Fatalf("partial move: %+v %v", got, err)
	}
}

func TestSameOwnerCNAMETypeMoveRestoresTheOriginalWhenTheReplacementFails(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "CNAME", "name": "www", "data": "target.example.net", "ttl": 300})
	posts := 0
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
		}
		if r.Method == http.MethodPost && posts == 1 {
			s.fail(w, http.StatusUnprocessableEntity, "unprocessable_entity", "Record limit reached")
			return
		}
		s.handler(w, r)
	})
	before := dnsprovider.Record{ID: strconv.Itoa(id), Type: "CNAME", Name: "www.example.com", Value: "target.example.net.", TTL: 300}
	after := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	_, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err == nil || !strings.Contains(err.Error(), "restored as Record 28448502") {
		t.Fatalf("partial move: %v", err)
	}
	if !reflect.DeepEqual(s.writes, []string{"DELETE " + before.ID, "POST 28448502"}) {
		t.Fatalf("writes: %v", s.writes)
	}
	set, err := p.Records(context.Background(), exampleZone, dnsprovider.RecordFilter{Contains: "www.example.com"})
	want := before
	want.ID = "28448502"
	if err != nil || len(set.Records) != 1 || !reflect.DeepEqual(set.Records[0], want) {
		t.Fatalf("after restoring: %+v %v", set, err)
	}
}

func TestSameOwnerCNAMETypeMoveReportsLossWhenRestoringFails(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "CNAME", "name": "www", "data": "target.example.net", "ttl": 300})
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			s.fail(w, http.StatusUnprocessableEntity, "unprocessable_entity", "Record limit reached")
			return
		}
		s.handler(w, r)
	})
	before := dnsprovider.Record{ID: strconv.Itoa(id), Type: "CNAME", Name: "www.example.com", Value: "target.example.net.", TTL: 300}
	after := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	_, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err == nil || !strings.Contains(err.Error(), "original Record "+before.ID+" was deleted") || !strings.Contains(err.Error(), "restoring it failed") {
		t.Fatalf("partial move: %v", err)
	}
	if !reflect.DeepEqual(s.writes, []string{"DELETE " + before.ID}) {
		t.Fatalf("writes: %v", s.writes)
	}
}

func TestUpdateCollisionsAreCheckedBeforeWriting(t *testing.T) {
	s := newRecords(t)
	a := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
	s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.2", "ttl": 60})
	p := provider(t, s.handler)
	before := dnsprovider.Record{ID: strconv.Itoa(a), Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	after := before
	after.Value = "192.0.2.2"
	if _, err := p.UpdateRecord(context.Background(), exampleZone, before, after); !errors.Is(err, dnsprovider.ErrConflict) || len(s.writes) != 0 {
		t.Fatalf("collision: %v writes=%v", err, s.writes)
	}
}

func TestProviderManagedSOACannotBeEditedOrDeleted(t *testing.T) {
	s := newRecords(t)
	p := provider(t, s.handler)
	soa := dnsprovider.Record{ID: "28448441", Type: "SOA", Name: "example.com", Value: "1800", TTL: 1800}
	if err := p.DeleteRecord(context.Background(), exampleZone, soa); err == nil || !strings.Contains(err.Error(), "SOA") {
		t.Fatalf("delete: %v", err)
	}
	after := dnsprovider.Record{Type: "TXT", Name: "example.com", Value: "x", TTL: 300}
	if _, err := p.UpdateRecord(context.Background(), exampleZone, soa, after); err == nil || !strings.Contains(err.Error(), "SOA") {
		t.Fatalf("update: %v", err)
	}
	if len(s.writes) != 0 {
		t.Fatalf("writes: %v", s.writes)
	}
}

func TestMissingRecordsAreNotFoundAndDeleteRemovesOnlyTheSelectedRecord(t *testing.T) {
	s := newRecords(t)
	a := s.add(map[string]any{"type": "TXT", "name": "www", "data": "one", "ttl": 300})
	b := s.add(map[string]any{"type": "TXT", "name": "www", "data": "two", "ttl": 300})
	p := provider(t, s.handler)
	ctx := context.Background()
	missing := dnsprovider.Record{ID: "999", Type: "TXT", Name: "www.example.com", Value: "one", TTL: 300}
	if err := p.DeleteRecord(ctx, exampleZone, missing); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if _, err := p.UpdateRecord(ctx, exampleZone, missing, missing); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if err := p.DeleteRecord(ctx, exampleZone, dnsprovider.Record{Type: "TXT", Name: "www.example.com", Value: "one"}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("delete without ID: %v", err)
	}
	for _, id := range []int{a, b} {
		if err := p.DeleteRecord(ctx, exampleZone, dnsprovider.Record{ID: strconv.Itoa(id), Type: "TXT", Name: "www.example.com"}); err != nil {
			t.Fatal(err)
		}
		set, err := p.Records(ctx, exampleZone, dnsprovider.RecordFilter{Type: "TXT"})
		if err != nil || (id == a && (len(set.Records) != 1 || set.Records[0].ID != strconv.Itoa(b))) || (id == b && len(set.Records) != 0) {
			t.Fatalf("after deleting %d: %+v %v", id, set, err)
		}
	}
}

func TestRecordsPageThroughTheFixture(t *testing.T) {
	s := newRecords(t)
	for i := range 450 {
		s.add(map[string]any{"type": "A", "name": fmt.Sprintf("h%d", i), "data": "192.0.2.1", "ttl": 300})
	}
	p := provider(t, s.handler)
	set, err := p.Records(context.Background(), exampleZone, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 451 {
		t.Fatalf("Records: %d %v", len(set.Records), err)
	}
}

func TestApplyRejectsStaleChangesWithoutWriting(t *testing.T) {
	for _, kind := range []dnsprovider.ChangeKind{dnsprovider.ChangeModify, dnsprovider.ChangeDelete} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			s := newRecords(t)
			id := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
			p := provider(t, s.handler)
			before := dnsprovider.Record{ID: strconv.Itoa(id), Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 60}
			after := before
			after.Value = "192.0.2.2"
			added := dnsprovider.Record{Type: "A", Name: "new.example.com", Value: "192.0.2.3", TTL: 300}
			_, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: exampleZone, Changes: []dnsprovider.Change{
				{Kind: dnsprovider.ChangeAdd, After: added}, {Kind: kind, Before: before, After: after},
			}})
			if !errors.Is(err, dnsprovider.ErrStale) || len(s.writes) != 0 {
				t.Fatalf("stale Apply: %v writes=%v", err, s.writes)
			}
		})
	}
}

func TestApplyOrdersCRUDAndKeepsAccurateOutcomes(t *testing.T) {
	s := newRecords(t)
	a := s.add(map[string]any{"type": "A", "name": "a", "data": "192.0.2.1", "ttl": 300})
	b := s.add(map[string]any{"type": "A", "name": "b", "data": "192.0.2.2", "ttl": 300})
	p := provider(t, s.handler)
	ra := dnsprovider.Record{ID: strconv.Itoa(a), Type: "A", Name: "a.example.com", Value: "192.0.2.1", TTL: 300}
	rb := dnsprovider.Record{ID: strconv.Itoa(b), Type: "A", Name: "b.example.com", Value: "192.0.2.2", TTL: 300}
	modified := rb
	modified.TTL = 600
	cs := dnsprovider.Changeset{Zone: exampleZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "c.example.com", Value: "192.0.2.3", TTL: 300}},
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "b.example.com", Value: "192.0.2.2", TTL: 300}},
		{Kind: dnsprovider.ChangeModify, Before: rb, After: modified},
		{Kind: dnsprovider.ChangeDelete, Before: ra},
	}}
	result, err := dnsprovider.Apply(context.Background(), p, cs)
	if err != nil || len(result.Results) != 4 {
		t.Fatalf("Apply: %+v %v", result, err)
	}
	if !reflect.DeepEqual(s.writes, []string{"DELETE " + ra.ID, "PUT " + rb.ID, "POST 28448503"}) {
		t.Fatalf("write order: %v", s.writes)
	}
	for i, cr := range result.Results {
		if !reflect.DeepEqual(cr.Change, cs.Changes[i]) {
			t.Fatalf("result %d out of order: %+v", i, cr)
		}
	}
	if result.Results[0].Err != nil || result.Results[0].Record.ID != "28448503" ||
		!errors.Is(result.Results[1].Err, dnsprovider.ErrConflict) ||
		result.Results[2].Err != nil || result.Results[2].Record.TTL != 600 || result.Results[3].Err != nil {
		t.Fatalf("outcomes: %+v", result.Results)
	}
}

func TestCAAValuesSeparatedByAnyWhitespaceAreWritten(t *testing.T) {
	for _, sep := range []string{"\u2003", "\u00a0", "\v", "\u2028"} {
		t.Run(strconv.Quote(sep), func(t *testing.T) {
			s := newRecords(t)
			p := provider(t, s.handler)
			value := "0" + sep + "issue" + sep + `"letsencrypt.org"`
			r, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "CAA", Name: "example.com", Value: value, TTL: 300})
			if err != nil || r.Value != `0 issue "letsencrypt.org"` {
				t.Fatalf("create: %+v %v", r, err)
			}
		})
	}
}

func TestZonesNamedOnlyByIDAreWrittenUnderTheirName(t *testing.T) {
	s := newRecords(t)
	p := provider(t, s.handler)
	ctx := context.Background()
	zone := dnsprovider.Zone{ID: "Example.com."}
	r, err := p.CreateRecord(ctx, zone, dnsprovider.Record{Type: "CNAME", Name: "www", Value: "target.example.net.", TTL: 300})
	if err != nil || r.Name != "www.example.com" || s.bodies[0]["name"] != "www" {
		t.Fatalf("create: %+v %v body=%v", r, err, s.bodies)
	}
	after := r
	after.Value = "other.example.net."
	got, err := p.UpdateRecord(ctx, zone, r, after)
	if err != nil || !reflect.DeepEqual(got, after) {
		t.Fatalf("update: %+v %v", got, err)
	}
	if err := p.DeleteRecord(ctx, zone, got); err != nil {
		t.Fatal(err)
	}
}

func TestCAAIssuerDomainsAreWrittenWithTheirTrailingDotAndReadInEitherForm(t *testing.T) {
	s := newRecords(t)
	s.add(map[string]any{"type": "CAA", "name": "@", "data": "pki.goog.", "ttl": 300, "flags": 0, "tag": "issuewild"})
	s.add(map[string]any{"type": "CAA", "name": "@", "data": "letsencrypt.org", "ttl": 300, "flags": 0, "tag": "issue"})
	p := provider(t, s.handler)
	ctx := context.Background()
	set, err := p.Records(ctx, exampleZone, dnsprovider.RecordFilter{Type: "CAA"})
	if err != nil || len(set.Records) != 2 || set.Records[0].Value != `0 issuewild "pki.goog"` || set.Records[1].Value != `0 issue "letsencrypt.org"` {
		t.Fatalf("read: %+v %v", set, err)
	}
	for _, v := range []string{`0 issue "letsencrypt.org"`, `0 issue "letsencrypt.org."`, `0 issuewild "pki.goog"`} {
		if _, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "CAA", Name: "example.com", Value: v, TTL: 60}); !errors.Is(err, dnsprovider.ErrConflict) {
			t.Errorf("duplicate %s: %v", v, err)
		}
	}
	for _, tc := range []struct{ value, data, want string }{
		{`0 issuewild "sectigo.com"`, "sectigo.com.", `0 issuewild "sectigo.com"`},
		{`0 issue ";"`, ";", `0 issue ";"`},
		{`0 issue "ca.example.net; account=1"`, "ca.example.net; account=1", `0 issue "ca.example.net; account=1"`},
		{`0 iodef "mailto:caa@example.com"`, "mailto:caa@example.com", `0 iodef "mailto:caa@example.com"`},
	} {
		s.bodies = nil
		r, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "CAA", Name: "example.com", Value: tc.value, TTL: 300})
		if err != nil || r.Value != tc.want || s.bodies[0]["data"] != tc.data {
			t.Errorf("create %s: %+v %v sent %v", tc.value, r, err, s.bodies)
		}
	}
}

func TestCAAValuesRoundTripDecimalEscapesAndControlCharacters(t *testing.T) {
	s := newRecords(t)
	ctl := s.add(map[string]any{"type": "CAA", "name": "@", "data": "mailto:a\x01b@example.com", "ttl": 300, "flags": 0, "tag": "iodef"})
	p := provider(t, s.handler)
	ctx := context.Background()
	set, err := p.Records(ctx, exampleZone, dnsprovider.RecordFilter{Type: "CAA"})
	if err != nil || len(set.Records) != 1 || set.Records[0].ID != strconv.Itoa(ctl) || set.Records[0].Value != `0 iodef "mailto:a\001b@example.com"` {
		t.Fatalf("read: %+v %v", set, err)
	}
	r, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "CAA", Name: "example.com", Value: `0 iodef "mailto:\034c\092d\"@example.com"`, TTL: 300})
	if err != nil || s.bodies[0]["data"] != `mailto:"c\d"@example.com` || r.Value != `0 iodef "mailto:\"c\\d\"@example.com"` {
		t.Fatalf("create: %+v %v sent %v", r, err, s.bodies)
	}
	for _, bad := range []string{`0 iodef "a\25"`, `0 iodef "a\256"`, `0 iodef "a\"`, `0 iodef "a"b"`} {
		if _, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "CAA", Name: "example.com", Value: bad, TTL: 300}); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if len(s.writes) != 1 {
		t.Fatalf("writes: %v", s.writes)
	}
}

func TestWritesListRecordsWithoutReadingTheDomain(t *testing.T) {
	s := newRecords(t)
	s.emptyAnswers = true
	p := provider(t, s.handler)
	ctx := context.Background()
	r, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	after := r
	after.Value = "192.0.2.2"
	if _, err := p.UpdateRecord(ctx, exampleZone, r, after); err != nil {
		t.Fatal(err)
	}
	if s.domainReads != 0 {
		t.Fatalf("the Domain was read %d times", s.domainReads)
	}
}
