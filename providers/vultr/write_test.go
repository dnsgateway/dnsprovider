package vultr_test

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
		{"A", "example.com", "192.0.2.1", "", map[string]any{"name": "", "data": "192.0.2.1", "type": "A", "ttl": 300.0, "priority": nil}},
		{"AAAA", "*.example.com", "2001:db8::1", "", map[string]any{"name": "*", "data": "2001:db8::1"}},
		{"CNAME", "www.example.com", "target.example.net", "target.example.net.", map[string]any{"name": "www", "data": "target.example.net"}},
		{"NS", "sub.example.com", "ns1.example.net.", "", map[string]any{"name": "sub", "data": "ns1.example.net"}},
		{"MX", "example.com", "10 mail.example.net.", "", map[string]any{"data": "mail.example.net", "priority": 10.0}},
		{"MX", "example.com", "0 .", "", map[string]any{"data": ".", "priority": 0.0}},
		{"SRV", "_sip._tcp.example.com", " 0\t5 5060 sip.example.net. ", "0 5 5060 sip.example.net.", map[string]any{"name": "_sip._tcp", "data": "5 5060 sip.example.net", "priority": 0.0}},
		{"TXT", "example.com", `v=spf1 -all \ backslash`, "", map[string]any{"data": `"v=spf1 -all \ backslash"`, "priority": nil}},
		{"CAA", "example.com", `0 issue "letsencrypt.org"`, "", map[string]any{"data": `0 issue "letsencrypt.org"`}},
		{"CAA", "example.com", "128 iodef \"mailto:security@example.com\"", `128 iodef "mailto:security@example.com"`, map[string]any{"data": `128 iodef "mailto:security@example.com"`}},
		{"CAA", "example.com", `0 iodef "mailto:\034c\092d\"@example.com"`, `0 iodef "mailto:\"c\\d\"@example.com"`, map[string]any{"data": `0 iodef "mailto:\"c\\d\"@example.com"`}},
	} {
		t.Run(tc.typ+" "+tc.value, func(t *testing.T) {
			s := newRecords(t)
			p := provider(t, s.handler)
			want := tc.want
			if want == "" {
				want = tc.value
			}
			r, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: tc.typ, Name: tc.name, Value: tc.value, TTL: 300})
			if err != nil || r.ID != recordID(1) || r.Value != want || r.Name != tc.name || r.TTL != 300 || r.Type != tc.typ {
				t.Fatalf("create: %+v %v", r, err)
			}
			body := s.bodies[0]
			for k, v := range tc.sent {
				if !reflect.DeepEqual(body[k], v) {
					t.Errorf("sent %s = %#v, want %#v (body %v)", k, body[k], v, body)
				}
			}
			set, err := p.ListRecords(context.Background(), exampleZone, dnsprovider.RecordFilter{})
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
		{Type: "SSHFP", Name: "example.com", Value: "4 2 1234", TTL: 300},
		{Type: "TXT", Name: "example.com", Value: `say "hi"`, TTL: 300},
		{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 10},
		{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 1},
		{Type: "A", Name: "other.org.", Value: "192.0.2.1", TTL: 300},
		{Type: "CAA", Name: "example.com", Value: `0 issue "unclosed`, TTL: 300},
	} {
		if _, err := p.CreateRecord(context.Background(), exampleZone, r); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	if len(s.writes) != 0 || len(s.bodies) != 0 {
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

func TestServiceValidationFailuresKeepTheirMessageAndAreNotUnconfirmed(t *testing.T) {
	s := newRecords(t)
	s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 1800})
	p := provider(t, s.handler)
	_, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.2", TTL: 60})
	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest || !strings.Contains(err.Error(), "same TTL") ||
		errors.Is(err, dnsprovider.ErrUnconfirmed) || errors.Is(err, dnsprovider.ErrConflict) || len(s.writes) != 0 {
		t.Fatalf("create: %v", err)
	}
}

func TestCreateIsNeverAutomaticallyRetried(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			s := newRecords(t)
			posts := 0
			p := provider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts++
					w.Header().Set("Retry-After", "0")
					s.fail(w, status, "Internal error")
					return
				}
				s.handler(w, r)
			})
			_, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300})
			if err == nil || posts != 1 {
				t.Fatalf("create: %v posts=%d", err, posts)
			}
			if errors.Is(err, dnsprovider.ErrUnconfirmed) != (status >= 500) {
				t.Fatalf("create: %v, want ErrUnconfirmed only for a server error", err)
			}
		})
	}
}

func TestMalformedCreateAcknowledgementsAreReadBackWithoutRepeatingTheWrite(t *testing.T) {
	for _, answer := range []string{``, `{"record":{"id":`, `{"record":{"id":"cb676a46-66fd-4dfb-b839-000000000001"}}`, `{"record":null}`} {
		t.Run(answer, func(t *testing.T) {
			s := newRecords(t)
			s.malformedCreate = answer
			if answer == "" {
				s.malformedCreate = " "
			}
			p := provider(t, s.handler)
			created, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "MX", Name: "example.com", Value: "0 mail.example.net.", TTL: 300})
			want := dnsprovider.Record{ID: recordID(1), Type: "MX", Name: "example.com", Value: "0 mail.example.net.", TTL: 300}
			if err != nil || !reflect.DeepEqual(created, want) {
				t.Fatalf("create: %+v %v", created, err)
			}
			if !reflect.DeepEqual(s.writes, []string{"POST " + recordID(1)}) {
				t.Fatalf("writes: %v", s.writes)
			}
		})
	}
}

func TestMalformedCreateAcknowledgementWithFailedReadBackReportsPossiblyCompletedWrite(t *testing.T) {
	s := newRecords(t)
	s.malformedCreate = `{}`
	posted := false
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if posted && r.Method == http.MethodGet {
			s.fail(w, http.StatusInternalServerError, "Internal error")
			return
		}
		posted = posted || r.Method == http.MethodPost
		s.handler(w, r)
	})
	_, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) || !strings.Contains(err.Error(), "acknowledged") || len(s.writes) != 1 {
		t.Fatalf("malformed create: %v writes=%v", err, s.writes)
	}
}

func TestPatchAcknowledgementsAreReadBackWithoutRepeatingTheWrite(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "MX", "name": "", "data": "mail.example.net", "priority": 10, "ttl": 300})
	sibling := s.add(map[string]any{"type": "MX", "name": "", "data": "backup.example.net", "priority": 20, "ttl": 300})
	p := provider(t, s.handler)
	before := dnsprovider.Record{ID: id, Type: "MX", Name: "example.com", Value: "10 mail.example.net.", TTL: 300}
	after := before
	after.Value = "0 mx.example.net."
	got, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err != nil || !reflect.DeepEqual(got, after) {
		t.Fatalf("update: %+v %v", got, err)
	}
	if !reflect.DeepEqual(s.writes, []string{"PATCH " + id}) || s.bodies[0]["priority"] != 0.0 || s.bodies[0]["data"] != "mx.example.net" {
		t.Fatalf("writes %v bodies %v", s.writes, s.bodies)
	}
	if s.records[sibling]["data"] != "backup.example.net" || s.records[sibling]["priority"] != 20 {
		t.Fatalf("sibling changed: %v", s.records[sibling])
	}
}

func TestFailedReadBackAfterPatchReportsPossiblyCompletedWrite(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
	patched := false
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if patched && r.Method == http.MethodGet {
			s.fail(w, http.StatusInternalServerError, "Internal error")
			return
		}
		patched = patched || r.Method == http.MethodPatch
		s.handler(w, r)
	})
	before := dnsprovider.Record{ID: id, Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	after := before
	after.Value = "192.0.2.2"
	_, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) || !strings.Contains(err.Error(), "acknowledged") || len(s.writes) != 1 {
		t.Fatalf("update: %v writes=%v", err, s.writes)
	}
}

func TestLostPatchAnswerIsUnconfirmedAndNotRetried(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
	patches := 0
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			patches++
			s.fail(w, http.StatusBadGateway, "Bad gateway")
			return
		}
		s.handler(w, r)
	})
	before := dnsprovider.Record{ID: id, Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	after := before
	after.TTL = 600
	_, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) || patches != 1 {
		t.Fatalf("update: %v patches=%d", err, patches)
	}
}

func TestAWriteWhoseAnswerIsLostIsUnconfirmed(t *testing.T) {
	s := newRecords(t)
	posts := 0
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		s.handler(w, r)
	})
	_, err := p.CreateRecord(context.Background(), exampleZone, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) || posts != 1 {
		t.Fatalf("create: %v posts=%d", err, posts)
	}
}

func TestUpdateEditsNameValueAndTTLInPlaceAndPreservesSiblings(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "SRV", "name": "_sip._tcp", "data": "5 5060 sip.example.net", "ttl": 1800, "priority": 0})
	sibling := s.add(map[string]any{"type": "SRV", "name": "_sip._tcp", "data": "5 5060 sip2.example.net", "ttl": 1800, "priority": 10})
	p := provider(t, s.handler)
	before := dnsprovider.Record{ID: id, Type: "SRV", Name: "_sip._tcp.example.com", Value: "0 5 5060 sip.example.net.", TTL: 1800}
	after := before
	after.Name = "_sips._tcp.example.com"
	after.Value = "1 2 5061 sips.example.net."
	after.TTL = 600
	got, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err != nil || !reflect.DeepEqual(got, after) {
		t.Fatalf("update: %+v %v", got, err)
	}
	if !reflect.DeepEqual(s.writes, []string{"PATCH " + id}) || s.records[sibling]["data"] != "5 5060 sip2.example.net" || s.records[sibling]["ttl"] != 1800 {
		t.Fatalf("writes %v, sibling %v", s.writes, s.records[sibling])
	}
	if _, ok := s.bodies[0]["type"]; ok {
		t.Fatalf("PATCH sent a type: %v", s.bodies[0])
	}
}

func TestTypeMoveReplacesTheRecordAndDropsOldTypeFields(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "MX", "name": "", "data": "mail.example.net", "ttl": 300, "priority": 10})
	p := provider(t, s.handler)
	before := dnsprovider.Record{ID: id, Type: "MX", Name: "example.com", Value: "10 mail.example.net.", TTL: 300}
	after := dnsprovider.Record{ID: before.ID, Type: "TXT", Name: "moved.example.com", Value: "hello", TTL: 300}
	got, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	want := dnsprovider.Record{ID: recordID(2), Type: "TXT", Name: "moved.example.com", Value: "hello", TTL: 300}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("move: %+v %v", got, err)
	}
	if _, ok := s.records[id]; ok || s.bodies[0]["priority"] != nil {
		t.Fatalf("state: %v bodies %v", s.records, s.bodies)
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
	before := dnsprovider.Record{ID: id, Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
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
			s.fail(w, http.StatusBadRequest, "Unable to create record")
			return
		}
		s.handler(w, r)
	})
	before := dnsprovider.Record{ID: id, Type: "CNAME", Name: "www.example.com", Value: "target.example.net.", TTL: 300}
	after := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	_, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err == nil || !strings.Contains(err.Error(), "restored as Record "+recordID(2)) {
		t.Fatalf("partial move: %v", err)
	}
	if !reflect.DeepEqual(s.writes, []string{"DELETE " + before.ID, "POST " + recordID(2)}) {
		t.Fatalf("writes: %v", s.writes)
	}
	set, err := p.ListRecords(context.Background(), exampleZone, dnsprovider.RecordFilter{Contains: "www.example.com"})
	want := before
	want.ID = recordID(2)
	if err != nil || len(set.Records) != 1 || !reflect.DeepEqual(set.Records[0], want) {
		t.Fatalf("after restoring: %+v %v", set, err)
	}
}

func TestSameOwnerCNAMETypeMoveReportsLossWhenRestoringFails(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "CNAME", "name": "www", "data": "target.example.net", "ttl": 300})
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			s.fail(w, http.StatusBadRequest, "Unable to create record")
			return
		}
		s.handler(w, r)
	})
	before := dnsprovider.Record{ID: id, Type: "CNAME", Name: "www.example.com", Value: "target.example.net.", TTL: 300}
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
	s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.2", "ttl": 300})
	p := provider(t, s.handler)
	before := dnsprovider.Record{ID: a, Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	after := before
	after.Value = "192.0.2.2"
	after.TTL = 60
	if _, err := p.UpdateRecord(context.Background(), exampleZone, before, after); !errors.Is(err, dnsprovider.ErrConflict) || len(s.writes) != 0 {
		t.Fatalf("collision: %v writes=%v", err, s.writes)
	}
}

func TestMissingRecordsAreNotFoundAndDeleteRemovesOnlyTheSelectedRecord(t *testing.T) {
	s := newRecords(t)
	a := s.add(map[string]any{"type": "TXT", "name": "www", "data": `"one"`, "ttl": 300})
	b := s.add(map[string]any{"type": "TXT", "name": "www", "data": `"two"`, "ttl": 300})
	p := provider(t, s.handler)
	ctx := context.Background()
	missing := dnsprovider.Record{ID: recordID(999), Type: "TXT", Name: "www.example.com", Value: "one", TTL: 300}
	if err := p.DeleteRecord(ctx, exampleZone, missing); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if _, err := p.UpdateRecord(ctx, exampleZone, missing, missing); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	for _, id := range []string{"", "../records", "a/b"} {
		if err := p.DeleteRecord(ctx, exampleZone, dnsprovider.Record{ID: id, Type: "TXT", Name: "www.example.com", Value: "one"}); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("delete with ID %q: %v", id, err)
		}
	}
	if len(s.writes) != 0 {
		t.Fatalf("writes: %v", s.writes)
	}
	for _, id := range []string{a, b} {
		if err := p.DeleteRecord(ctx, exampleZone, dnsprovider.Record{ID: id, Type: "TXT", Name: "www.example.com"}); err != nil {
			t.Fatal(err)
		}
		set, err := p.ListRecords(ctx, exampleZone, dnsprovider.RecordFilter{Type: "TXT"})
		if err != nil || (id == a && (len(set.Records) != 1 || set.Records[0].ID != b)) || (id == b && len(set.Records) != 0) {
			t.Fatalf("after deleting %s: %+v %v", id, set, err)
		}
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

func TestApplyRejectsStaleChangesWithoutWriting(t *testing.T) {
	for _, kind := range []dnsprovider.ChangeKind{dnsprovider.ChangeModify, dnsprovider.ChangeDelete} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			s := newRecords(t)
			id := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
			p := provider(t, s.handler)
			before := dnsprovider.Record{ID: id, Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 60}
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
	ra := dnsprovider.Record{ID: a, Type: "A", Name: "a.example.com", Value: "192.0.2.1", TTL: 300}
	rb := dnsprovider.Record{ID: b, Type: "A", Name: "b.example.com", Value: "192.0.2.2", TTL: 300}
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
	if !reflect.DeepEqual(s.writes, []string{"DELETE " + a, "PATCH " + b, "POST " + recordID(3)}) {
		t.Fatalf("write order: %v", s.writes)
	}
	for i, cr := range result.Results {
		if !reflect.DeepEqual(cr.Change, cs.Changes[i]) {
			t.Fatalf("result %d out of order: %+v", i, cr)
		}
	}
	if result.Results[0].Err != nil || result.Results[0].Record.ID != recordID(3) ||
		!errors.Is(result.Results[1].Err, dnsprovider.ErrConflict) ||
		result.Results[2].Err != nil || result.Results[2].Record.TTL != 600 || result.Results[3].Err != nil {
		t.Fatalf("outcomes: %+v", result.Results)
	}
}

func TestWritesAvoidReadingTheZoneMoreThanNeeded(t *testing.T) {
	s := newRecords(t)
	var calls []string
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method)
		s.handler(w, r)
	})
	ctx := context.Background()
	r, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300})
	if err != nil || !reflect.DeepEqual(calls, []string{"GET", "POST"}) {
		t.Fatalf("create: %v calls=%v", err, calls)
	}
	calls = nil
	after := r
	after.Value = "192.0.2.2"
	if _, err := p.UpdateRecord(ctx, exampleZone, r, after); err != nil || !reflect.DeepEqual(calls, []string{"GET", "PATCH", "GET"}) {
		t.Fatalf("update: %v calls=%v", err, calls)
	}
	calls = nil
	if err := p.DeleteRecord(ctx, exampleZone, after); err != nil || !reflect.DeepEqual(calls, []string{"DELETE"}) {
		t.Fatalf("delete: %v calls=%v", err, calls)
	}
}
