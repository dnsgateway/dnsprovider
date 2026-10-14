package dnsimple_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// DNSimple wire fixture preserves server-only metadata and accepts only the
// documented mutation fields. PATCH cannot change type.
type recordServer struct {
	records    map[string]map[string]any
	next       int
	writes     []string
	failDelete bool
}

func newRecords() *recordServer {
	return &recordServer{records: map[string]map[string]any{}, next: 100}
}

func (s *recordServer) handler(w http.ResponseWriter, r *http.Request) {
	const base = "/12/zones/example.com/records"
	if !strings.HasPrefix(r.URL.Path, base) {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, base+"/")
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path == base {
			rows := make([]map[string]any, 0, len(s.records))
			for _, v := range s.records {
				rows = append(rows, v)
			}
			json.NewEncoder(w).Encode(map[string]any{"data": rows, "pagination": map[string]any{"current_page": 1, "per_page": 100, "total_pages": 1}})
		} else if v, ok := s.records[id]; ok {
			json.NewEncoder(w).Encode(map[string]any{"data": v})
		} else {
			http.NotFound(w, r)
		}
	case http.MethodPost, http.MethodPatch:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if _, has := body["type"]; has && r.Method == http.MethodPatch {
			http.Error(w, `{"message":"type is not updateable"}`, http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodPost {
			for _, existing := range s.records {
				if existing["name"] == body["name"] && (existing["type"] == "CNAME" || body["type"] == "CNAME") {
					http.Error(w, `{"message":"CNAME conflicts with existing records"}`, http.StatusBadRequest)
					return
				}
			}
			s.next++
			id = strconv.Itoa(s.next)
			s.records[id] = map[string]any{"id": s.next, "zone_id": "example.com", "system_record": false, "regions": []string{"global"}}
		}
		v, ok := s.records[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		for k, val := range body {
			if k != "integrated_zones" {
				v[k] = val
			}
		}
		s.writes = append(s.writes, r.Method+" "+id)
		json.NewEncoder(w).Encode(map[string]any{"data": v})
	case http.MethodDelete:
		if s.failDelete {
			http.Error(w, `{"message":"service restriction"}`, http.StatusBadRequest)
			return
		}
		if _, ok := s.records[id]; !ok {
			http.NotFound(w, r)
			return
		}
		delete(s.records, id)
		s.writes = append(s.writes, "DELETE "+id)
		w.WriteHeader(http.StatusNoContent)
	default:
		fmt.Fprint(w, `{"message":"unexpected"}`)
	}
}

func TestCRUDReturnsStoredIDsAndPreservesMetadataAndSiblings(t *testing.T) {
	s := newRecords()
	p := provider(t, s.handler)
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "7", Name: "example.com"}
	a, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "MX", Name: "example.com", Value: "10 mail.example.net.", TTL: 60})
	if err != nil || a.ID != "101" || a.Value != "10 mail.example.net." {
		t.Fatalf("create: %+v %v", a, err)
	}
	_, err = p.CreateRecord(ctx, z, dnsprovider.Record{Type: "MX", Name: "example.com", Value: "20 other.example.net.", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	s.records[a.ID]["regions"] = []string{"IAD", "SV1"}
	s.records[a.ID]["opaque"] = "retained"
	after := a
	after.Name = "*.example.com"
	after.Value = "30 new.example.net."
	after.TTL = 120
	got, err := p.UpdateRecord(ctx, z, a, after)
	if err != nil || got.ID != a.ID || got.Name != "*.example.com" || got.Extras["regions"] != `["IAD","SV1"]` {
		t.Fatalf("update: %+v %v", got, err)
	}
	if s.records[a.ID]["opaque"] != "retained" || len(s.records) != 2 {
		t.Fatal("metadata or sibling lost")
	}
	if err := p.DeleteRecord(ctx, z, got); err != nil {
		t.Fatal(err)
	}
	set, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 1 || set.Records[0].ID != "102" {
		t.Fatalf("delete: %+v %v", set, err)
	}
}

func TestRoundTripsSupportedRecordPresentation(t *testing.T) {
	cases := []struct{ typ, name, value string }{
		{"A", "example.com", "192.0.2.1"},
		{"AAAA", "www.example.com", "2001:db8::1"},
		{"CNAME", "alias.example.com", "target.example.net."},
		{"NS", "sub.example.com", "ns.example.net."},
		{"MX", "example.com", "0 ."},
		{"SRV", "_sip._tcp.example.com", "10 5 443 sip.example.net."},
		{"TXT", "*.example.com", `hello "world"`},
		{"CAA", "example.com", `0 issue "letsencrypt.org"`},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			s := newRecords()
			p := provider(t, s.handler)
			z := dnsprovider.Zone{Name: "example.com"}
			r, err := p.CreateRecord(context.Background(), z, dnsprovider.Record{Type: tc.typ, Name: tc.name, Value: tc.value, TTL: 60})
			if err != nil || r.Value != tc.value || r.Name != tc.name || r.ID == "" {
				t.Fatalf("create: %+v %v", r, err)
			}
			set, err := p.ListRecords(context.Background(), z, dnsprovider.RecordFilter{})
			if err != nil || len(set.Records) != 1 || set.Records[0].Value != tc.value {
				t.Fatalf("read: %+v %v", set, err)
			}
		})
	}
}

func TestTypeMoveUsesReplacementAndPreservesRegionalPlacement(t *testing.T) {
	s := newRecords()
	p := provider(t, s.handler)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	before, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	s.records[before.ID]["regions"] = []string{"IAD", "SV1"}
	after := before
	after.Type = "AAAA"
	after.Value = "2001:db8::1"
	after.Name = "moved.example.com"
	got, err := p.UpdateRecord(ctx, z, before, after)
	if err != nil || got.ID == before.ID || got.Extras["regions"] != `["IAD","SV1"]` || got.Name != "moved.example.com" {
		t.Fatalf("move: %+v %v", got, err)
	}
	set, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 1 || set.Records[0].ID != got.ID {
		t.Fatalf("move state: %+v %v", set, err)
	}
}

func TestTypeMoveReportsReplacementWhenOriginalDeletionFails(t *testing.T) {
	s := newRecords()
	p := provider(t, s.handler)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	before, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	s.failDelete = true
	after := before
	after.Type = "AAAA"
	after.Value = "2001:db8::1"
	got, err := p.UpdateRecord(ctx, z, before, after)
	if err == nil || got.ID == "" || !strings.Contains(err.Error(), "replacement Record "+got.ID) || !strings.Contains(err.Error(), "original "+before.ID) {
		t.Fatalf("partial move: %+v %v", got, err)
	}
	set, readErr := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if readErr != nil || len(set.Records) != 2 {
		t.Fatalf("partial state: %+v %v", set, readErr)
	}
}

func TestDuplicatesAndUnsupportedWritesLeaveDNSUnchanged(t *testing.T) {
	s := newRecords()
	p := provider(t, s.handler)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	original, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 0})
	if err != nil {
		t.Fatal(err)
	}
	duplicate := original
	duplicate.Name = "WWW.EXAMPLE.COM."
	duplicate.TTL = 120
	if _, err := p.CreateRecord(ctx, z, duplicate); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	target, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "AAAA", Name: "moved.example.com", Value: "2001:db8::1", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpdateRecord(ctx, z, original, target); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("move collision: %v", err)
	}
	if _, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "URI", Name: "example.com", Value: `10 1 "https://example.com/"`, TTL: 60}); err == nil {
		t.Fatal("URI accepted")
	}
	if len(s.writes) != 2 || len(s.records) != 2 {
		t.Fatal("rejected writes changed DNS")
	}
	s.records[original.ID]["system_record"] = true
	if _, err := p.UpdateRecord(ctx, z, original, duplicate); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("system update: %v", err)
	}
	if err := p.DeleteRecord(ctx, z, original); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("system delete: %v", err)
	}
}

func TestApplyRejectsStaleChangesWithoutWriting(t *testing.T) {
	for _, kind := range []dnsprovider.ChangeKind{dnsprovider.ChangeModify, dnsprovider.ChangeDelete} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			s := newRecords()
			p := provider(t, s.handler)
			ctx := context.Background()
			z := dnsprovider.Zone{Name: "example.com"}
			before, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 60})
			if err != nil {
				t.Fatal(err)
			}
			s.writes = nil
			s.records[before.ID]["ttl"] = 120
			after := before
			after.Value = "192.0.2.2"
			_, err = dnsprovider.Apply(ctx, p, dnsprovider.Changeset{Zone: z, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeAdd, After: after}, {Kind: kind, Before: before, After: after}}})
			if !errors.Is(err, dnsprovider.ErrStale) || len(s.writes) != 0 {
				t.Fatalf("stale Apply: %v writes=%v", err, s.writes)
			}
		})
	}
}

func TestApplyOrdersCRUDAndReportsResultsInChangesetOrder(t *testing.T) {
	s := newRecords()
	p := provider(t, s.handler)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	a, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "A", Name: "other.example.com", Value: "192.0.2.2", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	s.writes = nil
	after := b
	after.TTL = 120
	cs := dnsprovider.Changeset{Zone: z, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeAdd, After: a}, {Kind: dnsprovider.ChangeModify, Before: b, After: after}, {Kind: dnsprovider.ChangeDelete, Before: a}}}
	result, err := dnsprovider.Apply(ctx, p, cs)
	if err != nil || len(result.Results) != 3 {
		t.Fatalf("Apply: %+v %v", result, err)
	}
	if !reflect.DeepEqual(s.writes, []string{"DELETE 101", "PATCH 102", "POST 103"}) {
		t.Fatalf("write order: %v", s.writes)
	}
	for i, cr := range result.Results {
		if cr.Err != nil || !reflect.DeepEqual(cr.Change, cs.Changes[i]) {
			t.Fatalf("result %d: %+v", i, cr)
		}
	}
}

func TestPriorityWhitespaceIsConvertedWithoutChangingItsMeaning(t *testing.T) {
	s := newRecords()
	p := provider(t, s.handler)
	r, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.Record{Type: "SRV", Name: "_sip._tcp.example.com", Value: " 10\t5 443 sip.example.net. ", TTL: 60})
	if err != nil || r.Value != "10 5 443 sip.example.net." {
		t.Fatalf("SRV: %+v %v", r, err)
	}
}

func TestSameOwnerCNAMETypeMoveUsesDeleteThenCreate(t *testing.T) {
	s := newRecords()
	p := provider(t, s.handler)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	before, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "CNAME", Name: "www.example.com", Value: "target.example.net", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	s.writes = nil
	after := before
	after.Type = "A"
	after.Value = "192.0.2.1"
	got, err := p.UpdateRecord(ctx, z, before, after)
	if err != nil || got.ID == before.ID || got.Type != "A" {
		t.Fatalf("CNAME move: %+v %v", got, err)
	}
	if !reflect.DeepEqual(s.writes, []string{"DELETE 101", "POST 102"}) {
		t.Fatalf("move order: %v", s.writes)
	}
}

func TestCNAMETypeMoveExposesOriginalDeletionWhenReplacementFails(t *testing.T) {
	s := newRecords()
	reject := false
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if reject && r.Method == http.MethodPost {
			http.Error(w, `{"message":"record limit"}`, http.StatusBadRequest)
			return
		}
		s.handler(w, r)
	})
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	before, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "CNAME", Name: "www.example.com", Value: "target.example.net", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	reject = true
	after := before
	after.Type = "A"
	after.Value = "192.0.2.1"
	_, err = p.UpdateRecord(ctx, z, before, after)
	if err == nil || !strings.Contains(err.Error(), "original Record "+before.ID+" was deleted") {
		t.Fatalf("partial move: %v", err)
	}
	set, readErr := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if readErr != nil || len(set.Records) != 0 {
		t.Fatalf("partial state: %+v %v", set, readErr)
	}
}

func TestCNAMECollisionWithSiblingIsCheckedBeforeDeletingOriginal(t *testing.T) {
	s := newRecords()
	p := provider(t, s.handler)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	a, err := p.CreateRecord(ctx, z, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.CreateRecord(ctx, z, dnsprovider.Record{Type: "AAAA", Name: "www.example.com", Value: "2001:db8::1", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	s.writes = nil
	after := a
	after.Type = "CNAME"
	after.Value = "target.example.net"
	_, err = p.UpdateRecord(ctx, z, a, after)
	if !errors.Is(err, dnsprovider.ErrConflict) || len(s.writes) != 0 {
		t.Fatalf("CNAME conflict: %v writes=%v", err, s.writes)
	}
}

func TestMalformedMutationAnswerIsUnconfirmed(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"data":[],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
		} else {
			fmt.Fprint(w, `{"data":{"id":101}}`)
		}
	})
	_, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 60})
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("malformed create: %v", err)
	}
}

func TestMalformedRequiredMutationFieldsAreUnconfirmed(t *testing.T) {
	for _, field := range []string{"name", "content", "ttl"} {
		t.Run(field, func(t *testing.T) {
			row := map[string]any{"id": 101, "zone_id": "example.com", "name": "", "type": "TXT", "content": "hello", "ttl": 0}
			delete(row, field)
			p := provider(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					fmt.Fprint(w, `{"data":[],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"data": row})
			})
			_, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.Record{Type: "TXT", Name: "example.com", Value: "hello", TTL: 0})
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("malformed %s: %v", field, err)
			}
		})
	}
}

func TestAWriteWhoseAnswerIsLostIsUnconfirmed(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"data":[],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
			return
		}
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	})
	_, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 60})
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("lost create: %v", err)
	}
}

func TestAWriteTheProviderRefusesIsNotUnconfirmed(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"data":[],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
			return
		}
		http.Error(w, `{"message":"Validation failed"}`, http.StatusBadRequest)
	})
	_, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.Record{Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 60})
	if err == nil || errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("refused create: %v", err)
	}
}
