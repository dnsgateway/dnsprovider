package scaleway_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/scaleway"
)

type fixture struct {
	t             *testing.T
	records       []map[string]any
	writes        int
	fail          int
	ack           bool
	partial       bool
	normalizeTTL  uint32
	normalizeData string
	malformed     bool
	failRead      bool
	next          int
	operations    []string
}

func newFixture(t *testing.T) (*fixture, *scaleway.Provider) {
	t.Helper()
	f := &fixture{t: t, next: 10, records: []map[string]any{
		{"id": "a", "name": "www", "type": "A", "data": "192.0.2.1", "priority": 0, "ttl": 300, "comment": "keep comment", "weighted_config": map[string]any{"weighted_ips": []any{map[string]any{"ip": "192.0.2.1", "weight": 1}}}, "updated_at": "2026-10-01T00:00:00Z"},
		{"id": "b", "name": "www", "type": "A", "data": "192.0.2.2", "priority": 0, "ttl": 300},
	}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	p, err := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, dnsprovider.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return f, p
}

func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth-Token") != "secret" {
		f.t.Error("missing authentication")
	}
	if r.Method == http.MethodGet && r.URL.Query().Get("project_id") != project {
		f.t.Error("read without project")
	}
	if r.URL.Path == "/dns-zones" {
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 1, "dns_zones": []any{map[string]any{"domain": "example.com", "subdomain": "dev", "project_id": project, "status": "active"}}})
		return
	}
	if r.URL.Path != "/dns-zones/dev.example.com/records" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if f.failRead && f.writes > 0 {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"denied"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(f.records), "records": f.records})
		return
	}
	if r.Method != http.MethodPatch {
		f.t.Errorf("unexpected method %s", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	f.writes++
	if f.fail != 0 {
		w.WriteHeader(f.fail)
		fmt.Fprint(w, `{"type":"invalid_argument","message":"secret failure"}`)
		return
	}
	var body struct {
		Changes   []map[string]json.RawMessage `json:"changes"`
		ReturnAll bool                         `json:"return_all_records"`
		Disallow  bool                         `json:"disallow_new_zone_creation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Error(err)
	}
	if !body.Disallow || !body.ReturnAll {
		f.t.Error("unsafe mutation flags")
	}
	if f.partial {
		f.normalizeRecords(f.records...)
		_ = json.NewEncoder(w).Encode(map[string]any{"records": f.records})
		return
	}
	for _, op := range body.Changes {
		if len(op) != 1 {
			f.t.Error("operation must have precisely one action")
		}
		for kind, raw := range op {
			f.operations = append(f.operations, kind)
			if kind == "clear" {
				f.t.Fatal("clear operation")
			}
			var change struct {
				ID       string           `json:"id"`
				IDFields json.RawMessage  `json:"id_fields"`
				Records  []map[string]any `json:"records"`
			}
			_ = json.Unmarshal(raw, &change)
			if kind != "add" && (change.ID == "" || len(change.IDFields) > 0) {
				f.t.Error("operation was not targeted by native ID")
			}
			if kind == "delete" || kind == "set" {
				at := slices.IndexFunc(f.records, func(r map[string]any) bool { return r["id"] == change.ID })
				if at < 0 {
					f.t.Error("missing targeted record")
				} else {
					f.records = slices.Delete(f.records, at, at+1)
				}
			}
			for _, record := range change.Records {
				if _, ok := record["id"]; ok {
					f.t.Error("sent read-side ID in replacement")
				}
				f.next++
				f.normalizeRecords(record)
				record["id"] = strconv.Itoa(f.next)
				f.records = append(f.records, record)
			}
		}
	}
	if f.malformed {
		fmt.Fprint(w, `{}`)
		return
	}
	records := f.records
	if f.ack {
		records = []map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"records": records})
}

var testZone = dnsprovider.Zone{ID: "dev.example.com", Name: "dev.example.com"}

func TestTargetedEditsRetainSiblingsAndDynamicMetadata(t *testing.T) {
	f, p := newFixture(t)
	ctx := context.Background()
	set, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	before := set.Records[0]
	after := before
	after.Name = "new.dev.example.com"
	after.Value = "192.0.2.9"
	after.TTL = 600
	stored, err := p.UpdateRecord(ctx, testZone, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID == "a" || stored.ID == "" || stored.Name != after.Name || stored.TTL != 600 {
		t.Fatalf("stored: %+v", stored)
	}
	got, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 2 || got.Records[0].ID != "b" {
		t.Fatalf("siblings: %+v", got)
	}
	replacement := f.records[1]
	if replacement["comment"] != "keep comment" || replacement["weighted_config"] == nil {
		t.Fatalf("metadata lost: %+v", replacement)
	}
	if err = p.DeleteRecord(ctx, testZone, stored); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || f.records[0]["id"] != "b" {
		t.Fatalf("delete sibling: %+v", f.records)
	}
	if err = p.DeleteRecord(ctx, testZone, got.Records[0]); err != nil {
		t.Fatal(err)
	}
	remaining, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	if err != nil || len(remaining.Records) != 0 {
		t.Fatalf("last sibling: %+v %v", remaining, err)
	}
}

func TestDuplicateAndUnsafeMetadataFailBeforeWrites(t *testing.T) {
	f, p := newFixture(t)
	ctx := context.Background()
	_, err := p.CreateRecord(ctx, testZone, dnsprovider.Record{Type: "a", Name: "WWW.DEV.EXAMPLE.COM", Value: "192.0.2.1", TTL: 600})
	if !errors.Is(err, dnsprovider.ErrConflict) || f.writes != 0 {
		t.Fatalf("duplicate: %v writes %d", err, f.writes)
	}
	set, _ := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	before := set.Records[0]
	after := before
	after.Type = "TXT"
	after.Value = "hello"
	if _, err = p.UpdateRecord(ctx, testZone, before, after); err == nil || f.writes != 0 {
		t.Fatalf("unsafe routing type edit: %v", err)
	}
	f.records[1]["unfamiliar_metadata"] = true
	before = set.Records[1]
	after = before
	after.TTL = 600
	if _, err = p.UpdateRecord(ctx, testZone, before, after); err == nil || f.writes != 0 {
		t.Fatalf("unsafe unknown metadata: %v", err)
	}
	if err = p.DeleteRecord(ctx, testZone, dnsprovider.Record{ID: "absent"}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestApplyOrderResultsReadbackAndStaleness(t *testing.T) {
	f, p := newFixture(t)
	ctx := context.Background()
	set, _ := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	modified := set.Records[0]
	modified.TTL = 600
	added := dnsprovider.Record{Type: "A", Name: "added", Value: "192.0.2.10", TTL: 600}
	cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: added},
		{Kind: dnsprovider.ChangeModify, Before: set.Records[0], After: modified},
		{Kind: dnsprovider.ChangeDelete, Before: set.Records[1]},
	}}
	f.ack = true
	result, err := dnsprovider.Apply(ctx, p, cs)
	if err != nil {
		t.Fatal(err)
	}
	if f.writes != 1 || !slices.Equal(f.operations, []string{"delete", "set", "add"}) {
		t.Fatalf("batch: %d %v", f.writes, f.operations)
	}
	if len(result.Results) != 3 || result.Results[0].Record.Name != "added.dev.example.com" || result.Results[1].Record.TTL != 600 || result.Results[2].Record.ID != "" {
		t.Fatalf("results %+v", result)
	}
	if _, err = dnsprovider.Apply(ctx, p, cs); !errors.Is(err, dnsprovider.ErrStale) || f.writes != 1 {
		t.Fatalf("stale: %v writes %d", err, f.writes)
	}
}

func TestWholeBatchFailureIsNotRetried(t *testing.T) {
	for _, status := range []int{403, 409, 429, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			f, p := newFixture(t)
			f.fail = status
			_, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "TXT", Name: "new", Value: "text", TTL: 600})
			if err == nil || f.writes != 1 || strings.Contains(err.Error(), "secret") {
				t.Fatalf("err %v writes %d", err, f.writes)
			}
			if status == 500 && !strings.Contains(err.Error(), "may have completed") {
				t.Fatalf("uncertain failure %v", err)
			}
		})
	}
}

func TestUnchangedPartialBatchDoesNotConfirmTTLModification(t *testing.T) {
	f, p := newFixture(t)
	ctx := context.Background()
	f.partial = true
	set, _ := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	after := set.Records[0]
	after.TTL = 600
	res, err := dnsprovider.Apply(ctx, p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeModify, Before: set.Records[0], After: after}}})
	if err == nil || len(res.Results) != 1 || res.Results[0].Err == nil || f.writes != 1 {
		t.Fatalf("partial: %+v %v writes %d", res, err, f.writes)
	}
}

func TestTypeEditDropsOldPriorityAndKeepsComment(t *testing.T) {
	f, p := newFixture(t)
	f.records = []map[string]any{{"id": "mx", "type": "MX", "name": "mail", "data": "mail.example.net.", "priority": 10, "ttl": 600, "comment": "preserve"}}
	ctx := context.Background()
	set, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	after := set.Records[0]
	after.Type = "TXT"
	after.Value = "text"
	stored, err := p.UpdateRecord(ctx, testZone, set.Records[0], after)
	if err != nil || stored.Type != "TXT" || stored.Value != "text" {
		t.Fatalf("type edit: %+v %v", stored, err)
	}
	if f.records[0]["priority"] != float64(0) || f.records[0]["comment"] != "preserve" {
		t.Fatalf("type metadata: %+v", f.records[0])
	}
}

func TestStoredNormalizedTTLIsAuthoritative(t *testing.T) {
	f, p := newFixture(t)
	f.normalizeTTL = 900
	ctx := context.Background()
	added, err := p.CreateRecord(ctx, testZone, dnsprovider.Record{Type: "TXT", Name: "new", Value: "text", TTL: 600})
	if err != nil || added.TTL != 900 {
		t.Fatalf("normalized create: %+v %v", added, err)
	}
	set, _ := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	after := set.Records[0]
	after.TTL = 600
	modified, err := p.UpdateRecord(ctx, testZone, set.Records[0], after)
	if err != nil || modified.TTL != 900 {
		t.Fatalf("normalized update: %+v %v", modified, err)
	}
}

func TestMalformedAcknowledgementReadsBackWithoutRepeatingWrite(t *testing.T) {
	f, p := newFixture(t)
	f.malformed = true
	r, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "TXT", Name: "new", Value: "text", TTL: 600})
	if err != nil || r.ID == "" || f.writes != 1 {
		t.Fatalf("ack readback %+v %v writes %d", r, err, f.writes)
	}
}

func TestReadbackFailureRetainsUncertainChangeOutcome(t *testing.T) {
	f, p := newFixture(t)
	f.malformed = true
	f.failRead = true
	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "new", Value: "text", TTL: 600}}}})
	if err == nil || !strings.Contains(err.Error(), "may have completed") || len(res.Results) != 1 || res.Results[0].Err == nil || f.writes != 1 {
		t.Fatalf("readback failure %+v %v writes %d", res, err, f.writes)
	}
}

func (f *fixture) normalizeRecords(records ...map[string]any) {
	for _, record := range records {
		if f.normalizeData != "" {
			record["data"] = f.normalizeData
		}
		if f.normalizeTTL != 0 {
			record["ttl"] = f.normalizeTTL
		}
	}
}
