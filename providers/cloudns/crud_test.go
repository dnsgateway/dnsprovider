package cloudns_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudns"
)

type dnsState struct {
	sync.Mutex
	records map[string]map[string]string
	writes  []string
	next    int
	fail    string
}

func fixture(t *testing.T) (*dnsState, *cloudns.Provider) {
	t.Helper()
	s := &dnsState{records: map[string]map[string]string{"1": {"id": "1", "host": "www", "type": "A", "record": "192.0.2.1", "ttl": "300", "status": "0", "geodns_location": "5", "note": "retain"}, "2": {"id": "2", "host": "www", "type": "A", "record": "192.0.2.2", "ttl": "300"}}, next: 3}
	p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
		s.Lock()
		defer s.Unlock()
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/dns/records.json":
			_ = json.NewEncoder(w).Encode(s.records)
		case "/dns/get-available-ttl.json":
			fmt.Fprint(w, `[60,300,3600]`)
		case "/dns/set-record-note.json":
			s.writes = append(s.writes, r.URL.Path)
			s.records[r.PostForm.Get("record-id")]["note"] = r.PostForm.Get("note")
			fmt.Fprint(w, `{"status":"Success"}`)
		case "/dns/add-record.json", "/dns/mod-record.json", "/dns/delete-record.json":
			s.writes = append(s.writes, r.URL.Path)
			if s.fail == r.URL.Path {
				fmt.Fprint(w, `{"status":"Failed","statusDescription":"Permission denied"}`)
				return
			}
			id := r.PostForm.Get("record-id")
			if r.URL.Path == "/dns/delete-record.json" {
				delete(s.records, id)
				fmt.Fprint(w, `{"status":"Success"}`)
				return
			}
			if r.URL.Path == "/dns/add-record.json" {
				id = strconv.Itoa(s.next)
				s.next++
				s.records[id] = map[string]string{"id": id, "type": r.PostForm.Get("record-type")}
			}
			rec := s.records[id]
			if rec == nil {
				fmt.Fprint(w, `{"status":"Failed","statusDescription":"Record not found"}`)
				return
			}
			for k, v := range r.PostForm {
				if k != "record-type" && k != "record-id" && k != "domain-name" && k != "auth-password" && k != "auth-id" {
					rec[k] = v[0]
				}
			}
			if loc := r.PostForm.Get("geodns-location"); loc != "" {
				rec["geodns_location"] = loc
				delete(rec, "geodns-location")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "Success", "statusDescription": "The record is added."})
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
	})
	return s, p
}

var testZone = dnsprovider.Zone{ID: "example.com", Name: "example.com"}

func TestCreateReturnsStoredRecordAndRejectsDuplicatesRegardlessOfTTL(t *testing.T) {
	state, p := fixture(t)
	ctx := context.Background()
	r := dnsprovider.Record{Type: "A", Name: "new.example.com", Value: "192.0.2.3", TTL: 300}
	created, err := p.CreateRecord(ctx, testZone, r)
	if err != nil || created.ID != "3" || created.Name != r.Name || created.Value != r.Value {
		t.Fatalf("Create = %+v, %v", created, err)
	}
	r.Name = "NEW.EXAMPLE.COM"
	r.TTL = 3600
	if _, err = p.CreateRecord(ctx, testZone, r); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatal(err)
	}
	state.Lock()
	defer state.Unlock()
	if len(state.writes) != 1 || len(state.records) != 3 {
		t.Fatal(state.writes, state.records)
	}
}

func TestUpdateRetainsNativeIDMetadataAndSiblingThenDeletesOnlySelection(t *testing.T) {
	state, p := fixture(t)
	ctx := context.Background()
	rs, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	before := rs.Records[0]
	after := before
	after.Name = "moved.example.com"
	after.Value = "192.0.2.9"
	after.TTL = 3600
	got, err := p.UpdateRecord(ctx, testZone, before, after)
	if err != nil || got.ID != before.ID || got.Name != after.Name || got.Extras["note"] != "retain" || got.Extras["status"] != "0" || got.Extras["geodns_location"] != "5" {
		t.Fatalf("Update = %+v, %v", got, err)
	}
	if err = p.DeleteRecord(ctx, testZone, got); err != nil {
		t.Fatal(err)
	}
	rs, err = p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	if err != nil || len(rs.Records) != 1 || rs.Records[0].ID != "2" {
		t.Fatalf("remaining = %+v, %v", rs, err)
	}
	if err = p.DeleteRecord(ctx, testZone, got); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatal(err)
	}
	state.Lock()
	defer state.Unlock()
	if len(state.writes) != 2 {
		t.Fatal(state.writes)
	}
}

func TestTypeMovePreservesMetadataAndReportsPartialDeletionFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			state, p := fixture(t)
			ctx := context.Background()
			rs, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
			if err != nil {
				t.Fatal(err)
			}
			before := rs.Records[0]
			after := before
			after.Type = "AAAA"
			after.Value = "2001:db8::1"
			if fail {
				state.fail = "/dns/delete-record.json"
			}
			got, err := p.UpdateRecord(ctx, testZone, before, after)
			if fail {
				if !errors.Is(err, dnsprovider.ErrUnauthorized) || !strings.Contains(err.Error(), "replacement 3 created") {
					t.Fatalf("partial error %v", err)
				}
			} else if err != nil || got.ID != "3" || got.Type != "AAAA" || got.Extras["note"] != "retain" || got.Extras["status"] != "0" {
				t.Fatalf("move = %+v, %v", got, err)
			}
			rs, readErr := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
			if readErr != nil {
				t.Fatal(readErr)
			}
			want := 2
			if fail {
				want = 3
			}
			if len(rs.Records) != want {
				t.Fatal(rs)
			}
		})
	}
}

func TestRecordWritesRoundTripSupportedTypesAndRejectUnavailableTTLs(t *testing.T) {
	_, p := fixture(t)
	ctx := context.Background()
	for i, r := range []dnsprovider.Record{{Type: "AAAA", Value: "2001:db8::1"}, {Type: "CNAME", Value: "target.example.net"}, {Type: "NS", Value: "ns.example.net"}, {Type: "MX", Value: "0 ."}, {Type: "SRV", Value: "10 20 443 target.example.net"}, {Type: "CAA", Value: `0 issue "example.org; validationmethods=dns-01"`}, {Type: "TXT", Value: `quoted "text" and backslash\`}} {
		r.Name = fmt.Sprintf("r%d.example.com", i)
		r.TTL = 300
		got, err := p.CreateRecord(ctx, testZone, r)
		if err != nil || got.Value != r.Value {
			t.Fatalf("round trip %+v = %+v, %v", r, got, err)
		}
	}
	for _, r := range []dnsprovider.Record{{Type: "A", Value: "192.0.2.9", TTL: 61}, {Type: "A", Value: "192.0.2.9", TTL: 1}, {Type: "URI", Value: `10 1 "https://example.com"`, TTL: 300}} {
		r.Name = "bad.example.com"
		if _, err := p.CreateRecord(ctx, testZone, r); err == nil {
			t.Fatal("accepted unsupported write")
		}
	}
}

func TestCAADNSPresentationEscapesRoundTripAndSemanticDuplicatesConflict(t *testing.T) {
	_, p := fixture(t)
	ctx := context.Background()
	r := dnsprovider.Record{Type: "CAA", Name: "caa.example.com", Value: `0 issue "example.org;\032validationmethods=dns-01"`, TTL: 300}
	got, err := p.CreateRecord(ctx, testZone, r)
	if err != nil || got.Value != `0 issue "example.org; validationmethods=dns-01"` {
		t.Fatalf("CAA escape = %+v, %v", got, err)
	}
	r.Value = `0 issue "example.org; validationmethods=dns-01"`
	r.TTL = 3600
	if _, err = p.CreateRecord(ctx, testZone, r); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatal(err)
	}
}
