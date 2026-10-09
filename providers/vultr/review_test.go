package vultr_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

func TestIDsThatAreNotUUIDsNameNoRecordAndAreNeverSent(t *testing.T) {
	var requests int
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	})
	ctx := context.Background()
	for _, id := range []string{"abc", "123", "cb676a46-66fd-4dfb-b839", "cb676a46-66fd-4dfb-b839-00000000000g", "cb676a4666fd4dfbb839000000000001"} {
		r := dnsprovider.Record{ID: id, Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
		if err := p.DeleteRecord(ctx, exampleZone, r); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Errorf("delete %q: %v", id, err)
		}
		if _, err := p.UpdateRecord(ctx, exampleZone, r, r); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Errorf("update %q: %v", id, err)
		}
	}
	if requests != 0 {
		t.Fatalf("%d requests sent", requests)
	}
}

// A write the rate limiter refuses before sending, as its wait would pass
// the deadline, plainly failed: it is not reported unconfirmed.
func TestWritesRefusedBeforeSendingAreNotUnconfirmed(t *testing.T) {
	s := newRecords(t)
	var posts int
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
		}
		s.handler(w, r)
	})
	// The Zone's list takes the endpoint's one token; the next comes
	// 50ms later, past the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, err := p.CreateRecord(ctx, exampleZone, dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300})
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "unconfirmed") || posts != 0 {
		t.Fatalf("create: %v posts=%d", err, posts)
	}
}

// A replacement whose creation may have completed is not followed by
// re-creating the original, which could leave both at one owner.
func TestSameOwnerCNAMETypeMoveDoesNotRestoreWhenTheReplacementMayExist(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "CNAME", "name": "www", "data": "target.example.net", "ttl": 300})
	var posts int
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			s.fail(w, http.StatusBadGateway, "Bad gateway")
			return
		}
		s.handler(w, r)
	})
	before := dnsprovider.Record{ID: id, Type: "CNAME", Name: "www.example.com", Value: "target.example.net.", TTL: 300}
	after := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	_, err := p.UpdateRecord(context.Background(), exampleZone, before, after)
	if err == nil || !strings.Contains(err.Error(), "original Record "+id+" was deleted") ||
		!strings.Contains(err.Error(), "may have completed") || !strings.Contains(err.Error(), "not restored") {
		t.Fatalf("partial move: %v", err)
	}
	if posts != 1 {
		t.Fatalf("POSTs: %d, want the replacement alone", posts)
	}
}

// A Record whose data does not parse for its type is listed with that
// data as its Value; it does not fail the Zone's other Records.
func TestRecordsWithUnparseableDataAreListedWithTheirRawData(t *testing.T) {
	s := newRecords(t)
	good := s.add(map[string]any{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 300})
	cases := map[string]map[string]any{
		"mail.example.net":  {"type": "MX", "name": "", "data": "mail.example.net", "priority": nil, "ttl": 60},
		"5 sip.example.net": {"type": "SRV", "name": "_sip._tcp", "data": "5 sip.example.net", "priority": 1, "ttl": 60},
		"0 issue":           {"type": "CAA", "name": "", "data": "0 issue", "ttl": 60},
		"":                  {"type": "CNAME", "name": "alias", "data": "", "ttl": 60},
	}
	want := map[string]string{good: "192.0.2.1"}
	for data, row := range cases {
		want[s.add(row)] = data
	}
	p := provider(t, s.handler)
	set, err := p.Records(context.Background(), exampleZone, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != len(want) {
		t.Fatalf("Records: %+v %v", set, err)
	}
	for _, r := range set.Records {
		if r.Value != want[r.ID] {
			t.Errorf("%s %s Value %q, want %q", r.Type, r.ID, r.Value, want[r.ID])
		}
	}
}

// TXT data of several quoted strings is their concatenation, which writes
// back as one string.
func TestMultiStringTXTDataReadsAsItsTextAndWritesBack(t *testing.T) {
	s := newRecords(t)
	id := s.add(map[string]any{"type": "TXT", "name": "", "data": `"v=DKIM1; p=part1" "part2"`, "ttl": 300})
	p := provider(t, s.handler)
	ctx := context.Background()
	set, err := p.Records(ctx, exampleZone, dnsprovider.RecordFilter{Type: "TXT"})
	if err != nil || len(set.Records) != 1 || set.Records[0].Value != "v=DKIM1; p=part1part2" {
		t.Fatalf("Records: %+v %v", set, err)
	}
	after := set.Records[0]
	after.TTL = 600
	got, err := p.UpdateRecord(ctx, exampleZone, set.Records[0], after)
	if err != nil || got.ID != id || got.Value != after.Value || got.TTL != 600 {
		t.Fatalf("update: %+v %v", got, err)
	}
	if data := s.bodies[0]["data"]; data != `"v=DKIM1; p=part1part2"` {
		t.Fatalf("sent data %#v", data)
	}
}

// A same-owner move whose original could not be written back is refused
// before anything is deleted.
func TestSameOwnerCNAMETypeMoveOfAnUnrestorableOriginalWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name          string
		stored        map[string]any
		before, after dnsprovider.Record
	}{
		{
			"TTL outside the writable range",
			map[string]any{"type": "CNAME", "name": "www", "data": "target.example.net", "ttl": 10},
			dnsprovider.Record{Type: "CNAME", Name: "www.example.com", Value: "target.example.net.", TTL: 10},
			dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300},
		},
		{
			"type the module does not write",
			map[string]any{"type": "SSHFP", "name": "www", "data": "4 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789", "ttl": 300},
			dnsprovider.Record{Type: "SSHFP", Name: "www.example.com", Value: "4 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789", TTL: 300},
			dnsprovider.Record{Type: "CNAME", Name: "www.example.com", Value: "target.example.net.", TTL: 300},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRecords(t)
			tc.before.ID = s.add(tc.stored)
			p := provider(t, s.handler)
			if _, err := p.UpdateRecord(context.Background(), exampleZone, tc.before, tc.after); err == nil {
				t.Fatal("move accepted")
			}
			if len(s.writes) != 0 {
				t.Fatalf("writes: %v", s.writes)
			}
		})
	}
}
