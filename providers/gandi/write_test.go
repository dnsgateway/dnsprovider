package gandi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
)

type service struct {
	sets   map[string]map[string]any
	writes []string
	fail   string
}

var testZone = dnsprovider.Zone{ID: "example.org", Name: "example.org"}

func newService(t *testing.T, sets ...map[string]any) (*service, *gandi.Provider) {
	t.Helper()
	f := &service{sets: map[string]map[string]any{}}
	for _, s := range sets {
		f.sets[s["rrset_name"].(string)+"/"+s["rrset_type"].(string)] = s
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat_test" {
			t.Error("missing bearer token")
		}
		prefix := "/domains/example.org/records"
		key := strings.TrimPrefix(r.URL.Path, prefix+"/")
		if r.Method != http.MethodGet {
			f.writes = append(f.writes, r.Method+" "+key)
			if key == f.fail {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"code":403,"message":"forbidden"}`))
				return
			}
			if r.Method == http.MethodDelete {
				delete(f.sets, key)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if r.Method != http.MethodPut {
				t.Error("unexpected write method")
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("expected JSON")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			parts := strings.Split(key, "/")
			body["rrset_name"] = parts[0]
			body["rrset_type"] = parts[1]
			f.sets[key] = body
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"message":"updated"}`))
			return
		}
		if r.URL.Path == prefix {
			var page []map[string]any
			if r.URL.Query().Get("page") == "1" {
				for _, k := range slices.Sorted(func(yield func(string) bool) {
					for k := range f.sets {
						if !yield(k) {
							return
						}
					}
				}) {
					page = append(page, f.sets[k])
				}
			}
			if page == nil {
				page = []map[string]any{}
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		if set, ok := f.sets[key]; ok {
			_ = json.NewEncoder(w).Encode(set)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":404,"message":"not found"}`))
	}))
	t.Cleanup(server.Close)
	p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	return f, p
}

func aSet(name string, ttl uint32, values ...string) map[string]any {
	return map[string]any{"rrset_name": name, "rrset_type": "A", "rrset_ttl": ttl, "rrset_values": values}
}

func read(t *testing.T, p *gandi.Provider) []dnsprovider.Record {
	t.Helper()
	rs, err := p.ListRecords(context.Background(), testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	return rs.Records
}

func TestSharedTTLRequiresEveryRemainingSibling(t *testing.T) {
	f, p := newService(t, aSet("@", 300, "192.0.2.1", "192.0.2.2"))
	before := read(t, p)
	after := before[0]
	after.TTL = 600
	if _, err := p.UpdateRecord(context.Background(), testZone, before[0], after); err == nil {
		t.Fatal("accepted implicit sibling TTL change")
	}
	if len(f.writes) != 0 {
		t.Fatalf("wrote invalid final TTLs: %v", f.writes)
	}
	second := before[1]
	second.TTL = 600
	cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeModify, Before: before[0], After: after},
		{Kind: dnsprovider.ChangeModify, Before: before[1], After: second},
	}}
	result, err := dnsprovider.Apply(context.Background(), p, cs)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.writes) != 1 {
		t.Fatalf("group writes = %v", f.writes)
	}
	for _, r := range result.Results {
		if r.Err != nil || r.Record.TTL != 600 || r.Record.ID == "" {
			t.Fatalf("result = %+v", result)
		}
	}
	if got := read(t, p); len(got) != 2 || got[0].TTL != 600 || got[1].TTL != 600 {
		t.Fatalf("stored = %+v", got)
	}
}

func TestMovesPreserveSiblingsAndDeleteFinalSourceValue(t *testing.T) {
	f, p := newService(t, aSet("@", 300, "192.0.2.1", "192.0.2.2"), aSet("www", 300, "192.0.2.3"))
	initial := read(t, p)
	moved := initial[0]
	moved.Name = "www.example.org"
	moved.Value = "192.0.2.4"
	cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Name: "www.example.org", Type: "A", Value: "192.0.2.2", TTL: 300}},
		{Kind: dnsprovider.ChangeModify, Before: initial[0], After: moved},
		{Kind: dnsprovider.ChangeDelete, Before: initial[1]},
	}}
	result, err := dnsprovider.Apply(context.Background(), p, cs)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.writes, []string{"DELETE @/A", "PUT www/A"}) {
		t.Fatalf("write order = %v", f.writes)
	}
	for i, r := range result.Results {
		if r.Err != nil || r.Change.Kind != cs.Changes[i].Kind {
			t.Fatalf("result = %+v", result)
		}
	}
	got := read(t, p)
	if len(got) != 3 || got[0].Name != "www.example.org" {
		t.Fatalf("stored = %+v", got)
	}
	if !slices.ContainsFunc(got, func(r dnsprovider.Record) bool { return r.Value == "192.0.2.3" }) {
		t.Fatal("destination sibling lost")
	}
}

func TestMissingBeforeAndDuplicateWrites(t *testing.T) {
	f, p := newService(t, aSet("@", 300, "192.0.2.1"))
	r := read(t, p)[0]
	duplicate := r
	duplicate.Name = "EXAMPLE.ORG."
	duplicate.TTL = 900
	if _, err := p.CreateRecord(context.Background(), testZone, duplicate); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("duplicate = %v", err)
	}
	missing := r
	missing.Value = "192.0.2.9"
	if err := p.DeleteRecord(context.Background(), testZone, missing); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("Delete = %v", err)
	}
	if _, err := p.UpdateRecord(context.Background(), testZone, missing, r); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("Update = %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
}

func TestStaleApplyWritesNothing(t *testing.T) {
	for _, kind := range []dnsprovider.ChangeKind{dnsprovider.ChangeModify, dnsprovider.ChangeDelete} {
		t.Run(strconv.Itoa(int(kind)), func(t *testing.T) {
			f, p := newService(t, aSet("@", 300, "192.0.2.1"))
			before := read(t, p)[0]
			before.TTL = 600
			_, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: kind, Before: before, After: before}}})
			if !errors.Is(err, dnsprovider.ErrStale) || len(f.writes) != 0 {
				t.Fatalf("stale = %v, writes = %v", err, f.writes)
			}
		})
	}
}

func TestMoveFailuresReportPartialStateAndIndependentSuccess(t *testing.T) {
	for _, fail := range []string{"@/A", "www/A"} {
		t.Run(fail, func(t *testing.T) {
			f, p := newService(t, aSet("@", 300, "192.0.2.1"))
			before := read(t, p)[0]
			after := before
			after.Name = "www.example.org"
			f.fail = fail
			cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
				{Kind: dnsprovider.ChangeModify, Before: before, After: after},
				{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Name: "other", Type: "A", Value: "192.0.2.2", TTL: 300}},
			}}
			res, err := dnsprovider.Apply(context.Background(), p, cs)
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(res.Results[0].Err, dnsprovider.ErrUnauthorized) || res.Results[0].Record.ID != "" || res.Results[1].Err != nil {
				t.Fatalf("partial results = %+v", res)
			}
			got := read(t, p)
			if fail == "@/A" && len(got) != 2 {
				t.Fatalf("source failure lost data = %+v", got)
			}
			if fail == "www/A" && len(got) != 1 {
				t.Fatalf("destination failure state = %+v", got)
			}
		})
	}
}

func TestAllFinalTTLChecksPrecedeEveryWrite(t *testing.T) {
	f, p := newService(t, aSet("www", 300, "192.0.2.1", "192.0.2.2"))
	existing := read(t, p)
	after := existing[0]
	after.TTL = 600
	cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Name: "other", Type: "A", Value: "192.0.2.3", TTL: 300}},
		{Kind: dnsprovider.ChangeModify, Before: existing[0], After: after},
	}}
	if _, err := dnsprovider.Apply(context.Background(), p, cs); err == nil {
		t.Fatal("accepted inconsistent TTLs")
	}
	if len(f.writes) != 0 {
		t.Fatalf("preflight wrote %v", f.writes)
	}
}

func TestTypeMoveLeavesUnrelatedAndUnfamiliarDataUntouched(t *testing.T) {
	opaque := map[string]any{"rrset_name": "opaque", "rrset_type": "HTTPS", "rrset_ttl": 300, "rrset_values": []string{`1 . alpn="h2"`}, "future_metadata": true}
	f, p := newService(t, aSet("@", 300, "192.0.2.1", "192.0.2.2"), opaque)
	initial := read(t, p)
	before := initial[0]
	after := before
	after.Type = "AAAA"
	after.Value = "2001:db8::1"
	got, err := p.UpdateRecord(context.Background(), testZone, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "AAAA" || got.ID == before.ID {
		t.Fatalf("type move = %+v", got)
	}
	if f.sets["opaque/HTTPS"]["future_metadata"] != true || len(read(t, p)) != 3 {
		t.Fatal("lost unrelated data")
	}
	if !slices.Equal(f.writes, []string{"PUT @/A", "PUT @/AAAA"}) {
		t.Fatalf("write order = %v", f.writes)
	}
}

func TestMutationIsNeverRetriedAndReadbackFailureReportsWrittenState(t *testing.T) {
	for _, mode := range []string{"failed-write", "malformed-ack", "malformed-readback", "wrong-readback", "missing-readback", "authoritative-ttl"} {
		t.Run(mode, func(t *testing.T) {
			writes := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					writes++
					if mode == "failed-write" {
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = w.Write([]byte(`{"code":500,"message":"unavailable"}`))
						return
					}
					if mode == "malformed-ack" {
						_, _ = w.Write([]byte(`[]`))
						return
					}
					_, _ = w.Write([]byte(`{"message":"updated"}`))
					return
				}
				if r.URL.Query().Get("page") != "" {
					_, _ = w.Write([]byte(`[]`))
					return
				}
				switch mode {
				case "malformed-readback":
					_, _ = w.Write([]byte(`{}`))
				case "wrong-readback":
					_, _ = w.Write([]byte(`{"rrset_name":"other","rrset_type":"A","rrset_ttl":300,"rrset_values":["192.0.2.1"]}`))
				case "missing-readback":
					_, _ = w.Write([]byte(`{"rrset_name":"@","rrset_type":"A","rrset_ttl":300,"rrset_values":["192.0.2.9"]}`))
				default:
					_, _ = w.Write([]byte(`{"rrset_name":"@","rrset_type":"A","rrset_ttl":600,"rrset_values":["192.0.2.1"]}`))
				}
			}))
			defer s.Close()
			p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Name: "@", Type: "A", Value: "192.0.2.1", TTL: 300})
			if writes != 1 {
				t.Fatalf("repeated mutation %d times", writes)
			}
			if mode == "authoritative-ttl" {
				if err != nil || got.TTL != 600 || got.ID == "" {
					t.Fatalf("readback = %+v %v", got, err)
				}
				return
			}
			if err == nil || got.ID != "" {
				t.Fatalf("unconfirmed = %+v %v", got, err)
			}
			if strings.Contains(mode, "readback") && !strings.Contains(err.Error(), "written") {
				t.Fatalf("lost written context: %v", err)
			}
		})
	}
}

func TestMoveFailureReportsDestinationWrittenForEarlierChange(t *testing.T) {
	f, p := newService(t, aSet("@", 300, "192.0.2.1"), aSet("www", 300, "192.0.2.2"))
	before := read(t, p)
	after := before[0]
	after.Name = "www.example.org"
	f.fail = "@/A"
	cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeDelete, Before: before[1]},
		{Kind: dnsprovider.ChangeModify, Before: before[0], After: after},
	}}
	res, err := dnsprovider.Apply(context.Background(), p, cs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Results[0].Err != nil || !errors.Is(res.Results[1].Err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("partial results = %+v", res)
	}
	message := res.Results[1].Err.Error()
	if !strings.Contains(message, "www/A mutation already acknowledged") || !strings.Contains(message, "@/A deletion unconfirmed") {
		t.Fatalf("partial context = %v", res.Results[1].Err)
	}
	if !slices.Equal(f.writes, []string{"PUT www/A", "DELETE @/A"}) {
		t.Fatalf("write order = %v", f.writes)
	}
	got := read(t, p)
	if len(got) != 2 || got[0].Value != "192.0.2.1" || got[1].Value != "192.0.2.1" {
		t.Fatalf("partial stored state = %+v", got)
	}
}
