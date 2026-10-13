package gandi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
)

type service struct {
	mu     sync.Mutex
	sets   map[string]map[string]any
	writes []string
	bodies []map[string]any
	fail   string
	// failStatus is the status a fail write answers; 403 when zero.
	failStatus int
	// acknowledgeOnly makes writes answer success but change nothing.
	acknowledgeOnly bool
	// onWrite, when set, runs once before the next write is applied: a
	// change by another writer after the Changeset read the RRsets.
	onWrite func(f *service)
	// barrier, when set, holds every write until snapshots reads of the
	// Zone's records have been answered.
	barrier   chan struct{}
	snapshots int
}

var testZone = dnsprovider.Zone{ID: "example.org", Name: "example.org"}

// holdWritesUntil makes writes wait until n reads of the Zone's records.
func (f *service) holdWritesUntil(n int) {
	f.barrier = make(chan struct{})
	f.snapshots = n
}

func newService(t *testing.T, sets ...map[string]any) (*service, *gandi.Provider) {
	t.Helper()
	f := &service{sets: map[string]map[string]any{}}
	for _, s := range sets {
		f.sets[s["rrset_name"].(string)+"/"+s["rrset_type"].(string)] = s
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && f.barrier != nil {
			<-f.barrier
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer pat_test" {
			t.Error("missing bearer token")
		}
		prefix := "/domains/example.org/records"
		key := strings.TrimPrefix(r.URL.Path, prefix+"/")
		if r.Method != http.MethodGet {
			f.write(t, w, r, key)
			return
		}
		if r.URL.Path == prefix {
			var page []map[string]any
			if r.URL.Query().Get("page") == "1" {
				if f.barrier != nil && f.snapshots > 0 {
					if f.snapshots--; f.snapshots == 0 {
						close(f.barrier)
					}
				}
				for _, k := range slices.Sorted(maps.Keys(f.sets)) {
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

// write is LiveDNS's answer to a POST or PATCH of an RRset, as its docs
// describe them. A PATCH of a missing RRset answers 404 (undocumented).
func (f *service) write(t *testing.T, w http.ResponseWriter, r *http.Request, key string) {
	f.writes = append(f.writes, r.Method+" "+key)
	answer := func(status int, message string) {
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"code":%d,"message":%q}`, status, message)
	}
	if key == f.fail {
		status := f.failStatus
		if status == 0 {
			status = http.StatusForbidden
		}
		answer(status, "rejected")
		return
	}
	if f.onWrite != nil {
		onWrite := f.onWrite
		f.onWrite = nil
		onWrite(f)
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Error("expected JSON")
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Error(err)
	}
	f.bodies = append(f.bodies, body)
	name, typ, _ := strings.Cut(key, "/")
	set, exists := f.sets[key]
	switch r.Method {
	case http.MethodPost:
		if exists {
			answer(http.StatusConflict, "A record with that name / type pair already exists")
			return
		}
		if !f.acknowledgeOnly {
			f.sets[key] = map[string]any{"rrset_name": name, "rrset_type": typ, "rrset_ttl": body["rrset_ttl"], "rrset_values": body["rrset_values"]}
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"message":"created"}`))
	case http.MethodPatch:
		if !exists {
			answer(http.StatusNotFound, "not found")
			return
		}
		values := strs(set["rrset_values"])
		for _, v := range strs(body["add_rrset_values"]) {
			if !slices.Contains(values, v) {
				values = append(values, v)
			}
		}
		values = slices.DeleteFunc(values, func(v string) bool { return slices.Contains(strs(body["remove_rrset_values"]), v) })
		next := maps.Clone(set)
		stored := make([]any, len(values))
		for i, v := range values {
			stored[i] = v
		}
		next["rrset_values"] = stored
		if ttl, ok := body["rrset_ttl"]; ok {
			next["rrset_ttl"] = ttl
		}
		switch {
		case f.acknowledgeOnly:
			next = set
		case len(values) == 0:
			delete(f.sets, key)
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			f.sets[key] = next
		}
		_ = json.NewEncoder(w).Encode(next)
	default:
		t.Errorf("unexpected write method %s", r.Method)
		answer(http.StatusMethodNotAllowed, "unexpected")
	}
}

// strs is a JSON list of strings, decoded or as built.
func strs(v any) []string {
	switch l := v.(type) {
	case []string:
		return slices.Clone(l)
	case []any:
		out := make([]string, len(l))
		for i, s := range l {
			out[i], _ = s.(string)
		}
		return out
	}
	return nil
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

func TestMovesPreserveSiblingsAndEmptyTheSourceWithoutDeletingIt(t *testing.T) {
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
	if !slices.Equal(f.writes, []string{"PATCH www/A", "PATCH @/A"}) {
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
			if !strings.Contains(res.Results[0].Err.Error(), "partial side effects") {
				t.Fatalf("partial context = %v", res.Results[0].Err)
			}
			// The destination is written first: a failed source leaves the
			// value at both ends, a failed destination leaves the source.
			got := read(t, p)
			if fail == "@/A" && len(got) != 3 {
				t.Fatalf("source failure state = %+v", got)
			}
			if fail == "www/A" && (len(got) != 2 || got[0].Name != "example.org") {
				t.Fatalf("destination failure lost the source = %+v", got)
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
	if !slices.Equal(f.writes, []string{"POST @/AAAA", "PATCH @/A"}) {
		t.Fatalf("write order = %v", f.writes)
	}
}

func TestMutationIsNeverRetriedAndReadbackFailureReportsWrittenState(t *testing.T) {
	for _, mode := range []string{"failed-write", "malformed-ack", "malformed-readback", "wrong-readback", "missing-readback", "authoritative-ttl"} {
		t.Run(mode, func(t *testing.T) {
			writes := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
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
			if err == nil || got.ID != "" {
				t.Fatalf("unconfirmed = %+v %v", got, err)
			}
			if (strings.Contains(mode, "readback") || mode == "authoritative-ttl") && !strings.Contains(err.Error(), "unconfirmed") {
				t.Fatalf("lost written context: %v", err)
			}
			// Stored with another TTL than planned, or without the value:
			// another write may have replaced this one.
			if (mode == "missing-readback" || mode == "authoritative-ttl") != errors.Is(err, dnsprovider.ErrConflict) {
				t.Fatalf("conflict = %v", err)
			}
		})
	}
}

func TestMoveFailureAtTheSourceFailsItsWholeGroup(t *testing.T) {
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
	// The move joins both RRsets into one group, which fails as a whole.
	for _, r := range res.Results {
		if !errors.Is(r.Err, dnsprovider.ErrUnauthorized) || !strings.Contains(r.Err.Error(), "partial side effects") {
			t.Fatalf("partial results = %+v", res)
		}
	}
	if !slices.Equal(f.writes, []string{"PATCH www/A", "PATCH @/A"}) {
		t.Fatalf("write order = %v", f.writes)
	}
	got := read(t, p)
	if len(got) != 2 || got[0].Value != "192.0.2.1" || got[1].Value != "192.0.2.1" {
		t.Fatalf("partial stored state = %+v", got)
	}
}

func txtSet(name string, ttl uint32, values ...string) map[string]any {
	return map[string]any{"rrset_name": name, "rrset_type": "TXT", "rrset_ttl": ttl, "rrset_values": values}
}

func TestAddingToAnExistingRRsetPatchesOnlyTheNewValue(t *testing.T) {
	f, p := newService(t, aSet("www", 300, "192.0.2.1"))
	if _, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Name: "www", Type: "A", Value: "192.0.2.2", TTL: 300}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.writes, []string{"PATCH www/A"}) {
		t.Fatalf("writes = %v", f.writes)
	}
	if body := f.bodies[0]; len(body) != 1 || !slices.Equal(strs(body["add_rrset_values"]), []string{"192.0.2.2"}) {
		t.Fatalf("PATCH body = %v, want only add_rrset_values", body)
	}
}

func TestAddingToAMissingRRsetPostsAndPatchesWhenAnotherWriterCreatedIt(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		t.Run(strconv.FormatBool(concurrent), func(t *testing.T) {
			f, p := newService(t)
			want := []string{"POST _acme-challenge/TXT"}
			if concurrent {
				f.onWrite = func(f *service) {
					f.sets["_acme-challenge/TXT"] = txtSet("_acme-challenge", 300, `"other"`)
				}
				want = append(want, "PATCH _acme-challenge/TXT")
			}
			r, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Name: "_acme-challenge", Type: "TXT", Value: "token", TTL: 300})
			if err != nil || r.Value != "token" {
				t.Fatalf("create = %+v, %v", r, err)
			}
			if !slices.Equal(f.writes, want) {
				t.Fatalf("writes = %v, want %v", f.writes, want)
			}
		})
	}
}

func TestDeletingTheLastValuePatchesItAwayWithoutADelete(t *testing.T) {
	f, p := newService(t, aSet("www", 300, "192.0.2.1"))
	if err := p.DeleteRecord(context.Background(), testZone, read(t, p)[0]); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.writes, []string{"PATCH www/A"}) || len(read(t, p)) != 0 {
		t.Fatalf("writes = %v, stored = %v", f.writes, f.sets)
	}
}

func TestRemovingATXTValueNamesItsStoredWireForm(t *testing.T) {
	f, p := newService(t, txtSet("@", 300, `"one" "two"`, `"a\032b"`, `"keep"`))
	for _, r := range read(t, p)[:2] {
		if err := p.DeleteRecord(context.Background(), testZone, r); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(strs(f.bodies[0]["remove_rrset_values"]), []string{`"one" "two"`}) || !slices.Equal(strs(f.bodies[1]["remove_rrset_values"]), []string{`"a\032b"`}) {
		t.Fatalf("PATCH bodies = %v, want the wire strings as stored", f.bodies)
	}
	if got := strs(f.sets["@/TXT"]["rrset_values"]); !slices.Equal(got, []string{`"keep"`}) {
		t.Fatalf("stored = %v", got)
	}
}

func TestAModificationWithinOneRRsetIsOnePatch(t *testing.T) {
	f, p := newService(t, aSet("www", 300, "192.0.2.1", "192.0.2.2"))
	before := read(t, p)[0]
	after := before
	after.Value = "192.0.2.9"
	if _, err := p.UpdateRecord(context.Background(), testZone, before, after); err != nil {
		t.Fatal(err)
	}
	body := f.bodies[0]
	if len(f.writes) != 1 || !slices.Equal(strs(body["add_rrset_values"]), []string{"192.0.2.9"}) || !slices.Equal(strs(body["remove_rrset_values"]), []string{before.Value}) || body["rrset_ttl"] != nil {
		t.Fatalf("writes = %v, body = %v", f.writes, body)
	}
}

func TestConcurrentChangesetsOnOneRRsetKeepEachOthersValues(t *testing.T) {
	add := func(v string) dnsprovider.Change {
		return dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "_acme-challenge.example.org", Value: v, TTL: 300}}
	}
	for _, tc := range []struct {
		name      string
		existing  []map[string]any
		changes   func(existing []dnsprovider.Record) [][]dnsprovider.Change
		snapshots int
		want      []string
	}{
		{
			name: "two additions",
			changes: func([]dnsprovider.Record) [][]dnsprovider.Change {
				return [][]dnsprovider.Change{{add("a")}, {add("b")}}
			},
			snapshots: 2,
			want:      []string{"a", "b"},
		},
		{
			name:     "an addition and a deletion of the last value",
			existing: []map[string]any{txtSet("_acme-challenge", 300, `"old"`)},
			changes: func(existing []dnsprovider.Record) [][]dnsprovider.Change {
				return [][]dnsprovider.Change{{add("new")}, {{Kind: dnsprovider.ChangeDelete, Before: existing[0]}}}
			},
			// Apply re-reads before a deletion.
			snapshots: 3,
			want:      []string{"new"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, p := newService(t, tc.existing...)
			changesets := tc.changes(read(t, p))
			f.holdWritesUntil(tc.snapshots)

			var wg sync.WaitGroup
			results := make([]dnsprovider.ApplyResult, len(changesets))
			errs := make([]error, len(changesets))
			for i, changes := range changesets {
				wg.Add(1)
				go func() {
					defer wg.Done()
					results[i], errs[i] = dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: testZone, Changes: changes})
				}()
			}
			wg.Wait()

			for i := range changesets {
				if errs[i] != nil || results[i].Results[0].Err != nil {
					t.Errorf("Apply %d = %+v, %v", i, results[i], errs[i])
				}
			}
			var got []string
			for _, r := range read(t, p) {
				got = append(got, r.Value)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("stored %v, want %v; writes = %v", got, tc.want, f.writes)
			}
		})
	}
}

func TestReadBackIgnoresValuesAnotherWriterAdded(t *testing.T) {
	f, p := newService(t, aSet("www", 300, "192.0.2.1"))
	f.onWrite = func(f *service) {
		f.sets["www/A"] = aSet("www", 300, "192.0.2.1", "192.0.2.77")
	}
	if _, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Name: "www", Type: "A", Value: "192.0.2.2", TTL: 300}); err != nil {
		t.Fatal(err)
	}
}

func TestReadBackMissingAnAddOrHoldingARemovalIsAConflict(t *testing.T) {
	f, p := newService(t, aSet("www", 300, "192.0.2.1", "192.0.2.2"))
	f.acknowledgeOnly = true
	if _, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Name: "www", Type: "A", Value: "192.0.2.3", TTL: 300}); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("missing add = %v", err)
	}
	if err := p.DeleteRecord(context.Background(), testZone, read(t, p)[0]); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("held removal = %v", err)
	}
}

func TestAPatchRejectionIsReturnedWithoutFallingBackToDelete(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{
		{http.StatusNotFound, dnsprovider.ErrNotFound},
		{http.StatusConflict, dnsprovider.ErrConflict},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			f, p := newService(t, aSet("www", 300, "192.0.2.1"))
			f.fail, f.failStatus = "www/A", tc.status
			err := p.DeleteRecord(context.Background(), testZone, read(t, p)[0])
			if !errors.Is(err, tc.want) || !slices.Equal(f.writes, []string{"PATCH www/A"}) {
				t.Fatalf("delete = %v, writes = %v", err, f.writes)
			}
		})
	}
}
