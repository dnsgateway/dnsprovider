package hetzner_test

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/hetzner"
)

type value struct {
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}
type rrset struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	TTL        *uint32           `json:"ttl"`
	Labels     map[string]string `json:"labels"`
	Protection map[string]bool   `json:"protection"`
	Records    []value           `json:"records"`
}
type fixture struct {
	t               *testing.T
	mu              sync.Mutex
	sets            map[string]rrset
	writes          []string
	actionStatus    string
	polls           int
	zoneTTL         uint32
	normalize       map[string]string
	pending         map[string]rrset
	failPath        string
	readFail        bool
	secondary       bool
	acknowledgeOnly bool
	// failCode is the error code a failPath write answers; invalid_input
	// when empty.
	failCode string
	// onWrite, when set, runs once before the next write is applied: a
	// change by another writer after the Changeset read the RRsets.
	onWrite func(f *fixture)
	// barrier, when set, holds every write until snapshots reads of the
	// Zone's RRsets have been answered, so concurrent Changesets all plan
	// from the same RRsets before any of them writes.
	barrier   chan struct{}
	snapshots int
	s         *httptest.Server
	p         *hetzner.Provider
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, sets: map[string]rrset{"www/A": {Name: "www", Type: "A", TTL: nil, Labels: map[string]string{"team": "dns"}, Records: []value{{Value: "192.0.2.1", Comment: "one"}, {Value: "192.0.2.2", Comment: "two"}}}}, actionStatus: "success"}
	f.s = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.s.Close)
	var err error
	f.p, err = hetzner.New(hetzner.Config{Token: "test-token"}, dnsprovider.WithBaseURL(f.s.URL), dnsprovider.WithHTTPClient(f.s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// holdWritesUntil makes writes wait until n reads of the Zone's RRsets.
func (f *fixture) holdWritesUntil(n int) {
	f.barrier = make(chan struct{})
	f.snapshots = n
}

func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && f.barrier != nil {
		<-f.barrier
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer test-token" {
		f.t.Error("unauthenticated request")
	}
	w.Header().Set("Content-Type", "application/json")
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.Method == http.MethodGet {
		f.read(w, r)
		return
	}

	f.writes = append(f.writes, r.Method+" "+r.URL.Path)
	reject := func(code string) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		write(map[string]any{"error": map[string]string{"code": code, "message": "rejected"}})
	}
	if f.failPath != "" && strings.Contains(r.URL.Path, f.failPath) {
		code := f.failCode
		if code == "" {
			code = "invalid_input"
		}
		reject(code)
		return
	}
	previous := maps.Clone(f.sets)
	base := strings.TrimPrefix(r.URL.Path, "/zones/1/rrsets/")
	if f.onWrite != nil {
		onWrite := f.onWrite
		f.onWrite = nil
		onWrite(f)
		previous = maps.Clone(f.sets)
	}
	if r.Method == http.MethodDelete {
		delete(f.sets, base)
	} else {
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			f.t.Error(err)
		}
		if r.URL.Path == "/zones/1/rrsets" {
			var s rrset
			b, _ := json.Marshal(body)
			_ = json.Unmarshal(b, &s)
			if labels, ok := body["labels"]; ok && string(labels) == "null" {
				w.WriteHeader(http.StatusUnprocessableEntity)
				write(map[string]any{"error": map[string]string{"code": "invalid_input", "message": "labels must be an object"}})
				return
			}
			if s.Name == f.failPath {
				reject("invalid_input")
				return
			}
			if _, ok := f.sets[s.Name+"/"+s.Type]; ok {
				reject("uniqueness_error")
				return
			}
			for i := range s.Records {
				if v, ok := f.normalize[s.Records[i].Value]; ok {
					s.Records[i].Value = v
				}
			}
			f.sets[s.Name+"/"+s.Type] = s
		} else {
			key, action, _ := strings.Cut(base, "/actions/")
			if code := f.action(key, action, body); code != "" {
				reject(code)
				return
			}
		}
	}
	if f.acknowledgeOnly {
		f.sets = previous
	}
	status := f.actionStatus
	if status != "success" {
		if status == "running-success" || status == "running" {
			f.pending = f.sets
		}
		f.sets = previous
	}
	if status == "running-success" {
		status = "running"
	}
	w.WriteHeader(http.StatusCreated)
	write(map[string]any{"action": map[string]any{"id": 99, "status": status, "error": map[string]string{"code": "action_failed", "message": "test-token failed"}}})
}

// action applies an RRset action to the fixture's RRsets, or returns the
// error code Hetzner answers it with.
func (f *fixture) action(key, action string, body map[string]json.RawMessage) string {
	s := f.sets[key]
	switch action {
	case "set_records":
		if len(body) != 1 {
			f.t.Errorf("invalid set_records payload %v", body)
		}
		_ = json.Unmarshal(body["records"], &s.Records)
		if len(s.Records) == 0 {
			f.t.Error("empty RRset write")
		}
		for i := range s.Records {
			if v, ok := f.normalize[s.Records[i].Value]; ok {
				s.Records[i].Value = v
			}
		}
	case "add_records":
		var add struct {
			TTL     *uint32 `json:"ttl"`
			Records []value `json:"records"`
		}
		b, _ := json.Marshal(body)
		_ = json.Unmarshal(b, &add)
		if len(add.Records) == 0 || len(add.Records) > 50 {
			f.t.Errorf("invalid add_records payload %v", body)
		}
		if _, exists := f.sets[key]; !exists {
			name, typ, _ := strings.Cut(key, "/")
			s = rrset{Name: name, Type: typ, TTL: add.TTL}
		} else if add.TTL != nil && s.TTL != nil && *add.TTL != *s.TTL {
			return "invalid_input"
		}
		s.Records = slices.Clone(s.Records)
		for _, v := range add.Records {
			if n, ok := f.normalize[v.Value]; ok {
				v.Value = n
			}
			s.Records = append(s.Records, v)
		}
	case "remove_records":
		var remove []value
		_ = json.Unmarshal(body["records"], &remove)
		if len(remove) == 0 || len(remove) > 50 {
			f.t.Errorf("invalid remove_records payload %v", body)
		}
		kept := []value{}
		for _, v := range s.Records {
			if !slices.ContainsFunc(remove, func(r value) bool { return r.Value == v.Value }) {
				kept = append(kept, v)
			}
		}
		s.Records = kept
	case "change_ttl":
		v, ok := body["ttl"]
		if !ok {
			f.t.Error("TTL is required")
		}
		_ = json.Unmarshal(v, &s.TTL)
	default:
		f.t.Errorf("unexpected action %s", action)
	}
	if len(s.Records) == 0 {
		delete(f.sets, key)
	} else {
		f.sets[key] = s
	}
	return ""
}

func readRecords(t *testing.T, f *fixture) []dnsprovider.Record {
	t.Helper()
	rs, err := f.p.ListRecords(context.Background(), dnsprovider.Zone{ID: "1", Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	return rs.Records
}

func recordValue(rs []dnsprovider.Record, v string) dnsprovider.Record {
	for _, r := range rs {
		if r.Value == v {
			return r
		}
	}
	return dnsprovider.Record{}
}

var testZone = dnsprovider.Zone{ID: "1", Name: "example.com"}

func TestRecordEditsPreserveSiblingsAndMetadata(t *testing.T) {
	f := newFixture(t)
	rs := readRecords(t, f)
	before := recordValue(rs, "192.0.2.1")
	after := before
	after.Value = "192.0.2.3"
	stored, err := f.p.UpdateRecord(context.Background(), testZone, before, after)
	if err != nil || stored.Value != after.Value || stored.ID == before.ID || stored.TTL != 300 || stored.Extras[hetzner.ExtraComment] != "one" {
		t.Fatalf("update=%+v,%v", stored, err)
	}
	if want := []string{"POST /zones/1/rrsets/www/A/actions/add_records", "POST /zones/1/rrsets/www/A/actions/remove_records"}; !slices.Equal(f.writes, want) || f.sets["www/A"].TTL != nil || f.sets["www/A"].Labels["team"] != "dns" {
		t.Fatalf("inheritance/labels lost: %+v %+v", f.sets, f.writes)
	}
	siblings := readRecords(t, f)
	if len(siblings) != 2 || recordValue(siblings, "192.0.2.2").Extras[hetzner.ExtraComment] != "two" {
		t.Fatalf("siblings=%+v", siblings)
	}
	if err := f.p.DeleteRecord(context.Background(), testZone, stored); err != nil {
		t.Fatal(err)
	}
	last := readRecords(t, f)[0]
	if err := f.p.DeleteRecord(context.Background(), testZone, last); err != nil {
		t.Fatal(err)
	}
	if len(readRecords(t, f)) != 0 || f.writes[len(f.writes)-1] != "POST /zones/1/rrsets/www/A/actions/remove_records" || slices.ContainsFunc(f.writes, func(w string) bool { return strings.HasPrefix(w, "DELETE ") }) {
		t.Fatalf("last deletion=%+v", f.writes)
	}
}

func TestMissingDuplicateProtectionAndTTLConflictMakeNoWrites(t *testing.T) {
	for _, kind := range []string{"missing update", "missing delete", "duplicate", "ttl", "protected", "secondary", "managed"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			before := readRecords(t, f)[0]
			after := before
			var err error
			switch kind {
			case "missing update":
				before.Value = "192.0.2.99"
				_, err = f.p.UpdateRecord(context.Background(), testZone, before, after)
			case "missing delete":
				before.Value = "192.0.2.99"
				err = f.p.DeleteRecord(context.Background(), testZone, before)
			case "duplicate":
				after.TTL = 600
				_, err = f.p.CreateRecord(context.Background(), testZone, after)
			case "ttl":
				after.TTL = 600
				_, err = f.p.UpdateRecord(context.Background(), testZone, before, after)
			case "protected":
				s := f.sets["www/A"]
				s.Protection = map[string]bool{"change": true}
				f.sets["www/A"] = s
				err = f.p.DeleteRecord(context.Background(), testZone, before)
			case "secondary":
				f.secondary = true
				err = f.p.DeleteRecord(context.Background(), testZone, before)
			case "managed":
				f.sets = map[string]rrset{"@/SOA": {Name: "@", Type: "SOA", Records: []value{{Value: "ns. hostmaster. 123 3600 600 86400 60"}}}}
				before = readRecords(t, f)[0]
				err = f.p.DeleteRecord(context.Background(), testZone, before)
			}
			if err == nil || len(f.writes) != 0 {
				t.Fatalf("error=%v writes=%v", err, f.writes)
			}
			if strings.HasPrefix(kind, "missing") && !errors.Is(err, dnsprovider.ErrNotFound) {
				t.Fatalf("missing=%v", err)
			}
			if kind == "duplicate" && !errors.Is(err, dnsprovider.ErrConflict) {
				t.Fatalf("duplicate=%v", err)
			}
		})
	}
}

func TestApplyChangesSharedTTLAndGroupsMoves(t *testing.T) {
	f := newFixture(t)
	rs := readRecords(t, f)
	a := recordValue(rs, "192.0.2.1")
	b := recordValue(rs, "192.0.2.2")
	aa := a
	bb := b
	aa.TTL = 600
	bb.TTL = 600
	result, err := dnsprovider.Apply(context.Background(), f.p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeModify, Before: b, After: bb}, {Kind: dnsprovider.ChangeModify, Before: a, After: aa}}})
	if err != nil || len(result.Results) != 2 || result.Results[0].Err != nil || result.Results[0].Record.Value != b.Value || result.Results[0].Record.TTL != 600 {
		t.Fatalf("Apply=%+v,%v", result, err)
	}
	if len(f.writes) != 1 || !strings.HasSuffix(f.writes[0], "/actions/change_ttl") || f.sets["www/A"].TTL == nil || *f.sets["www/A"].TTL != 600 {
		t.Fatalf("TTL writes=%v sets=%+v", f.writes, f.sets)
	}
	rs = readRecords(t, f)
	a = recordValue(rs, "192.0.2.1")
	b = recordValue(rs, "192.0.2.2")
	aa = a
	bb = b
	aa.Name = "moved.example.com"
	bb.Name = aa.Name
	f.writes = nil
	result, err = dnsprovider.Apply(context.Background(), f.p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeModify, Before: a, After: aa}, {Kind: dnsprovider.ChangeModify, Before: b, After: bb}}})
	if err != nil || result.Results[0].Err != nil || result.Results[1].Err != nil || len(f.writes) != 2 {
		t.Fatalf("move=%+v,%v writes=%v", result, err, f.writes)
	}
	dest := f.sets["moved/A"]
	if len(dest.Records) != 2 || dest.Labels["team"] != "dns" || dest.Records[0].Comment != "one" {
		t.Fatalf("move metadata=%+v", dest)
	}
}

func TestActionsWaitFailAndCancelWithoutResubmitting(t *testing.T) {
	for _, status := range []string{"running-success", "error", "running", "bogus"} {
		t.Run(status, func(t *testing.T) {
			f := newFixture(t)
			f.actionStatus = status
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			r, err := f.p.CreateRecord(ctx, testZone, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.8", TTL: 300})
			if len(f.writes) != 1 {
				t.Fatalf("resubmitted: %v", f.writes)
			}
			if status == "running-success" {
				if err != nil || r.ID == "" || f.polls != 1 {
					t.Fatalf("completion=%+v,%v polls=%d", r, err, f.polls)
				}
			} else if err == nil || strings.Contains(err.Error(), "test-token") {
				t.Fatalf("action error=%v", err)
			}
			if status != "running-success" && len(f.sets["new/A"].Records) != 0 {
				t.Fatal("unsuccessful action published a Record")
			}
			if status == "running" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("canceled=%v", err)
			}
			// An action the answer reports failed was refused; one still
			// running, or of an unknown status, may yet apply.
			if unconfirmed := status == "running" || status == "bogus"; errors.Is(err, dnsprovider.ErrUnconfirmed) != unconfirmed {
				t.Fatalf("%s=%v, want unconfirmed: %v", status, err, unconfirmed)
			}
		})
	}
}

func TestApplyStaleAndPartialOutcomes(t *testing.T) {
	f := newFixture(t)
	before := readRecords(t, f)[0]
	after := before
	after.Value = "192.0.2.3"
	before.TTL = 600
	_, err := dnsprovider.Apply(context.Background(), f.p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeModify, Before: before, After: after}}})
	if !errors.Is(err, dnsprovider.ErrStale) || len(f.writes) != 0 {
		t.Fatalf("stale=%v writes=%v", err, f.writes)
	}
	f.failPath = "bad"
	result, err := dnsprovider.Apply(context.Background(), f.p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "bad", Value: "192.0.2.4", TTL: 300}}, {Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "good", Value: "192.0.2.5", TTL: 300}}}})
	if err != nil || len(result.Results) != 2 || result.Results[0].Err == nil || result.Results[1].Err != nil || result.Results[1].Record.Name != "good.example.com" {
		t.Fatalf("partial=%+v,%v", result, err)
	}
	if len(f.writes) != 2 || len(readRecords(t, f)) != 3 {
		t.Fatalf("partial writes=%v", f.writes)
	}
}

func TestRelativeTargetRecordCanBeEditedByItsPublicContent(t *testing.T) {
	f := newFixture(t)
	f.sets = map[string]rrset{"alias/CNAME": {Name: "alias", Type: "CNAME", Records: []value{{Value: "target", Comment: "keep"}}}}
	before := readRecords(t, f)[0]
	if before.Value != "target.example.com." {
		t.Fatalf("relative target=%+v", before)
	}
	after := before
	after.Value = "other.example.net."
	stored, err := f.p.UpdateRecord(context.Background(), testZone, before, after)
	if err != nil || stored.Value != after.Value || stored.Extras[hetzner.ExtraComment] != "keep" {
		t.Fatalf("relative edit=%+v,%v", stored, err)
	}
}

func TestWritesRoundTripNativePresentation(t *testing.T) {
	for _, tc := range []struct{ typ, value, want string }{
		{"A", "192.0.2.9", "192.0.2.9"},
		{"AAAA", "2001:db8::1", "2001:db8::1"},
		{"CNAME", "target.example.net", "target.example.net."},
		{"NS", "ns.example.net", "ns.example.net."},
		{"MX", "10 mail.example.net", "10 mail.example.net."},
		{"SRV", "10 5 443 host.example.net", "10 5 443 host.example.net."},
		{"CAA", `0 issue "letsencrypt.org"`, `0 issue "letsencrypt.org"`},
		{"TXT", `"one" "two"`, `"one" "two"`},
		{"TXT", "plain text", `"plain text"`},
	} {
		t.Run(tc.typ+tc.value, func(t *testing.T) {
			f := newFixture(t)
			r, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: tc.typ, Name: "*.new", Value: tc.value, TTL: 600})
			if err != nil || r.Name != "*.new.example.com" || r.Value != tc.want || r.TTL != 600 || r.ID == "" {
				t.Fatalf("roundtrip=%+v,%v", r, err)
			}
		})
	}
}

func TestDeletionRequiresAuthoritativeAbsence(t *testing.T) {
	f := newFixture(t)
	f.acknowledgeOnly = true
	f.sets = map[string]rrset{"www/A": {Name: "www", Type: "A", Records: []value{{Value: "192.0.2.1"}}}}
	r := readRecords(t, f)[0]
	err := f.p.DeleteRecord(context.Background(), testZone, r)
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) || len(f.writes) != 1 {
		t.Fatalf("unconfirmed deletion=%v writes=%v", err, f.writes)
	}
}

func TestMoveFailureAtTheDestinationKeepsTheSource(t *testing.T) {
	f := newFixture(t)
	f.failPath = "bad"
	before := recordValue(readRecords(t, f), "192.0.2.1")
	after := before
	after.Name = "bad.example.com"
	_, err := f.p.UpdateRecord(context.Background(), testZone, before, after)
	if err == nil || !strings.Contains(err.Error(), "partial side effects") || len(f.writes) != 1 {
		t.Fatalf("replacement=%v writes=%v", err, f.writes)
	}
	if recordValue(readRecords(t, f), "192.0.2.1").ID == "" {
		t.Fatal("source removed although its value never reached the destination")
	}
}

func TestCreateWithoutLabelsUsesValidSchema(t *testing.T) {
	f := newFixture(t)
	r, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.8", TTL: 300})
	if err != nil || r.Value != "192.0.2.8" {
		t.Fatalf("create=%+v,%v", r, err)
	}
}

func (f *fixture) defaultTTL() uint32 {
	if f.zoneTTL != 0 {
		return f.zoneTTL
	}
	return 300
}

func TestMoveRetainsSourceTTLMode(t *testing.T) {
	for _, mode := range []string{"inherited", "explicit", "changed"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			if mode == "explicit" {
				s := f.sets["www/A"]
				ttl := uint32(300)
				s.TTL = &ttl
				f.sets["www/A"] = s
			}
			before := recordValue(readRecords(t, f), "192.0.2.1")
			after := before
			after.Name = "moved.example.com"
			if mode == "changed" {
				after.TTL = 600
			}
			stored, err := f.p.UpdateRecord(context.Background(), testZone, before, after)
			if err != nil || stored.Extras[hetzner.ExtraComment] != "one" {
				t.Fatalf("move=%+v,%v", stored, err)
			}
			dest := f.sets["moved/A"]
			if (dest.TTL == nil) != (mode == "inherited") || dest.Labels["team"] != "dns" {
				t.Fatalf("mode lost: %+v", dest)
			}
			f.zoneTTL = 900
			stored = recordValue(readRecords(t, f), before.Value)
			want := after.TTL
			if mode == "inherited" {
				want = 900
			}
			if stored.TTL != want {
				t.Fatalf("zone default change: %+v want TTL %d", stored, want)
			}
		})
	}
}

func TestWritesReturnEquivalentAuthoritativePresentation(t *testing.T) {
	for _, tc := range []struct{ typ, input, stored string }{
		{"TXT", `"a\032b"  "c\"d"`, `"a b" "c\034d"`},
		{"CAA", `00 issue "letsencrypt.org"`, `0  issue  "letsencrypt\046org"`},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			f := newFixture(t)
			f.normalize = map[string]string{tc.input: tc.stored}
			r, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: tc.typ, Name: "new", Value: tc.input, TTL: 300})
			if err != nil || r.Value != tc.stored || len(f.writes) != 1 {
				t.Fatalf("stored=%+v,%v writes=%v", r, err, f.writes)
			}
			after := r
			after.Name = "moved.example.com"
			moved, err := f.p.UpdateRecord(context.Background(), testZone, r, after)
			if err != nil || moved.Value != tc.stored {
				t.Fatalf("move normalized=%+v,%v", moved, err)
			}
		})
	}
}

func TestTXTReadbackDoesNotIgnoreChunkBoundaries(t *testing.T) {
	f := newFixture(t)
	f.normalize = map[string]string{`"ab" "cd"`: `"abcd"`}
	_, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "TXT", Name: "new", Value: `"ab" "cd"`, TTL: 300})
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) || len(f.writes) != 1 {
		t.Fatalf("different TXT=%v writes=%v", err, f.writes)
	}
}

func (f *fixture) read(w http.ResponseWriter, r *http.Request) {
	write := func(v any) { _ = json.NewEncoder(w).Encode(v) }

	if strings.HasPrefix(r.URL.Path, "/zones/actions/") {
		f.polls++
		status := f.actionStatus
		if status == "running-success" {
			status = "success"
			f.sets = f.pending
			f.pending = nil
		}
		write(map[string]any{"action": map[string]any{"id": 99, "status": status, "error": map[string]string{"code": "action_failed", "message": "test-token failed"}}})
		return
	}
	if r.URL.Path == "/zones/1" || r.URL.Path == "/zones/example.com" {
		mode := "primary"
		if f.secondary {
			mode = "secondary"
		}
		write(map[string]any{"zone": map[string]any{"id": 1, "name": "example.com", "ttl": f.defaultTTL(), "status": "ok", "mode": mode}})
		return
	}
	if r.URL.Path == "/zones/1/rrsets" {
		if f.barrier != nil && f.snapshots > 0 {
			if f.snapshots--; f.snapshots == 0 {
				close(f.barrier)
			}
		}
		if f.pending != nil {
			f.t.Error("authoritative readback before action success")
			w.WriteHeader(http.StatusConflict)
			write(map[string]any{"error": map[string]string{"code": "locked"}})
			return
		}
		if f.readFail && len(f.writes) > 0 {
			w.WriteHeader(http.StatusInternalServerError)
			write(map[string]any{"error": map[string]string{"code": "server_error"}})
			return
		}
		sets := []rrset{}
		for _, s := range f.sets {
			sets = append(sets, s)
		}
		write(map[string]any{"rrsets": sets, "meta": map[string]any{"pagination": map[string]any{"page": 1, "next_page": nil}}})
		return
	}
	f.t.Errorf("unexpected read %s", r.URL.Path)
	w.WriteHeader(http.StatusNotFound)
}

func TestAddingToAnExistingRRsetSendsOnlyTheNewValue(t *testing.T) {
	f := newFixture(t)
	if _, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.3", TTL: 300}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"POST /zones/1/rrsets/www/A/actions/add_records"}; !slices.Equal(f.writes, want) {
		t.Fatalf("writes=%v, want %v", f.writes, want)
	}
	if got := f.sets["www/A"]; len(got.Records) != 3 || got.TTL != nil || got.Records[0].Comment != "one" {
		t.Fatalf("RRset=%+v, want the siblings, their comments and inheritance kept", got)
	}
}

func TestAddingToAMissingRRsetSendsAddRecords(t *testing.T) {
	f := newFixture(t)
	r, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "TXT", Name: "_acme-challenge", Value: "token", TTL: 60})
	if err != nil || r.Value != `"token"` || r.TTL != 60 {
		t.Fatalf("create=%+v,%v", r, err)
	}
	if want := []string{"POST /zones/1/rrsets/_acme-challenge/TXT/actions/add_records"}; !slices.Equal(f.writes, want) {
		t.Fatalf("writes=%v, want %v", f.writes, want)
	}
}

func TestChangingAValueAddsTheNewOneBeforeRemovingTheOld(t *testing.T) {
	f := newFixture(t)
	f.sets = map[string]rrset{"www/A": {Name: "www", Type: "A", Records: []value{{Value: "192.0.2.1"}}}}
	before := readRecords(t, f)[0]
	after := before
	after.Value = "192.0.2.9"
	f.writes = nil
	if _, err := f.p.UpdateRecord(context.Background(), testZone, before, after); err != nil {
		t.Fatal(err)
	}
	if want := []string{"POST /zones/1/rrsets/www/A/actions/add_records", "POST /zones/1/rrsets/www/A/actions/remove_records"}; !slices.Equal(f.writes, want) {
		t.Fatalf("writes=%v, want %v", f.writes, want)
	}
}

func TestChangingTheOnlyValueAndTheTTLChangesTheTTLFirst(t *testing.T) {
	f := newFixture(t)
	ttl := uint32(300)
	f.sets = map[string]rrset{"www/A": {Name: "www", Type: "A", TTL: &ttl, Records: []value{{Value: "192.0.2.1"}}}}
	before := readRecords(t, f)[0]
	after := before
	after.Value, after.TTL = "192.0.2.9", 600
	stored, err := f.p.UpdateRecord(context.Background(), testZone, before, after)
	if err != nil || stored.TTL != 600 {
		t.Fatalf("update=%+v,%v writes=%v", stored, err, f.writes)
	}
	if want := []string{"POST /zones/1/rrsets/www/A/actions/change_ttl", "POST /zones/1/rrsets/www/A/actions/add_records", "POST /zones/1/rrsets/www/A/actions/remove_records"}; !slices.Equal(f.writes, want) {
		t.Fatalf("writes=%v, want %v", f.writes, want)
	}
}

func TestConcurrentChangesetsOnOneRRsetKeepEachOthersValues(t *testing.T) {
	add := func(v string) dnsprovider.Change {
		return dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "_acme-challenge.example.com", Value: v, TTL: 60}}
	}
	for _, tc := range []struct {
		name      string
		existing  []value
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
			want:      []string{`"a"`, `"b"`},
		},
		{
			name:     "an addition and a deletion of the last value",
			existing: []value{{Value: `"old"`}},
			changes: func(existing []dnsprovider.Record) [][]dnsprovider.Change {
				return [][]dnsprovider.Change{{add("new")}, {{Kind: dnsprovider.ChangeDelete, Before: existing[0]}}}
			},
			// Apply re-reads before a deletion.
			snapshots: 3,
			want:      []string{`"new"`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.sets = map[string]rrset{}
			if tc.existing != nil {
				ttl := uint32(60)
				f.sets["_acme-challenge/TXT"] = rrset{Name: "_acme-challenge", Type: "TXT", TTL: &ttl, Records: tc.existing}
			}
			changesets := tc.changes(readRecords(t, f))
			f.holdWritesUntil(tc.snapshots)

			var wg sync.WaitGroup
			results := make([]dnsprovider.ApplyResult, len(changesets))
			errs := make([]error, len(changesets))
			for i, changes := range changesets {
				wg.Go(func() {
					results[i], errs[i] = dnsprovider.Apply(context.Background(), f.p, dnsprovider.Changeset{Zone: testZone, Changes: changes})
				})
			}
			wg.Wait()

			for i := range changesets {
				if errs[i] != nil || results[i].Results[0].Err != nil {
					t.Errorf("Apply %d = %+v, %v", i, results[i], errs[i])
				}
			}
			var got []string
			for _, r := range readRecords(t, f) {
				got = append(got, r.Value)
			}
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("stored %v, want %v; writes=%v", got, tc.want, f.writes)
			}
		})
	}
}

func TestReadBackIgnoresValuesAnotherWriterAdded(t *testing.T) {
	f := newFixture(t)
	f.onWrite = func(f *fixture) {
		s := f.sets["www/A"]
		s.Records = append(slices.Clone(s.Records), value{Value: "192.0.2.77"})
		f.sets["www/A"] = s
	}
	r, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.3", TTL: 300})
	if err != nil || r.Value != "192.0.2.3" {
		t.Fatalf("create=%+v,%v", r, err)
	}
}

func TestReadBackMissingAnAddedValueIsAnUnconfirmedConflict(t *testing.T) {
	f := newFixture(t)
	f.acknowledgeOnly = true
	_, err := f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.3", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrConflict) || !errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("lost write=%v", err)
	}
}

func TestPerValueWriteErrorsMapToTheCommonSentinels(t *testing.T) {
	for _, tc := range []struct {
		action, code string
		want         error
	}{
		// Assumed: Hetzner does not document how add_records answers a
		// value the RRset holds, nor remove_records one it does not.
		{"add_records", "uniqueness_error", dnsprovider.ErrConflict},
		{"remove_records", "not_found", dnsprovider.ErrNotFound},
	} {
		t.Run(tc.action, func(t *testing.T) {
			f := newFixture(t)
			f.failPath, f.failCode = tc.action, tc.code
			var err error
			if tc.action == "add_records" {
				_, err = f.p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.3", TTL: 300})
			} else {
				err = f.p.DeleteRecord(context.Background(), testZone, readRecords(t, f)[0])
			}
			if !errors.Is(err, tc.want) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("%s=%v, want %v", tc.action, err, tc.want)
			}
		})
	}
}

func TestMoveToAnRRsetAnotherWriterCreatedAddsToIt(t *testing.T) {
	f := newFixture(t)
	before := recordValue(readRecords(t, f), "192.0.2.1")
	after := before
	after.Name = "moved.example.com"
	f.onWrite = func(f *fixture) {
		f.sets["moved/A"] = rrset{Name: "moved", Type: "A", Records: []value{{Value: "192.0.2.50"}}}
	}
	if _, err := f.p.UpdateRecord(context.Background(), testZone, before, after); err != nil {
		t.Fatal(err)
	}
	if want := []string{"POST /zones/1/rrsets", "POST /zones/1/rrsets/moved/A/actions/add_records", "POST /zones/1/rrsets/www/A/actions/remove_records"}; !slices.Equal(f.writes, want) {
		t.Fatalf("writes=%v, want %v", f.writes, want)
	}
	if got := f.sets["moved/A"]; len(got.Records) != 2 {
		t.Fatalf("destination=%+v, want both values", got)
	}
}
