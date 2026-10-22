package infomaniak_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

const updateKey = "PUT /2/zones/example.ch/records/22585703"

func TestUpdateRecordInPlaceSendsOnePutAndReturnsTheStoredRecord(t *testing.T) {
	f := newFake(t)
	f.script(updateKey, http.StatusOK, fixture(t, "record_updated.json"))

	after := heldRecord
	after.Value, after.TTL = "192.0.2.11", 600

	got, err := f.provider().UpdateRecord(context.Background(), exampleCH, heldRecord, after)
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Record{ID: "22585703", Type: "A", Name: "test.example.ch", Value: "192.0.2.11", TTL: 600}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UpdateRecord = %+v, want %+v", got, want)
	}

	bodies := f.sent(updateKey)
	if len(bodies) != 1 {
		t.Fatalf("sent %d PUTs, want 1", len(bodies))
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(bodies[0]), &body); err != nil {
		t.Fatal(err)
	}

	if wantBody := map[string]any{"target": "192.0.2.11", "ttl": 600.0}; !reflect.DeepEqual(body, wantBody) {
		t.Fatalf("PUT body = %v, want %v", body, wantBody)
	}

	if n := len(f.sent(createKey)) + len(f.sent(deleteKey)); n != 0 {
		t.Fatalf("sent %d creates or deletes, want none", n)
	}
}

func TestUpdateRecordWithAnUnknownOutcomeIsUnconfirmed(t *testing.T) {
	for name, replies := range map[string][]int{
		"lost answer": {lost},
		"5xx":         {http.StatusInternalServerError, http.StatusInternalServerError, http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			for _, status := range replies {
				f.script(updateKey, status, fixture(t, "cannot_update_object.json"))
			}

			after := heldRecord
			after.TTL = 600

			if _, err := f.provider().UpdateRecord(context.Background(), exampleCH, heldRecord, after); !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("UpdateRecord = %v, want ErrUnconfirmed", err)
			}
		})
	}
}

func TestUpdateRecordOfARecordNoLongerHeldIsErrNotFoundWithoutAWrite(t *testing.T) {
	f := newFake(t)

	before := heldRecord
	before.ID = "99"

	after := before
	after.TTL = 600

	if _, err := f.provider().UpdateRecord(context.Background(), exampleCH, before, after); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("UpdateRecord = %v, want ErrNotFound", err)
	}

	if n := len(f.writeLog()); n != 0 {
		t.Fatalf("sent %d writes, want none", n)
	}
}

// moved is heldRecord moved to another name.
var moved = dnsprovider.Record{ID: "22585703", Type: "A", Name: "new.example.ch", Value: "192.0.2.10", TTL: 3600}

// writeLog is every write the fake received, as "METHOD path", in order.
func (f *fake) writeLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []string

	for _, r := range f.requests {
		if r.Method != http.MethodGet {
			out = append(out, r.Method+" "+r.URL.Path)
		}
	}

	return out
}

func TestUpdateRecordMoveCreatesThenDeletes(t *testing.T) {
	for name, tc := range map[string]struct {
		after   dnsprovider.Record
		created string
		want    dnsprovider.Record
	}{
		"another name": {
			after: moved, created: fixture(t, "record_created.json"),
			want: dnsprovider.Record{ID: "32824", Type: "A", Name: "new.example.ch", Value: "192.0.2.10", TTL: 3600},
		},
		"another type": {
			after:   dnsprovider.Record{Type: "TXT", Name: "test.example.ch", Value: "hello", TTL: 3600},
			created: `{"result":"success","data":{"id":32825,"source":"test","type":"TXT","ttl":3600,"target":"hello","updated_at":1779826643}}`,
			want:    dnsprovider.Record{ID: "32825", Type: "TXT", Name: "test.example.ch", Value: "hello", TTL: 3600},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.script(createKey, http.StatusOK, tc.created)
			f.script(deleteKey, http.StatusOK, fixture(t, "record_deleted.json"))

			got, err := f.provider().UpdateRecord(context.Background(), exampleCH, heldRecord, tc.after)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("UpdateRecord = %+v, want %+v", got, tc.want)
			}

			if writes, want := f.writeLog(), []string{createKey, deleteKey}; !reflect.DeepEqual(writes, want) {
				t.Fatalf("writes = %q, want %q", writes, want)
			}
		})
	}
}

func TestUpdateRecordMoveWhoseCreateIsRefusedLeavesTheOriginal(t *testing.T) {
	f := newFake(t)
	f.script(createKey, http.StatusBadRequest, fixture(t, "invalid_dns_record.json"))

	_, err := f.provider().UpdateRecord(context.Background(), exampleCH, heldRecord, moved)

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("UpdateRecord = %v, want the create's refusal", err)
	}

	if writes, want := f.writeLog(), []string{createKey}; !reflect.DeepEqual(writes, want) {
		t.Fatalf("writes = %q, want %q", writes, want)
	}
}

func TestUpdateRecordMoveWhoseDeleteFailsReportsBothHalves(t *testing.T) {
	f := newFake(t)
	f.script(createKey, http.StatusOK, fixture(t, "record_created.json"))
	f.script(deleteKey, lost, "")

	got, err := f.provider().UpdateRecord(context.Background(), exampleCH, heldRecord, moved)
	if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("UpdateRecord = %v, want the delete's ErrUnconfirmed", err)
	}

	if msg := err.Error(); got.ID != "32824" || !strings.Contains(msg, "Record 32824 was created") || !strings.Contains(msg, "Record 22585703 failed") {
		t.Fatalf("UpdateRecord = %+v, %v; want the created Record 32824 and the original's failed delete", got, err)
	}

	if writes, want := f.writeLog(), []string{createKey, deleteKey}; !reflect.DeepEqual(writes, want) {
		t.Fatalf("writes = %q, want %q: a move is not undone", writes, want)
	}
}

func TestUpdateRecordToARecordTheZoneHoldsIsErrConflictWithoutAWrite(t *testing.T) {
	f := newFake(t)

	// records.json holds * A 192.0.2.9.
	after := dnsprovider.Record{Type: "A", Name: "*.example.ch", Value: "192.0.2.9", TTL: 600}

	if _, err := f.provider().UpdateRecord(context.Background(), exampleCH, heldRecord, after); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("UpdateRecord = %v, want ErrConflict", err)
	}

	if n := len(f.writeLog()); n != 0 {
		t.Fatalf("sent %d writes, want none", n)
	}
}

// heldByID is the Record of the ID the fake's Zone holds.
func heldByID(t *testing.T, p dnsprovider.Provider, id string) dnsprovider.Record {
	t.Helper()

	set, err := p.ListRecords(context.Background(), exampleCH, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range set.Records {
		if r.ID == id {
			return r
		}
	}

	t.Fatalf("the Zone holds no Record %s", id)

	return dnsprovider.Record{}
}

func TestApplyWithAStaleChangesetSendsNoWrite(t *testing.T) {
	f := newFake(t)

	stale := heldRecord
	stale.TTL = 600

	after := stale
	after.Value = "192.0.2.11"

	_, err := dnsprovider.Apply(context.Background(), f.provider(), dnsprovider.Changeset{Zone: exampleCH, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: newRecord},
		{Kind: dnsprovider.ChangeModify, Before: stale, After: after},
	}})
	if !errors.Is(err, dnsprovider.ErrStale) {
		t.Fatalf("Apply = %v, want ErrStale", err)
	}

	if n := len(f.writeLog()); n != 0 {
		t.Fatalf("sent %d writes, want none", n)
	}
}

func TestApplyOverCRUDReturnsPerChangeResultsInOrder(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	mx := heldByID(t, p, "22592805")
	caa := heldByID(t, p, "22592561")

	retimed := heldRecord
	retimed.Value, retimed.TTL = "192.0.2.11", 600

	mxKey := "DELETE /2/zones/example.ch/records/22592805"

	f.script(mxKey, http.StatusOK, fixture(t, "record_deleted.json"))
	f.script(updateKey, http.StatusOK, fixture(t, "record_updated.json"))
	f.script(createKey, http.StatusOK, fixture(t, "record_created.json"))

	changes := []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: newRecord},
		{Kind: dnsprovider.ChangeModify, Before: heldRecord, After: retimed},
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "CAA", Name: "@", Value: caa.Value, TTL: 300}},
		{Kind: dnsprovider.ChangeDelete, Before: mx},
	}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: exampleCH, Changes: changes})
	if err != nil {
		t.Fatal(err)
	}

	want := []struct {
		id       string
		conflict bool
	}{{id: "32824"}, {id: "22585703"}, {conflict: true}, {}}

	if len(res.Results) != len(want) {
		t.Fatalf("Apply returned %d results, want %d", len(res.Results), len(want))
	}

	for i, w := range want {
		got := res.Results[i]
		if !reflect.DeepEqual(got.Change, changes[i]) || got.Record.ID != w.id || errors.Is(got.Err, dnsprovider.ErrConflict) != w.conflict || (got.Err != nil) != w.conflict {
			t.Errorf("result %d = %+v, want Record %q, ErrConflict %v", i, got, w.id, w.conflict)
		}
	}

	// Apply deletes, then modifies, then adds.
	if writes, wantWrites := f.writeLog(), []string{mxKey, updateKey, createKey}; !reflect.DeepEqual(writes, wantWrites) {
		t.Fatalf("writes = %q, want %q", writes, wantWrites)
	}
}
