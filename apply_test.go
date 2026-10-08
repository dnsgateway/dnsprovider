package dnsprovider_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

var applyZone = dnsprovider.Zone{ID: "z1", Name: "example.com"}

// build builds a Provider from a fake.
func build(t *testing.T, fake *providertest.Provider) dnsprovider.Provider {
	t.Helper()

	p, err := fake.Factory().New(map[string]string{"token": "t"})
	if err != nil {
		t.Fatal(err)
	}

	return p
}

// ops are the write operations recorded on a fake, in order.
func ops(fake *providertest.Provider) []providertest.Op {
	var out []providertest.Op

	for _, c := range fake.Calls() {
		switch c.Op {
		case providertest.OpCreateRecord, providertest.OpUpdateRecord, providertest.OpDeleteRecord, providertest.OpApply:
			out = append(out, c.Op)
		}
	}

	return out
}

func TestApplyWithoutABatcherDeletesThenModifiesThenAdds(t *testing.T) {
	www := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	old := dnsprovider.Record{ID: "r2", Type: "TXT", Name: "example.com", Value: "old", TTL: 300}
	fake := providertest.New().AddZone(applyZone, www, old)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "api.example.com", Value: "192.0.2.9", TTL: 300}}
	edited := www
	edited.Value = "192.0.2.2"
	modify := dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: www, After: edited}
	del := dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: old}

	res, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{add, modify, del}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	want := []providertest.Op{providertest.OpDeleteRecord, providertest.OpUpdateRecord, providertest.OpCreateRecord}
	if got := ops(fake); !equalOps(got, want) {
		t.Errorf("calls = %v, want %v", got, want)
	}

	if len(res.Results) != 3 {
		t.Fatalf("results = %+v, want 3 in Changeset order", res.Results)
	}

	for i, c := range []dnsprovider.Change{add, modify, del} {
		r := res.Results[i]
		if r.Err != nil || r.Change.Kind != c.Kind {
			t.Errorf("result %d = %+v, want %v confirmed", i, r, c.Kind)
		}
	}

	if r := res.Results[0].Record; r.ID == "" || r.Value != "192.0.2.9" {
		t.Errorf("added Record = %+v, want it as stored with an ID", r)
	}

	if r := res.Results[1].Record; r.ID != "r1" || r.Value != "192.0.2.2" {
		t.Errorf("modified Record = %+v, want r1 with the new Value", r)
	}

	if r := res.Results[2].Record; r.ID != "" || r.Type != "" {
		t.Errorf("deleted Record = %+v, want none", r)
	}
}

func equalOps(a, b []providertest.Op) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func TestApplyWithoutABatcherGoesOnPastAFailedChange(t *testing.T) {
	www := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	api := dnsprovider.Record{ID: "r2", Type: "A", Name: "api.example.com", Value: "192.0.2.5", TTL: 300}
	fake := providertest.New().AddZone(applyZone, www, api)
	boom := errors.New("boom")
	fake.Fail(providertest.OpDeleteRecord, boom)
	edited := www
	edited.TTL = 600

	// The modification of api fails as one the Provider no longer finds
	// would, after the re-check.
	fake.FailChanges(func(c dnsprovider.Change) error {
		if c.Before.ID == "r2" {
			return fmt.Errorf("fake: %w", dnsprovider.ErrNotFound)
		}

		return nil
	})

	res, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeDelete, Before: www},
		{Kind: dnsprovider.ChangeModify, Before: api, After: api},
		{Kind: dnsprovider.ChangeModify, Before: www, After: edited},
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !errors.Is(res.Results[0].Err, boom) {
		t.Errorf("failed deletion: err = %v, want %v", res.Results[0].Err, boom)
	}

	if !errors.Is(res.Results[1].Err, dnsprovider.ErrNotFound) {
		t.Errorf("modification the Provider no longer finds: err = %v, want ErrNotFound", res.Results[1].Err)
	}

	if r := res.Results[2]; r.Err != nil || r.Record.TTL != 600 {
		t.Errorf("modification after the failures = %+v, want it made", r)
	}
}

func TestApplyGoesThroughTheBatcherWhenThereIsOne(t *testing.T) {
	fake := providertest.New().AddZone(applyZone).SetSerial("z1", 4)
	fake.SetBatcher(true)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{add}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got, want := ops(fake), []providertest.Op{providertest.OpApply}; !equalOps(got, want) {
		t.Errorf("calls = %v, want %v", got, want)
	}

	if len(res.Results) != 1 || res.Results[0].Err != nil || res.Serial != 5 {
		t.Errorf("result = %+v, want the addition confirmed with serial 5", res)
	}
}

func TestApplyReturnsABatchersWholeChangesetFailure(t *testing.T) {
	fake := providertest.New().AddZone(applyZone)
	fake.SetBatcher(true)
	boom := errors.New("boom")
	fake.Fail(providertest.OpApply, boom)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}}

	if _, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{add}}); !errors.Is(err, boom) {
		t.Errorf("Apply: err = %v, want %v", err, boom)
	}
}

func TestApplyOrderIsDeletionsThenModificationsThenAdditionsEachInChangesetOrder(t *testing.T) {
	changes := []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd},
		{Kind: dnsprovider.ChangeModify},
		{Kind: dnsprovider.ChangeDelete},
		{Kind: dnsprovider.ChangeAdd},
		{Kind: dnsprovider.ChangeDelete},
		{Kind: dnsprovider.ChangeModify},
	}

	if got, want := dnsprovider.ApplyOrder(changes), []int{2, 4, 1, 5, 0, 3}; !slices.Equal(got, want) {
		t.Errorf("ApplyOrder = %v, want %v", got, want)
	}
}

func TestApplyWithoutABatcherFailsAsAWholeWhenTheProviderHasNoTenant(t *testing.T) {
	www := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	fake := providertest.New().AddZone(applyZone, www)
	fake.Fail(providertest.OpDeleteRecord, fmt.Errorf("fake: %w", dnsprovider.ErrNoTenant))

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "api.example.com", Value: "192.0.2.9", TTL: 300}}
	del := dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: www}

	if _, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{add, del}}); !errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Errorf("Apply: err = %v, want ErrNoTenant for the whole Changeset", err)
	}

	if got, want := ops(fake), []providertest.Op{providertest.OpDeleteRecord}; !equalOps(got, want) {
		t.Errorf("calls = %v, want %v: nothing tried after the Provider said it has no Tenant", got, want)
	}
}

func TestApplyRefusesAChangesetWhoseBeforeChangedOrIsGoneAndWritesNothing(t *testing.T) {
	for _, batcher := range []bool{false, true} {
		t.Run(fmt.Sprintf("batcher=%v", batcher), func(t *testing.T) {
			www := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
			txt := dnsprovider.Record{ID: "r2", Type: "TXT", Name: "example.com", Value: "v=spf1 -all", TTL: 300}
			mail := dnsprovider.Record{ID: "r3", Type: "MX", Name: "example.com", Value: "10 mail.example.com", TTL: 300}
			fake := providertest.New().AddZone(applyZone, www, txt, mail)
			fake.SetBatcher(batcher)

			// The Changeset was built from a www and a gone Record that the
			// Provider no longer holds as they were.
			builtFrom := www
			builtFrom.Value = "192.0.2.9"
			gone := dnsprovider.Record{ID: "r9", Type: "A", Name: "old.example.com", Value: "192.0.2.7", TTL: 300}
			edited := builtFrom
			edited.Value = "192.0.2.2"
			changes := []dnsprovider.Change{
				{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "api.example.com", Value: "192.0.2.3", TTL: 300}},
				{Kind: dnsprovider.ChangeModify, Before: builtFrom, After: edited},
				{Kind: dnsprovider.ChangeDelete, Before: txt},
				{Kind: dnsprovider.ChangeDelete, Before: gone},
			}

			_, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: changes})
			if !errors.Is(err, dnsprovider.ErrStale) {
				t.Fatalf("Apply: err = %v, want ErrStale", err)
			}

			var stale *dnsprovider.StaleError
			if !errors.As(err, &stale) {
				t.Fatalf("Apply: err = %#v, want a *StaleError", err)
			}

			want := []dnsprovider.StaleChange{
				{Change: changes[1], Now: www},
				{Change: changes[3]},
			}
			if len(stale.Changes) != len(want) {
				t.Fatalf("stale changes = %+v, want %+v", stale.Changes, want)
			}

			for i, s := range stale.Changes {
				if s.Change.Before.ID != want[i].Change.Before.ID || s.Change.Kind != want[i].Change.Kind || s.Now.ID != want[i].Now.ID || s.Now.Value != want[i].Now.Value {
					t.Errorf("stale change %d = %+v, want %+v", i, s, want[i])
				}
			}

			if got := ops(fake); len(got) != 0 {
				t.Errorf("writes = %v, want none", got)
			}
		})
	}
}

// reads are the Records reads recorded on a fake, by their filters.
func reads(fake *providertest.Provider) []dnsprovider.RecordFilter {
	var out []dnsprovider.RecordFilter

	for _, c := range fake.Calls() {
		if c.Op == providertest.OpRecords {
			out = append(out, c.RecordFilter)
		}
	}

	return out
}

func TestApplyReReadsTheRecordsItTouchesByTypeWhenTheyShareOne(t *testing.T) {
	www := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	api := dnsprovider.Record{ID: "r2", Type: "a", Name: "api.example.com", Value: "192.0.2.2", TTL: 300}
	txt := dnsprovider.Record{ID: "r3", Type: "TXT", Name: "example.com", Value: "v=spf1 -all", TTL: 300}

	edited := www
	edited.Type, edited.Value = "CNAME", "shop.example.net"

	for _, tc := range []struct {
		name    string
		changes []dnsprovider.Change
		want    []dnsprovider.RecordFilter
	}{
		{
			// A modification is re-read by the type it was built from.
			name: "one type",
			changes: []dnsprovider.Change{
				{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "example.com", Value: "hello", TTL: 300}},
				{Kind: dnsprovider.ChangeModify, Before: www, After: edited},
				{Kind: dnsprovider.ChangeDelete, Before: api},
			},
			want: []dnsprovider.RecordFilter{{Type: "A"}},
		},
		{
			name: "two types",
			changes: []dnsprovider.Change{
				{Kind: dnsprovider.ChangeDelete, Before: www},
				{Kind: dnsprovider.ChangeDelete, Before: txt},
			},
			want: []dnsprovider.RecordFilter{{}},
		},
		{
			name: "additions only",
			changes: []dnsprovider.Change{
				{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new.example.com", Value: "192.0.2.9", TTL: 300}},
			},
		},
	} {
		for _, batcher := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/batcher=%v", tc.name, batcher), func(t *testing.T) {
				fake := providertest.New().AddZone(applyZone, www, api, txt)
				fake.SetBatcher(batcher)

				res, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: tc.changes})
				if err != nil {
					t.Fatalf("Apply: %v", err)
				}

				for i, r := range res.Results {
					if r.Err != nil {
						t.Errorf("result %d: %v", i, r.Err)
					}
				}

				if got := reads(fake); !slices.Equal(got, tc.want) {
					t.Errorf("reads = %+v, want %+v", got, tc.want)
				}
			})
		}
	}
}

func TestApplyTakesARecordAsStaleWhenItsTTLOrExtrasChangedButNotForAProxyFlagOff(t *testing.T) {
	read := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}

	for _, tc := range []struct {
		name  string
		now   func(r dnsprovider.Record) dnsprovider.Record
		stale bool
	}{
		{"TTL", func(r dnsprovider.Record) dnsprovider.Record { r.TTL = 600; return r }, true},
		{"proxied", func(r dnsprovider.Record) dnsprovider.Record {
			r.Extras = map[string]string{dnsprovider.ExtraProxied: "true"}
			return r
		}, true},
		{"proxy flag off", func(r dnsprovider.Record) dnsprovider.Record {
			r.Extras = map[string]string{dnsprovider.ExtraProxied: "false"}
			return r
		}, false},
		{"name case and trailing dot", func(r dnsprovider.Record) dnsprovider.Record { r.Name = "WWW.example.com."; return r }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := providertest.New().AddZone(applyZone, tc.now(read))

			_, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{
				{Kind: dnsprovider.ChangeDelete, Before: read},
			}})
			if got := errors.Is(err, dnsprovider.ErrStale); got != tc.stale {
				t.Errorf("Apply: err = %v, want stale %v", err, tc.stale)
			}
		})
	}
}

func TestApplyFailsWithoutWritingWhenTheReCheckCannotRead(t *testing.T) {
	www := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	fake := providertest.New().AddZone(applyZone, www)
	fake.Fail(providertest.OpRecords, fmt.Errorf("fake: %w", dnsprovider.ErrNoTenant))

	_, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeDelete, Before: www},
	}})
	if !errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Errorf("Apply: err = %v, want the read's ErrNoTenant", err)
	}

	if got := ops(fake); len(got) != 0 {
		t.Errorf("writes = %v, want none", got)
	}
}

// staleNow applies a Changeset to a fake holding records and returns the
// Now of each stale change, failing the test when Apply is not refused.
func staleNow(t *testing.T, fake *providertest.Provider, changes ...dnsprovider.Change) []dnsprovider.Record {
	t.Helper()

	_, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: changes})

	var stale *dnsprovider.StaleError
	if !errors.As(err, &stale) {
		t.Fatalf("Apply: err = %v, want a *StaleError", err)
	}

	now := make([]dnsprovider.Record, len(stale.Changes))
	for i, s := range stale.Changes {
		now[i] = s.Now
	}

	return now
}

func TestApplyFindsABeforeWithoutAnIDByItsTypeNameAndValue(t *testing.T) {
	www := dnsprovider.Record{ID: "A www.example.com 300 192.0.2.1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	other := dnsprovider.Record{ID: "A www.example.com 300 192.0.2.2", Type: "A", Name: "www.example.com", Value: "192.0.2.2", TTL: 300}

	// Built without a read: no ID, the name in another case.
	before := dnsprovider.Record{Type: "a", Name: "WWW.example.com.", Value: "192.0.2.1", TTL: 300}

	fake := providertest.New().AddZone(applyZone, other, www)

	_, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeDelete, Before: before},
	}})
	if errors.Is(err, dnsprovider.ErrStale) {
		t.Fatalf("Apply: err = %v, want the Record found by its content", err)
	}

	// Its TTL changed since: stale, and Now is the Record as it is.
	longer := www
	longer.TTL, longer.ID = 600, "A www.example.com 600 192.0.2.1"

	now := staleNow(t, providertest.New().AddZone(applyZone, other, longer), dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: before})
	if len(now) != 1 || now[0].ID != longer.ID {
		t.Errorf("Now = %+v, want %+v", now, longer)
	}
}

// keyed is a Record with an ID built from its content, as GoDaddy and
// Namecheap key theirs.
func keyed(typ, name, value string, ttl uint32) dnsprovider.Record {
	return dnsprovider.Record{ID: fmt.Sprintf("%s %s %d %s", typ, name, ttl, value), Type: typ, Name: name, Value: value, TTL: ttl}
}

func TestApplyNamesWhatAContentKeyedRecordBecameWhenItsIDIsGone(t *testing.T) {
	read := keyed("A", "www.example.com", "192.0.2.1", 300)
	del := func(b dnsprovider.Record) dnsprovider.Change {
		return dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: b}
	}
	api := keyed("A", "api.example.com", "192.0.2.1", 300)

	for _, tc := range []struct {
		name    string
		live    []dnsprovider.Record
		changes []dnsprovider.Change
		want    []string // the IDs of the stale changes' Nows
	}{
		{"its TTL changed", []dnsprovider.Record{api, keyed("A", "www.example.com", "192.0.2.1", 600)}, []dnsprovider.Change{del(read)}, []string{"A www.example.com 600 192.0.2.1"}},
		{"its Value changed", []dnsprovider.Record{api, keyed("A", "www.example.com", "192.0.2.5", 300)}, []dnsprovider.Change{del(read)}, []string{"A www.example.com 300 192.0.2.5"}},
		{"its TTL changed beside another Value", []dnsprovider.Record{keyed("A", "www.example.com", "192.0.2.2", 600), keyed("A", "www.example.com", "192.0.2.1", 600)}, []dnsprovider.Change{del(read)}, []string{"A www.example.com 600 192.0.2.1"}},
		// Either could be what it became: it is reported gone.
		{"its RRset holds two other Values", []dnsprovider.Record{keyed("A", "www.example.com", "192.0.2.2", 300), keyed("A", "www.example.com", "192.0.2.3", 300)}, []dnsprovider.Change{del(read)}, []string{""}},
		// The other Value is one the Changeset was built from as it is.
		{"the other Value is the Changeset's", []dnsprovider.Record{keyed("A", "www.example.com", "192.0.2.2", 300)}, []dnsprovider.Change{del(read), del(keyed("A", "www.example.com", "192.0.2.2", 300))}, []string{""}},
		{"no Record of its type and name", []dnsprovider.Record{api}, []dnsprovider.Change{del(read)}, []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := staleNow(t, providertest.New().AddZone(applyZone, tc.live...), tc.changes...)

			got := make([]string, len(now))
			for i, r := range now {
				got[i] = r.ID
			}

			if !slices.Equal(got, tc.want) {
				t.Errorf("Now IDs = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestApplyNamesARecordWhoseTypeChangedUnderItsID(t *testing.T) {
	read := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	now := dnsprovider.Record{ID: "r1", Type: "CNAME", Name: "www.example.com", Value: "shop.example.net", TTL: 300}
	fake := providertest.New().AddZone(applyZone, now)

	got := staleNow(t, fake, dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: read})
	if len(got) != 1 || got[0].ID != "r1" || got[0].Type != "CNAME" {
		t.Errorf("Now = %+v, want %+v", got, now)
	}

	// The read by type misses it; the whole Zone is read for it.
	if got, want := reads(fake), []dnsprovider.RecordFilter{{Type: "A"}, {}}; !slices.Equal(got, want) {
		t.Errorf("reads = %+v, want %+v", got, want)
	}
}

func TestApplyReChecksAChangeOfNoKnownKindBuiltFromARecord(t *testing.T) {
	read := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
	now := read
	now.TTL = 600

	got := staleNow(t, providertest.New().AddZone(applyZone, now), dnsprovider.Change{Kind: 99, Before: read, After: read})
	if len(got) != 1 || got[0].TTL != 600 {
		t.Errorf("Now = %+v, want %+v", got, now)
	}
}
