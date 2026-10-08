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
	fake := providertest.New().AddZone(applyZone, www)
	boom := errors.New("boom")
	fake.Fail(providertest.OpDeleteRecord, boom)

	gone := dnsprovider.Record{ID: "r9", Type: "A", Name: "gone.example.com", Value: "192.0.2.7", TTL: 300}
	edited := www
	edited.TTL = 600

	res, err := dnsprovider.Apply(context.Background(), build(t, fake), dnsprovider.Changeset{Zone: applyZone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeDelete, Before: www},
		{Kind: dnsprovider.ChangeModify, Before: gone, After: gone},
		{Kind: dnsprovider.ChangeModify, Before: www, After: edited},
	}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if !errors.Is(res.Results[0].Err, boom) {
		t.Errorf("failed deletion: err = %v, want %v", res.Results[0].Err, boom)
	}

	if !errors.Is(res.Results[1].Err, dnsprovider.ErrNotFound) {
		t.Errorf("modification of a Record not there: err = %v, want ErrNotFound", res.Results[1].Err)
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
