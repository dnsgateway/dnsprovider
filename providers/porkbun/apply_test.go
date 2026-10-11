package porkbun_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestApplyRejectsStaleModificationsAndDeletionsBeforeWriting(t *testing.T) {
	for _, kind := range []dnsprovider.ChangeKind{dnsprovider.ChangeModify, dnsprovider.ChangeDelete} {
		t.Run(map[dnsprovider.ChangeKind]string{dnsprovider.ChangeModify: "modify", dnsprovider.ChangeDelete: "delete"}[kind], func(t *testing.T) {
			api, p := fixtureAPI(t)
			ctx := context.Background()
			z := dnsprovider.Zone{Name: "example.com"}
			rs, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
			if err != nil {
				t.Fatal(err)
			}
			stale := rs.Records[0]
			stale.TTL = 1200
			_, err = dnsprovider.Apply(ctx, p, dnsprovider.Changeset{Zone: z, Changes: []dnsprovider.Change{
				{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.9", TTL: 600}},
				{Kind: kind, Before: stale, After: rs.Records[0]},
			}})
			if !errors.Is(err, dnsprovider.ErrStale) {
				t.Fatalf("Apply error=%v", err)
			}
			api.mu.Lock()
			defer api.mu.Unlock()
			if len(api.writes) != 0 {
				t.Fatalf("stale changeset wrote %v", api.writes)
			}
		})
	}
}

func TestApplyReportsOriginalOrderAndPartialFailures(t *testing.T) {
	api, p := fixtureAPI(t)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	rs, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	api.mu.Lock()
	api.fail = "edit"
	api.mu.Unlock()
	changes := []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.9", TTL: 600}},
		{Kind: dnsprovider.ChangeModify, Before: rs.Records[0], After: dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:db8::1", TTL: 600}},
		{Kind: dnsprovider.ChangeDelete, Before: rs.Records[1]},
	}
	result, err := dnsprovider.Apply(ctx, p, dnsprovider.Changeset{Zone: z, Changes: changes})
	if err != nil || len(result.Results) != 3 {
		t.Fatalf("Apply=%+v,%v", result, err)
	}
	if result.Results[0].Record.ID == "" || result.Results[0].Err != nil || result.Results[1].Err == nil || result.Results[2].Err != nil {
		t.Fatalf("results=%+v", result.Results)
	}
	for i, r := range result.Results {
		if r.Change.Kind != changes[i].Kind {
			t.Error("result order differs from Changeset")
		}
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if !slices.Equal(api.writes, []string{"delete", "edit", "create"}) {
		t.Fatalf("mutation order=%v", api.writes)
	}
}
