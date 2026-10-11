package cloudns_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestApplyRejectsStaleModificationsAndDeletionsWithoutWrites(t *testing.T) {
	for _, kind := range []dnsprovider.ChangeKind{dnsprovider.ChangeModify, dnsprovider.ChangeDelete} {
		state, p := fixture(t)
		ctx := context.Background()
		rs, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
		if err != nil {
			t.Fatal(err)
		}
		before := rs.Records[0]
		before.Value = "192.0.2.99"
		_, err = dnsprovider.Apply(ctx, p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: kind, Before: before, After: before}, {Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new.example.com", Value: "192.0.2.9", TTL: 300}}}})
		if !errors.Is(err, dnsprovider.ErrStale) {
			t.Fatal(err)
		}
		state.Lock()
		if len(state.writes) != 0 {
			t.Error(state.writes)
		}
		state.Unlock()
	}
}

func TestApplyUsesCRUDOrderAndKeepsOriginalResultOrder(t *testing.T) {
	for _, fail := range []bool{false, true} {
		state, p := fixture(t)
		ctx := context.Background()
		rs, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
		if err != nil {
			t.Fatal(err)
		}
		after := rs.Records[0]
		after.Value = "192.0.2.8"
		cs := dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "new.example.com", Value: "192.0.2.9", TTL: 300}}, {Kind: dnsprovider.ChangeModify, Before: rs.Records[0], After: after}, {Kind: dnsprovider.ChangeDelete, Before: rs.Records[1]}}}
		if fail {
			state.fail = "/dns/mod-record.json"
		}
		result, err := dnsprovider.Apply(ctx, p, cs)
		if err != nil || len(result.Results) != 3 {
			t.Fatalf("Apply = %+v, %v", result, err)
		}
		for i, res := range result.Results {
			if !reflect.DeepEqual(res.Change, cs.Changes[i]) {
				t.Fatal(result)
			}
			if i == 1 && fail {
				if !errors.Is(res.Err, dnsprovider.ErrUnauthorized) {
					t.Fatal(res)
				}
			} else if res.Err != nil {
				t.Fatal(res)
			}
		}
		state.Lock()
		if !reflect.DeepEqual(state.writes, []string{"/dns/delete-record.json", "/dns/mod-record.json", "/dns/add-record.json"}) {
			t.Error(state.writes)
		}
		state.Unlock()
	}
}
