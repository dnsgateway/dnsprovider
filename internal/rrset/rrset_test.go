package rrset_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/rrset"
)

// fake is an in-memory Adapter: it holds values by Key, records every
// Delta written, and fails the writes and read-back it is told to.
type fake struct {
	held     map[rrset.Key][]dnsprovider.Record
	writes   []rrset.Delta
	failKey  rrset.Key
	readFail error
	// drop makes writes acknowledged but not applied.
	drop bool
}

func (f *fake) Name() string { return "fake" }

func (f *fake) Normalize(r dnsprovider.Record, _ bool) (dnsprovider.Record, error) {
	r.Name = strings.ToLower(r.Name)

	return r, nil
}

func (f *fake) Same(_, a, b string) bool { return a == b }

func (f *fake) Writable(*rrset.Set) error { return nil }

func (f *fake) Wire(after dnsprovider.Record, _ *rrset.Value, _ *rrset.Set) any { return after.Value }

func (f *fake) Write(_ context.Context, d rrset.Delta) error {
	f.writes = append(f.writes, d)
	if d.Key == f.failKey {
		return errors.New("rejected")
	}

	if f.drop {
		return nil
	}

	rs := f.held[d.Key]
	if d.TTLChanged {
		for i := range rs {
			rs[i].TTL = d.TTL
		}
	}

	for _, v := range d.Add {
		rs = append(rs, v.Record)
	}

	rs = slices.DeleteFunc(rs, func(r dnsprovider.Record) bool {
		return slices.ContainsFunc(d.Remove, func(v rrset.Value) bool { return v.Record.Value == r.Value })
	})
	f.held[d.Key] = rs

	return nil
}

func (f *fake) ReadBack(context.Context, []rrset.Key) (dnsprovider.RecordSet, error) {
	if f.readFail != nil {
		return dnsprovider.RecordSet{}, f.readFail
	}

	var out []dnsprovider.Record
	for _, rs := range f.held {
		out = append(out, rs...)
	}

	return dnsprovider.RecordSet{Records: out}, nil
}

func (f *fake) sets() []rrset.Set {
	var out []rrset.Set

	for k, rs := range f.held {
		s := rrset.Set{Key: k, TTL: rs[0].TTL}
		for _, r := range rs {
			s.Values = append(s.Values, rrset.Value{Record: r, Wire: r.Value})
		}

		out = append(out, s)
	}

	return out
}

func a(name, value string, ttl uint32) dnsprovider.Record {
	return dnsprovider.Record{Type: "A", Name: name, Value: value, TTL: ttl}
}

func www() *fake {
	return &fake{held: map[rrset.Key][]dnsprovider.Record{
		{Name: "www.example.com", Type: "A"}: {a("www.example.com", "192.0.2.1", 300), a("www.example.com", "192.0.2.2", 300)},
	}}
}

func apply(t *testing.T, f *fake, changes ...dnsprovider.Change) dnsprovider.ApplyResult {
	t.Helper()

	res, err := rrset.Apply(context.Background(), f, dnsprovider.Changeset{Changes: changes}, f.sets())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	return res
}

func TestADeltaNamesOnlyTheValuesItsChangesTouch(t *testing.T) {
	f := www()
	res := apply(t, f,
		dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: a("www.example.com", "192.0.2.3", 300)},
		dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: a("www.example.com", "192.0.2.1", 300)},
	)

	if len(f.writes) != 1 {
		t.Fatalf("writes = %+v, want one Delta", f.writes)
	}

	d := f.writes[0]
	if len(d.Add) != 1 || d.Add[0].Record.Value != "192.0.2.3" || len(d.Remove) != 1 || d.Remove[0].Record.Value != "192.0.2.1" || d.TTLChanged {
		t.Errorf("Delta = %+v, want add .3 and remove .1 only", d)
	}

	if res.Results[0].Err != nil || res.Results[0].Record.Value != "192.0.2.3" || res.Results[1].Err != nil {
		t.Errorf("results = %+v", res.Results)
	}
}

func TestAChangeOfTheSharedTTLChangesItOnceForTheRRset(t *testing.T) {
	f := www()
	apply(t, f,
		dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: a("www.example.com", "192.0.2.1", 300), After: a("www.example.com", "192.0.2.1", 600)},
		dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: a("www.example.com", "192.0.2.2", 300), After: a("www.example.com", "192.0.2.2", 600)},
	)

	if len(f.writes) != 1 || !f.writes[0].TTLChanged || f.writes[0].TTL != 600 || len(f.writes[0].Add) != 0 || len(f.writes[0].Remove) != 0 {
		t.Errorf("writes = %+v, want one TTL change and no values", f.writes)
	}
}

func TestConflictingFinalTTLsFailTheWholePlanBeforeAnyWrite(t *testing.T) {
	f := www()

	_, err := rrset.Apply(context.Background(), f, dnsprovider.Changeset{Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: a("new.example.com", "192.0.2.9", 300)},
		{Kind: dnsprovider.ChangeModify, Before: a("www.example.com", "192.0.2.1", 300), After: a("www.example.com", "192.0.2.1", 600)},
	}}, f.sets())
	if err == nil || len(f.writes) != 0 {
		t.Errorf("Apply = %v, writes %+v; want a refusal and no write", err, f.writes)
	}
}

func TestAMissingBeforeOrADuplicateFailsAloneWithTheSentinel(t *testing.T) {
	f := www()
	res := apply(t, f,
		dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: a("www.example.com", "192.0.2.99", 300)},
		dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: a("www.example.com", "192.0.2.2", 300)},
		dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: a("www.example.com", "192.0.2.3", 300)},
	)

	if !errors.Is(res.Results[0].Err, dnsprovider.ErrNotFound) || !errors.Is(res.Results[1].Err, dnsprovider.ErrConflict) || res.Results[2].Err != nil {
		t.Errorf("results = %+v", res.Results)
	}
}

func TestAMoveAddsAtTheDestinationBeforeRemovingFromTheSource(t *testing.T) {
	f := www()
	res := apply(t, f, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: a("www.example.com", "192.0.2.1", 300), After: a("moved.example.com", "192.0.2.1", 300)})

	if len(f.writes) != 2 || f.writes[0].Key.Name != "moved.example.com" || f.writes[1].Key.Name != "www.example.com" {
		t.Errorf("writes = %+v, want the destination first", f.writes)
	}

	if res.Results[0].Err != nil || res.Results[0].Record.Name != "moved.example.com" {
		t.Errorf("result = %+v", res.Results[0])
	}
}

func TestAFailedWriteFailsItsGroupAndStopsIt(t *testing.T) {
	f := www()
	f.failKey = rrset.Key{Name: "moved.example.com", Type: "A"}
	res := apply(t, f,
		dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: a("www.example.com", "192.0.2.1", 300), After: a("moved.example.com", "192.0.2.1", 300)},
		dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: a("other.example.com", "192.0.2.5", 300)},
	)

	if len(f.writes) != 2 || f.writes[1].Key.Name != "other.example.com" {
		t.Errorf("writes = %+v, want the source left alone and the other group written", f.writes)
	}

	if err := res.Results[0].Err; err == nil || !strings.Contains(err.Error(), "partial side effects") {
		t.Errorf("move = %v, want a partial-side-effects error", err)
	}

	if res.Results[1].Err != nil {
		t.Errorf("other = %v", res.Results[1].Err)
	}
}

func TestAWriteTheReadBackMissesIsAConflict(t *testing.T) {
	f := www()
	f.drop = true
	res := apply(t, f, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: a("www.example.com", "192.0.2.3", 300)})

	if !errors.Is(res.Results[0].Err, dnsprovider.ErrConflict) {
		t.Errorf("result = %v, want ErrConflict", res.Results[0].Err)
	}
}

func TestAFailedReadBackIsUncertainNotAConflict(t *testing.T) {
	f := www()
	f.readFail = errors.New("timeout")
	res := apply(t, f, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: a("www.example.com", "192.0.2.3", 300)})

	err := res.Results[0].Err
	if err == nil || errors.Is(err, dnsprovider.ErrConflict) || !strings.Contains(err.Error(), "unconfirmed") {
		t.Errorf("result = %v, want an unconfirmed completion", err)
	}
}

func TestAChangeThatChangesNothingWritesNothing(t *testing.T) {
	f := www()
	r := a("www.example.com", "192.0.2.1", 300)
	res := apply(t, f, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: r, After: r})

	if len(f.writes) != 0 || res.Results[0].Err != nil || res.Results[0].Record.Value != r.Value {
		t.Errorf("writes = %+v, result = %+v", f.writes, res.Results[0])
	}
}
