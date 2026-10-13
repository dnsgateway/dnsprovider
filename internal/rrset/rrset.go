// Package rrset applies a Changeset to Providers that hold Records as
// RRsets and write single values: it plans each touched RRset's Delta,
// the values to add and to remove, from one read of the Zone, has the
// adapter write it, and checks the Changeset's own effects in what the
// adapter reads back (readback.Verify).
//
// A Delta names only the values its changes touch, so a concurrent write
// of other values of the same RRset survives. The RRset's TTL is shared by
// its values and stays last-writer-wins.
package rrset

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/readback"
)

// Key tells RRsets apart: the absolute owner name, lower-cased and
// without a trailing dot, and the upper-cased type.
type Key struct {
	Name, Type string
}

// KeyOf is the Key of the RRset a Record belongs to.
func KeyOf(r dnsprovider.Record) Key {
	return Key{Name: strings.ToLower(strings.TrimSuffix(r.Name, ".")), Type: strings.ToUpper(r.Type)}
}

func (k Key) String() string {
	return k.Name + " " + k.Type
}

// Value is one value of an RRset: the Record as the adapter reads it, and
// Wire, what the adapter needs to write or remove it, such as the value
// exactly as stored and its comment.
type Value struct {
	Record dnsprovider.Record
	Wire   any
}

// Set is an RRset as read: its shared TTL, its values, and Wire, what
// the adapter keeps of it, such as labels or protection.
type Set struct {
	Key    Key
	TTL    uint32
	Values []Value
	Wire   any
}

// Delta is what a Changeset changes in one RRset.
type Delta struct {
	Key Key
	// Set is the RRset as read; nil when it did not exist.
	Set *Set
	// TTL is the TTL every value left in the RRset shares; 0 when the
	// Changeset leaves none of them.
	TTL uint32
	// TTLChanged is set when the RRset existed and the values left in it
	// take another TTL: the RRset's TTL changes before values are added.
	TTLChanged bool
	// Add are the values to add, with the planned TTL.
	Add []Value
	// Remove are the values to remove, as read.
	Remove []Value
}

func (d Delta) empty() bool {
	return len(d.Add) == 0 && len(d.Remove) == 0 && !d.TTLChanged
}

// Adapter is what a Provider supplies to Apply.
type Adapter interface {
	// Name prefixes errors, such as "hetzner".
	Name() string
	// Normalize qualifies and canonicalizes a Record of the Zone, and
	// validates it when it is the After of a change.
	Normalize(r dnsprovider.Record, after bool) (dnsprovider.Record, error)
	// Same reports whether two values of a type are one resource record.
	Same(typ, a, b string) bool
	// Writable is an error for an RRset the Changeset may not change;
	// s is nil for an RRset that does not exist.
	Writable(s *Set) error
	// Wire is what the adapter writes for after: for a modification,
	// carrying what it keeps of from, the value it replaces, of fromSet.
	// from and fromSet are nil for an addition.
	Wire(after dnsprovider.Record, from *Value, fromSet *Set) any
	// Write makes a Delta: the TTL change, then the additions, then the
	// removals, so a modified RRset is never empty in between. It never
	// replaces or deletes the whole RRset to remove values.
	Write(ctx context.Context, d Delta) error
	// ReadBack reads the Records of the RRsets with keys after a write.
	ReadBack(ctx context.Context, keys []Key) (dnsprovider.RecordSet, error)
}

// Apply applies a Changeset to the RRsets read in sets. Changes are
// planned in dnsprovider.ApplyOrder: one built from a value the RRset no
// longer holds fails with ErrNotFound, and one that adds a value the
// RRset holds already with ErrConflict. A plan that leaves an RRset with
// values of different TTLs fails whole before any write.
//
// RRsets that a change moves a value between are written together, the
// ones that add first, and read back. A change fails with the first
// error of its group; after a write began the error says so, as the group
// may be partly applied. A read-back that misses this Changeset's own
// effects is an error matching ErrConflict.
func Apply(ctx context.Context, a Adapter, cs dnsprovider.Changeset, sets []Set) (dnsprovider.ApplyResult, error) {
	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}
	for i, c := range cs.Changes {
		res.Results[i].Change = c
	}

	p := newPlan(a, sets, len(cs.Changes))
	for _, i := range dnsprovider.ApplyOrder(cs.Changes) {
		res.Results[i].Err = p.change(i, cs.Changes[i])
	}

	deltas, err := p.deltas()
	if err != nil {
		return res, err
	}

	for _, group := range p.groups() {
		p.apply(ctx, group, deltas, &res)
	}

	return res, nil
}

type state struct {
	read    *Set
	final   []Value
	changes []int
}

type plan struct {
	a     Adapter
	sets  map[Key]*state
	order []Key
	// added are the Records the changes add, by change, as planned.
	added []dnsprovider.Record
	// link joins the RRsets one change touches into one group.
	link map[Key]Key
}

func newPlan(a Adapter, sets []Set, n int) *plan {
	p := &plan{a: a, sets: map[Key]*state{}, added: make([]dnsprovider.Record, n), link: map[Key]Key{}}
	for i := range sets {
		s := &sets[i]
		p.sets[s.Key] = &state{read: s, final: slices.Clone(s.Values)}
	}

	return p
}

func (p *plan) get(k Key) *state {
	s := p.sets[k]
	if s == nil {
		s = &state{}
		p.sets[k] = s
	}

	if !slices.Contains(p.order, k) {
		p.order = append(p.order, k)
	}

	return s
}

func (p *plan) find(s *state, r dnsprovider.Record) int {
	return slices.IndexFunc(s.final, func(v Value) bool { return p.a.Same(r.Type, v.Record.Value, r.Value) })
}

func (p *plan) change(i int, c dnsprovider.Change) error {
	if c.Kind != dnsprovider.ChangeAdd && c.Kind != dnsprovider.ChangeModify && c.Kind != dnsprovider.ChangeDelete {
		return fmt.Errorf("%s: unknown change kind %d", p.a.Name(), c.Kind)
	}

	var (
		source, target *state
		at             = -1
		from           *Value
		after          dnsprovider.Record
		sourceKey      Key
	)

	if c.Kind != dnsprovider.ChangeAdd {
		before, err := p.a.Normalize(c.Before, false)
		if err != nil {
			return err
		}

		sourceKey = KeyOf(before)
		source = p.get(sourceKey)

		if at = p.find(source, before); at < 0 {
			return fmt.Errorf("%s: %s %q is not in the RRset: %w", p.a.Name(), sourceKey, before.Value, dnsprovider.ErrNotFound)
		}

		if err := p.a.Writable(source.read); err != nil {
			return err
		}

		v := source.final[at]
		from = &v
	}

	if c.Kind != dnsprovider.ChangeDelete {
		var err error
		if after, err = p.a.Normalize(c.After, true); err != nil {
			return err
		}

		target = p.get(KeyOf(after))
		if err := p.a.Writable(target.read); err != nil {
			return err
		}

		if dup := p.find(target, after); dup >= 0 && (source != target || dup != at) {
			return fmt.Errorf("%s: %s %q is in the RRset already: %w", p.a.Name(), KeyOf(after), after.Value, dnsprovider.ErrConflict)
		}
	}

	if source != nil {
		source.final = slices.Delete(source.final, at, at+1)
		source.changes = append(source.changes, i)
	}

	if target != nil {
		var fromSet *Set
		if source != nil {
			fromSet = source.read
		}

		target.final = append(target.final, Value{Record: after, Wire: p.a.Wire(after, from, fromSet)})
		target.changes = append(target.changes, i)
		p.added[i] = after
	}

	if source != nil && target != nil {
		p.union(sourceKey, KeyOf(after))
	}

	return nil
}

func (p *plan) root(k Key) Key {
	for {
		up, ok := p.link[k]
		if !ok || up == k {
			return k
		}

		k = up
	}
}

func (p *plan) union(a, b Key) {
	if ra, rb := p.root(a), p.root(b); ra != rb {
		p.link[rb] = ra
	}
}

// deltas are the Deltas of the touched RRsets, or an error when one would
// leave values of different TTLs.
func (p *plan) deltas() (map[Key]Delta, error) {
	out := map[Key]Delta{}

	for _, k := range p.order {
		s := p.sets[k]
		if len(s.changes) == 0 {
			continue
		}

		d := Delta{Key: k, Set: s.read}

		for _, v := range s.final {
			if d.TTL == 0 {
				d.TTL = v.Record.TTL
			}

			if v.Record.TTL != d.TTL {
				return nil, fmt.Errorf("%s: conflicting final TTLs in RRset %s; include every remaining sibling with the same TTL", p.a.Name(), k)
			}
		}

		var read []Value
		if s.read != nil {
			read = s.read.Values
			d.TTLChanged = len(s.final) > 0 && d.TTL != s.read.TTL
		}

		held := func(vs []Value, v Value) bool {
			return slices.ContainsFunc(vs, func(w Value) bool { return p.a.Same(k.Type, w.Record.Value, v.Record.Value) })
		}

		for _, v := range s.final {
			if !held(read, v) {
				d.Add = append(d.Add, v)
			}
		}

		for _, v := range read {
			if !held(s.final, v) {
				d.Remove = append(d.Remove, v)
			}
		}

		out[k] = d
	}

	return out, nil
}

type group struct {
	keys    []Key
	changes []int
}

// groups are the touched RRsets joined by the changes that move values
// between them, in the order they were first touched.
func (p *plan) groups() []group {
	var (
		out []group
		at  = map[Key]int{}
	)

	for _, k := range p.order {
		s := p.sets[k]
		if len(s.changes) == 0 {
			continue
		}

		r := p.root(k)

		i, ok := at[r]
		if !ok {
			i = len(out)
			at[r] = i
			out = append(out, group{})
		}

		out[i].keys = append(out[i].keys, k)

		for _, c := range s.changes {
			if !slices.Contains(out[i].changes, c) {
				out[i].changes = append(out[i].changes, c)
			}
		}
	}

	return out
}

func (p *plan) apply(ctx context.Context, g group, deltas map[Key]Delta, res *dnsprovider.ApplyResult) {
	// Additions go first, so a moved value is at its destination before
	// it leaves its source.
	keys := slices.Clone(g.keys)
	slices.SortStableFunc(keys, func(a, b Key) int {
		return rank(deltas[a]) - rank(deltas[b])
	})

	var (
		failure error
		wrote   bool
		held    []dnsprovider.Record
	)

	for _, k := range keys {
		if deltas[k].empty() {
			continue
		}

		wrote = true

		if failure = p.a.Write(ctx, deltas[k]); failure != nil {
			break
		}
	}

	switch {
	case failure != nil:
	case wrote:
		stored, err := p.a.ReadBack(ctx, g.keys)
		if err != nil {
			failure = p.uncertain(err)

			break
		}

		res.Serial = stored.Serial
		held = stored.Records
	default:
		for _, k := range g.keys {
			if s := p.sets[k].read; s != nil {
				for _, v := range s.Values {
					held = append(held, v.Record)
				}
			}
		}
	}

	var stored []dnsprovider.Record
	if failure == nil {
		stored, failure = readback.Verify(p.effects(g, deltas), held, p.same)
		if failure != nil {
			failure = p.uncertain(failure)
		}
	}

	if failure != nil && wrote {
		failure = fmt.Errorf("%s: RRset group may have partial side effects: %w", p.a.Name(), failure)
	}

	for _, i := range g.changes {
		if res.Results[i].Err != nil {
			continue
		}

		if failure != nil {
			res.Results[i].Err = failure

			continue
		}

		res.Results[i].Record = stored[i]
	}
}

// effects are the group's changes' own effects: the values they add, and
// those they remove that no change adds back.
func (p *plan) effects(g group, deltas map[Key]Delta) readback.Effects {
	e := readback.Effects{Added: make([]dnsprovider.Record, len(p.added))}
	for _, i := range g.changes {
		e.Added[i] = p.added[i]
	}

	for _, k := range g.keys {
		for _, v := range deltas[k].Remove {
			e.Removed = append(e.Removed, readback.Removal{Record: v.Record})
		}
	}

	return e
}

func (p *plan) same(a, b dnsprovider.Record) bool {
	return KeyOf(a) == KeyOf(b) && p.a.Same(KeyOf(a).Type, a.Value, b.Value)
}

func (p *plan) uncertain(err error) error {
	if errors.Is(err, dnsprovider.ErrConflict) {
		return fmt.Errorf("%s: read-back completion is unconfirmed, another write may have replaced this Changeset's; re-read Records before retrying: %w", p.a.Name(), err)
	}

	return fmt.Errorf("%s: read-back completion is unconfirmed; re-read Records before retrying: %w", p.a.Name(), err)
}

func rank(d Delta) int {
	if len(d.Add) > 0 {
		return 0
	}

	return 1
}
