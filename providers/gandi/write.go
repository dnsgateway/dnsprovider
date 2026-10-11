package gandi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

var (
	_ dnsprovider.Provider = (*Provider)(nil)
	_ dnsprovider.Batcher  = (*Provider)(nil)
)

func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Create(ctx, p, z, r)
}

func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Update(ctx, p, z, before, after)
}

func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	return batch.Delete(ctx, p, z, r)
}

type entry struct {
	record    dnsprovider.Record
	wireValue string
}
type group struct {
	wire      wireSet
	name, typ string
	entries   []entry
	changes   []int
	err       error
	stored    []dnsprovider.Record
	written   bool
}

func groupKey(r dnsprovider.Record) string {
	return names.ZoneName(r.Name) + "\x00" + strings.ToUpper(r.Type)
}

func same(a, b dnsprovider.Record) bool {
	return strings.EqualFold(a.Type, b.Type) && strings.EqualFold(strings.TrimSuffix(a.Name, "."), strings.TrimSuffix(b.Name, ".")) && a.Value == b.Value
}

func index(g *group, r dnsprovider.Record) int {
	return slices.IndexFunc(g.entries, func(e entry) bool { return same(e.record, r) })
}

// ApplyChangeset plans the complete final state before any write. Every RRset
// is replaced at most once, and each successful replacement is read back.
// There is no transaction across RRsets: errors identify the changes whose
// source or destination failed, including moves that succeeded only partly.
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	groups, err := p.readGroups(ctx, cs.Zone)
	if err != nil {
		return dnsprovider.ApplyResult{}, err
	}
	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}
	for i, c := range cs.Changes {
		res.Results[i].Change = c
	}
	affected := make([][]*group, len(cs.Changes))
	var ordered []*group
	touch := func(g *group, i int) {
		if !slices.Contains(ordered, g) {
			ordered = append(ordered, g)
		}
		if !slices.Contains(g.changes, i) {
			g.changes = append(g.changes, i)
		}
		if !slices.Contains(affected[i], g) {
			affected[i] = append(affected[i], g)
		}
	}
	for _, i := range dnsprovider.ApplyOrder(cs.Changes) {
		c := cs.Changes[i]
		var source, dest *group
		at := -1
		if c.Kind == dnsprovider.ChangeDelete || c.Kind == dnsprovider.ChangeModify {
			before := c.Before
			abs, err := dnsprovider.QualifyName(cs.Zone.Name, before.Name)
			if err != nil {
				res.Results[i].Err = err
				continue
			}
			before.Name = abs
			source = groups[groupKey(before)]
			if source != nil {
				at = index(source, before)
			}
			if at < 0 {
				res.Results[i].Err = fmt.Errorf("gandi: before Record absent: %w", dnsprovider.ErrNotFound)
				continue
			}
		}
		var after dnsprovider.Record
		if c.Kind == dnsprovider.ChangeModify || c.Kind == dnsprovider.ChangeAdd {
			after, err = normalize(cs.Zone, c.After)
			if err != nil {
				res.Results[i].Err = err
				continue
			}
			key := groupKey(after)
			dest = groups[key]
			if dest == nil {
				dest = &group{wire: wireSet{}, name: names.RelativeName(cs.Zone.Name, after.Name), typ: after.Type}
				groups[key] = dest
			}
			duplicate := index(dest, after)
			if duplicate >= 0 && !(source == dest && duplicate == at) {
				res.Results[i].Err = fmt.Errorf("gandi: duplicate Record: %w", dnsprovider.ErrConflict)
				continue
			}
		}
		var original entry
		if source != nil {
			original = source.entries[at]
		}
		switch c.Kind {
		case dnsprovider.ChangeModify, dnsprovider.ChangeDelete:
			source.entries = slices.Delete(source.entries, at, at+1)
			touch(source, i)
		case dnsprovider.ChangeAdd:
		default:
			res.Results[i].Err = fmt.Errorf("gandi: unknown change kind %d", c.Kind)
			continue
		}
		if dest != nil {
			wire := valueOnWire(after, original)
			dest.entries = append(dest.entries, entry{record: after, wireValue: wire})
			touch(dest, i)
			res.Results[i].Record = after
		}
	}
	if err := validateFinalTTLs(ordered); err != nil {
		return dnsprovider.ApplyResult{}, err
	}
	p.writeGroups(ctx, cs.Zone, ordered, affected)
	return finish(cs, res, affected), nil
}

func (p *Provider) writeGroup(ctx context.Context, z dnsprovider.Zone, g *group) error {
	path := p.recordPath(z) + "/" + url.PathEscape(g.name) + "/" + url.PathEscape(g.typ)
	if len(g.entries) == 0 {
		err := p.request(ctx, p.baseURL, http.MethodDelete, path, nil, nil, nil)
		if err != nil {
			return fmt.Errorf("gandi: RRset %s/%s deletion unconfirmed: %w", g.name, g.typ, err)
		}
		g.written = true
		return nil
	}
	body := maps.Clone(g.wire)
	values := make([]string, 0, len(g.entries))
	for _, e := range g.entries {
		values = append(values, e.wireValue)
	}
	body["rrset_values"], _ = json.Marshal(values)
	body["rrset_ttl"], _ = json.Marshal(g.entries[0].record.TTL)
	// Identity/href fields in GET responses are read-only. Retain all other
	// metadata rather than rebuilding a lossy request from modeled fields.
	delete(body, "rrset_name")
	delete(body, "rrset_type")
	delete(body, "rrset_href")
	if err := p.request(ctx, p.baseURL, http.MethodPut, path, nil, body, nil); err != nil {
		return fmt.Errorf("gandi: RRset %s/%s replacement unconfirmed: %w", g.name, g.typ, err)
	}
	g.written = true
	var w wireSet
	if err := p.request(ctx, p.baseURL, http.MethodGet, path, nil, nil, &w); err != nil {
		return fmt.Errorf("gandi: RRset %s/%s written but readback failed: %w", g.name, g.typ, err)
	}
	s, err := decode(w)
	if err != nil {
		return fmt.Errorf("gandi: RRset %s/%s written but readback malformed: %w", g.name, g.typ, err)
	}
	if !strings.EqualFold(s.Name, g.name) || !strings.EqualFold(s.Type, g.typ) {
		return fmt.Errorf("gandi: RRset %s/%s written but readback names a different RRset", g.name, g.typ)
	}
	g.stored = records(z, s)
	for _, e := range g.entries {
		if !slices.ContainsFunc(g.stored, func(r dnsprovider.Record) bool { return same(r, e.record) }) {
			return fmt.Errorf("gandi: RRset %s/%s written but requested value absent in readback", g.name, g.typ)
		}
	}
	return nil
}

func (p *Provider) readGroups(ctx context.Context, z dnsprovider.Zone) (map[string]*group, error) {
	all, err := list[wireSet](ctx, p, p.baseURL, p.recordPath(z))
	if err != nil {
		return nil, err
	}
	groups := make(map[string]*group, len(all))
	for _, w := range all {
		s, err := decode(w)
		if err != nil {
			return nil, err
		}
		rs := records(z, s)
		g := &group{wire: w, name: s.Name, typ: s.Type, entries: make([]entry, 0, len(rs))}
		for i, r := range rs {
			g.entries = append(g.entries, entry{record: r, wireValue: s.Values[i]})
		}
		key := names.ZoneName(names.AbsoluteName(z.Name, s.Name)) + "\x00" + strings.ToUpper(s.Type)
		if _, exists := groups[key]; exists {
			return nil, errors.New("gandi: duplicate RRset in response")
		}
		groups[key] = g
	}
	return groups, nil
}

func validateFinalTTLs(ordered []*group) error {
	// A remaining sibling carries its original TTL. Thus changing a shared TTL
	// requires all remaining siblings to be explicitly modified consistently.
	for _, g := range ordered {
		if len(g.entries) == 0 {
			continue
		}
		ttl := g.entries[0].record.TTL
		for _, e := range g.entries {
			if e.record.TTL != ttl {
				return errors.New("gandi: inconsistent final RRset TTLs; include every remaining sibling in a shared TTL change")
			}
		}
	}
	return nil
}

func finish(cs dnsprovider.Changeset, res dnsprovider.ApplyResult, affected [][]*group) dnsprovider.ApplyResult {
	for i := range res.Results {
		if res.Results[i].Err != nil {
			continue
		}
		for _, g := range affected[i] {
			if g.err != nil {
				res.Results[i].Err = errors.Join(res.Results[i].Err, g.err)
			}
		}
		if res.Results[i].Err != nil {
			res.Results[i].Record = dnsprovider.Record{}
			for _, g := range affected[i] {
				if g.written {
					res.Results[i].Err = fmt.Errorf("%w; RRset %s/%s mutation already acknowledged", res.Results[i].Err, g.name, g.typ)
				}
			}
			continue
		}
		if cs.Changes[i].Kind == dnsprovider.ChangeDelete {
			continue
		}
		desired := res.Results[i].Record
		for _, g := range affected[i] {
			for _, r := range g.stored {
				if same(r, desired) {
					res.Results[i].Record = r
				}
			}
		}
	}
	return res
}

func (p *Provider) writeGroups(ctx context.Context, z dnsprovider.Zone, ordered []*group, affected [][]*group) {
	for _, g := range ordered {
		// Skip dependent groups not yet attempted after a failure. A group
		// may already have been written because another earlier change touched
		// it; finish reports every acknowledged partial mutation.
		for _, i := range g.changes {
			for _, dep := range affected[i] {
				if dep.err != nil {
					g.err = fmt.Errorf("gandi: skipped RRset after dependent failure: %w", dep.err)
				}
			}
		}
		if g.err == nil {
			g.err = p.writeGroup(ctx, z, g)
		}
	}
}

// New TXT values are literal text. When an existing TXT value is unchanged,
// retain its original presentation, including chunk boundaries and escapes.
func valueOnWire(after dnsprovider.Record, original entry) string {
	if after.Type != "TXT" {
		return after.Value
	}
	if original.record.Type == "TXT" && original.record.Value == after.Value {
		return original.wireValue
	}
	return quoteDNS(after.Value)
}
