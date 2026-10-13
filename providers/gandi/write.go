package gandi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
	rrsets "github.com/dnsgateway/dnsprovider/internal/rrset"
)

var _ dnsprovider.Provider = (*Provider)(nil)

func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Create(ctx, p, z, r)
}

func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Update(ctx, p, z, before, after)
}

func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	return batch.Delete(ctx, p, z, r)
}

// writer is the rrset.Adapter of one Zone.
type writer struct {
	p    *Provider
	zone dnsprovider.Zone
	// stored are the RRsets as PATCH answered them, by Key: nil for one
	// the PATCH emptied, which LiveDNS deletes.
	stored map[rrsets.Key]*rrset
}

// sets are the Zone's RRsets as rrset.Apply plans from them, each value
// with its wire string, the form remove_rrset_values names it by.
func (p *Provider) sets(ctx context.Context, z dnsprovider.Zone) ([]rrsets.Set, error) {
	all, err := list[wireSet](ctx, p, p.baseURL, p.recordPath(z))
	if err != nil {
		return nil, err
	}
	out := make([]rrsets.Set, 0, len(all))
	seen := map[rrsets.Key]bool{}
	for _, w := range all {
		s, err := decode(w)
		if err != nil {
			return nil, err
		}
		rs := records(z, s)
		set := rrsets.Set{Key: rrsets.KeyOf(dnsprovider.Record{Name: names.AbsoluteName(z.Name, s.Name), Type: s.Type}), TTL: *s.TTL, Wire: s}
		if seen[set.Key] {
			return nil, errors.New("gandi: duplicate RRset in response")
		}
		seen[set.Key] = true
		for i, r := range rs {
			set.Values = append(set.Values, rrsets.Value{Record: r, Wire: s.Values[i]})
		}
		out = append(out, set)
	}
	return out, nil
}

// ApplyChangeset writes only the values each change names, with PATCH
// add_rrset_values and remove_rrset_values, never a replacement or
// deletion of the whole RRset, so a concurrent Changeset on the same
// RRset keeps its values. The RRset's TTL stays last-writer-wins. There is
// no transaction across RRsets: a move adds at its destination before it
// removes at its source, and errors say when a group may be partly
// applied.
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	sets, err := p.sets(ctx, cs.Zone)
	if err != nil {
		return dnsprovider.ApplyResult{}, err
	}
	return rrsets.Apply(ctx, &writer{p: p, zone: cs.Zone, stored: map[rrsets.Key]*rrset{}}, cs, sets)
}

func (w *writer) Name() string { return "gandi" }

func (w *writer) Normalize(r dnsprovider.Record, after bool) (dnsprovider.Record, error) {
	if after {
		return normalize(w.zone, r)
	}
	abs, err := dnsprovider.QualifyName(w.zone.Name, r.Name)
	if err != nil {
		return r, err
	}
	r.Name, r.Type = names.ZoneName(abs), strings.ToUpper(r.Type)
	return r, nil
}

func (w *writer) Same(_, a, b string) bool { return a == b }

func (w *writer) Writable(*rrsets.Set) error { return nil }

// Wire is a value's wire string. New TXT values are literal text. A TXT
// value a modification keeps retains its original presentation,
// including chunk boundaries and escapes.
func (w *writer) Wire(after dnsprovider.Record, from *rrsets.Value, _ *rrsets.Set) any {
	if after.Type != "TXT" {
		return after.Value
	}
	if from != nil && from.Record.Type == "TXT" && from.Record.Value == after.Value {
		return from.Wire
	}
	return charstr.Quote(after.Value)
}

func (w *writer) path(k rrsets.Key) string {
	return w.p.recordPath(w.zone) + "/" + url.PathEscape(names.RelativeName(w.zone.Name, k.Name)) + "/" + url.PathEscape(k.Type)
}

// Write creates a missing RRset with POST, or adds to it with PATCH when
// another writer created it first (409). An existing RRset takes one PATCH
// with the values to add, the values to remove as stored, and rrset_ttl
// only when the Changeset changes the shared TTL.
func (w *writer) Write(ctx context.Context, d rrsets.Delta) error {
	path := w.path(d.Key)
	if d.Set == nil {
		err := w.p.request(ctx, w.p.baseURL, http.MethodPost, path, nil, map[string]any{"rrset_values": wires(d.Add), "rrset_ttl": d.TTL}, nil)
		if !errors.Is(err, dnsprovider.ErrConflict) {
			if err != nil {
				return fmt.Errorf("gandi: RRset %s creation: %w", d.Key, err)
			}
			return nil
		}
	}
	body := map[string]any{}
	if len(d.Add) > 0 {
		body["add_rrset_values"] = wires(d.Add)
	}
	if len(d.Remove) > 0 {
		body["remove_rrset_values"] = wires(d.Remove)
	}
	if d.TTLChanged {
		body["rrset_ttl"] = d.TTL
	}
	var answer wireSet
	if err := w.p.request(ctx, w.p.baseURL, http.MethodPatch, path, nil, body, &answer); err != nil {
		return fmt.Errorf("gandi: RRset %s change: %w", d.Key, err)
	}
	if answer == nil {
		w.stored[d.Key] = nil
		return nil
	}
	if s, err := decode(answer); err == nil {
		w.stored[d.Key] = &s
	}
	return nil
}

func wires(vs []rrsets.Value) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.Wire.(string)
	}
	return out
}

// ReadBack takes each RRset from its PATCH answer, or reads it with GET;
// an RRset that is gone holds no Records.
func (w *writer) ReadBack(ctx context.Context, keys []rrsets.Key) (dnsprovider.RecordSet, error) {
	var out []dnsprovider.Record
	for _, k := range keys {
		if s, ok := w.stored[k]; ok {
			if s != nil {
				out = append(out, records(w.zone, *s)...)
			}
			continue
		}
		var answer wireSet
		err := w.p.request(ctx, w.p.baseURL, http.MethodGet, w.path(k), nil, nil, &answer)
		if errors.Is(err, dnsprovider.ErrNotFound) {
			continue
		}
		if err != nil {
			return dnsprovider.RecordSet{}, err
		}
		s, err := decode(answer)
		if err != nil {
			return dnsprovider.RecordSet{}, err
		}
		if rrsets.KeyOf(dnsprovider.Record{Name: names.AbsoluteName(w.zone.Name, s.Name), Type: s.Type}) != k {
			return dnsprovider.RecordSet{}, fmt.Errorf("gandi: read-back of RRset %s names another RRset", k)
		}
		out = append(out, records(w.zone, s)...)
	}
	return dnsprovider.RecordSet{Records: out}, nil
}
