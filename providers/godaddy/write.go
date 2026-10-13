package godaddy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/internal/rrset"
)

// writeTypes are the types a Changeset may add or modify to. GoDaddy
// manages SOA itself, and has no URI records.
var writeTypes = []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"}

// writer is the rrset.Adapter of one Zone.
type writer struct {
	p    *Provider
	zone dnsprovider.Zone
}

// wireValue is the Wire of a value: its record as GoDaddy holds it, with
// its recordId, or as it will be sent.
type wireValue struct {
	rec wireRecord
}

// ApplyChangeset implements dnsprovider.Provider (CapBatcher). It writes
// only the records each change names: POST for a value added, DELETE by
// recordId for a value removed, and PUT of each kept record for a TTL
// change, so a concurrent Changeset on the same RRset keeps its values.
// The RRset's TTL stays last-writer-wins. There is no transaction across
// records: a modification adds before it removes, and errors say when a
// group of RRsets may be partly applied.
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	if len(cs.Changes) == 0 {
		return dnsprovider.ApplyResult{Results: []dnsprovider.ChangeResult{}}, nil
	}

	sets, err := p.sets(ctx, cs.Zone, readTypes(cs.Changes))
	if err != nil {
		return dnsprovider.ApplyResult{}, p.notServed(ctx, cs.Zone, err)
	}

	return rrset.Apply(ctx, writer{p: p, zone: cs.Zone}, cs, sets)
}

// readTypes are the types a Changeset touches, to read the RRsets of; nil,
// for the whole Zone, when one is a type GoDaddy does not filter by.
func readTypes(changes []dnsprovider.Change) []string {
	var types []string

	for _, c := range changes {
		for _, r := range []dnsprovider.Record{c.Before, c.After} {
			typ := strings.ToUpper(r.Type)
			if typ == "" {
				continue
			}

			if !slices.Contains(recordTypes, typ) {
				return nil
			}

			if !slices.Contains(types, typ) {
				types = append(types, typ)
			}
		}
	}

	return types
}

// read reads the Zone's records of types, or of every type when types is
// nil.
func (p *Provider) read(ctx context.Context, zone dnsprovider.Zone, types []string) ([]wireRecord, error) {
	if types == nil {
		return p.listRecords(ctx, zone, "")
	}

	var out []wireRecord

	for _, typ := range types {
		rs, err := p.listRecords(ctx, zone, typ)
		if err != nil {
			return nil, err
		}

		out = append(out, rs...)
	}

	return out, nil
}

// sets are the Zone's RRsets of types as rrset.Apply plans from them.
func (p *Provider) sets(ctx context.Context, zone dnsprovider.Zone, types []string) ([]rrset.Set, error) {
	read, err := p.read(ctx, zone, types)
	if err != nil {
		return nil, err
	}

	var out []rrset.Set

	at := map[rrset.Key]int{}

	for _, w := range read {
		r := toRecord(zone.Name, w)
		k := rrset.KeyOf(r)

		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, rrset.Set{Key: k, TTL: r.TTL})
		}

		out[i].Values = append(out[i].Values, rrset.Value{Record: r, Wire: wireValue{rec: w}})
	}

	return out, nil
}

func (w writer) Name() string { return "godaddy" }

// Normalize qualifies a Record's name and, for the After of a change,
// checks it is a type, TTL and Value GoDaddy takes.
func (w writer) Normalize(r dnsprovider.Record, after bool) (dnsprovider.Record, error) {
	r.Type = strings.ToUpper(r.Type)

	abs, err := dnsprovider.QualifyName(w.zone.Name, r.Name)
	if err != nil {
		return r, err
	}

	r.Name = names.ZoneName(abs)

	if !after {
		return r, nil
	}

	if !slices.Contains(writeTypes, r.Type) {
		return r, fmt.Errorf("godaddy: GoDaddy does not take %s records", r.Type)
	}

	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return r, err
	}

	if err := ttlRange.Check(r.TTL); err != nil {
		return r, err
	}

	if _, err := toWire(w.zone.Name, r); err != nil {
		return r, err
	}

	return r, nil
}

// Same compares two values of a type. A host name target ignores case and
// a trailing dot, as GoDaddy may store it either way; a CAA value ignores
// its quoting and its tag's case.
func (w writer) Same(typ, a, b string) bool {
	switch typ {
	case "CNAME", "NS", "MX", "SRV":
		fa, fb := strings.Fields(a), strings.Fields(b)
		if len(fa) != len(fb) || len(fa) == 0 {
			return a == b
		}

		last := len(fa) - 1
		host := func(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

		return slices.Equal(fa[:last], fb[:last]) && host(fa[last]) == host(fb[last])
	case "CAA":
		return charstr.Equivalent(typ, a, b)
	}

	return a == b
}

// Writable refuses the SOA, which GoDaddy manages.
func (w writer) Writable(s *rrset.Set) error {
	if s != nil && s.Key.Type == "SOA" {
		return fmt.Errorf("godaddy: GoDaddy manages the SOA of %s", w.zone.Name)
	}

	return nil
}

// Wire is the record a value is sent as. Normalize has checked it.
func (w writer) Wire(after dnsprovider.Record, _ *rrset.Value, _ *rrset.Set) any {
	rec, _ := toWire(w.zone.Name, after)

	return wireValue{rec: rec}
}

// Write changes the TTL of each record the RRset keeps with PUT, then
// adds each value with POST, then removes each with DELETE by recordId.
// A record another writer removed first (404) is gone as planned. A POST
// is never repeated: replayed after a lost answer, it can add a duplicate.
func (w writer) Write(ctx context.Context, d rrset.Delta) error {
	if d.TTLChanged {
		for _, v := range d.Set.Values {
			rec := v.Wire.(wireValue).rec
			if slices.ContainsFunc(d.Remove, func(r rrset.Value) bool { return r.Wire.(wireValue).rec.RecordID == rec.RecordID }) {
				continue
			}

			id := rec.RecordID
			rec.RecordID, rec.TTL = "", d.TTL

			if err := w.p.api().Do(ctx, http.MethodPut, recordsPath(w.zone)+"/"+url.PathEscape(id), nil, rec, nil); err != nil {
				return fmt.Errorf("godaddy: TTL of %s: %w", d.Key, err)
			}
		}
	}

	post := w.p.api()
	post.Attempts = 1

	for _, v := range d.Add {
		if err := post.Do(ctx, http.MethodPost, recordsPath(w.zone), nil, v.Wire.(wireValue).rec, nil); err != nil {
			return fmt.Errorf("godaddy: add to %s: %w", d.Key, err)
		}
	}

	for _, v := range d.Remove {
		id := v.Wire.(wireValue).rec.RecordID

		err := w.p.api().Do(ctx, http.MethodDelete, recordsPath(w.zone)+"/"+url.PathEscape(id), nil, nil, nil)
		if err != nil && !errors.Is(err, dnsprovider.ErrNotFound) {
			return fmt.Errorf("godaddy: remove from %s: %w", d.Key, err)
		}
	}

	return nil
}

// ReadBack reads the records of the keys' types and keeps those of the
// keys' RRsets.
func (w writer) ReadBack(ctx context.Context, keys []rrset.Key) (dnsprovider.RecordSet, error) {
	var types []string

	for _, k := range keys {
		if !slices.Contains(types, k.Type) {
			types = append(types, k.Type)
		}
	}

	read, err := w.p.read(ctx, w.zone, types)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	var out []dnsprovider.Record

	for _, rec := range read {
		if r := toRecord(w.zone.Name, rec); slices.Contains(keys, rrset.KeyOf(r)) {
			out = append(out, r)
		}
	}

	return dnsprovider.RecordSet{Records: out}, nil
}

// CreateRecord implements dnsprovider.Provider: a one-change Changeset
// through ApplyChangeset.
func (p *Provider) CreateRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Create(ctx, p, zone, r)
}

// UpdateRecord implements dnsprovider.Provider: a one-change Changeset
// through ApplyChangeset. before is found by its content in its RRset:
// ErrNotFound when the RRset no longer holds it.
func (p *Provider) UpdateRecord(ctx context.Context, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Update(ctx, p, zone, before, after)
}

// DeleteRecord implements dnsprovider.Provider: a one-change Changeset
// through ApplyChangeset, found as UpdateRecord finds before.
func (p *Provider) DeleteRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) error {
	return batch.Delete(ctx, p, zone, r)
}
