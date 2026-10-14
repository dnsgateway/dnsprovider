package ovhcloud

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

var _ dnsprovider.Provider = (*Provider)(nil)

// ErrUnpublished marks a change the API staged whose Zone refresh was not
// confirmed: the edit is stored but may not be served. Re-read and
// refresh again rather than resubmitting the edit.
var ErrUnpublished = errors.New("ovhcloud: staged change is not confirmed published; the Zone refresh failed")

// editable are the types this adapter writes.
var editable = []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"}

// CreateRecord stages the Record, refreshes the Zone and returns the
// Record as the API stored it.
func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Create(ctx, p, z, r)
}

// UpdateRecord finds before by its native ID (or, without one, by its
// content), stages the edit, refreshes the Zone and reads the stored
// Record back. A type change replaces the Record, so its ID changes.
func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Update(ctx, p, z, before, after)
}

// DeleteRecord deletes only the selected Record and refreshes the Zone.
func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	return batch.Delete(ctx, p, z, r)
}

// ApplyChangeset stages each change in Apply's order, then refreshes the
// Zone once when any edit was, or may have been, staged, including when
// others failed. A failed refresh marks every such change ErrUnpublished,
// joined to its own error when it has one (a failed read-back, a partial
// type move, a lost answer); refused changes keep their errors. Nothing
// is rolled back or resubmitted; a confirmed refresh is not global
// propagation. The serial is the SOA serial read after the refresh, or
// the one read before when nothing was staged.
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}
	for i, c := range cs.Changes {
		res.Results[i].Change = c
	}

	if len(cs.Changes) == 0 {
		return res, nil
	}

	snap, err := p.read(ctx, cs.Zone, "")
	if err != nil {
		return res, err
	}

	// touched are the changes the API took, or may have taken, even
	// partly: each needs the refresh.
	var touched []int

	for _, i := range dnsprovider.ApplyOrder(cs.Changes) {
		r, wrote, err := p.stageChange(ctx, &snap, cs.Changes[i])
		res.Results[i].Record, res.Results[i].Err = r, err

		if wrote {
			touched = append(touched, i)
		}
	}

	if len(touched) == 0 {
		res.Serial = snap.serial

		return res, nil
	}

	if err := p.write(ctx, http.MethodPost, zonePath(snap.zone)+"/refresh", nil, nil, nil); err != nil {
		unpublished := fmt.Errorf("%w: %w", ErrUnpublished, err)
		if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
			// A refused refresh still leaves the edits staged.
			unpublished = fmt.Errorf("%w; %w", unpublished, dnsprovider.ErrUnconfirmed)
		}
		for _, i := range touched {
			res.Results[i].Err = joinUnpublished(res.Results[i].Err, unpublished)
			res.Results[i].Record = dnsprovider.Record{}
		}

		return res, fmt.Errorf("ovhcloud: Zone %s has staged edits whose publication is unconfirmed: %w", snap.zone, unpublished)
	}

	// The refresh is confirmed; a failed SOA read only leaves the
	// serial unknown.
	if soa, err := p.soa(ctx, snap.zone); err == nil {
		res.Serial = soa.serial()
	}

	return res, nil
}

// normalizeValue puts a caller's value in the presentation reads return:
// host names are absolute, as callers write them.
func normalizeValue(typ, value string) string {
	return presentValue(typ, value, func(v string) string {
		if v == "." {
			return v
		}

		return strings.ToLower(strings.TrimSuffix(v, ".")) + "."
	})
}

// prepareRecord validates and normalizes a Record to write.
func prepareRecord(zone string, r dnsprovider.Record) (dnsprovider.Record, error) {
	r.Type = strings.ToUpper(r.Type)
	if !slices.Contains(editable, r.Type) {
		return dnsprovider.Record{}, fmt.Errorf("ovhcloud: unsupported editable type %s", r.Type)
	}

	name, err := dnsprovider.QualifyName(zone, r.Name)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return dnsprovider.Record{}, err
	}

	if err := dnsprovider.DefaultTTLRange.Check(r.TTL); err != nil {
		return dnsprovider.Record{}, err
	}

	r.Name, r.Value = strings.ToLower(name), normalizeValue(r.Type, r.Value)

	return r, nil
}

func sameContent(a, b dnsprovider.Record) bool {
	return a.Type == b.Type && strings.EqualFold(a.Name, b.Name) && (a.Value == b.Value || charstr.Equivalent(a.Type, a.Value, b.Value))
}

// find locates a Record as last read: by native ID, or by content.
func (s *snapshot) find(r dnsprovider.Record) int {
	if r.ID != "" {
		return slices.IndexFunc(s.entries, func(e storedRecord) bool { return e.record.ID == r.ID })
	}

	want := dnsprovider.Record{Type: strings.ToUpper(r.Type), Name: names.ZoneName(r.Name), Value: normalizeValue(strings.ToUpper(r.Type), r.Value)}

	return slices.IndexFunc(s.entries, func(e storedRecord) bool { return sameContent(e.record, want) })
}

// collides reports whether another Record has the same content.
func (s *snapshot) collides(r dnsprovider.Record, except int) bool {
	for i, e := range s.entries {
		if i != except && sameContent(e.record, r) {
			return true
		}
	}

	return false
}

func subDomain(zone, name string) string {
	if rel := dnsprovider.RelativeName(zone, name); rel != "@" {
		return rel
	}

	return ""
}

// joinUnpublished adds the unconfirmed publication to a change's own
// error, when it has one.
func joinUnpublished(err, unpublished error) error {
	if err == nil {
		return unpublished
	}

	return errors.Join(err, unpublished)
}

// stageChange makes one change against the staged Zone. The bool reports
// a write the API took, or may have taken, which needs a refresh.
func (p *Provider) stageChange(ctx context.Context, s *snapshot, c dnsprovider.Change) (dnsprovider.Record, bool, error) {
	switch c.Kind {
	case dnsprovider.ChangeAdd:
		after, err := prepareRecord(s.zone, c.After)
		if err != nil {
			return dnsprovider.Record{}, false, err
		}

		if s.collides(after, -1) {
			return dnsprovider.Record{}, false, dnsprovider.ErrConflict
		}

		created, wrote, err := p.create(ctx, s, after, int64(after.TTL))
		if err != nil {
			return dnsprovider.Record{}, wrote, err
		}

		s.entries = append(s.entries, created)

		return created.record, true, nil
	case dnsprovider.ChangeModify:
		return p.modify(ctx, s, c)
	case dnsprovider.ChangeDelete:
		i := s.find(c.Before)
		if i < 0 {
			return dnsprovider.Record{}, false, dnsprovider.ErrNotFound
		}

		if err := p.write(ctx, http.MethodDelete, recordPath(s.zone, s.entries[i].wire.ID), nil, nil, nil); err != nil {
			return dnsprovider.Record{}, errors.Is(err, dnsprovider.ErrUnconfirmed), fmt.Errorf("ovhcloud: record deletion: %w", err)
		}

		s.entries = slices.Delete(s.entries, i, i+1)

		return dnsprovider.Record{}, true, nil
	}

	return dnsprovider.Record{}, false, fmt.Errorf("ovhcloud: unknown change kind %d", c.Kind)
}

// wireTTL is the TTL to send for after, which replaces src: an unchanged
// inherited TTL is zero, so it keeps following the Zone default.
func (s *snapshot) wireTTL(src storedRecord, after dnsprovider.Record) int64 {
	if src.wire.inherited() && after.TTL == s.defaultTTL {
		return 0
	}

	return int64(after.TTL)
}

// create posts a Record with the native TTL; the answer is the stored
// Record.
func (p *Provider) create(ctx context.Context, s *snapshot, r dnsprovider.Record, ttl int64) (storedRecord, bool, error) {
	body := map[string]any{"fieldType": r.Type, "subDomain": subDomain(s.zone, r.Name), "target": r.Value, "ttl": ttl}

	var w wireRecord
	if err := p.write(ctx, http.MethodPost, zonePath(s.zone)+"/record", nil, body, &w); err != nil {
		return storedRecord{}, errors.Is(err, dnsprovider.ErrUnconfirmed), fmt.Errorf("ovhcloud: record creation: %w", err)
	}

	e, err := publicRecord(s.zone, s.defaultTTL, w)
	if err != nil {
		return storedRecord{}, true, fmt.Errorf("ovhcloud: record creation: %w; %w", err, dnsprovider.ErrUnconfirmed)
	}

	return e, true, nil
}

func (p *Provider) modify(ctx context.Context, s *snapshot, c dnsprovider.Change) (dnsprovider.Record, bool, error) {
	i := s.find(c.Before)
	if i < 0 {
		return dnsprovider.Record{}, false, dnsprovider.ErrNotFound
	}

	after, err := prepareRecord(s.zone, c.After)
	if err != nil {
		return dnsprovider.Record{}, false, err
	}

	if s.collides(after, i) {
		return dnsprovider.Record{}, false, dnsprovider.ErrConflict
	}

	src := s.entries[i]
	if after.Type != src.record.Type {
		return p.replace(ctx, s, i, after)
	}

	body := map[string]any{"subDomain": subDomain(s.zone, after.Name), "target": after.Value, "ttl": s.wireTTL(src, after)}
	if err := p.write(ctx, http.MethodPut, recordPath(s.zone, src.wire.ID), nil, body, nil); err != nil {
		return dnsprovider.Record{}, errors.Is(err, dnsprovider.ErrUnconfirmed), fmt.Errorf("ovhcloud: record update: %w", err)
	}

	stored, err := p.record(ctx, s.zone, s.defaultTTL, src.wire.ID)
	if err != nil {
		return dnsprovider.Record{}, true, fmt.Errorf("ovhcloud: record %d update was staged but could not be read back: %w; %w", src.wire.ID, err, dnsprovider.ErrUnconfirmed)
	}

	s.entries[i] = stored

	return stored.record, true, nil
}

// replace moves a Record to another type, which the update contract does
// not take: it creates the new Record, then deletes the old one. Like an
// update, an unchanged inherited TTL stays inherited.
func (p *Provider) replace(ctx context.Context, s *snapshot, i int, after dnsprovider.Record) (dnsprovider.Record, bool, error) {
	old := s.entries[i]

	created, wrote, err := p.create(ctx, s, after, s.wireTTL(old, after))
	if err != nil {
		return dnsprovider.Record{}, wrote, fmt.Errorf("ovhcloud: type change of record %d: %w", old.wire.ID, err)
	}

	s.entries = append(s.entries, created)

	if err := p.write(ctx, http.MethodDelete, recordPath(s.zone, old.wire.ID), nil, nil, nil); err != nil {
		return dnsprovider.Record{}, true, fmt.Errorf("ovhcloud: type change partially staged: record %s was created but record %d remains: %w", created.record.ID, old.wire.ID, err)
	}

	s.entries = slices.DeleteFunc(s.entries, func(r storedRecord) bool { return r.wire.ID == old.wire.ID })

	return created.record, true, nil
}
