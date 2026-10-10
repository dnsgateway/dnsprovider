package dnsprovider

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// StaleError is Apply's refusal of a stale Changeset. It matches ErrStale
// with errors.Is.
type StaleError struct {
	// Changes are the modifications and deletions whose Before the
	// Provider no longer holds as it was, in Changeset order.
	Changes []StaleChange
}

// StaleChange is a change built from a Record that changed at the
// Provider since it was read.
type StaleChange struct {
	Change Change
	// Now is the Record as the Provider holds it now: the one with
	// Before's ID, or what Before became where the Provider keys Records
	// by content; empty when it is gone or which it became cannot be
	// told.
	Now Record
}

func (e *StaleError) Error() string {
	described := make([]string, len(e.Changes))
	for i, s := range e.Changes {
		described[i] = s.describe()
	}

	return ErrStale.Error() + ": " + strings.Join(described, "; ")
}

// Unwrap makes the error match ErrStale.
func (e *StaleError) Unwrap() error {
	return ErrStale
}

func (s StaleChange) describe() string {
	if s.Now.Type == "" {
		return describeRecord(s.Change.Before) + " no longer exists"
	}

	return describeRecord(s.Change.Before) + " is now " + describeRecord(s.Now)
}

func describeRecord(r Record) string {
	return fmt.Sprintf("%s %s %q (TTL %d)", r.Type, r.Name, r.Value, r.TTL)
}

// recheck re-reads the Records a Changeset modifies or deletes and
// returns a *StaleError when any no longer matches its Before. Every
// change but an addition is re-checked: a change of no known kind built
// from a Record too, as it may still be made from it. An addition is
// built from no Record, so a Changeset of additions alone is not read
// for. When every Record re-read has one type, the read is filtered by
// it, and the whole Zone is read again only when that read misses a
// Before's ID, so the Changeset is stale, for a Record that changed type.
func recheck(ctx context.Context, p Provider, cs Changeset) error {
	var (
		touched []Change
		f       RecordFilter
	)

	for _, c := range cs.Changes {
		if !builtFromRecord(c) {
			continue
		}

		switch {
		case len(touched) == 0:
			f.Type = c.Before.Type
		case !strings.EqualFold(f.Type, c.Before.Type):
			f.Type = ""
		}

		touched = append(touched, c)
	}

	if len(touched) == 0 {
		return nil
	}

	// A Before of no type matches no filter: read the whole Zone for it.
	live, err := p.Records(ctx, cs.Zone, f)
	if err != nil {
		return fmt.Errorf("re-check the Records the Changeset was built from: %w", err)
	}

	// A Record whose type changed keeps its ID on some Providers
	// (Cloudflare), out of the type's read: read the whole Zone for it.
	if f.Type != "" && slices.ContainsFunc(touched, func(c Change) bool {
		return c.Before.ID != "" && !slices.ContainsFunc(live.Records, func(r Record) bool { return r.ID == c.Before.ID })
	}) {
		if live, err = p.Records(ctx, cs.Zone, RecordFilter{}); err != nil {
			return fmt.Errorf("re-check the Records the Changeset was built from: %w", err)
		}
	}

	if stale := staleChanges(touched, live.Records); stale != nil {
		return &StaleError{Changes: stale}
	}

	return nil
}

// builtFromRecord reports whether a change was built from a Record read
// at the Provider: a modification or a deletion, or a change of no known
// kind that carries a Before.
func builtFromRecord(c Change) bool {
	switch c.Kind {
	case ChangeAdd:
		return false
	case ChangeModify, ChangeDelete:
		return true
	}

	return c.Before.ID != "" || c.Before.Type != "" || c.Before.Name != ""
}

// staleChanges are the touched changes whose Before live no longer holds
// as it was, each with what it is now (current).
func staleChanges(touched []Change, live []Record) []StaleChange {
	found := make([]int, len(touched))
	claimed := make(map[int]bool, len(touched))

	for i, c := range touched {
		found[i] = slices.IndexFunc(live, func(r Record) bool { return readAs(c.Before, r) })
		if found[i] >= 0 {
			claimed[found[i]] = true
		}
	}

	var stale []StaleChange

	for i, c := range touched {
		if found[i] >= 0 && unchanged(c.Before, live[found[i]]) {
			continue
		}

		var now Record
		if found[i] >= 0 {
			now = live[found[i]]
		} else {
			now = current(c.Before, live, claimed)
		}

		stale = append(stale, StaleChange{Change: c, Now: now})
	}

	return stale
}

// readAs reports whether r is the Record before was read as: the one with
// its ID or, for a Record built without one, the same resource record
// (SameRecord).
func readAs(before, r Record) bool {
	if before.ID == "" {
		return SameRecord(before, r)
	}

	return r.ID == before.ID
}

// current is what became of a Before that live holds no longer as read,
// as where a Provider keys Records by content (GoDaddy, Namecheap) any
// change to one changes its ID: among the Records no other change was
// read from, the one same resource record (SameRecord), whose TTL or
// Extras changed, or else the one Record of its RRset, whose Value
// changed. When none or several are, which it became cannot be told: the
// Record is taken as gone, and current is empty. On a Provider whose IDs
// hold (Cloudflare) a Before whose ID is gone was deleted, and a lone
// other Record of its RRset is named as what it became.
func current(before Record, live []Record, claimed map[int]bool) Record {
	for _, same := range []func(a, b Record) bool{SameRecord, sameRRset} {
		var (
			now Record
			n   int
		)

		for i, r := range live {
			if !claimed[i] && same(before, r) {
				now = r
				n++
			}
		}

		if n > 0 {
			if n > 1 {
				now = Record{}
			}

			return now
		}
	}

	return Record{}
}

// unchanged reports whether a Record is as it was read: the same
// resource record (SameRecord), TTL and Extras (SameExtras).
func unchanged(a, b Record) bool {
	return SameRecord(a, b) && a.TTL == b.TTL && SameExtras(a.Extras, b.Extras)
}
