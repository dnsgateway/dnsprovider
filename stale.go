package dnsprovider

import (
	"context"
	"fmt"
	"maps"
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
	// Now is the Record with Before's ID as the Provider holds it; empty
	// when it is gone.
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
// returns a *StaleError when any no longer matches its Before. An
// addition is built from no Record, so a Changeset of additions alone is
// not read for; a change of no known kind is left to fail on its own. When every Record re-read has one type, the read is
// filtered by it.
func recheck(ctx context.Context, p Provider, cs Changeset) error {
	var (
		touched []Change
		f       RecordFilter
	)

	for i, c := range cs.Changes {
		if c.Kind != ChangeModify && c.Kind != ChangeDelete {
			continue
		}

		switch {
		case len(touched) == 0:
			f.Type = c.Before.Type
		case !strings.EqualFold(f.Type, c.Before.Type):
			f.Type = ""
		}

		touched = append(touched, cs.Changes[i])
	}

	if len(touched) == 0 {
		return nil
	}

	// A Before of no type matches no filter: read the whole Zone for it.
	live, err := p.Records(ctx, cs.Zone, f)
	if err != nil {
		return fmt.Errorf("re-check the Records the Changeset was built from: %w", err)
	}

	stale := staleChanges(touched, live.Records)

	if stale != nil {
		return &StaleError{Changes: stale}
	}

	return nil
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

		now := Record{}
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
// resource record (SameRecord), TTL and Extras, a proxy flag that is off
// counting as none.
func unchanged(a, b Record) bool {
	return SameRecord(a, b) && a.TTL == b.TTL && maps.Equal(proxyOffDropped(a.Extras), proxyOffDropped(b.Extras))
}

// proxyOffDropped returns extras without a proxy flag that is off.
func proxyOffDropped(extras map[string]string) map[string]string {
	if extras[ExtraProxied] != "false" {
		return extras
	}

	out := maps.Clone(extras)
	delete(out, ExtraProxied)

	return out
}
