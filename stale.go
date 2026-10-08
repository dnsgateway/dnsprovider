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

	var stale []StaleChange

	for _, c := range touched {
		now, ok := current(c.Before, live.Records)
		if !ok || !unchanged(c.Before, now) {
			stale = append(stale, StaleChange{Change: c, Now: now})
		}
	}

	if stale != nil {
		return &StaleError{Changes: stale}
	}

	return nil
}

// current is the Record live holds for before: the one with its ID, or,
// for a Record built without one, the same resource record (SameRecord).
func current(before Record, live []Record) (Record, bool) {
	i := slices.IndexFunc(live, func(r Record) bool {
		if before.ID == "" {
			return SameRecord(before, r)
		}

		return r.ID == before.ID
	})
	if i < 0 {
		return Record{}, false
	}

	return live[i], true
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
