package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// Apply applies a Changeset. It first re-reads the Records the Changeset
// modifies or deletes and, when any no longer matches its Before, refuses
// the whole Changeset with a *StaleError (ErrStale) and writes nothing.
// The re-check is one read more than the Changeset's writes take, also
// where a Batcher reads the Zone again itself (Namecheap's getHosts before
// its setHosts): it is made the same way for every Provider, with a
// Batcher or without, so every one refuses a stale Changeset alike.
// It then applies the Changeset through the Provider's Batcher when it has
// one, otherwise one CRUD call per change, deletions first, then
// modifications, then additions, so a Record that takes another's place
// does not collide with it. A failed change does not stop the others,
// unless it failed with ErrNoTenant: that is the Provider's condition, not
// the change's, so no other change would succeed, and Apply returns it as
// the Changeset's error without trying the rest. The results are in
// Changeset order; without a Batcher they carry no serial.
func Apply(ctx context.Context, p Provider, cs Changeset) (ApplyResult, error) {
	if err := recheck(ctx, p, cs); err != nil {
		return ApplyResult{}, err
	}

	if b, ok := p.(Batcher); ok {
		return b.ApplyChangeset(ctx, cs)
	}

	res := ApplyResult{Results: make([]ChangeResult, len(cs.Changes))}

	for _, i := range ApplyOrder(cs.Changes) {
		c := cs.Changes[i]
		rec, err := applyChange(ctx, p, cs.Zone, c)
		if errors.Is(err, ErrNoTenant) {
			return ApplyResult{}, err
		}

		res.Results[i] = ChangeResult{Change: c, Record: rec, Err: err}
	}

	return res, nil
}

// ApplyOrder is the order Apply makes changes in, as indexes into
// changes: deletions, then modifications, then additions, each in
// Changeset order; a change of no known kind goes with the additions. It
// is exported for providertest, whose fake Batcher makes one change at a
// time in the same order.
func ApplyOrder(changes []Change) []int {
	rank := func(k ChangeKind) int {
		switch k {
		case ChangeDelete:
			return 0
		case ChangeModify:
			return 1
		default:
			return 2
		}
	}

	order := make([]int, len(changes))
	for i := range order {
		order[i] = i
	}

	slices.SortStableFunc(order, func(a, b int) int {
		return rank(changes[a].Kind) - rank(changes[b].Kind)
	})

	return order
}

// applyChange makes one change with one CRUD call; an empty Record for a
// deletion and for a failed change.
func applyChange(ctx context.Context, p Provider, zone Zone, c Change) (Record, error) {
	var (
		rec Record
		err error
	)

	switch c.Kind {
	case ChangeAdd:
		rec, err = p.CreateRecord(ctx, zone, c.After)
	case ChangeModify:
		rec, err = p.UpdateRecord(ctx, zone, c.Before, c.After)
	case ChangeDelete:
		err = p.DeleteRecord(ctx, zone, c.Before)
	default:
		err = fmt.Errorf("unknown change kind %d", c.Kind)
	}

	if err != nil {
		return Record{}, err
	}

	return rec, nil
}
