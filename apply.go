package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

// Apply rechecks Records modified or deleted by the Changeset and refuses
// writes with *StaleError (ErrStale) if any differ from their Before. It
// then hands the Changeset to ApplyChangeset when the Provider's Traits
// declare CapBatcher, or else applies changes in deletion,
// modification, and addition order. Individual failures do not stop other
// changes, except ErrNoTenant. Results follow Changeset order.
func Apply(ctx context.Context, p Provider, cs Changeset) (ApplyResult, error) {
	if err := recheck(ctx, p, cs); err != nil {
		return ApplyResult{}, err
	}

	if Can(p, CapBatcher) {
		return p.ApplyChangeset(ctx, cs)
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
// is exported for providertest, whose fake ApplyChangeset makes one change at a
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
