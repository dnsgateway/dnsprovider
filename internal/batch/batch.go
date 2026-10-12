// Package batch makes single Record writes through a Provider's
// ApplyChangeset, for Providers whose CRUD methods are a one-change
// Changeset.
package batch

import (
	"context"
	"fmt"

	"github.com/dnsgateway/dnsprovider"
)

// Batcher applies a Changeset whole: a Provider declaring
// dnsprovider.CapBatcher.
type Batcher interface {
	ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error)
}

// Create adds a Record through a Batcher.
func Create(ctx context.Context, b Batcher, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return one(ctx, b, zone, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: r})
}

// Update changes before into after through a Batcher.
func Update(ctx context.Context, b Batcher, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return one(ctx, b, zone, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: before, After: after})
}

// Delete removes a Record through a Batcher.
func Delete(ctx context.Context, b Batcher, zone dnsprovider.Zone, r dnsprovider.Record) error {
	_, err := one(ctx, b, zone, dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: r})

	return err
}

// one applies a one-change Changeset and returns its Record, or the
// change's own error, the more specific, else the Changeset's; an error
// when the Batcher does not answer with exactly one result.
func one(ctx context.Context, b Batcher, zone dnsprovider.Zone, c dnsprovider.Change) (dnsprovider.Record, error) {
	res, err := b.ApplyChangeset(ctx, dnsprovider.Changeset{Zone: zone, Changes: []dnsprovider.Change{c}})
	if len(res.Results) == 1 && res.Results[0].Err != nil {
		return dnsprovider.Record{}, res.Results[0].Err
	}

	if err != nil {
		return dnsprovider.Record{}, err
	}

	if len(res.Results) != 1 {
		return dnsprovider.Record{}, fmt.Errorf("a one-change Changeset came back with %d results", len(res.Results))
	}

	return res.Results[0].Record, nil
}
