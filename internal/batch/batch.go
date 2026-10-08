// Package batch makes single Record writes through a Provider's
// dnsprovider.Batcher, for Providers whose CRUD methods are a one-change
// Changeset.
package batch

import (
	"context"
	"fmt"

	"github.com/dnsgateway/dnsprovider"
)

// Create adds a Record through a Batcher.
func Create(ctx context.Context, b dnsprovider.Batcher, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return one(ctx, b, zone, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: r})
}

// Update changes before into after through a Batcher.
func Update(ctx context.Context, b dnsprovider.Batcher, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return one(ctx, b, zone, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: before, After: after})
}

// Delete removes a Record through a Batcher.
func Delete(ctx context.Context, b dnsprovider.Batcher, zone dnsprovider.Zone, r dnsprovider.Record) error {
	_, err := one(ctx, b, zone, dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: r})

	return err
}

// one applies a one-change Changeset and returns its Record, or the
// Changeset's error or the change's own; an error when the Batcher does
// not answer with exactly one result.
func one(ctx context.Context, b dnsprovider.Batcher, zone dnsprovider.Zone, c dnsprovider.Change) (dnsprovider.Record, error) {
	res, err := b.ApplyChangeset(ctx, dnsprovider.Changeset{Zone: zone, Changes: []dnsprovider.Change{c}})
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if len(res.Results) != 1 {
		return dnsprovider.Record{}, fmt.Errorf("a one-change Changeset came back with %d results", len(res.Results))
	}

	r := res.Results[0]
	if r.Err != nil {
		return dnsprovider.Record{}, r.Err
	}

	return r.Record, nil
}
