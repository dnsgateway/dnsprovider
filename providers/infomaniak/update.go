package infomaniak

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// wireUpdate is a record as an update sends it: Infomaniak changes the
// target and TTL of a record in place, never its source or type.
type wireUpdate struct {
	Target string `json:"target"`
	TTL    uint32 `json:"ttl"`
}

// UpdateRecord implements dnsprovider.Provider. It finds before by its
// native ID in one list of the Zone, which also shows a collision: a
// before the Zone no longer holds is ErrNotFound, and an after the Zone
// holds already, by SameRecord, is ErrConflict, both without a write.
// A change of Value or TTL is one PUT, keeping the ID, and returns the
// Record as Infomaniak stored it. A move to another name or type creates
// the new Record, then deletes the old one by its ID, and returns the new
// Record; a failure between the two is reported with the outcome of both
// halves and is not undone.
func (p *Provider) UpdateRecord(ctx context.Context, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	if err := checkWritable(before.Type); err != nil {
		return dnsprovider.Record{}, err
	}

	if err := checkID("update", before); err != nil {
		return dnsprovider.Record{}, err
	}

	name, err := zoneOf(zone)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	r, w, err := prepare(name, after)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	held, err := p.ListRecords(ctx, zone, dnsprovider.RecordFilter{})
	if err != nil {
		return dnsprovider.Record{}, err
	}

	i := slices.IndexFunc(held.Records, func(h dnsprovider.Record) bool { return h.ID == before.ID })
	if i < 0 {
		return dnsprovider.Record{}, fmt.Errorf("infomaniak: no Record %s in Zone %s: %w", before.ID, name, dnsprovider.ErrNotFound)
	}

	current := held.Records[i]

	for _, h := range held.Records {
		if h.ID != before.ID && dnsprovider.SameRecord(h, r) {
			return dnsprovider.Record{}, fmt.Errorf("infomaniak: the Zone holds %s %s %q already: %w", r.Type, r.Name, r.Value, dnsprovider.ErrConflict)
		}
	}

	if current.Type == r.Type && strings.EqualFold(current.Name, r.Name) {
		data, err := p.write(ctx, http.MethodPut, zonePath(name, "records", before.ID), wireUpdate{Target: w.Target, TTL: w.TTL})
		if err != nil {
			return dnsprovider.Record{}, fmt.Errorf("infomaniak: update: %w", err)
		}

		return stored(name, "update", data)
	}

	created, err := p.create(ctx, name, w)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("infomaniak: move: creating the replacement failed; the original Record %s was not deleted: %w", before.ID, err)
	}

	if err := p.DeleteRecord(ctx, zone, current); err != nil {
		return created, fmt.Errorf("infomaniak: move: the replacement Record %s was created; deleting the original Record %s failed, and both may remain: %w", created.ID, before.ID, err)
	}

	return created, nil
}
