package inwx

import (
	"context"
	"fmt"

	"github.com/dnsgateway/dnsprovider"
)

// UpdateRecord implements dnsprovider.Provider: it changes the Record
// of before's native ID into after, with one nameserver.updateRecord
// that sends the name, type, content, TTL and priority, so a move to
// another name or type is one write, never create-then-delete. Record
// IDs are unique across the account, so a fresh read first confirms the
// ID is this Zone's (ErrNotFound without a write otherwise); another
// Record the same as after, by SameRecord, is ErrConflict without a
// write. The answer carries no Record: the stored one is read back by
// its ID, and a read-back that fails or does not show after is an
// Unconfirmed Write. The write is never repeated.
func (p *Provider) UpdateRecord(ctx context.Context, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	name, err := namedZone(zone.Name)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := checkWritable(before.Type); err != nil {
		return dnsprovider.Record{}, err
	}

	id, err := checkID("update", before)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	r, params, err := prepare(name, after)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := p.checkRecordInZone(ctx, name, id); err != nil {
		return dnsprovider.Record{}, err
	}

	if err := p.unique(ctx, name, r, id); err != nil {
		return dnsprovider.Record{}, err
	}

	params["id"] = id

	if _, err := p.write(ctx, "nameserver.updateRecord", params, pendingUnconfirmed); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("inwx: update: %w", err)
	}

	return p.readBack(ctx, name, id, r)
}
