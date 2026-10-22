package netim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// UpdateRecord implements dnsprovider.Provider. It finds the Record as
// last read in a fresh read, then:
//
//   - a change of Value or TTL under the same owner and type is one Netim
//     zone update, which selects the Record by its subdomain, type and
//     value as held;
//   - a move to another owner or type deletes the Record and creates the
//     new one. Netim has no atomic move. If the create is refused, the
//     old Record is created again, and the error says whether that
//     restore held. After a create that is an Unconfirmed Write, the
//     Zone is read first, and nothing is restored when the read fails or
//     shows the old or the new Record.
//
// It returns the Record as read back. A Record the Zone no longer holds
// as read is ErrNotFound, and a destination the Zone holds already is
// ErrConflict; neither sends a write. Record options (Extras) are kept
// as they are: a change to them is refused, as is a move of a Record
// that has any.
func (p *Provider) UpdateRecord(ctx context.Context, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	if err := checkWritable(before.Type); err != nil {
		return dnsprovider.Record{}, err
	}

	extras := after.Extras
	after.Extras = nil

	after, w, err := prepare(zone, after)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	i, err := selectRecord(records, before)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	source := records[i]
	if !dnsprovider.SameExtras(source.Extras, extras) && (hasExtras(source.Extras) || hasExtras(extras)) {
		return dnsprovider.Record{}, errors.New("netim: cannot write record options (Extras)")
	}

	if err := rejectConflict(records, after, i); err != nil {
		return dnsprovider.Record{}, err
	}

	if source.Type != after.Type || !strings.EqualFold(source.Name, after.Name) {
		if hasExtras(source.Extras) {
			return dnsprovider.Record{}, errors.New("netim: cannot move a record with options (Extras): a create would drop them")
		}

		return p.move(ctx, zone, source, after, w)
	}

	body := map[string]any{"newValue": w.Value, "options": w.Options}
	for k, v := range selector(source.wire) {
		body[k] = v
	}

	if err := p.write(ctx, http.MethodPatch, domainPath(names.ZoneName(zone.Name), "zone", "update"), body); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("netim: update: %w", err)
	}

	return p.readBack(ctx, zone, after)
}

// move deletes source and creates after in its place, restoring source
// when the create did not take, as UpdateRecord describes.
func (p *Provider) move(ctx context.Context, zone dnsprovider.Zone, source entry, after dnsprovider.Record, w wireWrite) (dnsprovider.Record, error) {
	path := domainPath(names.ZoneName(zone.Name), "zone")

	if err := p.write(ctx, http.MethodDelete, path, selector(source.wire)); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("netim: move: delete: %w", err)
	}

	createErr := p.write(ctx, http.MethodPost, path, w)
	if createErr == nil {
		return p.readBack(ctx, zone, after)
	}

	const failed = "netim: move: the old record was deleted and the create failed"

	if errors.Is(createErr, dnsprovider.ErrUnconfirmed) {
		records, err := p.listRecords(ctx, zone)
		if err != nil {
			return dnsprovider.Record{}, fmt.Errorf("%s; nothing was restored, as the Zone could not be read: %w", failed, errors.Join(createErr, err))
		}

		for _, e := range records {
			if dnsprovider.SameRecord(e.Record, after) || dnsprovider.SameRecord(e.Record, source.Record) {
				return dnsprovider.Record{}, fmt.Errorf("%s; nothing was restored, as the Zone holds the old or the new record: %w", failed, createErr)
			}
		}
	}

	// The old Record as it was read, with its TTL now explicit.
	old, restore, err := prepare(zone, source.Record)
	if err == nil {
		err = p.write(ctx, http.MethodPost, path, restore)
	}

	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("%s; restoring the old record failed: %w", failed, errors.Join(createErr, err))
	}

	if _, err := p.readBack(ctx, zone, old); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("%s; restoring the old record was not confirmed: %w", failed, errors.Join(createErr, err))
	}

	return dnsprovider.Record{}, fmt.Errorf("%s; the old record was restored: %w", failed, createErr)
}
