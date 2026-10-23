package inwx

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// codeServerFailures is the first of the server-side failure codes: 2400
// (command failed) and the 25xx codes, as in EPP. INWX may have run a
// write it answers with one.
const codeServerFailures = 2400

// pending is what a write answered with a success code other than 1000,
// such as 1001 ("action pending"), counts as.
type pending int

const (
	// pendingUnconfirmed counts it an Unconfirmed Write, as for a Record
	// write.
	pendingUnconfirmed pending = iota
	// pendingTaken counts it done, as for a Zone write or a DNSSEC
	// write.
	pendingTaken
)

// checkWritable refuses, without a request, a Record type the adapter
// does not write: every type this module edits.
func checkWritable(typ string) error {
	if !dnsprovider.Editable(strings.ToUpper(strings.TrimSpace(typ))) {
		return fmt.Errorf("inwx: cannot write %s records", typ)
	}

	return nil
}

// checkID refuses, without a request, a Record without INWX's numeric
// ID, and returns the ID.
func checkID(op string, r dnsprovider.Record) (string, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.ID), 10, 64)
	if err != nil || id <= 0 {
		return "", fmt.Errorf("inwx: %s: the Record has no INWX ID; read it from ListRecords", op)
	}

	return strconv.FormatInt(id, 10), nil
}

// prepare checks a Record to write to the zone, before any request. It
// returns the Record as nameserver.info reads it back and the params
// every Record write sends, which a create adds the zone's domain to:
// the full name without a trailing dot, the type, the content, the TTL
// and the priority, which INWX keeps apart from the content of an MX,
// SRV or URI. Host names lose their trailing dot.
func prepare(zone string, r dnsprovider.Record) (dnsprovider.Record, map[string]any, error) {
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	if err := checkWritable(r.Type); err != nil {
		return dnsprovider.Record{}, nil, err
	}

	for k, v := range r.Extras {
		if v != "" {
			return dnsprovider.Record{}, nil, fmt.Errorf("inwx: cannot write the Extra %q", k)
		}
	}

	name, err := dnsprovider.QualifyName(zone, r.Name)
	if err != nil {
		return dnsprovider.Record{}, nil, fmt.Errorf("inwx: %w", err)
	}

	r.Name = names.ZoneName(name)

	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return dnsprovider.Record{}, nil, fmt.Errorf("inwx: %w", err)
	}

	if err := traits.TTL.Check(r.TTL); err != nil {
		return dnsprovider.Record{}, nil, fmt.Errorf("inwx: %w", err)
	}

	content, prio := r.Value, uint64(0)
	f := strings.Fields(r.Value)

	switch r.Type {
	case "CNAME", "NS":
		content = bare(r.Value)
	case "MX":
		prio, _ = strconv.ParseUint(f[0], 10, 16)
		content = bare(f[1])
	case "SRV":
		prio, _ = strconv.ParseUint(f[0], 10, 16)
		content = f[1] + " " + f[2] + " " + bare(f[3])
	case "URI":
		prio, _ = strconv.ParseUint(f[0], 10, 16)
		content = f[1] + " " + f[2]
	}

	if r.Value, err = presentation(r.Type, content, wireInt(prio)); err != nil { //nolint:gosec // a 16-bit priority.
		return dnsprovider.Record{}, nil, fmt.Errorf("inwx: %w", err)
	}

	params := map[string]any{"name": r.Name, "type": r.Type, "content": content, "ttl": r.TTL, "prio": prio}

	return r, params, nil
}

// bare is a host name without its trailing dot, as INWX stores it; the
// root stays ".".
func bare(name string) string {
	name = strings.TrimSpace(name)
	if name == "." {
		return name
	}

	return strings.TrimSuffix(name, ".")
}

// write sends a call that changes what INWX holds, once, with the
// session, and returns its answer. Code 1000 confirms it; another
// success code, such as 1001, confirms it too when onPending is
// pendingTaken and is an Unconfirmed Write when it is pendingUnconfirmed. A refusal
// (2000-2399) is an APIError, which says nothing was applied. A
// server-side failure code (2400 and up), a lost answer, any non-200
// answer and an answer that cannot be decoded are Unconfirmed Writes.
// The call is never repeated, other than once with a new session when
// INWX refuses the session, before running it.
func (p *Provider) write(ctx context.Context, method string, params map[string]any, onPending pending) (envelope, error) {
	return p.send(ctx, func(c *rest.Client) (envelope, error) {
		env, err := exchange(ctx, c.Write, method, params)

		switch {
		case errors.Is(err, errMalformed):
			return envelope{}, fmt.Errorf("%w: %w", err, dnsprovider.ErrUnconfirmed)
		case err != nil:
			// INWX answers every call with HTTP 200: a 4xx, which
			// Write keeps as a refusal, does not say the write failed.
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				err = fmt.Errorf("%w; %w", err, dnsprovider.ErrUnconfirmed)
			}

			return envelope{}, err
		}

		switch {
		case env.Code == codeSuccess, onPending == pendingTaken && env.Code < codeRefusals:
			return env, nil
		case env.Code >= codeServerFailures:
			return envelope{}, fmt.Errorf("%w; %w", c.RedactError(env.apiError()), dnsprovider.ErrUnconfirmed)
		case env.Code >= codeRefusals:
			return envelope{}, c.RedactError(env.apiError())
		}

		return envelope{}, fmt.Errorf("inwx: %s: answered %d %s: %w", method, env.Code, c.Redact(env.Msg), dnsprovider.ErrUnconfirmed)
	})
}

// readBack reads the record of id in the zone, after a write INWX
// confirmed, and returns it when it is want with its TTL. A failed
// read, or a record missing or other than want, is an Unconfirmed
// Write; the write is never sent again.
func (p *Provider) readBack(ctx context.Context, zone, id string, want dnsprovider.Record) (dnsprovider.Record, error) {
	info, err := p.zoneInfo(ctx, zone, map[string]any{"domain": zone, "recordId": id})
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("inwx: the write was confirmed but the read-back of record %s failed: %w; %w", id, err, dnsprovider.ErrUnconfirmed)
	}

	for _, w := range info.Records {
		if w.ID.String() != id {
			continue
		}

		r, err := toRecord(zone, w)
		if err != nil {
			return dnsprovider.Record{}, fmt.Errorf("inwx: the write was confirmed but its read-back failed: %w; %w", err, dnsprovider.ErrUnconfirmed)
		}

		if !dnsprovider.SameRecord(r, want) || r.TTL != want.TTL {
			return dnsprovider.Record{}, fmt.Errorf("inwx: the write was confirmed but record %s reads back as %s %s %q TTL %d: %w",
				id, r.Type, r.Name, r.Value, r.TTL, dnsprovider.ErrUnconfirmed)
		}

		return r, nil
	}

	return dnsprovider.Record{}, fmt.Errorf("inwx: the write was confirmed but the zone holds no record %s: %w", id, dnsprovider.ErrUnconfirmed)
}

// unique confirms with a fresh read that the zone holds no Record the
// same as r, by SameRecord, other than the one of the ID except: a
// duplicate is ErrConflict.
func (p *Provider) unique(ctx context.Context, zone string, r dnsprovider.Record, except string) error {
	held, err := p.ListRecords(ctx, dnsprovider.Zone{Name: zone}, dnsprovider.RecordFilter{Type: r.Type})
	if err != nil {
		return err
	}

	for _, h := range held.Records {
		if h.ID != except && dnsprovider.SameRecord(h, r) {
			return fmt.Errorf("inwx: the Zone holds %s %s %q already: %w", r.Type, r.Name, r.Value, dnsprovider.ErrConflict)
		}
	}

	return nil
}

// checkRecordInZone confirms with a fresh nameserver.info (recordId)
// that the zone holds the record of id. Record IDs are unique across the account, so
// one the zone does not hold, another Zone's or a deleted one, is
// ErrNotFound.
func (p *Provider) checkRecordInZone(ctx context.Context, zone, id string) error {
	info, err := p.zoneInfo(ctx, zone, map[string]any{"domain": zone, "recordId": id})
	if err != nil {
		return err
	}

	for _, w := range info.Records {
		if w.ID.String() == id {
			return nil
		}
	}

	return fmt.Errorf("inwx: the Zone %s holds no record %s: %w", zone, id, dnsprovider.ErrNotFound)
}

// CreateRecord implements dnsprovider.Provider: it adds an A, AAAA,
// CNAME, MX, TXT, NS, SRV, CAA or URI Record with its TTL in seconds,
// sending nameserver.createRecord once, and returns the Record read back
// by the ID INWX answers. A Record the Zone holds already, by
// SameRecord, is ErrConflict without a write, as is INWX's 2302.
func (p *Provider) CreateRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	name, err := namedZone(zone.Name)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	r, params, err := prepare(name, r)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := p.unique(ctx, name, r, ""); err != nil {
		return dnsprovider.Record{}, err
	}

	params["domain"] = name

	env, err := p.write(ctx, "nameserver.createRecord", params, pendingUnconfirmed)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("inwx: create: %w", err)
	}

	var created struct {
		ID wireInt `json:"id"`
	}
	if err := decode(env.ResData, &created); err != nil || created.ID <= 0 {
		return dnsprovider.Record{}, fmt.Errorf("inwx: create: the answer holds no record id: %w", dnsprovider.ErrUnconfirmed)
	}

	return p.readBack(ctx, name, created.ID.String(), r)
}

// DeleteRecord implements dnsprovider.Provider: it deletes the Record
// by its native ID, with one nameserver.deleteRecord. Record IDs are
// unique across the account, so a fresh read first confirms the ID is
// one of this Zone's: a Record it does not hold is ErrNotFound without a
// write. A Record without an ID, or of a type the adapter does not
// write, fails without a request.
func (p *Provider) DeleteRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) error {
	name, err := namedZone(zone.Name)
	if err != nil {
		return err
	}

	if err := checkWritable(r.Type); err != nil {
		return err
	}

	id, err := checkID("delete", r)
	if err != nil {
		return err
	}

	if err := p.checkRecordInZone(ctx, name, id); err != nil {
		return err
	}

	if _, err := p.write(ctx, "nameserver.deleteRecord", map[string]any{"id": id}, pendingUnconfirmed); err != nil {
		return fmt.Errorf("inwx: delete: %w", err)
	}

	return nil
}
