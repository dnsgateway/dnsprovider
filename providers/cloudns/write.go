package cloudns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// TTLRange reports documented bounds. Only the discrete TTLs returned for
// a Zone by get-available-ttl may be written; no automatic TTL is supported.
func (p *Provider) TTLRange() (minTTL, maxTTL uint32) {
	return ttlRange.Min, ttlRange.Max
}

// ttlRange is the TTLRange of every Provider, which TTLRange and
// Factory report.
var ttlRange = dnsprovider.TTLRange{Min: 60, Max: 2592000}

func (p *Provider) writeParams(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (url.Values, error) {
	if !slices.Contains([]string{"A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT", "CAA"}, r.Type) {
		return nil, fmt.Errorf("cloudns: unsupported record type %s", p.redact(r.Type))
	}
	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return nil, &redactedError{message: p.redact(err.Error()), cause: err}
	}
	if err := dnsprovider.TTLRangeOf(p).Check(r.TTL); err != nil {
		return nil, err
	}
	var ttls []json.Number
	if err := p.call(ctx, "/dns/get-available-ttl.json", url.Values{"domain-name": {z.Name}}, &ttls); err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(ttls, func(n json.Number) bool { return n.String() == strconv.FormatUint(uint64(r.TTL), 10) }) {
		return nil, fmt.Errorf("cloudns: TTL %d is unavailable for this Zone", r.TTL)
	}
	name, err := dnsprovider.QualifyName(z.Name, r.Name)
	if err != nil {
		return nil, err
	}
	host := names.RelativeName(z.Name, name)
	if host == "@" {
		host = ""
	}
	q := url.Values{"domain-name": {z.Name}, "record-type": {r.Type}, "host": {host}, "record": {r.Value}, "ttl": {strconv.FormatUint(uint64(r.TTL), 10)}}
	f := strings.Fields(r.Value)
	switch r.Type {
	case "MX":
		q.Set("priority", f[0])
		q.Set("record", f[1])
	case "SRV":
		q.Set("priority", f[0])
		q.Set("weight", f[1])
		q.Set("port", f[2])
		q.Set("record", f[3])
	case "CAA":
		value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(r.Value, f[0])), f[1]))
		if strings.HasPrefix(value, `"`) {
			value, err = unquoteDNS(value)
			if err != nil {
				return nil, errors.New("cloudns: malformed quoted CAA value")
			}
		}
		q.Del("record")
		q.Set("caa_flag", f[0])
		q.Set("caa_type", f[1])
		q.Set("caa_value", value)
	}
	return q, nil
}

func (p *Provider) collision(ctx context.Context, z dnsprovider.Zone, q url.Values, except string) error {
	rs, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if err != nil {
		return err
	}
	r, err := expectedRecord(z, q)
	if err != nil {
		return err
	}
	for _, existing := range rs.Records {
		if existing.ID != except && dnsprovider.SameRecord(existing, r) {
			return dnsprovider.ErrConflict
		}
	}
	return nil
}

func (p *Provider) stored(ctx context.Context, z dnsprovider.Zone, id string) (dnsprovider.Record, error) {
	rs, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if err != nil {
		return dnsprovider.Record{}, err
	}
	for _, r := range rs.Records {
		if r.ID == id {
			return r, nil
		}
	}
	return dnsprovider.Record{}, dnsprovider.ErrNotFound
}

// CreateRecord creates exactly one Record, then reads its authoritative form.
func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	q, err := p.writeParams(ctx, z, r)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if err = p.collision(ctx, z, q, ""); err != nil {
		return dnsprovider.Record{}, err
	}
	return p.create(ctx, z, q)
}

func (p *Provider) create(ctx context.Context, z dnsprovider.Zone, q url.Values) (dnsprovider.Record, error) {
	prior, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if err != nil {
		return dnsprovider.Record{}, err
	}
	known := make(map[string]bool, len(prior.Records))
	for _, r := range prior.Records {
		known[r.ID] = true
	}
	if err = p.ack(ctx, "/dns/add-record.json", q); err != nil {
		return dnsprovider.Record{}, err
	}
	rs, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("cloudns: create acknowledged but readback failed: %w", err)
	}
	expected, err := expectedRecord(z, q)
	if err != nil {
		return dnsprovider.Record{}, errors.New("cloudns: create acknowledged but expected record could not be decoded")
	}
	var found []dnsprovider.Record
	for _, r := range rs.Records {
		if !known[r.ID] && dnsprovider.SameRecord(r, expected) {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		return dnsprovider.Record{}, errors.New("cloudns: create acknowledged but readback did not identify exactly one new Record; write may have succeeded")
	}
	return found[0], nil
}

// metadataParams retains supported provider metadata when writing a Record.
func metadataParams(raw wireRecord) url.Values {
	q := url.Values{}
	for _, k := range []string{"geodns-location", "geodns-code"} {
		if v := raw[strings.ReplaceAll(k, "-", "_")]; v != "" {
			q.Set(k, v)
		}
	}
	return q
}

func (p *Provider) selected(ctx context.Context, z dnsprovider.Zone, id string) (wireRecord, error) {
	if id == "" {
		return nil, dnsprovider.ErrNotFound
	}
	raw, err := p.rawRecords(ctx, z)
	if err != nil {
		return nil, err
	}
	for _, w := range raw {
		if w["id"] == id {
			return w, nil
		}
	}
	return nil, dnsprovider.ErrNotFound
}

func (p *Provider) ack(ctx context.Context, path string, q url.Values) error {
	var env struct {
		Status string `json:"status"`
	}
	if err := p.call(ctx, path, q, &env); err != nil {
		return err
	}
	if !strings.EqualFold(env.Status, "Success") {
		return errors.New("cloudns: malformed mutation acknowledgement; write may have succeeded")
	}
	return nil
}

// UpdateRecord edits modeled fields by ID. Type moves create a replacement
// before deleting the old Record, and expose any partial failure.
func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	raw, err := p.selected(ctx, z, before.ID)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	q, err := p.writeParams(ctx, z, after)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if err = p.collision(ctx, z, q, before.ID); err != nil {
		return dnsprovider.Record{}, err
	}
	maps.Copy(q, metadataParams(raw))
	if raw["type"] != after.Type {
		return p.moveType(ctx, z, raw, q)
	}
	q.Set("record-id", before.ID)
	q.Del("record-type")
	if err = p.ack(ctx, "/dns/mod-record.json", q); err != nil {
		return dnsprovider.Record{}, err
	}
	r, err := p.stored(ctx, z, before.ID)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("cloudns: update acknowledged but readback failed: %w", err)
	}
	return r, nil
}

func (p *Provider) moveType(ctx context.Context, z dnsprovider.Zone, raw wireRecord, q url.Values) (dnsprovider.Record, error) {
	// Fields without a documented preservation mechanism must not disappear
	// in a replacement. Same-type updates leave these fields on the server.
	for k, v := range raw {
		if v == "" {
			continue
		}
		if !slices.Contains([]string{"id", "type", "host", "record", "ttl", "priority", "weight", "port", "caa_flag", "caa_type", "caa_value", "status", "note", "geodns_location", "geodns_code"}, k) {
			return dnsprovider.Record{}, errors.New("cloudns: type change cannot preserve unfamiliar record metadata")
		}
	}
	if status := raw["status"]; status != "" && status != "0" && status != "1" {
		return dnsprovider.Record{}, errors.New("cloudns: type change cannot preserve an unfamiliar record activation state")
	}
	if raw["note"] != "" && p.cfg.AuthID == "" {
		return dnsprovider.Record{}, errors.New("cloudns: type change of a noted Record requires main API credentials to preserve its note")
	}
	if status := raw["status"]; status != "" {
		q.Set("status", status)
	}
	created, err := p.create(ctx, z, q)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if note := raw["note"]; note != "" {
		if err = p.ack(ctx, "/dns/set-record-note.json", url.Values{"domain-name": {z.Name}, "record-id": {created.ID}, "note": {note}}); err != nil {
			return dnsprovider.Record{}, fmt.Errorf("cloudns: replacement %s created, note failed; original %s remains: %w", p.redact(created.ID), p.redact(raw["id"]), err)
		}
	}
	if err = p.ack(ctx, "/dns/delete-record.json", url.Values{"domain-name": {z.Name}, "record-id": {raw["id"]}}); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("cloudns: replacement %s created, original %s deletion failed: %w", p.redact(created.ID), p.redact(raw["id"]), err)
	}
	stored, err := p.stored(ctx, z, created.ID)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("cloudns: replacement completed but readback failed: %w", err)
	}
	return stored, nil
}

// DeleteRecord deletes only the selected native Record ID.
func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	if _, err := p.selected(ctx, z, r.ID); err != nil {
		return err
	}
	return p.ack(ctx, "/dns/delete-record.json", url.Values{"domain-name": {z.Name}, "record-id": {r.ID}})
}

func expectedRecord(z dnsprovider.Zone, q url.Values) (dnsprovider.Record, error) {
	wire := wireRecord{"id": "created", "type": q.Get("record-type")}
	for k, values := range q {
		if len(values) > 0 {
			wire[k] = values[0]
		}
	}
	return wire.public(z.Name)
}
