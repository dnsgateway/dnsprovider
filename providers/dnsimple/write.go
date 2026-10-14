package dnsimple

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// ttlRange is the TTLRange of every Provider, which its Traits
// report: the API schema minimum and the public uint32 ceiling. DNSimple
// enforces any narrower plan or traffic restrictions.
var ttlRange = dnsprovider.TTLRange{Min: 0, Max: ^uint32(0)}

func (p *Provider) payload(z dnsprovider.Zone, r dnsprovider.Record) (map[string]any, error) {
	r.Type = strings.ToUpper(r.Type)
	if !dnsprovider.Editable(r.Type) || r.Type == "URI" {
		return nil, fmt.Errorf("dnsimple: unsupported Record type %s", r.Type)
	}
	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return nil, err
	}
	if err := dnsprovider.TTLRangeOf(p).Check(r.TTL); err != nil {
		return nil, err
	}
	abs, err := dnsprovider.QualifyName(z.Name, r.Name)
	if err != nil {
		return nil, err
	}
	name := names.RelativeName(z.Name, abs)
	if name == "@" {
		name = ""
	}
	if r.Type == "CNAME" && name == "" {
		return nil, errors.New("dnsimple: CNAME is unsupported at the Zone apex")
	}
	body := map[string]any{"name": name, "type": r.Type, "content": r.Value, "ttl": r.TTL, "integrated_zones": []string{"dnsimple"}}
	if r.Type == "MX" || r.Type == "SRV" {
		var priority, content string
		// CheckValue accepts whitespace separators, so split at the first field.
		fs := strings.Fields(r.Value)
		priority = fs[0]
		content = strings.Join(fs[1:], " ")
		n, _ := strconv.ParseUint(priority, 10, 16)
		body["priority"] = n
		body["content"] = content
	}
	return body, nil
}

func (p *Provider) collision(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record, exclude string) error {
	abs, err := dnsprovider.QualifyName(z.Name, r.Name)
	if err != nil {
		return err
	}
	r.Name = abs
	set, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
	if err != nil {
		return err
	}
	for _, stored := range set.Records {
		if stored.ID != exclude && (dnsprovider.SameRecord(stored, r) || (strings.EqualFold(r.Type, "CNAME") && strings.EqualFold(stored.Name, r.Name))) {
			return fmt.Errorf("dnsimple: duplicate Record: %w", dnsprovider.ErrConflict)
		}
	}
	return nil
}

func (p *Provider) stored(ctx context.Context, z dnsprovider.Zone, id string) (wireRecord, error) {
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != id {
		return wireRecord{}, fmt.Errorf("dnsimple: missing or invalid Record ID: %w", dnsprovider.ErrNotFound)
	}
	var w wireRecord
	if _, err := p.data(ctx, http.MethodGet, p.recordPath(z)+"/"+url.PathEscape(id), nil, nil, &w); err != nil {
		return wireRecord{}, err
	}
	if _, err := toRecord(z.Name, w); err != nil {
		return wireRecord{}, err
	}
	if strconv.FormatUint(w.ID, 10) != id {
		return wireRecord{}, errors.New("dnsimple: response names a different Record")
	}
	return w, nil
}

// written is data for a write: an answer of success it cannot decode is
// an Unconfirmed Write.
func (p *Provider) written(ctx context.Context, method, path string, body, out any) error {
	var raw []byte
	if err := p.api().Write(ctx, method, path, nil, body, &raw); err != nil {
		return err
	}
	_, err := decodeData(raw, path, out)
	return dnsprovider.Unconfirmed(err)
}

func (p *Provider) create(ctx context.Context, z dnsprovider.Zone, body map[string]any) (dnsprovider.Record, error) {
	var w wireRecord
	if err := p.written(ctx, http.MethodPost, p.recordPath(z), body, &w); err != nil {
		return dnsprovider.Record{}, err
	}
	r, err := toRecord(z.Name, w)
	return r, dnsprovider.Unconfirmed(err)
}

// CreateRecord checks duplicates regardless of TTL and returns the API's
// authoritative Record. POST is never retried: a lost answer is an
// Unconfirmed Write.
func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	body, err := p.payload(z, r)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if err := p.collision(ctx, z, r, ""); err != nil {
		return dnsprovider.Record{}, err
	}
	return p.create(ctx, z, body)
}

func restricted(w wireRecord) bool { return w.System || (w.ParentID != nil && *w.ParentID != 0) }
func restriction() error {
	return &dnsprovider.APIError{Provider: "dnsimple", Kind: dnsprovider.ErrUnauthorized, Messages: []string{"system and service-managed Records cannot be edited"}}
}

// UpdateRecord patches modeled fields in place, leaving metadata untouched.
// A type move normally creates a replacement before deleting the original.
// Exclusive CNAME moves delete first. Failures report the partial outcome.
func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	body, err := p.payload(z, after)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	current, err := p.stored(ctx, z, before.ID)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if restricted(current) {
		return dnsprovider.Record{}, restriction()
	}
	if err := p.collision(ctx, z, after, before.ID); err != nil {
		return dnsprovider.Record{}, err
	}
	if strings.EqualFold(current.Type, after.Type) {
		delete(body, "type")
		var w wireRecord
		if err := p.written(ctx, http.MethodPatch, p.recordPath(z)+"/"+url.PathEscape(before.ID), body, &w); err != nil {
			return dnsprovider.Record{}, err
		}
		if strconv.FormatUint(w.ID, 10) != before.ID {
			return dnsprovider.Record{}, fmt.Errorf("dnsimple: response names a different Record: %w", dnsprovider.ErrUnconfirmed)
		}
		r, err := toRecord(z.Name, w)
		return r, dnsprovider.Unconfirmed(err)
	}
	// Do not resend the default global region: regional writes are plan gated.
	// A non-default placement must transfer, or creation fails before deletion.
	if len(current.Regions) > 0 && !(len(current.Regions) == 1 && current.Regions[0] == "global") {
		body["regions"] = current.Regions
	}
	// A CNAME cannot coexist with other data at its owner. For this move,
	// deleting first is unavoidable; a failed creation leaves a partial move.
	deleteFirst := strings.EqualFold(*current.Name, body["name"].(string)) && (current.Type == "CNAME" || strings.EqualFold(after.Type, "CNAME"))
	if deleteFirst {
		if err := p.api().Write(ctx, http.MethodDelete, p.recordPath(z)+"/"+url.PathEscape(before.ID), nil, nil, nil); err != nil {
			return dnsprovider.Record{}, fmt.Errorf("dnsimple: deleting original Record %s failed; replacement was not requested: %w", before.ID, err)
		}
		replacement, err := p.create(ctx, z, body)
		if err != nil {
			return dnsprovider.Record{}, fmt.Errorf("dnsimple: original Record %s was deleted; replacement creation failed: %w", before.ID, err)
		}
		return replacement, nil
	}
	replacement, err := p.create(ctx, z, body)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if err := p.api().Write(ctx, http.MethodDelete, p.recordPath(z)+"/"+url.PathEscape(before.ID), nil, nil, nil); err != nil {
		return replacement, fmt.Errorf("dnsimple: replacement Record %s was created; deleting original %s failed (both may remain): %w", replacement.ID, before.ID, err)
	}
	return replacement, nil
}

// DeleteRecord removes only the native ID selected by the caller.
func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	current, err := p.stored(ctx, z, r.ID)
	if err != nil {
		return err
	}
	if restricted(current) {
		return restriction()
	}
	return p.api().Write(ctx, http.MethodDelete, p.recordPath(z)+"/"+url.PathEscape(r.ID), nil, nil, nil)
}
