package porkbun

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// ttlRange is the TTLRange of every Provider, which its Traits
// report: the usual account minimum. Porkbun documents no universal
// maximum; the API remains authoritative for account-specific constraints.
var ttlRange = dnsprovider.TTLRange{Min: 600, Max: math.MaxUint32}

func (p *Provider) writeBody(z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, map[string]any, error) {
	r.Type = strings.ToUpper(r.Type)
	if r.Type == "URI" || !dnsprovider.Editable(r.Type) {
		return r, nil, errors.New("porkbun: unsupported record type for writes")
	}
	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return r, nil, err
	}
	if err := dnsprovider.TTLRangeOf(p).Check(r.TTL); err != nil {
		return r, nil, err
	}
	var err error
	r.Name, err = dnsprovider.QualifyName(names.ZoneName(z.Name), r.Name)
	if err != nil {
		return r, nil, err
	}
	name := names.RelativeName(z.Name, r.Name)
	if name == "@" {
		name = ""
	}
	content := r.Value
	priority := 0
	if r.Type == "MX" || r.Type == "SRV" {
		parts := strings.Fields(content)
		priority, err = strconv.Atoi(parts[0])
		if err != nil {
			return r, nil, errors.New("porkbun: invalid record priority")
		}
		content = strings.Join(parts[1:], " ")
		r.Value = strings.Join(parts, " ")
	}
	body := map[string]any{"name": name, "type": r.Type, "content": content, "ttl": r.TTL, "prio": priority}
	if notes, ok := r.Extras[ExtraNotes]; ok {
		body["notes"] = notes
	}
	return r, body, nil
}

func (p *Provider) collision(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record, except string) error {
	rs, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
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

// CreateRecord adds a nonduplicate Record and reads its stored representation.
func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	normalized, body, err := p.writeBody(z, r)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if err := p.collision(ctx, z, normalized, ""); err != nil {
		return dnsprovider.Record{}, err
	}
	var env struct{ ID string }
	if err := p.write(ctx, http.MethodPost, "/dns/create/"+zonePath(z), nil, body, &env); err != nil {
		return dnsprovider.Record{}, err
	}
	if env.ID == "" {
		return dnsprovider.Record{}, fmt.Errorf("porkbun: create succeeded without a record ID: %w", dnsprovider.ErrUnconfirmed)
	}
	stored, err := p.record(ctx, z, env.ID)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("porkbun: record created but readback failed: %w; %w", err, dnsprovider.ErrUnconfirmed)
	}
	return stored, nil
}

// UpdateRecord edits one native ID, retaining omitted server metadata.
func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	normalized, body, err := p.writeBody(z, after)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if _, err := p.record(ctx, z, before.ID); err != nil {
		return dnsprovider.Record{}, err
	}
	if err := p.collision(ctx, z, normalized, before.ID); err != nil {
		return dnsprovider.Record{}, err
	}
	if err := p.write(ctx, http.MethodPost, "/dns/edit/"+zonePath(z)+"/"+url.PathEscape(before.ID), nil, body, nil); err != nil {
		return dnsprovider.Record{}, err
	}
	stored, err := p.record(ctx, z, before.ID)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("porkbun: record updated but readback failed: %w; %w", err, dnsprovider.ErrUnconfirmed)
	}
	return stored, nil
}

// DeleteRecord removes only the Record identified by its native ID.
func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	if r.ID == "" {
		return dnsprovider.ErrNotFound
	}
	return p.write(ctx, http.MethodPost, "/dns/delete/"+zonePath(z)+"/"+url.PathEscape(r.ID), nil, map[string]any{}, nil)
}

// Authentication field names accepted by Factory.
const (
	FieldKey    = "key"
	FieldSecret = "secret"
)

// Factory builds a Provider from secret key and secret fields.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{
		{Name: FieldKey, Label: "API key", Secret: true},
		{Name: FieldSecret, Label: "Secret API key", Secret: true},
	}
	return fields.Factory("porkbun", fs, traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Key: m[FieldKey], Secret: m[FieldSecret]}, opts...)
	})
}

// traits are the Traits of every Provider, which Traits and Factory
// report.
var traits = dnsprovider.Traits{
	Capabilities: []dnsprovider.Capability{dnsprovider.CapDSRegistrar},
	TTL:          ttlRange,
	Extras:       []dnsprovider.ExtraSpec{{Key: ExtraNotes, Label: "Notes", Kind: dnsprovider.ExtraString, Writable: true}},
}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}

var _ dnsprovider.Provider = (*Provider)(nil)
