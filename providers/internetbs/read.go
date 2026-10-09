package internetbs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// ExtraWireValue preserves an API selector whose target formatting differs
// from the common Value. Consumers should retain it on Before Records.
const ExtraWireValue = "internetbs:wire_value"

type wireDomain struct {
	Name   string `json:"name"`
	NSList string `json:"nslist"`
}

// Zones reads the complete single-response domain inventory. Registration
// and its NSList alone do not establish whether DNS hosting is active.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	body, err := p.call(ctx, "Domain/List", url.Values{"CompactList": {"no"}, "ReturnFields": {"NSList"}})
	if err != nil {
		return nil, err
	}
	var domains []wireDomain
	if err := requiredList(body, "domain", &domains); err != nil {
		return nil, err
	}
	if err := checkCount(body, "domaincount", len(domains)); err != nil {
		return nil, err
	}
	out := make([]dnsprovider.Zone, 0, len(domains))
	for _, d := range domains {
		name := names.ZoneName(d.Name)
		if name == "" {
			return nil, errors.New("internetbs: domain list contains an empty name")
		}
		z := dnsprovider.Zone{ID: name, Name: name, State: dnsprovider.HostingUnknown}
		if err := checkZone(z); err != nil {
			return nil, p.cleanError(err)
		}
		for ns := range strings.SplitSeq(d.NSList, ",") {
			if ns = names.ZoneName(strings.TrimSpace(ns)); ns != "" {
				z.Nameservers = append(z.Nameservers, ns)
			}
		}
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}
	return out, nil
}

// Zone looks up a normalized exact domain name in the account inventory.
func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)
	zs, err := p.Zones(ctx, dnsprovider.ZoneFilter{})
	if err != nil {
		return dnsprovider.Zone{}, err
	}
	for _, z := range zs {
		if z.Name == name {
			return z, nil
		}
	}
	return dnsprovider.Zone{}, fmt.Errorf("internetbs: zone %q: %w", name, dnsprovider.ErrNotFound)
}

func checkCount(body map[string]json.RawMessage, field string, length int) error {
	var count int
	raw, ok := body[field]
	if !ok || string(raw) == "null" || json.Unmarshal(raw, &count) != nil || count != length {
		return fmt.Errorf("internetbs: incomplete or malformed %s", field)
	}
	return nil
}

type wireRecord struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Value    *string `json:"value"`
	TTL      *uint32 `json:"ttl"`
	Priority *uint32 `json:"priority"`
}

// Records reads all records and applies the common filters locally. Unknown
// types remain readable, including types the adapter cannot write.
func (p *Provider) Records(ctx context.Context, zone dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}
	out := make([]dnsprovider.Record, 0, len(records))
	for _, r := range records {
		if dnsprovider.MatchRecord(f, r) {
			out = append(out, r)
		}
	}
	return dnsprovider.RecordSet{Records: out}, nil
}

func (p *Provider) listRecords(ctx context.Context, zone dnsprovider.Zone) ([]dnsprovider.Record, error) {
	if err := checkZone(zone); err != nil {
		return nil, p.cleanError(err)
	}
	body, err := p.call(ctx, "Domain/DnsRecord/List", url.Values{"Domain": {names.ZoneName(zone.Name)}})
	if err != nil {
		return nil, err
	}
	var records []json.RawMessage
	if _, ok := body["records"]; ok {
		if err := requiredList(body, "records", &records); err != nil {
			return nil, err
		}
	}
	if err := checkCount(body, "total_records", len(records)); err != nil {
		return nil, err
	}
	out := make([]dnsprovider.Record, 0, len(records))
	for _, raw := range records {
		var w wireRecord
		if json.Unmarshal(raw, &w) != nil {
			return nil, errors.New("internetbs: malformed record")
		}
		r, err := toRecord(zone.Name, w)
		if err != nil {
			return nil, p.cleanError(err)
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		if _, reserved := fields[ExtraWireValue]; reserved {
			return nil, errors.New("internetbs: record metadata collides with reserved selector field")
		}
		for _, key := range []string{"name", "type", "value", "ttl"} {
			delete(fields, key)
		}
		if r.Type == "MX" {
			delete(fields, "priority")
		}
		if len(fields) > 0 {
			if r.Extras == nil {
				r.Extras = make(map[string]string, len(fields))
			}
			for key, value := range fields {
				r.Extras[key] = string(value)
			}
		}
		out = append(out, withID(r))
	}
	return out, nil
}

func toRecord(zone string, w wireRecord) (dnsprovider.Record, error) {
	if w.Name == "" || w.Type == "" || w.TTL == nil || w.Value == nil {
		return dnsprovider.Record{}, errors.New("internetbs: malformed record")
	}
	owner := names.ZoneName(w.Name)
	if owner == "@" {
		owner = names.ZoneName(zone)
	}
	if _, err := dnsprovider.QualifyName(names.ZoneName(zone), owner+"."); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("internetbs: malformed record owner: %w", err)
	}
	r := dnsprovider.Record{Name: owner, Type: strings.ToUpper(w.Type), Value: *w.Value, TTL: *w.TTL}
	switch r.Type {
	case "CNAME", "NS":
		r.Value = target(*w.Value)
	case "MX":
		if w.Priority == nil {
			return dnsprovider.Record{}, errors.New("internetbs: MX record has no priority")
		}
		r.Value = fmt.Sprintf("%d %s", *w.Priority, target(*w.Value))
	}
	if slices.Contains([]string{"A", "AAAA", "CNAME", "MX", "NS"}, r.Type) {
		if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
			return dnsprovider.Record{}, fmt.Errorf("internetbs: malformed record value: %w", err)
		}
	}
	if (r.Type == "CNAME" || r.Type == "NS" || r.Type == "MX") && target(*w.Value) != *w.Value {
		r.Extras = map[string]string{ExtraWireValue: *w.Value}
	}
	return withID(r), nil
}

func target(s string) string {
	if s == "." {
		return s
	}
	return strings.TrimSuffix(s, ".")
}

func withID(r dnsprovider.Record) dnsprovider.Record {
	identity, _ := json.Marshal([]any{r.Type, strings.ToLower(r.Name), r.TTL, r.Value, r.Extras[ExtraWireValue]})
	r.ID = fmt.Sprintf("%x", sha256.Sum256(identity))
	return r
}

func checkZone(zone dnsprovider.Zone) error {
	if err := dnsprovider.CheckValue("NS", names.ZoneName(zone.Name)); err != nil {
		return fmt.Errorf("internetbs: invalid zone name: %w", err)
	}
	return nil
}
