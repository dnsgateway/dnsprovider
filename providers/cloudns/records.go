package cloudns

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

type wireRecord map[string]string

func (w *wireRecord) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw == nil {
		return errors.New("cloudns: null record")
	}
	result := make(wireRecord, len(raw))
	for k, v := range raw {
		var str string
		if string(v) == "null" {
			if slices.Contains([]string{"id", "type", "host", "record", "ttl", "priority", "weight", "port", "caa_flag", "caa_type", "caa_value"}, k) {
				return errors.New("cloudns: null modeled record field")
			}
			result[k] = "null"
			continue
		}
		if err := json.Unmarshal(v, &str); err != nil {
			var n json.Number
			if err = json.Unmarshal(v, &n); err != nil {
				if slices.Contains([]string{"id", "type", "host", "record", "ttl", "priority", "weight", "port", "caa_flag", "caa_type", "caa_value"}, k) {
					return errors.New("cloudns: malformed modeled record field")
				}
				str = string(v)
				result[k] = str
				continue
			}
			str = n.String()
		}
		result[k] = str
	}
	*w = result
	return nil
}

func (w wireRecord) public(zone string) (dnsprovider.Record, error) {
	ttl, err := strconv.ParseUint(w["ttl"], 10, 32)
	if err != nil {
		return dnsprovider.Record{}, errors.New("cloudns: malformed record TTL")
	}
	if w["id"] == "" || w["type"] == "" {
		return dnsprovider.Record{}, errors.New("cloudns: record lacks ID or type")
	}
	if _, ok := w["host"]; !ok {
		return dnsprovider.Record{}, errors.New("cloudns: record lacks host")
	}
	typ := strings.ToUpper(w["type"])
	for i, c := range typ {
		if (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return dnsprovider.Record{}, errors.New("cloudns: malformed record type")
		}
	}
	value := w["record"]
	target := func(s string) string {
		if s == "." {
			return s
		}
		return strings.TrimSuffix(s, ".")
	}
	switch typ {
	case "CNAME", "NS":
		value = target(value)
	case "MX":
		value = w["priority"] + " " + target(value)
	case "SRV":
		value = w["priority"] + " " + w["weight"] + " " + w["port"] + " " + target(value)
	case "CAA":
		value = w["caa_flag"] + " " + w["caa_type"] + " " + charstr.Quote(w["caa_value"])
	}
	extras := maps.Clone(w)
	for _, k := range []string{"id", "type", "host", "record", "ttl", "priority", "weight", "port", "caa_flag", "caa_type", "caa_value"} {
		delete(extras, k)
	}
	if dnsprovider.Editable(typ) {
		if err := dnsprovider.CheckValue(typ, value); err != nil {
			return dnsprovider.Record{}, errors.New("cloudns: malformed structured record value")
		}
	}
	return dnsprovider.Record{ID: w["id"], Type: typ, Name: names.AbsoluteName(names.ZoneName(zone), w["host"]), Value: value, TTL: uint32(ttl), Extras: extras}, nil
}

func (p *Provider) rawRecords(ctx context.Context, zone dnsprovider.Zone) ([]wireRecord, error) {
	return rest.Pages(100, nil, func(page rest.Page) ([]wireRecord, error) {
		var raw json.RawMessage
		q := url.Values{
			"domain-name": {zone.Name}, "page": {strconv.Itoa(page.Number)},
			"rows-per-page": {strconv.Itoa(page.Size)}, "include-notes": {"1"},
		}
		if err := p.call(ctx, "/dns/records.json", q, &raw); err != nil {
			return nil, err
		}
		if len(raw) > 0 && raw[0] == '[' {
			var empty []json.RawMessage
			if json.Unmarshal(raw, &empty) == nil && len(empty) == 0 {
				return nil, nil
			}
			return nil, errors.New("cloudns: malformed record listing")
		}
		var records map[string]wireRecord
		if err := json.Unmarshal(raw, &records); err != nil || records == nil {
			return nil, errors.New("cloudns: malformed record listing")
		}
		ids := slices.Sorted(maps.Keys(records))
		out := make([]wireRecord, 0, len(ids))
		for _, id := range ids {
			w := records[id]
			if w["id"] == "" {
				w["id"] = id
			}
			out = append(out, w)
		}
		return out, nil
	})
}

// ListRecords reads all pages and applies shared filters locally, since the API
// silently ignores unknown type filters. Unfamiliar types retain raw values.
func (p *Provider) ListRecords(ctx context.Context, zone dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	raw, err := p.rawRecords(ctx, zone)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}
	rs := dnsprovider.RecordSet{Records: make([]dnsprovider.Record, 0, len(raw))}
	for _, w := range raw {
		r, err := w.public(zone.Name)
		if err != nil {
			return dnsprovider.RecordSet{}, err
		}
		if dnsprovider.MatchRecord(f, r) {
			rs.Records = append(rs.Records, r)
		}
	}
	return rs, nil
}
