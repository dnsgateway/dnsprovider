package netim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// ListRecords implements dnsprovider.Provider: every Record of the Zone
// that matches the filter, filtered locally. A Record without a custom
// TTL has the Zone's. Types this module does not write, such as TLSA,
// SVCB and HTTPS, are read too. Netim reports no Serial.
func (p *Provider) ListRecords(ctx context.Context, zone dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	out := make([]dnsprovider.Record, 0, len(records))

	for _, e := range records {
		if dnsprovider.MatchRecord(f, e.Record) {
			out = append(out, e.Record)
		}
	}

	return dnsprovider.RecordSet{Records: out}, nil
}

// wireZone is a domain's zone info. Netim documents it as an array but
// describes one object; both are read.
type wireZone struct {
	TTL     *number          `json:"ttl"`
	TTLUnit string           `json:"ttlUnit"`
	Records *json.RawMessage `json:"records"`
}

type wireRecord struct {
	Subdomain string                     `json:"subdomain"`
	Type      string                     `json:"type"`
	Value     *string                    `json:"value"`
	Options   map[string]json.RawMessage `json:"options"`
}

// entry is a Record as read, with the wire record it was read from,
// which selects it in an update or delete.
type entry struct {
	dnsprovider.Record

	wire wireRecord
}

// listRecords reads every Record of the Zone, with its wire record.
func (p *Provider) listRecords(ctx context.Context, zone dnsprovider.Zone) ([]entry, error) {
	name, err := zoneName(zone)
	if err != nil {
		return nil, err
	}

	var raw json.RawMessage
	if err := p.read(ctx, http.MethodGet, domainPath(name, "zone", "info"), nil, &raw); err != nil {
		return nil, err
	}

	var w wireZone
	if err := json.Unmarshal(raw, &w); err != nil {
		var list []wireZone
		if json.Unmarshal(raw, &list) != nil || len(list) != 1 {
			return nil, errors.New("netim: malformed zone info")
		}

		w = list[0]
	}

	if w.TTL == nil || w.Records == nil {
		return nil, errors.New("netim: the zone info has no TTL or no records")
	}

	zoneTTL, err := seconds(*w.TTL, w.TTLUnit)
	if err != nil {
		return nil, fmt.Errorf("netim: zone TTL: %w", err)
	}

	var wire []wireRecord
	if err := json.Unmarshal(*w.Records, &wire); err != nil {
		return nil, errors.New("netim: malformed zone records")
	}

	out := make([]entry, 0, len(wire))

	for _, wr := range wire {
		r, err := toRecord(name, zoneTTL, wr)
		if err != nil {
			return nil, err
		}

		out = append(out, entry{Record: r, wire: wr})
	}

	return out, nil
}

// handled are the record options every Record's fields carry; other
// options are Extras.
var handled = []string{"ttl", "ttlUnit", "customTtl"}

// folded are the options a type's Value or name carries.
var folded = map[string][]string{
	"MX":  {"priority"},
	"SRV": {"priority", "weight", "port", "service", "protocol"},
}

func toRecord(zone string, zoneTTL uint32, w wireRecord) (dnsprovider.Record, error) {
	if strings.TrimSpace(w.Type) == "" || w.Value == nil {
		return dnsprovider.Record{}, errors.New("netim: malformed record")
	}

	r := dnsprovider.Record{
		Type: strings.ToUpper(w.Type), Name: names.ZoneName(names.AbsoluteName(zone, w.Subdomain)),
		Value: *w.Value, TTL: zoneTTL,
	}

	var custom flag
	_ = json.Unmarshal(w.Options["customTtl"], &custom)

	if custom {
		var ttl number
		if err := json.Unmarshal(w.Options["ttl"], &ttl); err != nil || !ttl.set {
			return dnsprovider.Record{}, fmt.Errorf("netim: %s record %s has a custom TTL without a value", r.Type, r.Name)
		}

		var unit string
		_ = json.Unmarshal(w.Options["ttlUnit"], &unit)

		t, err := seconds(ttl, unit)
		if err != nil {
			return dnsprovider.Record{}, fmt.Errorf("netim: %s record %s: %w", r.Type, r.Name, err)
		}

		r.TTL = t
	}

	opt := func(key string) (uint64, bool) {
		var n number

		return n.value, json.Unmarshal(w.Options[key], &n) == nil && n.set
	}

	switch r.Type {
	case "CNAME", "NS":
		r.Value = target(r.Value)
	case "MX":
		priority, ok := opt("priority")
		if !ok {
			return dnsprovider.Record{}, fmt.Errorf("netim: MX record %s has no priority", r.Name)
		}

		r.Value = numbered(target(r.Value), priority)
	case "SRV":
		priority, ok1 := opt("priority")
		weight, ok2 := opt("weight")
		port, ok3 := opt("port")

		if !ok1 || !ok2 || !ok3 {
			return dnsprovider.Record{}, fmt.Errorf("netim: SRV record %s has no priority, weight or port", r.Name)
		}

		r.Value = numbered(target(r.Value), priority, weight, port)

		var service, protocol string
		_ = json.Unmarshal(w.Options["service"], &service)
		_ = json.Unmarshal(w.Options["protocol"], &protocol)

		if service = strings.TrimPrefix(strings.TrimSpace(service), "_"); service != "" {
			if protocol = strings.TrimPrefix(strings.TrimSpace(protocol), "_"); protocol != "" {
				r.Name = names.ZoneName("_" + service + "._" + protocol + "." + r.Name)
			}
		}
	}

	r.Extras = extras(r.Type, w.Options)

	return withID(r, bool(custom)), nil
}

// extras are the record options no field carries, as raw JSON, leaving
// out those that are null or empty.
func extras(typ string, options map[string]json.RawMessage) map[string]string {
	var out map[string]string

	for key, value := range options {
		if slices.Contains(handled, key) || slices.Contains(folded[typ], key) {
			continue
		}

		if v := bytes.TrimSpace(value); len(v) == 0 || string(v) == "null" || string(v) == `""` {
			continue
		}

		if out == nil {
			out = map[string]string{}
		}

		out[key] = string(value)
	}

	return out
}

// numbered is an MX or SRV Value: its numbers, then its target.
func numbered(target string, numbers ...uint64) string {
	var b strings.Builder
	for _, n := range numbers {
		b.WriteString(strconv.FormatUint(n, 10) + " ")
	}

	return b.String() + target
}

// target is a domain name Value without its trailing dot, except the root.
func target(s string) string {
	if s == "." {
		return s
	}

	return strings.TrimSuffix(s, ".")
}

// withID sets the Record's content-derived ID, as Internet.bs's adapter
// does. The TTL counts only when it is the Record's own: a Record that
// inherits the Zone's TTL keeps its ID when the Zone's TTL changes.
func withID(r dnsprovider.Record, customTTL bool) dnsprovider.Record {
	var ttl any
	if customTTL {
		ttl = r.TTL
	}

	identity, _ := json.Marshal([]any{r.Type, strings.ToLower(r.Name), ttl, r.Value, r.Extras})
	r.ID = fmt.Sprintf("%x", sha256.Sum256(identity))

	return r
}

// units are Netim's TTL units, in seconds.
var units = map[string]uint64{"": 1, "S": 1, "M": 60, "H": 3600, "D": 86400, "W": 604800}

// seconds is a TTL in a unit as seconds; a missing unit is seconds.
func seconds(ttl number, unit string) (uint32, error) {
	u, ok := units[strings.ToUpper(strings.TrimSpace(unit))]
	if !ok {
		return 0, fmt.Errorf("unknown TTL unit %q", unit)
	}

	if !ttl.set || ttl.value > math.MaxUint32/u {
		return 0, errors.New("TTL out of range")
	}

	return uint32(ttl.value * u), nil //nolint:gosec // bounded above
}

// number is an unsigned integer Netim sends as a JSON number or a
// numeric string; "" and null leave it unset.
type number struct {
	value uint64
	set   bool
}

func (n *number) UnmarshalJSON(data []byte) error {
	*n = number{}

	s := string(bytes.TrimSpace(data))
	if s == "null" {
		return nil
	}

	if unquoted, err := strconv.Unquote(s); err == nil {
		s = strings.TrimSpace(unquoted)
		if s == "" {
			return nil
		}
	}

	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("netim: %s is not a number", data)
	}

	*n = number{value: v, set: true}

	return nil
}

// flag is a boolean Netim sends as true or false, 1 or 0, or "1" or "0".
type flag bool

func (f *flag) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(bytes.TrimSpace(data)), `"`) {
	case "true", "1":
		*f = true
	default:
		*f = false
	}

	return nil
}
