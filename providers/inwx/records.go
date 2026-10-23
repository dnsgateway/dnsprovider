package inwx

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// recordTypes are the record types INWX serves, from its API
// documentation, and so filters nameserver.info by.
var recordTypes = []string{
	"A", "AAAA", "AFSDB", "ALIAS", "CAA", "CERT", "CNAME", "HINFO", "HTTPS", "IPSECKEY", "LOC", "MX", "NAPTR", "NS",
	"OPENPGPKEY", "PTR", "RP", "SMIMEA", "SOA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT", "URI", "URL",
}

// wireRecord is a record of nameserver.info. Pointers tell a missing
// field from an empty one.
type wireRecord struct {
	ID      wireInt  `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Content string   `json:"content"`
	TTL     *wireInt `json:"ttl"`
	Prio    wireInt  `json:"prio"`
}

// zoneName is a domain name as the adapter compares it: trimmed, lower
// case and without a trailing dot.
func zoneName(name string) string {
	return names.ZoneName(strings.TrimSpace(name))
}

// namedZone is the name of a Zone a call addresses it by; a Zone without
// one is ErrNotFound, without a request.
func namedZone(name string) (string, error) {
	if name = zoneName(name); name == "" {
		return "", fmt.Errorf("inwx: the Zone has no name: %w", dnsprovider.ErrNotFound)
	}

	return name, nil
}

// ListRecords implements dnsprovider.Provider: every record of the
// zone, from one nameserver.info, filtered exactly. A type INWX serves
// is pushed down; the rest of the filter is applied locally (the filter
// names no exact name to push down as nameserver.info's name). Types
// this module does not write, such as SOA, ALIAS, URL and TLSA, are read
// too. The Serial is the zone's SOAserial. A Zone without a name is
// read by its ID, its roId. ErrNotServed when the Account registers the
// domain but INWX hosts no zone of it.
func (p *Provider) ListRecords(ctx context.Context, zone dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	name := zoneName(zone.Name)
	params := map[string]any{}

	switch roID, err := strconv.ParseInt(strings.TrimSpace(zone.ID), 10, 64); {
	case name != "":
		params["domain"] = name
	case err == nil && roID > 0:
		params["roId"] = roID
	default:
		return dnsprovider.RecordSet{}, fmt.Errorf("inwx: the Zone has no name or ID: %w", dnsprovider.ErrNotFound)
	}

	typ := strings.ToUpper(strings.TrimSpace(f.Type))
	if slices.Contains(recordTypes, typ) {
		params["type"] = typ
	}

	info, err := p.zoneInfo(ctx, name, params)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	// A count above the records answered is a truncated list. The count
	// is only checked unfiltered: whether it counts the records of the
	// filter or of the zone is not documented.
	if info.Count != nil && params["type"] == nil && int(*info.Count) > len(info.Records) {
		return dnsprovider.RecordSet{}, fmt.Errorf("inwx: nameserver.info answered %d records of a count of %d", len(info.Records), *info.Count)
	}

	name = zoneName(info.Domain)
	set := dnsprovider.RecordSet{Records: make([]dnsprovider.Record, 0, len(info.Records))}

	if serial, err := strconv.ParseUint(strings.TrimSpace(info.SOAserial), 10, 32); err == nil {
		set.Serial = uint32(serial)
	}

	for _, w := range info.Records {
		r, err := toRecord(name, w)
		if err != nil {
			return dnsprovider.RecordSet{}, err
		}

		if dnsprovider.MatchRecord(f, r) {
			set.Records = append(set.Records, r)
		}
	}

	return set, nil
}

// recordName is a record's name as INWX answers it, full and without a
// trailing dot, as an absolute name. An empty name is the apex; a name
// outside the zone is read as relative to it.
func recordName(zone, name string) string {
	n := zoneName(name)

	switch {
	case n == "" || n == "@":
		return zone
	case n == zone || strings.HasSuffix(n, "."+zone):
		return n
	}

	return n + "." + zone
}

// toRecord is a wire record as a Record, its Value in presentation form.
func toRecord(zone string, w wireRecord) (dnsprovider.Record, error) {
	typ := strings.ToUpper(strings.TrimSpace(w.Type))
	if w.ID <= 0 || typ == "" || w.TTL == nil || *w.TTL < 0 {
		return dnsprovider.Record{}, errors.New("inwx: nameserver.info holds a malformed record")
	}

	r := dnsprovider.Record{ID: w.ID.String(), Type: typ, Name: recordName(zone, w.Name), TTL: uint32(*w.TTL)} //nolint:gosec // checked not negative; a TTL is 32-bit.

	value, err := presentation(typ, w.Content, w.Prio)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("inwx: %s record %s: %w", typ, r.Name, err)
	}

	r.Value = value

	return r, nil
}

// presentation is a record's content as a Value. INWX answers host
// names without their trailing dot, and the priority of MX, SRV and URI
// in its own prio field. TXT content is literal text; CAA content is in
// presentation form already, as is every type this module only reads.
func presentation(typ, content string, prio wireInt) (string, error) {
	switch typ {
	case "CNAME", "NS":
		return host(content), nil
	case "MX":
		return prio.String() + " " + host(content), nil
	case "SRV":
		f := strings.Fields(content)
		if len(f) != 3 {
			return "", errors.New("the content is not a weight, port and target")
		}

		return prio.String() + " " + f[0] + " " + f[1] + " " + host(f[2]), nil
	case "URI":
		return prio.String() + " " + strings.TrimSpace(content), nil
	}

	return content, nil
}

// host is a host name with its trailing dot; the root stays ".".
func host(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasSuffix(name, ".") {
		return name
	}

	return name + "."
}
