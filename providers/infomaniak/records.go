package infomaniak

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// readTypes are the record types Infomaniak lists, and so filters a list
// by.
var readTypes = []string{"A", "AAAA", "CAA", "CNAME", "DNAME", "DNSKEY", "DS", "MX", "NS", "PTR", "SMIMEA", "SOA", "SRV", "SSHFP", "TLSA", "TXT"}

// wireRecord is a record as Infomaniak lists it. Pointers tell a missing
// field from an empty one.
type wireRecord struct {
	ID     uint64  `json:"id"`
	Source *string `json:"source"`
	Type   string  `json:"type"`
	TTL    *uint32 `json:"ttl"`
	Target *string `json:"target"`
}

// zoneName is the name of a Zone, or its ID, which is its name, when the
// Zone was built with the ID alone.
func zoneName(z dnsprovider.Zone) string {
	if name := names.ZoneName(strings.TrimSpace(z.Name)); name != "" {
		return name
	}

	return names.ZoneName(strings.TrimSpace(z.ID))
}

// zoneOf is the Zone's zoneName, or ErrNotFound, without a request, when
// the Zone has neither a name nor an ID.
func zoneOf(z dnsprovider.Zone) (string, error) {
	if name := zoneName(z); name != "" {
		return name, nil
	}

	return "", fmt.Errorf("infomaniak: the Zone has no name: %w", dnsprovider.ErrNotFound)
}

// ListRecords implements dnsprovider.Provider: every record of the Zone,
// read page by page, filtered exactly. A type Infomaniak lists is pushed
// down; the rest of the filter is applied locally. Types this module
// does not write, such as DS, SSHFP and TLSA, are read too. Infomaniak
// reports no Serial. ErrNotServed when the Account registers the domain
// but Infomaniak holds no Zone of it.
func (p *Provider) ListRecords(ctx context.Context, zone dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	name, err := zoneOf(zone)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	q := url.Values{}
	if typ := strings.ToUpper(f.Type); slices.Contains(readTypes, typ) {
		q.Set("filter[types][]", typ)
	}

	all, err := list[wireRecord](ctx, p, zonePath(name, "records"), q)
	if err != nil {
		return dnsprovider.RecordSet{}, p.notServed(ctx, name, err)
	}

	set := dnsprovider.RecordSet{Records: make([]dnsprovider.Record, 0, len(all))}

	for _, w := range all {
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

// toRecord is a wire record as a Record: its name absolute, "." being
// the apex, and its Value in presentation form.
func toRecord(zone string, w wireRecord) (dnsprovider.Record, error) {
	if w.ID == 0 || strings.TrimSpace(w.Type) == "" || w.Source == nil || w.TTL == nil || w.Target == nil {
		return dnsprovider.Record{}, errors.New("infomaniak: malformed record")
	}

	source := strings.TrimSpace(*w.Source)
	if source == "." {
		source = ""
	}

	r := dnsprovider.Record{
		ID: strconv.FormatUint(w.ID, 10), Type: strings.ToUpper(strings.TrimSpace(w.Type)),
		Name: names.ZoneName(names.AbsoluteName(zone, source)), TTL: *w.TTL,
	}

	value, err := presentation(r.Type, *w.Target)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("infomaniak: %s record %s: %w", r.Type, r.Name, err)
	}

	r.Value = value

	return r, nil
}

// presentation is a target as a Value. Infomaniak answers host names
// without their trailing dot, MX and SRV with their numbers first, CAA
// in presentation form and TXT as its text.
func presentation(typ, target string) (string, error) {
	if i, ok := hostField[typ]; ok {
		f := strings.Fields(target)
		if len(f) != i+1 || slices.ContainsFunc(f[:i], func(n string) bool { return !isUint16(n) }) {
			return "", errors.New("malformed target")
		}

		f[i] = host(f[i])

		return strings.Join(f, " "), nil
	}

	switch typ {
	case "CAA":
		return caa(target)
	case "TXT":
		return txtText(target), nil
	}

	return target, nil
}

// hostField is, for each type whose value ends in a host name, the index
// of that host name among the value's fields: the last one, after
// 16-bit numbers. Infomaniak answers the host name without its trailing
// dot, and takes it so.
var hostField = map[string]int{"CNAME": 0, "NS": 0, "MX": 1, "SRV": 3}

// host is a host name with its trailing dot.
func host(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}

	return name + "."
}

func isUint16(s string) bool {
	_, err := strconv.ParseUint(s, 10, 16)

	return err == nil
}

// caa is a CAA target in presentation form: its flags, its tag and its
// value as one quoted character-string, quoted here when Infomaniak
// answers it bare.
func caa(target string) (string, error) {
	f := strings.Fields(target)
	if len(f) < 3 {
		return "", errors.New("malformed target")
	}

	if _, err := strconv.ParseUint(f[0], 10, 8); err != nil {
		return "", errors.New("malformed flags")
	}

	rest := strings.TrimSpace(target)
	rest = strings.TrimSpace(rest[strings.Index(rest, f[1])+len(f[1]):])

	value, err := charstr.Unquote(rest)
	if err != nil {
		value = rest
	}

	return f[0] + " " + f[1] + " " + charstr.Quote(value), nil
}

// txtText is a TXT target as its text. Infomaniak answers literal text;
// a target made only of quoted character-strings is read as their
// concatenation, as DNS joins the strings of one record.
func txtText(target string) string {
	if !strings.HasPrefix(strings.TrimSpace(target), `"`) {
		return target
	}

	chunks, err := charstr.Parse(target, " \t")
	if err != nil {
		return target
	}

	return strings.Join(chunks, "")
}
