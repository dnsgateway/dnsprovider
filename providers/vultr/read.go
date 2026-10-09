package vultr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// perPage is the largest page the list endpoints take.
const perPage = 500

// errNextPage means a list answered a cursor the adapter will not follow:
// one after an empty page.
var errNextPage = errors.New("vultr: invalid next page cursor")

type listMeta struct {
	Meta *struct {
		Total *int `json:"total"`
		Links *struct {
			Next string `json:"next"`
		} `json:"links"`
	} `json:"meta"`
}

// list reads every page of a list under key, passing the answer's
// meta.links.next cursor back until it is empty. A cursor is opaque: it is
// only ever sent as the cursor query parameter of the configured endpoint,
// never followed as a link, so the key goes nowhere else. A repeated
// cursor, a cursor after an empty page, or a count disagreeing with
// meta.total is an error, never a shorter result.
func list[T any](ctx context.Context, p *Provider, path, key string) ([]T, error) {
	var (
		done   bool
		cursor string
		total  int
		count  int
		seen   = map[string]bool{}
	)

	pages, err := rest.Pages(1, nil, func(rest.Page) ([][]T, error) {
		if done {
			return nil, nil
		}

		query := url.Values{"per_page": {strconv.Itoa(perPage)}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}

		var raw []byte
		if err := p.api().Do(ctx, http.MethodGet, path, query, nil, &raw); err != nil {
			return nil, err
		}

		var m listMeta
		if err := json.Unmarshal(raw, &m); err != nil || m.Meta == nil || m.Meta.Total == nil {
			return nil, fmt.Errorf("vultr: malformed answer for %s", path)
		}

		var body map[string]json.RawMessage
		_ = json.Unmarshal(raw, &body)

		var items []T
		if data, ok := body[key]; !ok || string(data) == "null" || json.Unmarshal(data, &items) != nil {
			return nil, fmt.Errorf("vultr: malformed %s in the answer for %s", key, path)
		}

		total = *m.Meta.Total
		count += len(items)

		next := ""
		if m.Meta.Links != nil {
			next = m.Meta.Links.Next
		}

		switch {
		case next == "":
			done = true
		case seen[next] || next == cursor:
			return nil, fmt.Errorf("vultr: %s: %w", path, rest.ErrSamePage)
		case len(items) == 0:
			return nil, errNextPage
		}

		seen[next] = true
		cursor = next

		if count > total || (done && count != total) {
			return nil, fmt.Errorf("vultr: %s answered %d items of a total of %d", path, count, total)
		}

		return [][]T{items}, nil
	})
	if err != nil {
		return nil, err
	}

	var out []T
	for _, page := range pages {
		out = append(out, page...)
	}

	return out, nil
}

type wireDomain struct {
	Domain string `json:"domain"`
}

// zone is a DNS Domain as a Zone. Its ID is its name, as Vultr keys
// Domains by name. A Domain proves Vultr holds the Zone, not that
// Delegation names its nameservers: the Hosting State is Unknown.
func zone(w wireDomain) (dnsprovider.Zone, error) {
	name := names.ZoneName(w.Domain)
	if name == "" {
		return dnsprovider.Zone{}, errors.New("vultr: malformed DNS Domain")
	}

	return dnsprovider.Zone{ID: name, Name: name, State: dnsprovider.HostingUnknown}, nil
}

// Zones lists every DNS Domain of the Account, filtered locally.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	all, err := list[wireDomain](ctx, p, "/domains", "domains")
	if err != nil {
		return nil, err
	}

	out := make([]dnsprovider.Zone, 0, len(all))

	for _, w := range all {
		z, err := zone(w)
		if err != nil {
			return nil, err
		}

		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}

	return out, nil
}

// Zone reads one DNS Domain by its exact name: ErrNotFound when the
// Account has none of that name.
func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)
	if name == "" {
		return dnsprovider.Zone{}, fmt.Errorf("vultr: empty Zone name: %w", dnsprovider.ErrNotFound)
	}

	var raw []byte
	if err := p.api().Do(ctx, http.MethodGet, "/domains/"+url.PathEscape(name), nil, nil, &raw); err != nil {
		return dnsprovider.Zone{}, err
	}

	var answer struct {
		Domain *wireDomain `json:"domain"`
	}

	if json.Unmarshal(raw, &answer) != nil || answer.Domain == nil {
		return dnsprovider.Zone{}, errors.New("vultr: malformed DNS Domain answer")
	}

	z, err := zone(*answer.Domain)
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	if z.Name != name {
		return dnsprovider.Zone{}, errors.New("vultr: the answer names a different DNS Domain")
	}

	return z, nil
}

// wireRecord is a DNS Record. Pointers tell a missing field from the apex
// "", empty text or a zero.
type wireRecord struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Name     *string `json:"name"`
	Data     *string `json:"data"`
	Priority *int64  `json:"priority"`
	TTL      *int64  `json:"ttl"`
}

// host is a host name in data as an absolute presentation name: Vultr
// leaves out the trailing dot, and writes the root as ".".
func host(data string) string {
	if strings.HasSuffix(data, ".") {
		return data
	}

	return data + "."
}

// toRecord is a DNS Record as a Record, its Value in presentation form.
// MX and SRV take their priority from the priority field, and SRV its
// weight, port and target from data, "weight port target"; TXT data is
// enclosed in quotes; CAA data is "flags tag value".
func toRecord(zone string, w wireRecord) (dnsprovider.Record, error) {
	if w.ID == "" || w.Type == "" || w.Name == nil || w.Data == nil || w.TTL == nil || *w.TTL < 0 || *w.TTL > math.MaxUint32 {
		return dnsprovider.Record{}, errors.New("vultr: malformed DNS Record")
	}

	r := dnsprovider.Record{
		ID: w.ID, Type: strings.ToUpper(w.Type), Name: names.AbsoluteName(zone, *w.Name), Value: *w.Data, TTL: uint32(*w.TTL),
	}

	data := *w.Data
	malformed := fmt.Errorf("vultr: malformed %s DNS Record %s", r.Type, w.ID)
	priority := func() (int64, bool) {
		return deref(w.Priority), w.Priority != nil && *w.Priority >= 0 && *w.Priority <= math.MaxUint16
	}

	switch r.Type {
	case "CNAME", "NS":
		if strings.TrimSpace(data) == "" {
			return dnsprovider.Record{}, malformed
		}

		r.Value = host(data)
	case "MX":
		n, ok := priority()
		if !ok || strings.TrimSpace(data) == "" {
			return dnsprovider.Record{}, malformed
		}

		r.Value = fmt.Sprintf("%d %s", n, host(data))
	case "SRV":
		n, ok := priority()
		f := strings.Fields(data)

		if !ok || len(f) != 3 || !isUint16(f[0]) || !isUint16(f[1]) {
			return dnsprovider.Record{}, malformed
		}

		r.Value = fmt.Sprintf("%d %s %s %s", n, f[0], f[1], host(f[2]))
	case "TXT":
		if len(data) >= 2 && strings.HasPrefix(data, `"`) && strings.HasSuffix(data, `"`) {
			r.Value = data[1 : len(data)-1]
		}
	case "CAA":
		flags, tag, value, err := caaFields(data)
		if err != nil {
			return dnsprovider.Record{}, malformed
		}

		r.Value = fmt.Sprintf("%s %s %s", flags, tag, quote(value))
	}

	return r, nil
}

func deref(n *int64) int64 {
	if n == nil {
		return 0
	}

	return *n
}

func isUint16(s string) bool {
	_, err := strconv.ParseUint(s, 10, 16)

	return err == nil
}

// caaFields splits CAA data or a CAA presentation Value into its flags,
// tag and value, the value unquoted. The fields may be split by any white
// space; a value without quotes is taken as it is.
func caaFields(s string) (flags, tag, value string, err error) {
	rest := strings.TrimSpace(s)

	var f [2]string

	for i := range f {
		j := strings.IndexFunc(rest, unicode.IsSpace)
		if j < 0 {
			return "", "", "", fmt.Errorf("vultr: the CAA value %q has no value after its flags and tag", s)
		}

		f[i], rest = rest[:j], strings.TrimLeftFunc(rest[j:], unicode.IsSpace)
	}

	if _, err := strconv.ParseUint(f[0], 10, 8); err != nil || f[1] == "" || rest == "" {
		return "", "", "", fmt.Errorf("vultr: malformed CAA value %q", s)
	}

	if !strings.HasPrefix(rest, `"`) {
		return f[0], f[1], rest, nil
	}

	value, err = unquote(rest)

	return f[0], f[1], value, err
}

// quote is a CAA value as a presentation character string: a quote or a
// backslash is escaped by a backslash, a control character as \DDD.
func quote(s string) string {
	var b strings.Builder

	b.WriteByte('"')

	for i := range len(s) {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 32 || c == 127:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}

	b.WriteByte('"')

	return b.String()
}

// unquote decodes a presentation character string: \DDD is a decimal
// byte, and a backslash before any other character stands for it.
func unquote(s string) (string, error) {
	if len(s) < 2 || s[len(s)-1] != '"' {
		return "", fmt.Errorf("vultr: the CAA value %s is not closed by a quote", s)
	}

	var b strings.Builder

	for i := 1; i < len(s)-1; i++ {
		c := s[i]

		switch {
		case c == '"':
			return "", fmt.Errorf("vultr: the CAA value %s has a stray quote", s)
		case c != '\\':
		case i+1 >= len(s)-1:
			return "", fmt.Errorf("vultr: the CAA value %s ends in an incomplete escape", s)
		case isDigit(s[i+1]):
			if i+3 >= len(s)-1 || !isDigit(s[i+2]) || !isDigit(s[i+3]) {
				return "", fmt.Errorf("vultr: the CAA value %s has a decimal escape of fewer than three digits", s)
			}

			n := int(s[i+1]-'0')*100 + int(s[i+2]-'0')*10 + int(s[i+3]-'0')
			if n > 255 {
				return "", fmt.Errorf("vultr: the CAA value %s has a decimal escape over 255", s)
			}

			c = byte(n)
			i += 3
		default:
			i++
			c = s[i]
		}

		b.WriteByte(c)
	}

	return b.String(), nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// zoneName is the name of a Zone, or its ID, which is its name, when the
// Zone was built with the ID alone.
func zoneName(z dnsprovider.Zone) string {
	if name := names.ZoneName(z.Name); name != "" {
		return name
	}

	return names.ZoneName(z.ID)
}

func recordsPath(z dnsprovider.Zone) string {
	return "/domains/" + url.PathEscape(zoneName(z)) + "/records"
}

// Records lists every page of the Zone's DNS Records. Vultr's list takes
// no filter: type and name filters are applied locally. A missing Zone is
// ErrNotFound. Vultr reports no SOA serial.
func (p *Provider) Records(ctx context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	all, err := p.records(ctx, z)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	set := dnsprovider.RecordSet{Records: []dnsprovider.Record{}}

	for _, r := range all {
		if dnsprovider.MatchRecord(f, r) {
			set.Records = append(set.Records, r)
		}
	}

	return set, nil
}

// records lists every DNS Record of the Zone.
func (p *Provider) records(ctx context.Context, z dnsprovider.Zone) ([]dnsprovider.Record, error) {
	if zoneName(z) == "" {
		return nil, fmt.Errorf("vultr: empty Zone name: %w", dnsprovider.ErrNotFound)
	}

	all, err := list[wireRecord](ctx, p, recordsPath(z), "records")
	if err != nil {
		return nil, err
	}

	out := make([]dnsprovider.Record, 0, len(all))

	for _, w := range all {
		r, err := toRecord(zoneName(z), w)
		if err != nil {
			return nil, err
		}

		out = append(out, r)
	}

	return out, nil
}
