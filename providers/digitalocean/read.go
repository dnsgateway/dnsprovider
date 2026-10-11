package digitalocean

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// perPage is the largest page the list endpoints take.
const perPage = 200

// wireTypes are the Record types the Domain Records API holds, and so may
// filter by.
var wireTypes = []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT"}

// errNextPage means a list answered a next-page link the adapter will not
// follow: on another host, for another list, or not the following page.
var errNextPage = errors.New("digitalocean: invalid next page link")

type listPage struct {
	Links *struct {
		Pages *struct {
			Next string `json:"next"`
		} `json:"pages"`
	} `json:"links"`
	Meta *struct {
		Total *int `json:"total"`
	} `json:"meta"`
}

// list reads every page of a list under key, following the answer's next
// link until it has none. A next link only says that there is a following
// page: it is checked to name this list on the configured or production
// host and the following page, and that page is then read through the
// configured endpoint, so the token never goes to a host the link names.
func list[T any](ctx context.Context, p *Provider, path, key string, q url.Values) ([]T, error) {
	var (
		done  bool
		total *int
		count int
	)

	pages, err := rest.Pages(1, nil, func(pg rest.Page) ([][]T, error) {
		if done {
			return nil, nil
		}

		query := url.Values{"page": {strconv.Itoa(pg.Number)}, "per_page": {strconv.Itoa(perPage)}}
		maps.Copy(query, q)

		var raw []byte
		if err := p.api().Do(ctx, http.MethodGet, path, query, nil, &raw); err != nil {
			return nil, err
		}

		var meta listPage
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("digitalocean: malformed answer for %s", path)
		}

		var body map[string]json.RawMessage
		_ = json.Unmarshal(raw, &body)

		var items []T
		if data, ok := body[key]; !ok || string(data) == "null" || json.Unmarshal(data, &items) != nil {
			return nil, fmt.Errorf("digitalocean: malformed %s in the answer for %s", key, path)
		}

		if meta.Meta != nil && meta.Meta.Total != nil {
			total = meta.Meta.Total
		}

		count += len(items)

		next := ""
		if meta.Links != nil && meta.Links.Pages != nil {
			next = meta.Links.Pages.Next
		}

		if next == "" {
			done = true
		} else {
			n, err := p.nextPage(path, next)
			if err != nil {
				return nil, err
			}

			if n == pg.Number {
				return nil, rest.ErrSamePage
			}

			if n != pg.Number+1 || len(items) == 0 {
				return nil, errNextPage
			}
		}

		if total != nil && (count > *total || (done && count != *total)) {
			return nil, fmt.Errorf("digitalocean: %s answered %d items of a total of %d", path, count, *total)
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

// nextPage is the page number a next link names, when it names the list
// at path on the configured or production endpoint.
func (p *Provider) nextPage(path, link string) (int, error) {
	u, err := url.Parse(link)
	if err != nil {
		return 0, errNextPage
	}

	ok := false

	for _, base := range []string{p.baseURL, DefaultBaseURL} {
		b, err := url.Parse(base)
		if err == nil && strings.EqualFold(u.Scheme, b.Scheme) && strings.EqualFold(u.Host, b.Host) && u.Path == strings.TrimRight(b.Path, "/")+path {
			ok = true
		}
	}

	n, err := strconv.Atoi(u.Query().Get("page"))
	if !ok || err != nil || n < 1 {
		return 0, errNextPage
	}

	return n, nil
}

type wireDomain struct {
	Name     string  `json:"name"`
	TTL      *uint32 `json:"ttl"`
	ZoneFile *string `json:"zone_file"`
}

// zone is a Domain as a Zone. Its ID is its name, as DigitalOcean keys
// Domains by name. A Domain proves DigitalOcean holds the Zone, not that
// Delegation names its nameservers: the Hosting State is Unknown.
func zone(w wireDomain) (dnsprovider.Zone, error) {
	name := names.ZoneName(w.Name)
	if name == "" {
		return dnsprovider.Zone{}, errors.New("digitalocean: malformed Domain")
	}

	return dnsprovider.Zone{ID: name, Name: name, State: dnsprovider.HostingUnknown}, nil
}

// ListZones implements dnsprovider.Provider: every Domain of the Account
// whose name matches the filter, filtered locally.
// The ZoneSet is a Full View.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	all, err := list[wireDomain](ctx, p, "/domains", "domains", nil)
	if err != nil {
		return dnsprovider.ZoneSet{}, err
	}

	out := make([]dnsprovider.Zone, 0, len(all))

	for _, w := range all {
		z, err := zone(w)
		if err != nil {
			return dnsprovider.ZoneSet{}, err
		}

		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}

	return dnsprovider.ZoneSet{Zones: out}, nil
}

// domain reads one Domain by its exact name.
func (p *Provider) domain(ctx context.Context, name string) (wireDomain, error) {
	name = names.ZoneName(name)
	if name == "" {
		return wireDomain{}, fmt.Errorf("digitalocean: empty Zone name: %w", dnsprovider.ErrNotFound)
	}

	var answer struct {
		Domain *wireDomain `json:"domain"`
	}

	if err := p.api().Do(ctx, http.MethodGet, "/domains/"+url.PathEscape(name), nil, nil, &answer); err != nil {
		return wireDomain{}, err
	}

	if answer.Domain == nil {
		return wireDomain{}, errors.New("digitalocean: malformed Domain answer")
	}

	if names.ZoneName(answer.Domain.Name) != name {
		return wireDomain{}, errors.New("digitalocean: the answer names a different Domain")
	}

	return *answer.Domain, nil
}

// GetZone reads one Domain by its exact name: ErrNotFound when the Account
// has none of that name.
func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	w, err := p.domain(ctx, name)
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	return zone(w)
}

// serial is the SOA serial of a Domain's zone file; zero when it has none.
func serial(zoneFile *string) uint32 {
	if zoneFile == nil {
		return 0
	}

	for line := range strings.SplitSeq(*zoneFile, "\n") {
		f := strings.Fields(line)

		i := slices.Index(f, "SOA")
		if i < 0 || len(f) < i+4 {
			continue
		}

		if n, err := strconv.ParseUint(f[i+3], 10, 32); err == nil {
			return uint32(n)
		}
	}

	return 0
}

// wireRecord is a Domain Record. Pointers tell a missing field from the
// apex "@", empty text or a zero.
type wireRecord struct {
	ID       uint64  `json:"id"`
	Type     string  `json:"type"`
	Name     *string `json:"name"`
	Data     *string `json:"data"`
	TTL      *uint32 `json:"ttl"`
	Priority *uint16 `json:"priority"`
	Port     *uint16 `json:"port"`
	Weight   *uint16 `json:"weight"`
	Flags    *uint8  `json:"flags"`
	Tag      *string `json:"tag"`
}

// host is a host name in data as an absolute presentation name: "@" is
// the Zone apex, and DigitalOcean leaves out the trailing dot.
func host(zone, data string) string {
	switch {
	case data == "@":
		return zone + "."
	case data == "." || strings.HasSuffix(data, "."):
		return data
	}

	return data + "."
}

// toRecord is a Domain Record as a Record, its Value in presentation form
// built from the structured priority, weight, port, flags and tag.
func toRecord(zone string, w wireRecord) (dnsprovider.Record, error) {
	zone = names.ZoneName(zone)

	if w.ID == 0 || w.Type == "" || w.Name == nil || w.Data == nil || w.TTL == nil {
		return dnsprovider.Record{}, errors.New("digitalocean: malformed Domain Record")
	}

	r := dnsprovider.Record{
		ID: strconv.FormatUint(w.ID, 10), Type: strings.ToUpper(w.Type), Name: names.AbsoluteName(zone, *w.Name),
		Value: *w.Data, TTL: *w.TTL,
	}

	missing := errors.New("digitalocean: malformed " + r.Type + " Domain Record")

	switch r.Type {
	case "CNAME", "NS":
		r.Value = host(zone, *w.Data)
	case "MX":
		if w.Priority == nil {
			return dnsprovider.Record{}, missing
		}

		r.Value = fmt.Sprintf("%d %s", *w.Priority, host(zone, *w.Data))
	case "SRV":
		if w.Priority == nil || w.Weight == nil || w.Port == nil {
			return dnsprovider.Record{}, missing
		}

		r.Value = fmt.Sprintf("%d %d %d %s", *w.Priority, *w.Weight, *w.Port, host(zone, *w.Data))
	case "CAA":
		if w.Flags == nil || w.Tag == nil || *w.Tag == "" {
			return dnsprovider.Record{}, missing
		}

		data := *w.Data
		if issuer(*w.Tag, data) && data != "." {
			data = strings.TrimSuffix(data, ".")
		}

		r.Value = fmt.Sprintf("%d %s %s", *w.Flags, *w.Tag, charstr.Quote(data))
	}

	return r, nil
}

// issuer reports whether data is the bare issuer domain of an issue or
// issuewild CAA Record: one DigitalOcean takes with a trailing dot and
// answers without it, as terraform-provider-digitalocean writes and reads
// it. Data with parameters, ";" alone and iodef URLs are left as they are.
func issuer(tag, data string) bool {
	tag = strings.ToLower(tag)

	return (tag == "issue" || tag == "issuewild") && data != "" &&
		!strings.Contains(data, ";") && strings.IndexFunc(data, unicode.IsSpace) < 0
}

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

// ListRecords reads the Domain, for its SOA serial and to tell a missing Zone,
// then every page of its Domain Records. A type filter DigitalOcean holds
// is pushed down; the rest is filtered locally.
func (p *Provider) ListRecords(ctx context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	d, err := p.domain(ctx, zoneName(z))
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	set := dnsprovider.RecordSet{Records: []dnsprovider.Record{}, Serial: serial(d.ZoneFile)}

	typ := strings.ToUpper(f.Type)
	if typ != "" && !slices.Contains(wireTypes, typ) {
		return set, nil
	}

	all, err := p.records(ctx, z, typ)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	for _, r := range all {
		if dnsprovider.MatchRecord(f, r) {
			set.Records = append(set.Records, r)
		}
	}

	return set, nil
}

// records lists every Domain Record of the Zone, of type typ unless it is
// empty, without reading the Domain itself.
func (p *Provider) records(ctx context.Context, z dnsprovider.Zone, typ string) ([]dnsprovider.Record, error) {
	q := url.Values{}
	if typ != "" {
		q.Set("type", typ)
	}

	all, err := list[wireRecord](ctx, p, recordsPath(z), "domain_records", q)
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
