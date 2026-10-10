package scaleway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// list uses total_count rather than short pages, retaining the endpoint and
// Project filter for every page. A repeated page or changing total is an error.
func list[T any](ctx context.Context, p *Provider, path, key string) ([]T, error) {
	var out, last []T
	total := -1
	for page := 1; ; page++ {
		var raw []byte
		q := url.Values{"project_id": {p.project}, "page": {strconv.Itoa(page)}, "page_size": {"100"}}
		if err := p.api().Do(ctx, http.MethodGet, path, q, nil, &raw); err != nil {
			return nil, err
		}
		var body map[string]json.RawMessage
		if json.Unmarshal(raw, &body) != nil {
			return nil, errors.New("scaleway: malformed list response")
		}
		var count *int
		var items []T
		if json.Unmarshal(body["total_count"], &count) != nil || count == nil || *count < 0 ||
			len(body[key]) == 0 || string(body[key]) == "null" || json.Unmarshal(body[key], &items) != nil {
			return nil, errors.New("scaleway: malformed list response")
		}
		if total >= 0 && total != *count {
			return nil, errors.New("scaleway: list total changed while paging")
		}
		total = *count
		if len(items) > 0 && reflect.DeepEqual(items, last) {
			return nil, rest.ErrSamePage
		}
		out = append(out, items...)
		if len(out) > total || (len(items) == 0 && len(out) != total) {
			return nil, errors.New("scaleway: invalid list pagination")
		}
		if len(out) == total {
			return out, nil
		}
		last = items
	}
}

type wireZone struct {
	Domain    string   `json:"domain"`
	Subdomain string   `json:"subdomain"`
	Project   string   `json:"project_id"`
	Status    string   `json:"status"`
	NS        []string `json:"ns"`
}

func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	if _, err := list[wireZone](ctx, p, "/dns-zones", "dns_zones"); err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	return dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: p.project}}, nil
}

// Zones implements dnsprovider.Provider: the Account's Zones that match
// the filter.
// The ZoneSet is a Full View.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	zs, err := p.zoneList(ctx, f)

	return dnsprovider.ZoneSet{Zones: zs}, err
}

// zoneList lists the Zones that Zones returns, as a bare slice: Zones
// wraps it in a ZoneSet, while Zone searches the slice itself.
func (p *Provider) zoneList(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	all, err := list[wireZone](ctx, p, "/dns-zones", "dns_zones")
	if err != nil {
		return nil, err
	}
	out := make([]dnsprovider.Zone, 0, len(all))
	for _, w := range all {
		if w.Project == "" || w.Domain == "" {
			return nil, errors.New("scaleway: malformed DNS Zone")
		}
		if !strings.EqualFold(w.Project, p.project) {
			continue
		}
		name := names.ZoneName(w.Domain)
		if w.Subdomain != "" {
			name = names.ZoneName(w.Subdomain) + "." + name
		}
		state := dnsprovider.HostingUnknown
		if w.Status == "active" {
			state = dnsprovider.HostingActive
		}
		z := dnsprovider.Zone{ID: name, Name: name, State: state, Nameservers: append([]string(nil), w.NS...)}
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}
	return out, nil
}

func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)
	all, err := p.zoneList(ctx, dnsprovider.ZoneFilter{})
	if err != nil {
		return dnsprovider.Zone{}, err
	}
	for _, z := range all {
		if z.Name == name {
			return z, nil
		}
	}
	return dnsprovider.Zone{}, fmt.Errorf("scaleway: Zone is absent from configured Project: %w", dnsprovider.ErrNotFound)
}

func zoneName(z dnsprovider.Zone) string {
	if z.Name != "" {
		return names.ZoneName(z.Name)
	}
	return names.ZoneName(z.ID)
}

func recordsPath(z dnsprovider.Zone) string {
	return "/dns-zones/" + url.PathEscape(zoneName(z)) + "/records"
}

type wireRecord map[string]json.RawMessage

func (w wireRecord) record(zone string) (dnsprovider.Record, error) {
	var fields struct {
		ID       string  `json:"id"`
		Name     *string `json:"name"`
		Type     string  `json:"type"`
		Data     *string `json:"data"`
		TTL      *uint32 `json:"ttl"`
		Priority uint32  `json:"priority"`
	}
	raw, _ := json.Marshal(w)
	if json.Unmarshal(raw, &fields) != nil || fields.ID == "" || fields.Name == nil || fields.Type == "" || fields.Data == nil || fields.TTL == nil {
		return dnsprovider.Record{}, errors.New("scaleway: malformed DNS Record")
	}
	typ := strings.ToUpper(fields.Type)
	value := *fields.Data
	switch typ {
	case "CNAME", "NS", "DNAME":
		value = absoluteTarget(zone, value)
	case "MX":
		value = fmt.Sprintf("%d %s", fields.Priority, absoluteTarget(zone, value))
	case "SRV":
		f := strings.Fields(value)
		if len(f) == 3 {
			value = fmt.Sprintf("%d %s %s %s", fields.Priority, f[0], f[1], absoluteTarget(zone, f[2]))
		}
	case "TXT":
		if strings.HasPrefix(value, `"`) {
			if decoded, err := txtValue(value); err == nil {
				value = decoded
			}
		}
	}
	return dnsprovider.Record{ID: fields.ID, Name: names.AbsoluteName(zone, *fields.Name), Type: typ, Value: value, TTL: *fields.TTL}, nil
}

func absoluteTarget(zone, value string) string {
	if strings.HasSuffix(value, ".") {
		return value
	}
	return value + "." + zone + "."
}

func (p *Provider) read(ctx context.Context, z dnsprovider.Zone) ([]wireRecord, error) {
	owned, err := p.Zone(ctx, zoneName(z))
	if err != nil {
		return nil, err
	}
	return list[wireRecord](ctx, p, recordsPath(owned), "records")
}

func (p *Provider) Records(ctx context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	all, err := p.read(ctx, z)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}
	set := dnsprovider.RecordSet{Records: make([]dnsprovider.Record, 0, len(all))}
	for _, w := range all {
		r, err := w.record(zoneName(z))
		if err != nil {
			return dnsprovider.RecordSet{}, err
		}
		if dnsprovider.MatchRecord(f, r) {
			set.Records = append(set.Records, r)
		}
		if r.Type == "SOA" {
			f := strings.Fields(r.Value)
			if len(f) >= 3 {
				if n, err := strconv.ParseUint(f[2], 10, 32); err == nil {
					set.Serial = uint32(n)
				}
			}
		}
	}
	return set, nil
}
