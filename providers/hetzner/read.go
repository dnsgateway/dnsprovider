package hetzner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

type wireZone struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	TTL         uint32 `json:"ttl"`
	Mode        string `json:"mode"`
	Status      string `json:"status"`
	Nameservers struct {
		Assigned []string `json:"assigned"`
	} `json:"authoritative_nameservers"`
}
type wireValue struct {
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

func (v *wireValue) UnmarshalJSON(data []byte) error {
	type plain wireValue
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	value, ok := fields["value"]
	if !ok || string(value) == "null" {
		return errors.New("hetzner: missing Record value")
	}
	return json.Unmarshal(data, (*plain)(v))
}

type wireRRset struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	TTL        *uint32           `json:"ttl"`
	Labels     map[string]string `json:"labels"`
	Protection struct {
		Change bool `json:"change"`
	} `json:"protection"`
	Records []wireValue `json:"records"`
}

func list[T any](ctx context.Context, p *Provider, path, key string) ([]T, error) {
	done := false
	seen := map[string]bool{}
	count := 0
	pageSize := "50"
	if key == "rrsets" {
		pageSize = "100"
	}
	pages, err := rest.Pages(1, nil, func(pg rest.Page) ([][]T, error) {
		if done {
			return nil, nil
		}
		var body map[string]json.RawMessage
		if err := p.api().Do(ctx, http.MethodGet, path, url.Values{"page": {strconv.Itoa(pg.Number)}, "per_page": {pageSize}}, nil, &body); err != nil {
			return nil, err
		}
		var items []T
		if data, ok := body[key]; !ok || string(data) == "null" || json.Unmarshal(data, &items) != nil {
			return nil, fmt.Errorf("hetzner: malformed %s response", key)
		}
		var meta struct {
			Pagination *struct {
				Page  int  `json:"page"`
				Next  *int `json:"next_page"`
				Total *int `json:"total_entries"`
			} `json:"pagination"`
		}
		if json.Unmarshal(body["meta"], &meta) != nil || meta.Pagination == nil || meta.Pagination.Page != pg.Number {
			return nil, errors.New("hetzner: invalid pagination")
		}
		for _, item := range items {
			var id string
			switch w := any(item).(type) {
			case wireZone:
				id = strconv.FormatInt(w.ID, 10)
			case wireRRset:
				id = rrkey(w)
			}
			if seen[id] {
				return nil, rest.ErrSamePage
			}
			seen[id] = true
		}
		count += len(items)
		next := meta.Pagination.Next
		if total := meta.Pagination.Total; total != nil && (count > *total || next == nil && count != *total) {
			return nil, errors.New("hetzner: incomplete or invalid inventory count")
		}

		switch {
		case next == nil:
			done = true
		case *next == pg.Number:
			return nil, rest.ErrSamePage
		case *next != pg.Number+1 || len(items) == 0:
			return nil, errors.New("hetzner: invalid next page")
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

func publicZone(w wireZone) (dnsprovider.Zone, error) {
	if w.ID <= 0 || names.ZoneName(w.Name) == "" || w.TTL == 0 {
		return dnsprovider.Zone{}, errors.New("hetzner: malformed Zone")
	}
	state := dnsprovider.HostingUnknown
	if w.Status == "ok" {
		state = dnsprovider.HostingActive
	}
	ns := make([]string, len(w.Nameservers.Assigned))
	for i, name := range w.Nameservers.Assigned {
		ns[i] = names.ZoneName(name)
	}
	return dnsprovider.Zone{ID: strconv.FormatInt(w.ID, 10), Name: names.ZoneName(w.Name), State: state, Nameservers: ns}, nil
}

// ListZones implements dnsprovider.Provider: every Zone of the project whose
// name matches the filter, filtered locally.
// The ZoneSet is a Full View.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	all, err := list[wireZone](ctx, p, "/zones", "zones")
	if err != nil {
		return dnsprovider.ZoneSet{}, err
	}
	out := []dnsprovider.Zone{}
	for _, w := range all {
		z, err := publicZone(w)
		if err != nil {
			return dnsprovider.ZoneSet{}, err
		}
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}
	return dnsprovider.ZoneSet{Zones: out}, nil
}

func (p *Provider) zone(ctx context.Context, z dnsprovider.Zone) (wireZone, error) {
	id := z.ID
	if id == "" {
		id = names.ZoneName(z.Name)
	}
	if id == "" {
		return wireZone{}, dnsprovider.ErrNotFound
	}
	var answer struct {
		Zone *wireZone `json:"zone"`
	}
	if err := p.api().Do(ctx, http.MethodGet, "/zones/"+url.PathEscape(id), nil, nil, &answer); err != nil {
		return wireZone{}, err
	}
	if answer.Zone == nil {
		return wireZone{}, errors.New("hetzner: malformed Zone response")
	}
	if _, err := publicZone(*answer.Zone); err != nil {
		return wireZone{}, err
	}
	if z.Name != "" && names.ZoneName(answer.Zone.Name) != names.ZoneName(z.Name) {
		return wireZone{}, errors.New("hetzner: response names another Zone")
	}
	return *answer.Zone, nil
}

// GetZone reads the exact Zone name, without hiding remote errors.
func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	w, err := p.zone(ctx, dnsprovider.Zone{Name: names.ZoneName(name)})
	if err != nil {
		return dnsprovider.Zone{}, err
	}
	return publicZone(w)
}
func zonePath(z wireZone) string { return "/zones/" + strconv.FormatInt(z.ID, 10) }
func rrPath(z wireZone, w wireRRset) string {
	return zonePath(z) + "/rrsets/" + url.PathEscape(w.Name) + "/" + url.PathEscape(w.Type)
}

func effectiveTTL(z wireZone, w wireRRset) uint32 {
	if w.TTL != nil {
		return *w.TTL
	}
	return z.TTL
}

func expand(z wireZone, w wireRRset) ([]dnsprovider.Record, error) {
	if w.Name == "" || w.Type == "" || w.Records == nil || effectiveTTL(z, w) == 0 {
		return nil, errors.New("hetzner: malformed RRset")
	}
	labels, _ := json.Marshal(w.Labels)
	out := make([]dnsprovider.Record, 0, len(w.Records))
	for _, v := range w.Records {
		r := dnsprovider.Record{
			Type: strings.ToUpper(w.Type), Name: names.AbsoluteName(names.ZoneName(z.Name), w.Name),
			Value: readValue(z.Name, strings.ToUpper(w.Type), v.Value), TTL: effectiveTTL(z, w),
			Extras: map[string]string{ExtraComment: v.Comment, ExtraProtected: strconv.FormatBool(w.Protection.Change)},
		}
		if len(w.Labels) > 0 {
			r.Extras[ExtraLabels] = string(labels)
		}
		sum := sha256.Sum256([]byte(strings.ToLower(r.Name) + "\x00" + r.Type + "\x00" + r.Value))
		r.ID = hex.EncodeToString(sum[:])
		out = append(out, r)
	}
	return out, nil
}

func (p *Provider) snapshot(ctx context.Context, z dnsprovider.Zone) (wireZone, []wireRRset, error) {
	wz, err := p.zone(ctx, z)
	if err != nil {
		return wireZone{}, nil, err
	}
	if wz.Mode != "primary" {
		return wireZone{}, nil, errors.New("hetzner: RRset reads require a primary Zone")
	}
	sets, err := list[wireRRset](ctx, p, zonePath(wz)+"/rrsets", "rrsets")
	if err != nil {
		return wireZone{}, nil, err
	}
	seen := map[string]bool{}
	for _, set := range sets {
		if _, err := expand(wz, set); err != nil {
			return wireZone{}, nil, err
		}
		key := rrkey(set)
		if seen[key] {
			return wireZone{}, nil, rest.ErrSamePage
		}
		seen[key] = true
	}
	return wz, sets, nil
}

// Records expands RRset values, including unfamiliar types, into Records.
func (p *Provider) Records(ctx context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	wz, sets, err := p.snapshot(ctx, z)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}
	out := dnsprovider.RecordSet{Records: []dnsprovider.Record{}}
	for _, set := range sets {
		rs, _ := expand(wz, set)
		for _, r := range rs {
			if r.Type == "SOA" && strings.EqualFold(r.Name, names.ZoneName(wz.Name)) {
				fields := strings.Fields(r.Value)
				if len(fields) == 7 {
					if n, err := strconv.ParseUint(fields[2], 10, 32); err == nil {
						out.Serial = uint32(n)
					}
				}
			}
			if dnsprovider.MatchRecord(f, r) {
				out.Records = append(out.Records, r)
			}
		}
	}
	return out, nil
}
func rrkey(w wireRRset) string { return strings.ToLower(w.Name) + "/" + strings.ToUpper(w.Type) }

func readValue(zone, typ, value string) string {
	target := func(v string) string {
		if v == "." || strings.HasSuffix(v, ".") {
			return strings.ToLower(v)
		}
		if v == "@" {
			return names.ZoneName(zone) + "."
		}
		return strings.ToLower(v) + "." + names.ZoneName(zone) + "."
	}
	switch typ {
	case "A", "AAAA":
		return normalizeValue(typ, value)
	case "CNAME", "NS", "PTR":
		return target(value)
	case "MX", "SRV":
		f := strings.Fields(value)
		if len(f) > 0 {
			f[len(f)-1] = target(f[len(f)-1])
			return normalizeValue(typ, strings.Join(f, " "))
		}
	}
	return value
}
