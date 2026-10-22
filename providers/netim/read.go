package netim

import (
	"cmp"
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

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// Account implements dnsprovider.Provider: it opens the session, or
// reuses it, and reads it to prove access. The Tenant is the reseller;
// Netim sets no account-wide nameservers.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var info map[string]any
	if err := p.read(ctx, http.MethodGet, "/session/", nil, &info); err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	return dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: p.id}}, nil
}

// ListZones implements dnsprovider.Provider: the domains that match the
// filter, read from the whole domain list and filtered locally. Netim
// documents no paging. A domain's status describes its Registration, not
// whether Netim serves its DNS, so every Zone's Hosting State is Unknown.
// The ZoneSet is a Full View.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	zs, err := p.zoneList(ctx, f)

	return dnsprovider.ZoneSet{Zones: zs}, err
}

func (p *Provider) zoneList(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	var domains []*struct {
		Domain string `json:"domain"`
	}
	if err := p.read(ctx, http.MethodPost, "/domains/", map[string]any{}, &domains); err != nil {
		return nil, err
	}

	if domains == nil {
		return nil, errors.New("netim: the domain list is not a list")
	}

	out := make([]dnsprovider.Zone, 0, len(domains))

	for _, d := range domains {
		if d == nil || names.ZoneName(d.Domain) == "" {
			return nil, errors.New("netim: the domain list holds a domain without a name")
		}

		name := names.ZoneName(d.Domain)

		z := dnsprovider.Zone{ID: name, Name: name, State: dnsprovider.HostingUnknown}
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}

	return out, nil
}

// GetZone implements dnsprovider.Provider: the domain of that name, found
// in the domain list, with the nameservers its info names. ErrNotFound
// when the list has no such domain.
func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	var info struct {
		NS nameservers `json:"ns"`
	}

	z, err := p.domainInfo(ctx, names.ZoneName(name), &info)
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	z.Nameservers = info.NS

	return z, nil
}

// domainInfo finds the domain of that name in the domain list, then
// reads its info into out. ErrNotFound when the list has no such domain.
func (p *Provider) domainInfo(ctx context.Context, name string, out any) (dnsprovider.Zone, error) {
	zs, err := p.zoneList(ctx, dnsprovider.ZoneFilter{})
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	i := slices.IndexFunc(zs, func(z dnsprovider.Zone) bool { return z.Name == name })
	if i < 0 {
		return dnsprovider.Zone{}, fmt.Errorf("netim: the Account has no domain %q: %w", name, dnsprovider.ErrNotFound)
	}

	if err := p.read(ctx, http.MethodGet, domainPath(name, "info"), nil, out); err != nil {
		return dnsprovider.Zone{}, err
	}

	return zs[i], nil
}

// zoneName is the Zone's domain name, which every call on the Zone
// needs.
func zoneName(zone dnsprovider.Zone) (string, error) {
	name := names.ZoneName(zone.Name)
	if name == "" {
		return "", errors.New("netim: the Zone has no name")
	}

	return name, nil
}

// domainPath is the path of a domain's resource, such as
// /domain/example.com/zone/info/.
func domainPath(domain string, resource ...string) string {
	return "/domain/" + url.PathEscape(domain) + "/" + strings.Join(append(resource, ""), "/")
}

// nameservers are a domain's ns: a list of names or of objects with a
// name, or an object of them keyed by their position, as Netim's
// Nameservers structure is. Each is a lower-case name without a trailing
// dot.
type nameservers []string

func (ns *nameservers) UnmarshalJSON(data []byte) error {
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		var byPosition map[string]json.RawMessage
		if json.Unmarshal(data, &byPosition) != nil {
			return errors.New("netim: malformed nameserver list")
		}

		keys := slices.Collect(maps.Keys(byPosition))
		slices.SortFunc(keys, func(a, b string) int {
			x, _ := strconv.Atoi(a)
			y, _ := strconv.Atoi(b)

			return cmp.Or(cmp.Compare(x, y), cmp.Compare(a, b))
		})

		for _, k := range keys {
			entries = append(entries, byPosition[k])
		}
	}

	*ns = nil

	for _, e := range entries {
		var host string
		if json.Unmarshal(e, &host) != nil {
			var obj struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(e, &obj) != nil {
				return errors.New("netim: malformed nameserver")
			}

			host = obj.Name
		}

		if host = names.ZoneName(strings.TrimSpace(host)); host != "" {
			*ns = append(*ns, host)
		}
	}

	return nil
}
