package cloudns

import (
	"context"
	"errors"
	"net/url"
	"strconv"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// Zones implements dnsprovider.Provider: every accessible DNS Zone that
// matches the filter, including secondary Zones.
// The listing does not establish whether a Zone is being served.
// The ZoneSet is a Full View.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	zs, err := p.zoneList(ctx, f)

	return dnsprovider.ZoneSet{Zones: zs}, err
}

// zoneList lists the Zones that Zones returns, as a bare slice: Zones
// wraps it in a ZoneSet, while Zone searches the slice itself.
func (p *Provider) zoneList(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	zs, err := rest.Pages(100, nil, func(page rest.Page) ([]struct {
		Name string `json:"name"`
	}, error,
	) {
		var zs []struct {
			Name string `json:"name"`
		}
		err := p.call(ctx, "/dns/list-zones.json", url.Values{"page": {strconv.Itoa(page.Number)}, "rows-per-page": {strconv.Itoa(page.Size)}}, &zs)
		if err == nil {
			for _, z := range zs {
				if z.Name == "" {
					return nil, errors.New("cloudns: malformed zone listing")
				}
			}
		}
		return zs, err
	})
	if err != nil {
		return nil, err
	}
	out := make([]dnsprovider.Zone, 0, len(zs))
	for _, z := range zs {
		n := names.ZoneName(z.Name)
		z := dnsprovider.Zone{ID: n, Name: n, State: dnsprovider.HostingUnknown}
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}
	return out, nil
}

// Zone performs a case-insensitive exact lookup without masking API errors.
func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	zs, err := p.zoneList(ctx, dnsprovider.ZoneFilter{})
	if err != nil {
		return dnsprovider.Zone{}, err
	}
	for _, z := range zs {
		if z.Name == names.ZoneName(name) {
			return z, nil
		}
	}
	return dnsprovider.Zone{}, dnsprovider.ErrNotFound
}
