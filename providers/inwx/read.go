package inwx

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// pageLimit is the page size the adapter asks nameserver.list for. INWX
// documents a default of 20 and no maximum; a page it answers smaller
// sets the size the later pages are held to.
const pageLimit = 100

// wireZone is a zone of nameserver.list.
type wireZone struct {
	RoID   wireInt `json:"roId"`
	Domain string  `json:"domain"`
}

// zones reads every page of nameserver.list until it holds count
// zones. A page repeating a zone, or a page shorter than the first
// before count is reached, is an error, as reading on would lose or
// repeat zones. The ID of each is its roId; the Hosting State is
// Unknown, as a hosted zone does not prove Delegation.
func (p *Provider) zones(ctx context.Context) ([]dnsprovider.Zone, error) {
	out := []dnsprovider.Zone{}
	seen := map[wireInt]bool{}
	size := 0

	for page := 1; ; page++ {
		var res struct {
			Count   *wireInt   `json:"count"`
			Domains []wireZone `json:"domains"`
		}

		if err := p.read(ctx, "nameserver.list", map[string]any{"domain": "*", "page": page, "pagelimit": pageLimit}, &res); err != nil {
			return nil, err
		}

		if res.Count == nil {
			return nil, fmt.Errorf("inwx: nameserver.list page %d has no count", page)
		}

		if page == 1 {
			size = len(res.Domains)
		}

		for _, d := range res.Domains {
			name := zoneName(d.Domain)
			if name == "" || d.RoID == 0 {
				return nil, errors.New("inwx: nameserver.list holds a zone without a name or roId")
			}

			if seen[d.RoID] {
				return nil, fmt.Errorf("inwx: nameserver.list page %d: %w", page, rest.ErrSamePage)
			}

			seen[d.RoID] = true

			out = append(out, dnsprovider.Zone{ID: d.RoID.String(), Name: name, State: dnsprovider.HostingUnknown})
		}

		total := int(*res.Count)

		switch {
		case len(out) == total:
			return out, nil
		case len(out) > total:
			return nil, fmt.Errorf("inwx: nameserver.list answered %d zones of a count of %d", len(out), total)
		case len(res.Domains) == 0 || len(res.Domains) < size:
			return nil, fmt.Errorf("inwx: nameserver.list page %d is short: %d zones, %d held of a count of %d", page, len(res.Domains), len(out), total)
		}
	}
}

// ListZones implements dnsprovider.Provider: every zone INWX hosts for
// the Account, master and slave, read page by page and filtered
// locally, exactly. The ZoneSet is a Full View. Nameservers are left
// nil, which would cost a call per zone; GetZone reads them.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	all, err := p.zones(ctx)
	if err != nil {
		return dnsprovider.ZoneSet{}, err
	}

	out := make([]dnsprovider.Zone, 0, len(all))

	for _, z := range all {
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}

	return dnsprovider.ZoneSet{Zones: out}, nil
}

// GetZone implements dnsprovider.Provider: the zone INWX hosts of that
// name, with the nameservers its apex NS Records name. ErrNotServed when
// the Account registers the domain but INWX hosts no zone of it, and
// ErrNotFound when it does neither.
func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name, err := namedZone(name)
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	info, err := p.zoneInfo(ctx, name, map[string]any{"domain": name, "type": "NS"})
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	z := dnsprovider.Zone{ID: info.RoID.String(), Name: name, State: dnsprovider.HostingUnknown}

	for _, w := range info.Records {
		if !strings.EqualFold(w.Type, "NS") || recordName(name, w.Name) != name {
			continue
		}

		if ns := zoneName(w.Content); ns != "" {
			z.Nameservers = append(z.Nameservers, ns)
		}
	}

	return z, nil
}

// wireInfo is nameserver.info's answer: a zone and its records.
type wireInfo struct {
	RoID      wireInt      `json:"roId"`
	Domain    string       `json:"domain"`
	SOAserial string       `json:"SOAserial"`
	Count     *wireInt     `json:"count"`
	Records   []wireRecord `json:"record"`
}

// zoneInfo reads nameserver.info with params for the zone name, or for
// its roId when name is empty. An unknown zone the Account registers is
// ErrNotServed.
func (p *Provider) zoneInfo(ctx context.Context, name string, params map[string]any) (wireInfo, error) {
	var info wireInfo
	if err := p.read(ctx, "nameserver.info", params, &info); err != nil {
		if name != "" {
			err = p.notServed(ctx, name, err)
		}

		return wireInfo{}, err
	}

	got := zoneName(info.Domain)
	if got == "" || info.RoID == 0 || (name != "" && got != name) {
		return wireInfo{}, fmt.Errorf("inwx: nameserver.info for %q answered another zone, or one without a name or roId", name)
	}

	return info, nil
}

// notServed turns the not-found of a zone into ErrNotServed when the
// Account registers the domain: INWX then hosts no zone of it. A domain
// it does not register leaves the not-found as it is, and a failed
// domain.info is returned, never taken for absence. Any other error is
// left as it is.
func (p *Provider) notServed(ctx context.Context, name string, err error) error {
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		return err
	}

	derr := p.read(ctx, "domain.info", map[string]any{"domain": name}, nil)

	switch {
	case derr == nil:
		return fmt.Errorf("inwx: zone %q: %w: %w", name, dnsprovider.ErrNotServed, err)
	case errors.Is(derr, dnsprovider.ErrNotFound):
		return err
	}

	return derr
}
