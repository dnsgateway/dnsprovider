package cloudflare

import (
	"context"

	"github.com/dnsgateway/dnsprovider"
)

// Zone reads a Zone by exact name.
//
// Deprecated: use GetZone.
func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	return p.GetZone(ctx, name)
}

// Zones lists exactly filtered Zones.
//
// Deprecated: use ListZones.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	return p.ListZones(ctx, f)
}

// Capabilities declares the supported Zone writes.
func (p *Provider) Capabilities() []dnsprovider.Capability {
	return []dnsprovider.Capability{dnsprovider.CapZoneCreator, dnsprovider.CapZoneUpdater, dnsprovider.CapZoneDeleter}
}
