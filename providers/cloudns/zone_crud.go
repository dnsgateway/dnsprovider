package cloudns

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

// Capabilities declares no supported Zone writes.
func (p *Provider) Capabilities() []dnsprovider.Capability { return nil }

// CreateZone is unavailable for this adapter.
func (p *Provider) CreateZone(context.Context, string) (dnsprovider.Zone, error) {
	return dnsprovider.Zone{}, dnsprovider.ErrNotImplemented
}

// UpdateZone is unavailable for this adapter.
func (p *Provider) UpdateZone(context.Context, dnsprovider.Zone, dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	return dnsprovider.ZoneStatus{}, dnsprovider.ErrNotImplemented
}

// DeleteZone is unavailable for this adapter.
func (p *Provider) DeleteZone(context.Context, dnsprovider.Zone) error {
	return dnsprovider.ErrNotImplemented
}
