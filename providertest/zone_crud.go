package providertest

import (
	"context"
	"slices"

	"github.com/dnsgateway/dnsprovider"
)

// scopedProvider retains the operation declarations and Tenant scope captured at construction.
type scopedProvider struct {
	*Provider
	scope
}

// Capabilities declares the scripted Zone writes.
func (p *Provider) Capabilities() []dnsprovider.Capability {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.zoneWrites()
}

// Capabilities declares the Zone writes scripted when this Provider was built.
func (p scopedProvider) Capabilities() []dnsprovider.Capability { return slices.Clone(p.writes) }

// CreateZone starts scripted DNS hosting.
func (p *Provider) CreateZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	p.mu.Lock()
	sc := scope{writes: p.zoneWrites(), unscoped: p.tenants != nil}
	p.mu.Unlock()
	return (scopedProvider{p, sc}).CreateZone(ctx, name)
}

// UpdateZone changes scripted settings.
func (p *Provider) UpdateZone(ctx context.Context, z dnsprovider.Zone, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	p.mu.Lock()
	sc := scope{writes: p.zoneWrites()}
	p.mu.Unlock()
	return (scopedProvider{p, sc}).UpdateZone(ctx, z, u)
}

// DeleteZone removes scripted DNS hosting.
func (p *Provider) DeleteZone(ctx context.Context, z dnsprovider.Zone) error {
	p.mu.Lock()
	sc := scope{writes: p.zoneWrites()}
	p.mu.Unlock()
	return (scopedProvider{p, sc}).DeleteZone(ctx, z)
}

func (p scopedProvider) CreateZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	if err := p.unscripted(dnsprovider.CapZoneCreator); err != nil {
		return dnsprovider.Zone{}, err
	}
	return p.createZone(ctx, p.unscoped, name)
}

func (p scopedProvider) UpdateZone(ctx context.Context, z dnsprovider.Zone, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	if err := p.unscripted(dnsprovider.CapZoneUpdater); err != nil {
		return dnsprovider.ZoneStatus{}, err
	}
	return p.updateZone(ctx, z, u)
}

func (p scopedProvider) DeleteZone(ctx context.Context, z dnsprovider.Zone) error {
	if err := p.unscripted(dnsprovider.CapZoneDeleter); err != nil {
		return err
	}
	return p.deleteZone(ctx, z)
}

// Zone reads a scripted Zone by name.
//
// Deprecated: use GetZone.
func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	return p.GetZone(ctx, name)
}

// Zones lists scripted Zones.
//
// Deprecated: use ListZones.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	return p.ListZones(ctx, f)
}
