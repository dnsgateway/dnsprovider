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

// Traits declare the scripted Zone writes, TTL range and proxiable types.
func (p *Provider) Traits() dnsprovider.Traits {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.traits()
}

// Traits declare the optional operations scripted when this Provider was
// built, and the TTL range and proxiable types scripted so far.
func (p scopedProvider) Traits() dnsprovider.Traits {
	t := p.Provider.Traits()
	t.Capabilities = slices.Clone(p.caps)
	return t
}

// scope is the scope of a call on the fake itself: the operations
// scripted so far.
func (p *Provider) scope() scope {
	p.mu.Lock()
	defer p.mu.Unlock()
	return scope{caps: p.capabilities(), unscoped: p.tenants != nil}
}

// CreateZone starts scripted DNS hosting.
func (p *Provider) CreateZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	return (scopedProvider{p, p.scope()}).CreateZone(ctx, name)
}

// UpdateZone changes scripted settings.
func (p *Provider) UpdateZone(ctx context.Context, z dnsprovider.Zone, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	return (scopedProvider{p, p.scope()}).UpdateZone(ctx, z, u)
}

// DeleteZone removes scripted DNS hosting.
func (p *Provider) DeleteZone(ctx context.Context, z dnsprovider.Zone) error {
	return (scopedProvider{p, p.scope()}).DeleteZone(ctx, z)
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

// ApplyChangeset applies a Changeset whole, when scripted (SetBatcher).
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	return (scopedProvider{p, p.scope()}).ApplyChangeset(ctx, cs)
}

// ListTenants lists the scripted Tenants (SetTenants).
func (p *Provider) ListTenants(ctx context.Context) ([]dnsprovider.Tenant, error) {
	return (scopedProvider{p, p.scope()}).ListTenants(ctx)
}

// ListDelegationSigners reads a scripted Registration's DS (SetRegistration).
func (p *Provider) ListDelegationSigners(ctx context.Context, z dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	return (scopedProvider{p, p.scope()}).ListDelegationSigners(ctx, z)
}

// SetDelegationSigners replaces a scripted Registration's DS (SetRegistration).
func (p *Provider) SetDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	return (scopedProvider{p, p.scope()}).SetDelegationSigners(ctx, z, keys)
}

// DeleteDelegationSigners removes a scripted Registration's DS (SetRegistration).
func (p *Provider) DeleteDelegationSigners(ctx context.Context, z dnsprovider.Zone) error {
	return (scopedProvider{p, p.scope()}).DeleteDelegationSigners(ctx, z)
}

func (p scopedProvider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	if err := p.unscripted(dnsprovider.CapBatcher); err != nil {
		return dnsprovider.ApplyResult{}, err
	}
	return p.applyChangeset(ctx, cs)
}

func (p scopedProvider) ListTenants(ctx context.Context) ([]dnsprovider.Tenant, error) {
	if err := p.unscripted(dnsprovider.CapTenantLister); err != nil {
		return nil, err
	}
	return p.tenantList(ctx)
}

func (p scopedProvider) ListDelegationSigners(ctx context.Context, z dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	if err := p.unscripted(dnsprovider.CapDSRegistrar); err != nil {
		return nil, err
	}
	return p.listDelegationSigners(ctx, z)
}

func (p scopedProvider) SetDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	if err := p.unscripted(dnsprovider.CapDSRegistrar); err != nil {
		return err
	}
	return p.setDelegationSigners(ctx, z, keys)
}

func (p scopedProvider) DeleteDelegationSigners(ctx context.Context, z dnsprovider.Zone) error {
	if err := p.unscripted(dnsprovider.CapDSRegistrar); err != nil {
		return err
	}
	return p.deleteDelegationSigners(ctx, z)
}

var (
	_ dnsprovider.Provider = (*Provider)(nil)
	_ dnsprovider.Provider = scopedProvider{}
)

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
