package dnsprovider

import (
	"context"
)

// Provider is one Account at a DNS hosting service.
type Provider interface { //nolint:interfacebloat // Zone and Record CRUD form the shared public Provider seam.
	// Account describes the Account and proves its credentials work, even
	// when it has no Zones: ErrUnauthorized when they do not.
	Account(ctx context.Context) (AccountInfo, error)
	// Traits declares what the Provider supports, as its Factory declares
	// it, in an independent copy on each call. Support does not imply
	// permission or a selected Tenant; merely exposing a method does not
	// imply support.
	Traits() Traits
	// GetZone reads one Zone by its name, in any Hosting State, set as ListZones
	// sets it: ErrNotFound when the Account has no Zone of that name.
	GetZone(ctx context.Context, name string) (Zone, error)
	// ListZones lists the Account's Zones that match the filter, in every
	// Hosting State, exactly filtered. Each has ID, Name and State set,
	// and Nameservers when the Provider assigns them per Zone. The adapter
	// pages through the whole list. The Providers in this module return a
	// Full View; an adapter in front of another service with its own
	// access rules, such as a Gateway's, may report a Partial View.
	ListZones(ctx context.Context, f ZoneFilter) (ZoneSet, error)
	// CreateZone starts DNS hosting only: it never registers the domain or
	// changes Delegation. It Onboards a name in the Provider's Tenant and returns
	// the new Zone as ListZones reports it: normally Pending, with the
	// nameservers Delegation must name before the Provider serves it. A
	// create the Provider took without saying what it made is still a
	// success: the Zone is then its name alone, Pending, without an ID or
	// nameservers, until ListZones or GetZone reads it.
	// ErrConflict when the Tenant already has a Zone of that name, or the
	// Provider refuses it as another account holds it (Cloudflare's zone
	// hold; without one, Cloudflare Onboards a name active in another
	// account, pending until Delegation names the new Zone's
	// nameservers); ErrNoTenant when the Provider has no Tenant to
	// Onboard it in.
	// Unsupported adapters return ErrNotImplemented without network traffic.
	CreateZone(ctx context.Context, name string) (Zone, error)
	// UpdateZone changes the settings u sets, leaving those it leaves nil
	// as they are, and returns the Zone Status as it is after the change:
	// each setting written as the Provider answered, and each other one
	// as read, Unknown when it could not be. A setting written before
	// one fails stays written: the error comes with the Zone Status as
	// far as it is known, the settings written as answered and the rest
	// as read or Unknown.
	// Unsupported adapters return ErrNotImplemented without network traffic.
	UpdateZone(ctx context.Context, zone Zone, u ZoneUpdate) (ZoneStatus, error)
	// DeleteZone removes DNS hosting and its Records only, leaving Registration
	// intact. It does not verify replacement hosting or Delegation.
	// It Offboards the Zone by its ID, as ListZones or GetZone read it.
	// A retried delete that finds the Zone gone succeeds when an earlier
	// try may have Offboarded it: it was sent, and its answer was lost or
	// a server error. Otherwise finding no such Zone is ErrNotFound, as
	// the Provider does not say whether it ever held it. A Provider
	// scoped to a Tenant refuses a Zone of another; an unscoped one
	// leaves that check to the caller.
	// Unsupported adapters return ErrNotImplemented without network traffic.
	DeleteZone(ctx context.Context, zone Zone) error
	// ZoneDetails reads a Zone's Provider-side properties, its Zone Status
	// and, when request asks, the Signing Keys the Provider signs it with
	// (never those a registrar holds), as GetZone or ListZones read it.
	// Each property's outcome is in Properties: read (possibly Unknown or
	// empty), unsupported by the Provider (without an error or a call),
	// or failed, with its error; an unrequested one is not requested. The
	// error joins the failed properties' errors, and the details come
	// with it as far as they are known. Independent properties need not
	// be an atomic snapshot. A consumer of a Provider whose Signing Keys
	// are unsupported reads the DNSKEY RRset from the Zone's nameservers.
	// Adapters that read no property embed UnimplementedZoneDetails.
	ZoneDetails(ctx context.Context, zone Zone, request ZoneDetailRequest) (ZoneDetails, error)
	// ListRecords lists a Zone's Records that match the filter, exactly
	// filtered, with the SOA serial when the Provider reports it. The
	// RecordSet's Partial follows the same rule as ListZones' ZoneSet.
	ListRecords(ctx context.Context, zone Zone, f RecordFilter) (RecordSet, error)
	// CreateRecord adds a Record and returns it as the Provider stored
	// it, with its ID: ErrConflict when the Zone holds a Record identical
	// to it.
	CreateRecord(ctx context.Context, zone Zone, r Record) (Record, error)
	// UpdateRecord changes before, the Record as last read, into after
	// and returns after as the Provider stored it, with its ID. A Provider
	// with record IDs finds before by its ID; one without, by its content,
	// and fails with ErrNotFound when the Zone no longer holds it.
	UpdateRecord(ctx context.Context, zone Zone, before, after Record) (Record, error)
	// DeleteRecord removes a Record as last read, found as UpdateRecord
	// finds before.
	DeleteRecord(ctx context.Context, zone Zone, r Record) error
	// ApplyChangeset applies a Changeset in fewer calls than one per
	// change, or atomically, and reports the result of each change, or an
	// error when the Changeset failed as a whole. Apply goes through it
	// when the Traits declare CapBatcher; consumers call Apply.
	// Adapters that do not batch embed UnimplementedBatch.
	ApplyChangeset(ctx context.Context, cs Changeset) (ApplyResult, error)
	// ListTenants lists the Tenants the credentials reach, such as
	// Cloudflare's accounts. It works before a Tenant is set. Supported
	// when the Traits declare CapTenantLister; adapters whose credentials
	// reach one Tenant embed UnimplementedTenants.
	ListTenants(ctx context.Context) ([]Tenant, error)
	// ListDelegationSigners, SetDelegationSigners and
	// DeleteDelegationSigners read and replace the Delegation Signer (DS)
	// records the registry publishes for a Registration, for a Provider
	// that registers domains, such as Porkbun or Gandi: a registrar
	// adapter. Supported when the Traits declare CapDSRegistrar; other
	// adapters embed UnimplementedDelegationSigners. Writing them changes
	// the Delegation, so callers should confirm the set first; they never
	// change the Delegation's NS records. Each returns ErrNotFound when
	// the Account does not register the domain.
	//
	// ListDelegationSigners returns the Signing Keys the registry holds
	// for the Zone's domain, none when it holds none.
	ListDelegationSigners(ctx context.Context, zone Zone) ([]SigningKey, error)
	// SetDelegationSigners replaces the Signing Keys the registry holds
	// for the Zone's domain with keys, at least one: ErrNoSigningKeys,
	// without a request, for none. The adapter sends each key in the
	// form its registrar takes, its DNSKEY or its DS: ErrUnsupported
	// when the registry refuses the key's algorithm or form for the
	// domain.
	SetDelegationSigners(ctx context.Context, zone Zone, keys []SigningKey) error
	// DeleteDelegationSigners removes every Signing Key the registry
	// holds for the Zone's domain, taking DNSSEC off the Delegation.
	DeleteDelegationSigners(ctx context.Context, zone Zone) error
}

// Can reports whether a Provider declares support for c in its Traits, as
// Factory.Can does before it is built. Support does not imply permission
// or a selected Tenant.
func Can(p Provider, c Capability) bool {
	return p.Traits().Can(c)
}

// UnimplementedZoneWrites is embedded by an adapter that supports no
// Zone write: each returns ErrNotImplemented without network traffic,
// and its Traits declare no Capabilities.
type UnimplementedZoneWrites struct{}

// CreateZone returns ErrNotImplemented.
func (UnimplementedZoneWrites) CreateZone(context.Context, string) (Zone, error) {
	return Zone{}, ErrNotImplemented
}

// UpdateZone returns ErrNotImplemented.
func (UnimplementedZoneWrites) UpdateZone(context.Context, Zone, ZoneUpdate) (ZoneStatus, error) {
	return ZoneStatus{}, ErrNotImplemented
}

// DeleteZone returns ErrNotImplemented.
func (UnimplementedZoneWrites) DeleteZone(context.Context, Zone) error {
	return ErrNotImplemented
}

// UnimplementedBatch is embedded by an adapter that makes one call per
// change: ApplyChangeset returns ErrNotImplemented without network
// traffic, and its Traits do not declare CapBatcher.
type UnimplementedBatch struct{}

// ApplyChangeset returns ErrNotImplemented.
func (UnimplementedBatch) ApplyChangeset(context.Context, Changeset) (ApplyResult, error) {
	return ApplyResult{}, ErrNotImplemented
}

// UnimplementedTenants is embedded by an adapter whose credentials reach
// one Tenant: ListTenants returns ErrNotImplemented without network
// traffic, and its Traits do not declare CapTenantLister.
type UnimplementedTenants struct{}

// ListTenants returns ErrNotImplemented.
func (UnimplementedTenants) ListTenants(context.Context) ([]Tenant, error) {
	return nil, ErrNotImplemented
}

// UnimplementedDelegationSigners is embedded by an adapter that is not a
// registrar adapter: each Delegation Signer method returns
// ErrNotImplemented without network traffic, and its Traits do not
// declare CapDSRegistrar.
type UnimplementedDelegationSigners struct{}

// ListDelegationSigners returns ErrNotImplemented.
func (UnimplementedDelegationSigners) ListDelegationSigners(context.Context, Zone) ([]SigningKey, error) {
	return nil, ErrNotImplemented
}

// SetDelegationSigners returns ErrNotImplemented.
func (UnimplementedDelegationSigners) SetDelegationSigners(context.Context, Zone, []SigningKey) error {
	return ErrNotImplemented
}

// DeleteDelegationSigners returns ErrNotImplemented.
func (UnimplementedDelegationSigners) DeleteDelegationSigners(context.Context, Zone) error {
	return ErrNotImplemented
}

// TTLRangeOf returns the TTLs a Provider takes, as its Traits declare
// them.
func TTLRangeOf(p Provider) TTLRange {
	return p.Traits().TTLRange()
}

// AutoTTLOf reports whether a Provider reads TTL TTLAuto as "automatic",
// such as Cloudflare. To any other Provider it is one second.
func AutoTTLOf(p Provider) bool {
	return TTLRangeOf(p).Auto
}

// ExtraProxied is the Record extra holding the proxy flag of a Provider
// that can proxy traffic to some Record types, such as Cloudflare: "true"
// or "false". It is set only on Records of the types the Provider can
// proxy. Its Traits declare that extra, writable, with these types as its
// Types (ProxiedExtra, Traits.ProxiableTypes).
const ExtraProxied = "proxied"

// ProxiableTypesOf returns the Record types a Provider can proxy; none
// when its Traits declare no ExtraProxied extra.
func ProxiableTypesOf(p Provider) []string {
	return p.Traits().ProxiableTypes()
}

// ZoneSet is the Account's Zones as the Provider returned them.
type ZoneSet struct {
	Zones []Zone
	// Partial reports a Partial View: the caller's access does not cover
	// every Zone of the Account. It does not mean any Zone was left out.
	// False is a Full View.
	Partial bool
}

// RecordSet is a Zone's Records as the Provider returned them.
type RecordSet struct {
	Records []Record
	// Serial is the Zone's SOA serial; zero when the Provider does not report it.
	Serial uint32
	// Partial reports a Partial View: the caller's access does not cover
	// every name and type in the Zone. It does not mean any Record was
	// left out. False is a Full View.
	Partial bool
}

// ChangeResult is the outcome of one change in a Changeset.
type ChangeResult struct {
	Change Change
	// Record is the Record as the Provider stored it; empty for a deletion
	// and for a failed change.
	Record Record
	// Err is nil when the Provider confirmed the change.
	Err error
}

// ApplyResult is the outcome of applying a Changeset.
type ApplyResult struct {
	// Results has one entry per change, in Changeset order.
	Results []ChangeResult
	// Serial is the Zone's new SOA serial; zero when not known.
	Serial uint32
}
