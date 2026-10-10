package dnsprovider

import "context"

// Provider is one Account at a DNS hosting service.
type Provider interface {
	// Account describes the Account and proves its credentials work, even
	// when it has no Zones: ErrUnauthorized when they do not.
	Account(ctx context.Context) (AccountInfo, error)
	// Zones lists the Account's Zones that match the filter, in every
	// Hosting State, exactly filtered. Each has ID, Name and State set,
	// and Nameservers when the Provider assigns them per Zone. The adapter
	// pages through the whole list. The Providers in this module return a
	// Full View; an adapter in front of another service with its own
	// access rules, such as a Gateway's, may report a Partial View.
	Zones(ctx context.Context, f ZoneFilter) (ZoneSet, error)
	// Zone reads one Zone by its name, in any Hosting State, set as Zones
	// sets it: ErrNotFound when the Account has no Zone of that name.
	Zone(ctx context.Context, name string) (Zone, error)
	// Records lists a Zone's Records that match the filter, exactly
	// filtered, with the SOA serial when the Provider reports it. The
	// RecordSet's Partial follows the same rule as Zones' ZoneSet.
	Records(ctx context.Context, zone Zone, f RecordFilter) (RecordSet, error)
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
}

// Batcher is implemented by a Provider that writes several Records in
// fewer calls than one per change, or atomically. Apply goes through it.
type Batcher interface {
	// ApplyChangeset applies a Changeset and reports the result of each
	// change, or an error when the Changeset failed as a whole.
	ApplyChangeset(ctx context.Context, cs Changeset) (ApplyResult, error)
}

// ZoneStatusReader is implemented by a Provider that reads the
// Provider-side Zone Status, such as Cloudflare. A Provider without it has
// every setting Unknown.
type ZoneStatusReader interface {
	// ZoneStatus reads a Zone's Zone Status.
	ZoneStatus(ctx context.Context, zone Zone) (ZoneStatus, error)
}

// ZoneStatusOf reads a Zone's Zone Status through the Provider's
// ZoneStatusReader, without a call when it has none: then every setting
// is Unknown.
func ZoneStatusOf(ctx context.Context, p Provider, zone Zone) (ZoneStatus, error) {
	if r, ok := p.(ZoneStatusReader); ok {
		return r.ZoneStatus(ctx, zone)
	}

	return ZoneStatus{DNSSEC: Unknown, HSTS: Unknown}, nil
}

// ZoneCreator is implemented by a Provider that can Onboard a zone name,
// such as Cloudflare ("add a site"). It starts DNS hosting only; it never
// registers the domain. It is a Zone write: a consumer asks the user
// first.
type ZoneCreator interface {
	// CreateZone Onboards a zone name in the Provider's Tenant and returns
	// the new Zone as Zones reports it: normally Pending, with the
	// nameservers Delegation must name before the Provider serves it. A
	// create the Provider took without saying what it made is still a
	// success: the Zone is then its name alone, Pending, without an ID or
	// nameservers, until Zones or Zone reads it.
	// ErrConflict when the Tenant already has a Zone of that name, or the
	// Provider refuses it as another account holds it (Cloudflare's zone
	// hold; without one, Cloudflare Onboards a name active in another
	// account, pending until Delegation names the new Zone's
	// nameservers); ErrNoTenant when the Provider has no Tenant to
	// Onboard it in.
	CreateZone(ctx context.Context, name string) (Zone, error)
}

// CanCreateZone reports whether a Provider implements ZoneCreator.
func CanCreateZone(p Provider) bool {
	_, ok := p.(ZoneCreator)

	return ok
}

// ZoneUpdater is implemented by a Provider that changes Zone settings,
// such as Cloudflare. It is a Zone write: a consumer asks the user first.
type ZoneUpdater interface {
	// UpdateZone changes the settings u sets, leaving those it leaves nil
	// as they are, and returns the Zone Status as it is after the change:
	// each setting written as the Provider answered, and each other one
	// as read, Unknown when it could not be. A setting written before
	// one fails stays written: the error comes with the Zone Status as
	// far as it is known, the settings written as answered and the rest
	// as read or Unknown.
	UpdateZone(ctx context.Context, zone Zone, u ZoneUpdate) (ZoneStatus, error)
}

// ZoneUpdate is the settings an UpdateZone changes: a nil one is left as
// it is.
type ZoneUpdate struct {
	DNSSEC *bool
	HSTS   *bool
	// MinTLS is one of TLSVersions.
	MinTLS *TLSVersion
}

// CanUpdateZone reports whether a Provider implements ZoneUpdater.
func CanUpdateZone(p Provider) bool {
	_, ok := p.(ZoneUpdater)

	return ok
}

// ZoneDeleter is implemented by a Provider that can Offboard a Zone, such
// as Cloudflare: stop hosting it and drop its Records there. It never
// touches the domain's registration. It is a Zone write that cannot be
// undone: a consumer asks the user first, and never Offboards the Live
// Zone, which would stop the domain resolving.
type ZoneDeleter interface {
	// DeleteZone Offboards the Zone by its ID, as Zones or Zone read it.
	// A retried delete that finds the Zone gone succeeds when an earlier
	// try may have Offboarded it: it was sent, and its answer was lost or
	// a server error. Otherwise finding no such Zone is ErrNotFound, as
	// the Provider does not say whether it ever held it. A Provider
	// scoped to a Tenant refuses a Zone of another; an unscoped one
	// leaves that check to the caller.
	DeleteZone(ctx context.Context, zone Zone) error
}

// CanDeleteZone reports whether a Provider implements ZoneDeleter.
func CanDeleteZone(p Provider) bool {
	_, ok := p.(ZoneDeleter)

	return ok
}

// TenantLister is implemented by a Provider whose credentials can reach
// several Tenants, such as Cloudflare. It works before a Tenant is set.
type TenantLister interface {
	// Tenants lists the Tenants the credentials reach.
	Tenants(ctx context.Context) ([]Tenant, error)
}

// CanListTenants reports whether a Provider implements TenantLister.
func CanListTenants(p Provider) bool {
	_, ok := p.(TenantLister)

	return ok
}

// KeyReader is implemented by a Provider whose API returns the keys it
// signs a Zone with, such as Cloudflare. A consumer of a Provider without
// it reads the DNSKEY RRset from the Zone's nameservers.
type KeyReader interface {
	// SigningKeys returns the Zone's key-signing keys, each with its DS
	// records; none when the Zone is not signed.
	SigningKeys(ctx context.Context, zone Zone) ([]SigningKey, error)
}

// CanReadKeys reports whether a Provider implements KeyReader.
func CanReadKeys(p Provider) bool {
	_, ok := p.(KeyReader)

	return ok
}

// SigningKeysOf reads a Zone's key-signing keys through the Provider's
// KeyReader, without a call when it has none: then there are none, as
// when the Zone is not signed, and a consumer reads the DNSKEY RRset from
// the Zone's nameservers instead.
func SigningKeysOf(ctx context.Context, p Provider, zone Zone) ([]SigningKey, error) {
	if r, ok := p.(KeyReader); ok {
		return r.SigningKeys(ctx, zone)
	}

	return nil, nil
}

// TTLLimits is implemented by a Provider whose Record TTLs have other
// limits than DefaultTTLRange. TTL TTLAuto is allowed only where
// the Provider implements AutoTTL. Its Factory declares the same range
// as its TTL.
type TTLLimits interface {
	// TTLRange is the shortest and the longest TTL, in seconds.
	TTLRange() (minTTL, maxTTL uint32)
}

// TTLRangeOf returns the TTLs a Provider takes, with TTLAuto allowed when
// it implements AutoTTL.
func TTLRangeOf(p Provider) TTLRange {
	r := DefaultTTLRange
	if l, ok := p.(TTLLimits); ok {
		r.Min, r.Max = l.TTLRange()
	}

	r.Auto = AutoTTLOf(p)

	return r
}

// AutoTTL is implemented by a Provider that reads TTL TTLAuto as
// "automatic", such as Cloudflare. To any other Provider it is one second.
// Its Factory declares it as TTL.Auto.
type AutoTTL interface {
	// AutoTTL reports whether TTL TTLAuto is automatic.
	AutoTTL() bool
}

// AutoTTLOf reports whether a Provider has an automatic TTL.
func AutoTTLOf(p Provider) bool {
	a, ok := p.(AutoTTL)

	return ok && a.AutoTTL()
}

// ExtraProxied is the Record extra holding the proxy flag of a Provider
// that implements ProxyFlag: "true" or "false". It is set only on Records
// of the types the Provider can proxy.
const ExtraProxied = "proxied"

// ProxyFlag is implemented by a Provider that can proxy traffic to some
// Record types, such as Cloudflare. Their Records carry the proxy flag in
// the extra ExtraProxied. Its Factory declares that extra, writable, with
// these types as its Types (ProxiedExtra, Factory.ProxiableTypes).
type ProxyFlag interface {
	// ProxiableTypes are the Record types the Provider can proxy.
	ProxiableTypes() []string
}

// ProxiableTypesOf returns the Record types a Provider can proxy; none
// when it does not implement ProxyFlag.
func ProxiableTypesOf(p Provider) []string {
	if f, ok := p.(ProxyFlag); ok {
		return f.ProxiableTypes()
	}

	return nil
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
