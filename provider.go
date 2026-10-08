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
	// pages through the whole list.
	Zones(ctx context.Context, f ZoneFilter) ([]Zone, error)
	// Zone reads one Zone by its name, in any Hosting State, set as Zones
	// sets it: ErrNotFound when the Account has no Zone of that name.
	Zone(ctx context.Context, name string) (Zone, error)
	// Records lists a Zone's Records that match the filter, exactly
	// filtered, with the SOA serial when the Provider reports it.
	Records(ctx context.Context, zone Zone, f RecordFilter) (RecordSet, error)
	// Apply applies a Changeset and reports the result of each change.
	Apply(ctx context.Context, cs Changeset) (ApplyResult, error)
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

// TTLLimits is implemented by a Provider whose Record TTLs have other
// limits than DefaultTTLRange. TTL TTLAuto is allowed only where
// the Provider implements AutoTTL.
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
// the extra ExtraProxied.
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

// RecordSet is a Zone's Records as the Provider returned them.
type RecordSet struct {
	Records []Record
	// Serial is the Zone's SOA serial; zero when the Provider does not report it.
	Serial uint32
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
