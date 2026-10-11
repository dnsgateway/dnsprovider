# Migrating to Provider Zone CRUD

`dnsprovider.Provider` now requires `CreateZone`, `GetZone`, `ListZones`,
`UpdateZone`, `DeleteZone`, and `Capabilities() []Capability`, alongside its
existing Account and Record operations. This is a breaking interface change
for external adapters and handwritten fakes.

## Consumer changes

Replace `p.Zone(ctx, name)` with `p.GetZone(ctx, name)` and
`p.Zones(ctx, filter)` with `p.ListZones(ctx, filter)`. Built-in concrete
adapters and `providertest.Provider` expose only the canonical read names.

Call Zone writes directly on the Provider. Discover support with
`CanCreateZone(p)`, `CanUpdateZone(p)`, and `CanDeleteZone(p)`, or inspect
`p.Capabilities()` for `CapZoneCreator`, `CapZoneUpdater`, and
`CapZoneDeleter`. These helpers read the explicit declaration.
`ZoneCreator`, `ZoneUpdater`, and `ZoneDeleter` have been removed; replace
parameters of those types with `Provider`.

```go
if dnsprovider.CanCreateZone(p) {
    zone, err := p.CreateZone(ctx, "example.com")
    // Handle permission errors, ErrNoTenant, and incomplete successful metadata.
    _ = zone
    _ = err
}
```

`Factory.Capabilities` and `Factory.Can` expose the same supported writes
before construction. Support says the adapter implements an operation;
it does not guarantee credentials, permissions, or a selected Tenant.
Cloudflare supports all three writes. The other twelve built-in adapters
expose the methods and return `ErrNotImplemented` without network traffic.
Use `errors.Is(err, dnsprovider.ErrNotImplemented)` to recognize absent
support. `ErrUnsupported` continues to describe a registry refusing a
Signing Key's form or algorithm on a DS write.

## External adapter changes

Rename or forward your existing reads to `GetZone` and `ListZones`, and
add all Zone-write methods. For writes you do not support, return the typed
sentinel immediately, including for a canceled context or invalid input:

```go
func (p *Provider) Capabilities() []dnsprovider.Capability { return nil }

func (p *Provider) CreateZone(context.Context, string) (dnsprovider.Zone, error) {
    return dnsprovider.Zone{}, dnsprovider.ErrNotImplemented
}

func (p *Provider) UpdateZone(context.Context, dnsprovider.Zone, dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
    return dnsprovider.ZoneStatus{}, dnsprovider.ErrNotImplemented
}

func (p *Provider) DeleteZone(context.Context, dnsprovider.Zone) error {
    return dnsprovider.ErrNotImplemented
}
```

Declare only supported writes. For example, an adapter implementing creation
alone returns `[]dnsprovider.Capability{dnsprovider.CapZoneCreator}` and
sets its Factory declaration to the same supported operation. Return an
independent slice on every `Capabilities()` call so callers cannot mutate
future discovery. Keep separate Factories' declaration slices independent
and verify Factory/runtime agreement at the public Provider seam. Retain
`var _ dnsprovider.Provider = (*Provider)(nil)` to catch missing methods.

Tenant listing, Zone Status reads, Signing Key reads, registrar DS writes,
batching, TTL limits, automatic TTLs, and proxy flags continue to use their
existing optional interfaces. Record CRUD and `Apply` retain their names
and behavior.

## Preserved behavior

Reads keep exact-name normalization, exact local filtering, all-page
pagination, Hosting State, Nameservers, and Tenant scope. A list's `Partial`
flag still describes a Partial View of access; pagination is completed
regardless of that flag.

Zone CRUD changes DNS hosting. Creation does not register a domain or change
its Delegation. Deletion removes hosting and Records, leaves Registration
intact, and does not check replacement hosting or alter Delegation NS
records. Consumers still own those checks and any registrar selection.

`UpdateZone` changes only non-nil fields. Cloudflare processes DNSSEC, HSTS,
then minimum TLS; earlier confirmed writes stay applied if a later setting
fails. The returned Zone Status describes known progress, with failed or
unread settings Unknown. Preserve typed errors and this partial result.

A successful create remains successful when metadata is missing; callers
refresh the Zone later rather than repeating creation. Cloudflare never
retries creation. A first deletion that finds no Zone returns `ErrNotFound`;
a not-found after a sent attempt with a lost response or server error can
confirm successful deletion. Tenant ownership checks remain in place.

## Scriptable Provider

`providertest.New()` exposes the same Zone CRUD seam. Enable each supported
write with `SetZoneCreator`, `SetZoneUpdater`, or `SetZoneDeleter` before
obtaining its Factory and building a Provider. Unscripted writes return
`ErrNotImplemented` without recording a call. The generated wrappers now
vary only the independently optional interfaces.

Built Providers capture Zone-write support and Tenant scope at construction
and share mutable Zone, Record, and failure scripts. A Factory's metadata
reflects scripts when it was obtained; its constructor reads scripts when
building. Obtain a new Factory after changing capability scripts and build
new Providers to adopt them. Existing Providers retain their captured
support. `DeleteZone` preserves scripted Registration and its Delegation
Signers; `RemoveZone` explicitly clears all state for an ID so a subsequent
`AddZone` starts clean.
