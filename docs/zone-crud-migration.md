# Migrating to Provider Zone CRUD

`dnsprovider.Provider` now requires `CreateZone`, `GetZone`, `ListZones`,
`UpdateZone`, `DeleteZone`, and `Traits() Traits`, alongside its
existing Account and Record operations. This is a breaking interface change
for external adapters and handwritten fakes.

## Consumer changes

Replace `p.Zone(ctx, name)` with `p.GetZone(ctx, name)` and
`p.Zones(ctx, filter)` with `p.ListZones(ctx, filter)`. Built-in concrete
adapters and `providertest.Provider` expose only the canonical read names.

Call Zone writes directly on the Provider. Discover support with
`Can(p, CapZoneCreator)`, `Can(p, CapZoneUpdater)`, or
`Can(p, CapZoneDeleter)`, which read `p.Traits().Capabilities`, the
explicit declaration. `CanCreateZone`, `CanUpdateZone`, and
`CanDeleteZone` have been removed in favour of `Can`.
`ZoneCreator`, `ZoneUpdater`, and `ZoneDeleter` have been removed; replace
parameters of those types with `Provider`.

```go
if dnsprovider.Can(p, dnsprovider.CapZoneCreator) {
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
type Provider struct {
    dnsprovider.UnimplementedZoneWrites
    // ...
}

// traits are declared once, for the Factory and every Provider.
var traits = dnsprovider.Traits{TTL: dnsprovider.TTLRange{Min: 60, Max: 86400}}

func (p *Provider) Traits() dnsprovider.Traits { return traits.Clone() }
```

Set `Factory.Traits` to the same declaration (`dnsprovider.Factory{Traits:
traits.Clone(), ...}`).

Declare only supported writes. For example, an adapter implementing creation
alone declares `Capabilities: []dnsprovider.Capability{dnsprovider.CapZoneCreator}`
in its Traits. Return an independent copy (`Traits.Clone`) on every
`Traits()` call so callers cannot mutate future discovery. Retain
`var _ dnsprovider.Provider = (*Provider)(nil)` to catch missing methods.

The `TTLLimits`, `AutoTTL`, and `ProxyFlag` interfaces are removed: declare
the TTL range (with `Auto`) as `Traits.TTL` and the proxiable types as a
`ProxiedExtra` entry in `Traits.Extras`. `TTLRangeOf`, `AutoTTLOf`, and
`ProxiableTypesOf` read them from `Traits()`. A `Factory` literal's
`Capabilities`, `TTL`, and `Extras` now sit in its embedded `Traits`.

Tenant listing, registrar DS writes and batching are now `Provider` methods
too, declared in Traits like Zone writes; see "Optional operations in
Traits" below.

`ZoneDetails(ctx, zone, request)` is now part of `Provider`; an adapter that
reads no Zone property embeds `dnsprovider.UnimplementedZoneDetails`. The
`ZoneStatusReader`, `KeyReader`, and `ZoneDetailsReader` interfaces and the
`ZoneStatusOf`, `SigningKeysOf`, and `CanReadKeys` helpers are removed: read
`ZoneDetailsOf(ctx, p, name, request)` and its `Status`, `SigningKeys`, and
`Properties`. A setting the Provider fails to read is now its property
failed, with its error, rather than a silent Unknown. In `providertest`,
`OpZoneStatus` and `OpSigningKeys` are now `OpZoneDetails`.

`DSRegistrar` now lists, sets, and deletes: rename `DelegationSigners` to
`ListDelegationSigners`, and replace `SetDelegationSigners(ctx, zone, nil)`
with `DeleteDelegationSigners(ctx, zone)`. `SetDelegationSigners` returns
`ErrNoSigningKeys` without a request when given no keys. In
`providertest`, `OpDelegationSigners` is now `OpListDelegationSigners`, and a
delete records `OpDeleteDelegationSigners`. Record CRUD and `Apply` retain their names
and behavior.

## Optional operations in Traits

The `Batcher`, `TenantLister`, and `DSRegistrar` interfaces and the
`CanListTenants` and `CanRegisterDS` helpers are removed. Their methods are
part of `Provider`, and Traits declare support:

| Was | Now |
| --- | --- |
| `p.(dnsprovider.Batcher)` | `dnsprovider.Can(p, dnsprovider.CapBatcher)` |
| `p.(dnsprovider.TenantLister)`, `CanListTenants(p)` | `dnsprovider.Can(p, dnsprovider.CapTenantLister)` |
| `TenantLister.Tenants(ctx)` | `p.ListTenants(ctx)` |
| `p.(dnsprovider.DSRegistrar)`, `CanRegisterDS(p)` | `dnsprovider.Can(p, dnsprovider.CapDSRegistrar)` |

An undeclared operation returns `ErrNotImplemented` without network
traffic. External adapters embed `dnsprovider.UnimplementedBatch`,
`UnimplementedTenants`, and `UnimplementedDelegationSigners` for the
operations they do not support, and add `CapBatcher`, `CapTenantLister`, or
`CapDSRegistrar` to their Traits for those they do. `Apply` goes through
`ApplyChangeset` only when the Traits declare `CapBatcher`, so an adapter
that implements the method without declaring it keeps the CRUD path.

In `providertest`, `OpTenants` is now `OpListTenants` (value
`"ListTenants"`), and the generated wrapper types are gone: every built
Provider has every method, its Traits declare what was scripted.

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
