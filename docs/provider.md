# Provider module design

This document describes the current implementation of
`github.com/dnsgateway/dnsprovider`. The module manages DNS hosting through a
shared Provider interface and provider-neutral types. Consumers own their
credential storage, caches, UI, and Delegation checks.

## Scope

- One vocabulary across adapters for Accounts, Zones, Records, and Changesets.
- A required core for account verification, Zone CRUD, supported Zone-write
  declarations, and Record CRUD.
- Optional interfaces for Tenant listing, Zone Status reads, signing
  key reads, DS writes at a registrar, batch writes, TTL limits, automatic
  TTLs, and proxy flags.
- Exactly filtered lists for consumers without a cache.
- Shared HTTP plumbing for GoDaddy and Namecheap; Cloudflare uses
  `cloudflare-go/v7`.

Onboarding and Offboarding start and stop DNS hosting. They never register,
renew, transfer, or cancel a domain. The module never changes the
Delegation's NS records; only a registrar adapter changes the Delegation's DS
records. It does not manage a consumer's locally stored Accounts.

## Module layout

```text
dnsprovider/
├── provider.go      Provider, optional interfaces, capability helpers, results
├── zone_details.go  explicit detailed Zone read, property outcomes
├── types.go         AccountInfo, Tenant, Zone, Record, Changeset, ZoneStatus,
│                    SigningKey
├── config.go        Options, Field, Factory, Registry
├── record.go        record validation, names, TTL ranges, SameRecord
├── filter.go        filters and matching helpers
├── apply.go         Apply and ApplyOrder
├── stale.go         pre-write re-check and StaleError
├── errors.go        typed errors and APIError
├── rest/            HTTP client, rate limiting, pagination
├── providertest/    scriptable in-memory Provider for consumers' tests
├── internal/        adapter helpers and test support
└── providers/
    ├── registry.go  Registry() collecting all adapters
    ├── cloudflare/
    ├── cloudns/
    ├── digitalocean/
    ├── dnsimple/
    ├── gandi/
    ├── godaddy/
    ├── hetzner/
    ├── internetbs/
    ├── namecheap/
    ├── netim/
    ├── ovhcloud/
    ├── porkbun/
    ├── scaleway/
    └── vultr/
```

Consumers can import only the adapters they use. Importing `providers`
brings in every adapter through `providers.Registry()`.
`go.mod` declares Go 1.24.0.

## Types and record rules

The root package owns the public types. Cache IDs, refresh timestamps,
credential storage, and the Live Zone marker belong to consumers.

```go
type Zone struct {
    ID          string // opaque Provider ID
    Name        string // "example.com"
    State       HostingState
    Nameservers []string // nil when unknown
}

type Record struct {
    ID     string
    Type   string
    Name   string // absolute, without a trailing dot
    Value  string // zone-file presentation form
    TTL    uint32 // seconds
    Extras map[string]string
}
```

Cloudflare, OVHcloud and GoDaddy assign record IDs. Namecheap, Gandi, Hetzner, Internet.bs, and Netim use content-derived
keys, which change when the Record changes. Keep the whole Record as read
for updates and deletions.

`QualifyName(zone, name)` converts user input to an absolute Record name and
checks that it is inside the Zone; `@` and an empty name mean the apex.
`RelativeName` converts back for display. Adapters translate names to their
wire format at the boundary.

`EditableTypes` contains A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, and URI.
`Editable` and `CheckValue` expose the shared rules. MX values include their
preference, SRV values their priority, weight, and port, and URI values
their priority and weight. An adapter may support fewer write types.

`SameRecord` compares type and name ignoring case and a trailing dot, and
compares Value exactly. It ignores ID, TTL, and Extras. Duplicate detection
uses this comparison; the stale re-check also compares TTL and Extras.

The shared proxy key is `dnsprovider.ExtraProxied` (`"proxied"`), also
exported as `cloudflare.ExtraProxied`. Values are `"true"` or `"false"`.
Cloudflare can proxy A, AAAA, and CNAME Records.

Each Provider's `Traits` list the Record Extras it reads as `Extras`, one
`ExtraSpec` per key: its `Label`, its `Kind` (`ExtraBool`, `ExtraString`
or `ExtraJSON`), the record `Types` that carry it (none means every type),
and whether it is `Writable`. A write sends a writable extra as given and
keeps any other as the Provider holds it, leaving it alone or refusing a
change. The key `ExtraOther` (`"*"`) stands for the API fields an adapter
passes through without modelling them. `Traits.Extra(key)` finds a key's
entry, `Traits.CheckExtras(r)` rejects a Record carrying an extra the
Traits do not declare for its type or a bool one that is not `true` or
`false`, `SameExtras(a, b)` compares two Records' extras as a re-check
does, a proxy flag that is off counting as none, and `Traits.ProxiableTypes()` reads
the `ExtraProxied` entry, as `ProxiableTypesOf(p)` does for a built Provider.

| Provider | Key | Kind | Writable | Types |
| --- | --- | --- | --- | --- |
| Cloudflare | `proxied` | bool | Yes | A, AAAA, CNAME |
| Cloudflare | `comment` | string | No | all |
| Cloudflare | `tags` | json | No | all |
| ClouDNS | `*` (other API fields) | string | No | all |
| DNSimple | `system_record` | bool | No | all |
| DNSimple | `regions` | json | No | all |
| DNSimple | `parent_id` | string | No | all |
| Hetzner | `comment` | string | No | all |
| Hetzner | `protected` | bool | No | all |
| Hetzner | `labels` | json | No | all |
| Internet.bs | `internetbs:wire_value` | string | No | CNAME, NS, MX |
| Internet.bs | `*` (other API fields) | json | No | all |
| Netim | `*` (other record options) | json | No | all |
| Porkbun | `notes` | string | Yes | all |

`TTLRangeOf(p)` reads the TTL range, with automatic TTL, from `p.Traits()`:

| Provider | Minimum TTL | Maximum TTL | Automatic TTL |
| --- | --- | --- | --- |
| Default | 30 | 86400 | No |
| Cloudflare | 60 | 86400 | `TTLAuto` (1) |
| GoDaddy | 600 | 86400 | No |
| Namecheap | 60 | 60000 | No; its 1799-second automatic value is an ordinary TTL here |
| DNSimple | 0 | 4294967295 | No; API schema bounds, with plan restrictions enforced by the service |
| Gandi | 300 | 2592000 | No; siblings in an RRset share their TTL |
| Hetzner | 60 | 2147483647 | No; inherited TTLs become effective numeric TTLs, and siblings share their TTL |
| DigitalOcean | 30 | 86400 | No; the default range, as DigitalOcean documents no bounds |
| Scaleway | 60 | 2592000 | No; explicit TTL, as validated by the official Terraform provider |
| Vultr | 30 | 86400 | No; the default range, as Vultr documents no bounds |
| OVHcloud | 30 | 86400 | No; the default range, as OVHcloud documents no bounds; a native zero TTL inherits the Zone default and reads as that effective TTL |
| Netim | 30 | 86400 | No; the default range, as Netim documents no bounds; a Record without a custom TTL reads as the Zone's TTL |

`Traits.TTLRange()` reads the declared `TTL`, with a zero `TTL` standing
for the default range; a Factory carries the same Traits, for a consumer
that knows only the Provider type.

`TTLRange.Check` validates a TTL. Shared validation helpers are available
to consumers; `Apply` does not run them automatically.

## Configuration and registry

Every adapter exposes a typed `Config`, `New`, and `Factory`. Construction
validates configuration without making a network call.

| Adapter | Config fields | Factory field names |
| --- | --- | --- |
| Cloudflare | `Token`, optional `TenantID` | `token`, `tenant_id` |
| GoDaddy | `Token` (personal access token) | `token` |
| Namecheap | `User`, `Key`, `ClientIP` | `user`, `key`, `client_ip` |
| Gandi | `Token` | `token` |
| Hetzner | `Token` | `token` (secret, project scoped) |
| DigitalOcean | `Token` | `token` |
| Scaleway | `SecretKey`, `ProjectID` | `secret_key` (secret), `project_id` |
| Vultr | `APIKey` | `api_key` |
| Internet.bs | `Key`, `Password` | `key`, `password` |
| Netim | `ID` (reseller ID), `Secret` | `id`, `secret` (both secret) |
| OVHcloud | `ApplicationKey`, `ApplicationSecret`, `ConsumerKey`, `Endpoint` | `application_key`, `application_secret`, `consumer_key` (all secret), `endpoint` (`ovh-eu` default, `ovh-ca`, `ovh-us`) |

Cloudflare's Tenant ID must be 32 lower-case hex digits. Its constructor
uses Config credentials rather than the SDK's environment credentials.
Namecheap requires a whitelisted client IPv4 address; it does not discover
the caller's public IP.

```go
p, err := cloudflare.New(cloudflare.Config{
    Token: token, TenantID: accountID,
}, dnsprovider.WithHTTPClient(client), dnsprovider.WithLogger(logger))
```

Options are `WithHTTPClient`, `WithBaseURL`, and `WithLogger`. Without a
custom HTTP client, adapters use a 30-second request timeout. A supplied
client keeps its own timeouts. Logging is disabled by default.

For selection at run time:

```go
reg := providers.Registry()
p, err := reg.New("namecheap", map[string]string{
    "user": "apiuser", "key": apiKey, "client_ip": "192.0.2.10",
})
```

`Field` describes each field's Name, Label, Secret flag, Tenant flag, Default,
and Choices. A field with a Default is optional: the Factory fills it in when
it is missing or empty. A field with Choices takes only one of them.
Factories reject unknown fields, missing required fields, and values not among
a field's Choices. `Registry.Types`
returns sorted provider names; `Registry.New` rejects unknown types.

`Traits` declare what a Provider type supports: its Zone writes
(`Capabilities`), its TTL range (`TTL`) and its Record Extras (`Extras`).
Each adapter declares them once; its `Factory` embeds them and every
Provider it builds reports them from `Traits()`, an independent copy on each
call. `Factory.Can` checks `CapZoneCreator`, `CapZoneUpdater`, or
`CapZoneDeleter` before credentials are available; `Can(p, c)` reads a
built Provider's Traits the same way.
Support does not guarantee credentials, permissions, or a selected Tenant.
An adapter supporting no Zone write embeds
`dnsprovider.UnimplementedZoneWrites`, whose writes return
`ErrNotImplemented` without network traffic.

## Required interface and filters

These signatures are in the root `dnsprovider` package:

```go
type Provider interface {
    Traits() Traits
    Account(context.Context) (AccountInfo, error)
    CreateZone(context.Context, string) (Zone, error)
    GetZone(context.Context, string) (Zone, error)
    ListZones(context.Context, ZoneFilter) (ZoneSet, error)
    UpdateZone(context.Context, Zone, ZoneUpdate) (ZoneStatus, error)
    DeleteZone(context.Context, Zone) error
    ZoneDetails(context.Context, Zone, ZoneDetailRequest) (ZoneDetails, error)
    ListRecords(context.Context, Zone, RecordFilter) (RecordSet, error)
    CreateRecord(context.Context, Zone, Record) (Record, error)
    UpdateRecord(ctx context.Context, zone Zone, before, after Record) (Record, error)
    DeleteRecord(context.Context, Zone, Record) error
}

type ZoneFilter struct {
    Contains string
}

type RecordFilter struct {
    Type     string
    Contains string
}
```

Zero filters match everything. Contains matches names ignoring case in
absolute form with a trailing dot: `example.com.` matches `example.com` and
`shop.example.com`, but not `example.community`. Type matches ignoring case.
Adapters push filters down where possible and apply `MatchZone` or
`MatchRecord` locally, so results are exactly filtered. Lists read all pages.
`GetZone(ctx, name)` matches an exact name ignoring case and a trailing dot,
and returns `ErrNotFound` when absent.

`RecordSet` contains Records and an optional SOA Serial. Adapters return zero for the serial when it is unknown.

`ZoneSet` contains Zones. Both `ZoneSet` and `RecordSet` carry `Partial`,
which marks a Partial View: the caller's access does not cover every Zone, or
every name and type in the Zone. It does not mean anything was left out;
false is a Full View. Every adapter in this module returns a Full View; only an
adapter in front of a service with its own access rules, such as a Gateway,
reports a Partial View.

## Accounts, Tenants, and Hosting State

`Account` verifies credentials even when the Account has no Zones and returns
`AccountInfo{Tenant, Nameservers}`. Nameservers are supplied at account level
only when shared across Zones. Cloudflare supplies them per Zone.

A Tenant is a Provider-side account. Cloudflare declares `CapTenantLister`;
`Can(p, CapTenantLister)` detects it. `ListTenants` lists accessible accounts
with or without a configured Tenant; other adapters return `ErrNotImplemented`. With TenantID, `ListZones` and `GetZone` are scoped to
that account. Without it, they reach every Zone the token can access.
Record and setting calls address a Zone by ID in either mode, without an
additional Tenant ownership check. `DeleteZone` checks ownership when scoped;
`CreateZone` requires a Tenant.

Cloudflare verifies an account-owned token in its Tenant first, falling back
to user-token verification on authorization or not-found errors. Without a
Tenant it verifies only a user token and returns an empty Tenant. With a
Tenant it looks up its name through `Tenants`; missing account-list permission
leaves the Tenant ID alone.

GoDaddy verifies by listing active registrations, stopping when it finds
nameservers on `domaincontrol.com`. Namecheap uses `users.getBalances` and
returns its user as the Tenant and BasicDNS nameservers.

`HostingState` has Unknown, Active, Pending, and Moved values:

- Cloudflare maps `active` to Active, `pending` and `initializing` to Pending,
  and `moved` and `deactivated` to Moved; other states are Unknown.
- GoDaddy maps any nameserver on `domaincontrol.com` to Active, all elsewhere
  to Moved, and no reported nameservers to Unknown.
- Namecheap lists only domains on its DNS and reports them Active.

Cloudflare can list several Zones of one name. `GetZone(name)` prefers Active,
then Pending, then the first listed Zone.

## Zone operations and optional settings reads

Every Provider exposes Zone CRUD. Cloudflare declares support for all three
Zone writes; other built-in adapters return `ErrNotImplemented` before any
network request. Test support with `Can(p, CapZoneCreator)`,
`CapZoneUpdater`, or `CapZoneDeleter`, then call the method directly on the
Provider.
`ZoneCreator`, `ZoneUpdater`, and `ZoneDeleter` have been removed; use
`Provider` instead.

Cloudflare's `ZoneDetails` reads Zone Status and Signing Keys; every other
built-in adapter embeds `dnsprovider.UnimplementedZoneDetails`, which reports
each property unsupported without a request. Porkbun, Gandi, and Internet.bs
declare `CapDSRegistrar`.

`CreateZone(ctx, name)` Onboards a name with `type: full` in the configured
Tenant. It returns `ErrNoTenant` without a request when unscoped and
`ErrConflict` for an existing name or zone-hold refusal. It is never retried.
If Cloudflare confirms creation without a usable Zone, the adapter reads it
back; if that fails or finds only a Moved copy, it returns the name alone,
Pending, without an ID or nameservers.

`DeleteZone(ctx, zone)` Offboards by ID and drops its Records. A missing ID
fails without a request. When scoped, it first reads the Zone to verify its
Tenant. A first-attempt not-found is `ErrNotFound`; a retried delete that finds
the Zone gone succeeds only when a prior sent attempt may have deleted it
(a lost response or server error).

```go
type ZoneStatus struct {
    DNSSEC Setting
    HSTS   Setting
    MinTLS TLSVersion
}

type ZoneUpdate struct {
    DNSSEC *bool
    HSTS   *bool
    MinTLS *TLSVersion
}
```

`Setting` is Unknown, Off, On, or Pending. DNSSEC may be Pending while
Cloudflare signs or unsigns the Zone. `TLSVersion` is a string;
`TLSVersions` lists TLS10, TLS11, TLS12, and TLS13 in order. TLSUnknown is
the empty string. Unknown settings and TLS versions display as `?`.

Zone Status is read with `ZoneDetails` (see Detailed Zone reads).
Cloudflare reads DNSSEC, HSTS, and minimum TLS concurrently; a failed read is
its property failed, with its error, and its value Unknown.

`UpdateZone` processes DNSSEC, HSTS, then MinTLS. Nil fields are read and
left unchanged. A failed write stops the operation, returning earlier
settings as known and the failed and subsequent settings Unknown; earlier
writes remain applied. An empty update reads the Zone Status, failing only
when every read fails.
HSTS writes preserve existing security-header fields, supplying a six-month
max-age when enabling it without one. MinTLS accepts only `TLSVersions`.

```go
type SigningKey struct {
    DNSKEY string   // "257 3 13 <base64>"
    KeyTag uint16
    DS     []string // "2371 13 2 1F98…", SHA-256 first
}
```

A Provider whose API returns the keys it signs a Zone with reads them in
`ZoneDetails` when `ZoneDetailRequest.SigningKeys` asks: none when the Zone is
unsigned. Where `Properties.SigningKeys` is `PropertyUnsupported`, a consumer
reads the DNSKEY RRset from the Zone's nameservers. DS digests are in upper
case. Cloudflare returns the key of its DNSSEC status while the Zone is
signed, pending or pending-disabled.

```go
// Provider methods, supported when Traits declare CapDSRegistrar.
ListDelegationSigners(ctx context.Context, zone Zone) ([]SigningKey, error)
SetDelegationSigners(ctx context.Context, zone Zone, keys []SigningKey) error
DeleteDelegationSigners(ctx context.Context, zone Zone) error
```

A registrar adapter, a Provider that registers domains and can replace the
DS records the registry publishes for them, declares `CapDSRegistrar`;
`Can(p, CapDSRegistrar)` detects it. Other adapters embed
`UnimplementedDelegationSigners` and return `ErrNotImplemented`. Each method returns `ErrNotFound` when the
Account does not register the domain: a consumer looking for the registrar
of a zone name skips that Account. `ListDelegationSigners` returns the
Signing Keys the registry holds for the Zone's domain, none when it holds
none. `SetDelegationSigners` replaces the whole set with at least one key,
keeping a DS in place through a rollover; given none it returns
`ErrNoSigningKeys` without a request, so DNSSEC never leaves the Delegation
by accident. `DeleteDelegationSigners` removes every key, taking DNSSEC off
the Delegation. Each adapter sends every key in the form its registrar takes,
the DNSKEY or the DS, and returns `ErrUnsupported` when the registry refuses
the key's algorithm, digest type or form for the domain. Porkbun implements
it, sending the DS, and Gandi, sending the DNSKEY. Internet.bs sends the
available DS and DNSKEY forms in one Registration update. Netim sends a key's
DNSKEY when it has one, and otherwise its DS, adding keys before removing
them.

## Detailed Zone reads

Use `dnsprovider.ZoneDetailsOf` to read identity and Zone properties together:

```go
details, err := dnsprovider.ZoneDetailsOf(ctx, p, "example.org",
    dnsprovider.ZoneDetailRequest{SigningKeys: true})
```

The result contains `Zone` (including Hosting State and Nameservers), `Status`
(DNSSEC, HSTS, minimum TLS), `SigningKeys`, and `Properties`. Zone Status is
always requested; Signing Keys require `SigningKeys: true`. `GetZone` and
`ListZones` retain their ordinary identity-only cost, and list Full View and
Partial View semantics are unchanged.

Every property outcome is a `PropertyResult` with `State` and `Err`:

| State | Meaning |
| --- | --- |
| `PropertyNotRequested` | Signing Keys were not requested. |
| `PropertyUnsupported` | The adapter lacks support for this property. |
| `PropertyRead` | The property was read successfully, possibly Unknown or an empty key list. |
| `PropertyFailed` | The supported read failed; `Err` retains its diagnostic. |

DNSSEC retains Unknown, Off, On, and Pending. Unknown does not mean disabled;
Pending covers signing and unsigning in progress. A successfully read empty
Signing Key list describes an unsigned Zone; unsupported and failed reads do
not establish that the Zone is unsigned. Inspect `Properties.SigningKeys`
before interpreting an empty list.

Identity is read first. If it fails, the helper returns no details and the
identity error. Once identity succeeds, known properties remain available
alongside a joined error for failed reads. Use `errors.Is` on that aggregate
or an individual property's `Err` for `ErrUnauthorized` and other typed errors;
`errors.As` retains the original `APIError` diagnostics. Unsupported properties
alone do not fail the read. Context cancellation remains visible in the
returned error, including when some details were obtained; inspect the result
and error together rather than treating cancellation as complete success.

`ZoneDetails` is part of `Provider`. `ZoneDetailsOf` passes the successfully
read Zone to it, then restores that identity in the result. An adapter that
reads no property embeds `dnsprovider.UnimplementedZoneDetails`, reporting
each requested property unsupported without a request.

Related properties can share one response, but independent Provider resources
are not an atomic snapshot. Signing Keys here describe Provider signing only:
this read never consults a Registration, substitutes registrar-held keys,
writes DS records, or establishes end-to-end DNSSEC validity.

## Applying a Changeset

```go
func Apply(ctx context.Context, p Provider, cs Changeset) (ApplyResult, error)

// Provider method, supported when Traits declare CapBatcher.
ApplyChangeset(context.Context, Changeset) (ApplyResult, error)
```

Use `Apply` for its common stale check, including on adapters that batch.
Direct CRUD and direct `ApplyChangeset` calls bypass that check. GoDaddy and
Namecheap still require the Before content to exist when updating or deleting;
Cloudflare finds Records by ID and patches their current state.

1. Re-read modifications and deletions. Additions alone need no re-check.
   When all touched Records have one type, filter by that type; if a Before
   ID is missing, read the whole Zone to detect a Record that changed type.
2. Compare each Before with the current Record, including TTL and Extras.
   An absent proxy flag and `proxied=false` are equivalent. If any differs,
   return `*StaleError` (matching `ErrStale`) without writing anything.
3. Use `ApplyChangeset` when the Traits declare `CapBatcher`. Otherwise run deletions, modifications, then
   additions, preserving order within each group through `ApplyOrder`.

The stale check is an additional read even when a Batcher reads again for
its write. It does not lock the Zone against intervening changes.
`StaleError.Changes` lists stale Changes and their current Record (`Now`),
empty when missing or no unambiguous replacement can be identified.

`ApplyResult.Results` is in original Changeset order, with a Change, stored
Record, and Err per entry. Deletions and failed changes carry an empty
Record. Individual CRUD failures do not stop other changes, except
`ErrNoTenant`, which aborts and returns a top-level error with an empty
result. A Batcher may return a top-level error for a whole-Changeset failure.
Serial is zero when unknown; the non-batch path never supplies one.

## Adapter operations and write granularity

| Operation | Cloudflare (v4 REST) | GoDaddy (v3 REST) | Namecheap (XML API) |
| --- | --- | --- | --- |
| Account / Tenants | account/user token verification; `GET /accounts` | `GET /domain-names?statuses=ACTIVE` | `users.getBalances` |
| ListZones | `GET /zones`, optional account and name filter | token-paged active domain list, local filter | paged `domains.getList`, SearchTerm and local filter |
| GetZone | exact-name list, preferring Active then Pending | domain detail, list fallback on 403/422 | domain list searched to an exact match |
| CreateZone / DeleteZone | `POST /zones`; `DELETE /zones/{id}` | Unsupported | Unsupported |
| ZoneStatus / UpdateZone | DNSSEC, `security_header`, `min_tls_version` reads and PATCHes | Unsupported | Unsupported |
| ListRecords | paged DNS record list with type/name filters | paged records, optional type filter, local filters | `domains.dns.getHosts`, local filters |
| Record writes | POST, PATCH (GET + PUT on type change), DELETE by ID | POST, PUT (TTL) and DELETE of single records by `recordId` | read and replace all hosts |
| Batcher | None | Per-record writes planned by RRset, read back | One getHosts, one setHosts, one getHosts read-back |

Cloudflare updates preserve unmodeled fields through PATCH. A type change
uses GET then PUT, preserving comment and tags and the proxy flag when
applicable, while dropping old type-specific settings. A missing proxy flag
in an update leaves the current flag unchanged where the new type can proxy.
Successful writes use the stored Record from the response when decodable;
otherwise they return the sent Record, which may have no ID after a create.
Creates are never retried. A retried record delete treats the specific
record-missing error as success, while other not-found errors remain errors.
Cloudflare currently applies Changesets through individual CRUD calls.

GoDaddy writes single records on the v3 API: a POST for each value added, a
DELETE by `recordId` for each value removed, and a PUT of each kept record
for a shared TTL change, so concurrent Changesets on one RRset keep each
other's values. Its CRUD methods use a one-change batch. A modification adds
before it removes; a move that fails partway is reported, not undone. Writes
are read back and checked for the Changeset's own effects; a miss matches
`ErrConflict` and `ErrUnconfirmed`.

Namecheap writes all hosts at once. Its CRUD methods use a one-change batch.
The Batcher preserves untouched hosts and EmailType, refusing the whole
Changeset on validation or preparation failure. It adds and modifies only
A, AAAA, CNAME, MX, TXT, and NS; NS writes must be below the apex. MX additions and modifications
require EmailType `MX` (Custom MX). All API commands use form-encoded POST
and are never retried, including reads. A setHosts whose answer is lost or
ambiguous is an Unconfirmed Write (`ErrUnconfirmed`). After a successful setHosts the
Batcher reads the hosts back and checks only the Changeset's own effects:
every host it added or modified is held with its TTL, and every host it
removed is gone. A miss is an error matching both `ErrConflict` and
`ErrUnconfirmed`, since a concurrent setHosts replaced the write; a failed
read-back matches `ErrUnconfirmed` alone. Results are the Records as read back. Every write replaces the
whole domain, so concurrent writers to one domain can lose each other's
changes; see the Namecheap provider doc.

## Errors

Use `errors.Is` for `ErrRateLimited`, `ErrUnauthorized`, `ErrNotFound`,
`ErrNotServed`, `ErrConflict`, `ErrUnconfirmed`, `ErrNoTenant`, `ErrStale`,
`ErrUnsupported`, and `ErrNotImplemented`. `ErrNotServed` is a domain the Account holds but the
Provider serves no DNS for, such as one delegated elsewhere; it also matches
`ErrNotFound`. `ErrUnsupported` is a DS write the registry refuses for the
domain.
`errors.As` exposes `*APIError` or `*StaleError` details.

`ErrUnconfirmed` is an Unconfirmed Write: the write was sent, but the Provider
may or may not have applied it, because its answer was lost, was a 5xx or
could not be read, or because the read-back after it failed. Re-read the
Records before retrying. A write the Provider refused in its answer, a 4xx
or an error inside a successful answer, is never unconfirmed, nor is a
failed read. A read-back that finds the Changeset's own effects replaced by
another writer's matches both `ErrUnconfirmed` and `ErrConflict`; a Changeset
refused before any write, such as an addition the Zone already holds,
matches `ErrConflict` alone. Check `ErrUnconfirmed` first.
Adapters mark a write's error with `Unconfirmed(err)`, or send it through
`rest.Client.Write`, which does.

`APIError` holds Provider, StatusCode, Messages, RetryAfter, and optional
Kind. Kind overrides HTTP classification; otherwise 429 maps to
ErrRateLimited, 401/403 to ErrUnauthorized, and 404 to ErrNotFound. StatusCode
zero represents an error reported inside a successful HTTP response.

Consult `Traits()` or the Zone-write helpers before offering Zone writes.
Detect absent optional interfaces before offering their operations.
`ErrNotImplemented` represents an operation the adapter has not implemented.

## Shared REST client

`rest.Client` provides BaseURL, HTTP, Auth, an optional `rest.Limiter`, an
error Decode callback, and retry/logging/body-size settings. Its request
methods are:

```go
func (c *Client) Do(ctx context.Context, method, path string,
    q url.Values, body, out any) error
func (c *Client) Write(ctx context.Context, method, path string,
    q url.Values, body, out any) error
```

`Write` is `Do` for a call that changes what the Provider holds, whatever
its method: once its request was sent, an error its answer does not refuse
the write with, and a success answer that cannot be decoded, match
`ErrUnconfirmed`. An error before any request was sent does not. `Do`
never marks an error unconfirmed, so a read POSTed to an RPC-style API
uses `Do`.

A `url.Values` body is form-encoded; other bodies are JSON. A `*[]byte`
output receives raw bytes for Namecheap's XML decoder. Any 2xx status is a
success. Response bodies default to a 64 MiB limit; Namecheap uses 4 MiB.

Set `Secrets` to the Account's credentials. No error `Do` returns or logs
shows one, raw or URL-escaped, including an `APIError`'s Messages and a
transport `*url.Error`'s URL; `errors.Is` still matches. Decode needs no
redaction of its own. For text or errors made outside `Do`, such as an
error read from a 2xx body, use `Redact` and `RedactError`.

Only GET, PUT, and DELETE retry HTTP 429/5xx responses; transport errors
are returned. Defaults are three attempts, 250 ms exponential backoff, and
a ten-second maximum wait. Retry-After accepts seconds or an HTTP date;
a requested wait over the maximum returns the error immediately. A retried
DELETE that receives HTTP 404 succeeds. Cloudflare uses its SDK's retry
machinery and adapter-specific delete rules instead.

`rest.AccountPerMinute` shares a rolling-window limiter between instances
for the same account and endpoint. GoDaddy uses 60 calls per minute,
Namecheap 20. `rest.Pages` supports page numbers, offsets, and markers,
and fails with `rest.ErrSamePage` on repeated pages or markers.

## Consumer responsibilities

Consumers decide how to store credentials, select Tenants, cache Records,
confirm writes, and refresh incomplete successful responses. The module
contains no TUI, vault, or cache migrations.

Zone writes and DS writes require consumer confirmation. Consumers must never Offboard
the Live Zone: resolve Delegation and verify that another Zone serves the
domain before deleting the old one. `DeleteZone` does not check Delegation.
Consumers also explain the registrar DS-record dependency when disabling
DNSSEC and the persistent browser effect of enabling HSTS.

A Migration workflow can be built from source `ListRecords`, supported target
`CreateZone`, and `Apply` with additions. The consumer checks target write
types, TTL limits, and Provider-specific Extras before copying, then handles
Delegation separately. There is no Migration API in this module.

## Testing

Adapter tests use `httptest` API responses. Run `go test ./...` for the test
suite and `go vet ./...` for static checks.

`providertest.New()` creates a scriptable fake with call recording, Zones,
Records, account data, failures, withheld results or serials, and Partial
Views (`SetPartialZones`, `SetPartialRecords`). Its
`Factory` builds Providers sharing the script. Configure optional operations
before building: `SetTenants`, `SetZoneStatus`, `SetSigningKeys`,
`SetRegistration`, `SetZoneDetails`, and `SetBatcher`. Configure supported Zone writes with
`SetZoneCreator`, `SetZoneUpdater`, and `SetZoneDeleter`. `SetRegistration`
makes a Zone one the Account registers,
with the DS records the registry holds; any other Zone is `ErrNotFound` to
the Delegation Signer methods. Every built Provider exposes every method;
its Traits declare the operations scripted, and unscripted ones
return `ErrNotImplemented` without recording a call. Factory and Provider
Traits declare only scripted writes. A built Provider keeps the write
support and Tenant scope captured at construction, while sharing mutable
Zone, Record, and failure scripts. Configure scripts before obtaining a
Factory and constructing Providers; obtain a fresh Factory after changing
capability scripts. `DeleteZone` removes hosting while retaining Registration
and its Delegation Signers. The explicit `RemoveZone` scripting helper clears
all associated state, including Registration, so re-adding its ID starts clean.
`SetZoneDetails(zoneID, details)` scripts a Zone's whole `ZoneDetails` answer.
Script `Properties` to distinguish successful, unsupported, and failed reads;
property errors are joined automatically. A Zone without it answers from
`SetZoneStatus` and `SetSigningKeys`, each property unsupported until scripted.
`Fail(OpZoneDetails, err)` adds a whole-read failure while retaining scripted
details. Unrequested keys are omitted. Combined reads
record `OpGetZone` then `OpZoneDetails`, with the requested flags in
`Call.ZoneDetailRequest`. Inputs and returned detail slices are independent copies.

The Traits' `TTL` is the range scripted with `SetTTLRange` and
`SetAutoTTL`, and their `Extras` hold the `ExtraProxied` entry for the types
scripted with `SetProxiableTypes`.

External implementations must migrate to the expanded interface. See the
[Zone CRUD migration guide](zone-crud-migration.md) for renamed reads,
unsupported-write implementations, and capability declarations.

Live tests only read and are skipped when required secret fields are unset.
Factory fields come from `DNSPROVIDER_<PROVIDER>_<FIELD>`:

| Provider | Environment variables |
| --- | --- |
| Cloudflare | `DNSPROVIDER_CLOUDFLARE_TOKEN`, optional `DNSPROVIDER_CLOUDFLARE_TENANT_ID` |
| DigitalOcean | `DNSPROVIDER_DIGITALOCEAN_TOKEN` |
| GoDaddy | `DNSPROVIDER_GODADDY_TOKEN` |
| Hetzner | `DNSPROVIDER_HETZNER_TOKEN` |
| Internet.bs | `DNSPROVIDER_INTERNETBS_KEY`, `DNSPROVIDER_INTERNETBS_PASSWORD` |
| Namecheap | `DNSPROVIDER_NAMECHEAP_USER`, `DNSPROVIDER_NAMECHEAP_KEY`, `DNSPROVIDER_NAMECHEAP_CLIENT_IP` |
| Netim | `DNSPROVIDER_NETIM_ID`, `DNSPROVIDER_NETIM_SECRET` |
| OVHcloud | `DNSPROVIDER_OVHCLOUD_APPLICATION_KEY`, `DNSPROVIDER_OVHCLOUD_APPLICATION_SECRET`, `DNSPROVIDER_OVHCLOUD_CONSUMER_KEY`, optional `DNSPROVIDER_OVHCLOUD_ENDPOINT` |
| Scaleway | `DNSPROVIDER_SCALEWAY_SECRET_KEY`, `DNSPROVIDER_SCALEWAY_PROJECT_ID` |
| Vultr | `DNSPROVIDER_VULTR_API_KEY` |

`DNSPROVIDER_<PROVIDER>_BASE_URL` overrides the live-test endpoint for a
sandbox or alternate API.

## Internet.bs

[Internet.bs setup and limitations](provider/internetbs.md) cover API access,
full unpaginated domain discovery, DNS eligibility, supported writes, exact
content selection, and replacement failures. Account verification uses
`Account/Balance/Get`; discovery uses `Domain/List`; DNS operations use
`Domain/DnsRecord/List`, `Add`, `Update`, and `Remove`. All commands use
form-encoded POST with body credentials and are never automatically retried.
Registration state does not establish DNS Hosting State, which is Unknown.
The adapter uses the common Apply CRUD fallback and content-derived Record
IDs; retain the complete Before Record for later edits and deletion.

## Netim

[Netim setup and limitations](provider/netim.md) cover the reseller ID and
API secret, OT&E, sessions, record reads and the sources the wire shapes
come from. The adapter opens one Netim session per Provider with
`POST /session/`, shares it between goroutines, reopens it once after a
401, and ends it with the concrete `(*netim.Provider).Close`. Account
verification reads `GET /session/`; discovery uses `POST /domains/` and
`GET /domain/{name}/info/`; Records come from `GET /domain/{name}/zone/info/`.
Hosting State is Unknown. Record IDs are content-derived. Creates send
`POST /domain/{name}/zone/` and deletes `DELETE /domain/{name}/zone/`, each
once; Netim's operation status decides between a confirmed write, a refusal
and an Unconfirmed Write, and creates are read back. Updates of Value or TTL
send one `PATCH /domain/{name}/zone/update/` and are read back; a move to
another owner or type deletes and then creates, restoring the old Record when
the create did not take. As a registrar adapter it reads and replaces the
Signing Keys of domains on other DNS servers through
`/domain/{name}/ds-record/`, adding keys before removing them.

## DigitalOcean

[DigitalOcean setup and limitations](provider/digitalocean.md) cover the
token, the `account:read` scope for verification and the `domain:*` scopes
for DNS, paginated discovery through validated next links, structured MX,
SRV and CAA fields, the provider-managed SOA, and type changes by
replacement. Account verification uses `GET /v2/account`; Domains are Zones
keyed by name with Unknown Hosting State; Domain Records are written by
native ID with POST, PUT and DELETE. Creates are never retried. The adapter
uses the common Apply CRUD fallback.

## Vultr

[Vultr setup and limitations](provider/vultr.md) cover the API key, its
access control and user permissions, cursor-paginated discovery, structured
MX and SRV priorities, quoted TXT data, PATCH updates read back by ID, and
type changes by replacement. Account verification uses `GET /v2/account`;
DNS Domains are Zones keyed by name with Unknown Hosting State; Records are
written by native ID with POST, PATCH and DELETE. Creates and PATCH updates
are never retried. The adapter uses the common Apply CRUD fallback.

## Scaleway

[Scaleway setup and limitations](provider/scaleway.md) cover Project scope,
secret key authentication, DNS permissions, targeted batched operations,
metadata retention, TTL bounds and Unconfirmed Writes. The adapter never
creates Zones implicitly.

## Hetzner

[Hetzner setup and limitations](provider/hetzner.md) cover Cloud API project
tokens, DNS permissions, inherited/shared TTLs, RRset metadata and protection,
and asynchronous action completion. Account verification uses an authenticated
Zone list and works with an empty project. Records have content-derived keys;
retain the complete Before Record. The Batcher writes single values
(`add_records`, `remove_records`), so concurrent Changesets on one RRset keep
each other's values; it waits for each write action and reads back its own
effects, reporting a lost write as `ErrConflict` and `ErrUnconfirmed`. An
action whose completion is unconfirmed matches `ErrUnconfirmed`; partial
moves remain visible as errors.

## OVHcloud

[OVHcloud setup and limitations](provider/ovhcloud.md) cover application and
consumer credentials, regional endpoints, signed requests with server-adjusted
timestamps, and the Account and DNS access rules. Account verification calls
the authenticated `GET /me`, not the public time API, and works without Zones.
Discovery lists DNS Zone services, not registrar domains. Records keep their
native IDs. Every edit is staged and then published by a Zone refresh: CRUD
refreshes after each edit, and the Batcher refreshes once after a Changeset's
staged edits. A failed refresh marks staged changes `ErrUnpublished`; type
changes replace the Record and return its new ID.
