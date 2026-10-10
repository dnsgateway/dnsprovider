# Provider module design

This document describes the current implementation of
`github.com/dnsgateway/dnsprovider`. The module manages DNS hosting through a
shared Provider interface and provider-neutral types. Consumers own their
credential storage, caches, UI, and Delegation checks.

## Scope

- One vocabulary across adapters for Accounts, Zones, Records, and Changesets.
- A required core for account verification, Zone reads, and Record CRUD.
- Optional interfaces for Tenant listing, Zone writes and settings, signing
  key reads, batch writes, TTL limits, automatic TTLs, and proxy flags.
- Exactly filtered lists for consumers without a cache.
- Shared HTTP plumbing for GoDaddy and Namecheap; Cloudflare uses
  `cloudflare-go/v7`.

Onboarding and Offboarding start and stop DNS hosting. They never register,
renew, transfer, or cancel a domain. The module does not change Delegation
or manage a consumer's locally stored Accounts.

## Module layout

```text
dnsprovider/
├── provider.go      Provider, optional interfaces, capability helpers, results
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

Cloudflare and OVHcloud assign record IDs. GoDaddy, Namecheap, Gandi, Hetzner, and Internet.bs use content-derived
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

Each `Factory` lists the Record Extras its Providers read as `Extras`, one
`ExtraSpec` per key: its `Label`, its `Kind` (`ExtraBool`, `ExtraString`
or `ExtraJSON`), the record `Types` that carry it (none means every type),
and whether it is `Writable`. A write sends a writable extra as given and
keeps any other as the Provider holds it, leaving it alone or refusing a
change. The key `ExtraOther` (`"*"`) stands for the API fields an adapter
passes through without modelling them. `Factory.Extra(key)` finds a key's
entry, `Factory.CheckExtras(r)` rejects a Record carrying an extra the
Factory does not declare for its type or a bool one that is not `true` or
`false`, `SameExtras(a, b)` compares two Records' extras as a re-check
does, a proxy flag that is off counting as none, and `Factory.ProxiableTypes()` reads
the `ExtraProxied` entry, matching `ProxiableTypesOf`, as a Registry
contract test checks.

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
| Porkbun | `notes` | string | Yes | all |

`TTLRangeOf(p)` combines optional `TTLLimits` and `AutoTTL` support:

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

Each `Factory` declares the same range as its `TTL`, for a consumer that
knows only the Provider type; `Factory.TTLRange()` reads it, with a zero
`TTL` standing for the default range. A Registry contract test keeps each
Factory's range equal to `TTLRangeOf` of a Provider it builds.

`TTLRange.Check` validates a TTL. Shared validation helpers are available
to consumers; `Apply` does not run them automatically.

## Configuration and registry

Every adapter exposes a typed `Config`, `New`, and `Factory`. Construction
validates configuration without making a network call.

| Adapter | Config fields | Factory field names |
| --- | --- | --- |
| Cloudflare | `Token`, optional `TenantID` | `token`, `tenant_id` |
| GoDaddy | `Key`, `Secret` | `key`, `secret` |
| Namecheap | `User`, `Key`, `ClientIP` | `user`, `key`, `client_ip` |
| Gandi | `Token` | `token` |
| Hetzner | `Token` | `token` (secret, project scoped) |
| DigitalOcean | `Token` | `token` |
| Scaleway | `SecretKey`, `ProjectID` | `secret_key` (secret), `project_id` |
| Vultr | `APIKey` | `api_key` |
| Internet.bs | `Key`, `Password` | `key`, `password` |
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

Factory capabilities declare optional Zone writes. `Factory.Can` checks
`CapZoneCreator`, `CapZoneUpdater`, or `CapZoneDeleter` before credentials are
available. These declarations are hints; check the built Provider with
`CanCreateZone`, `CanUpdateZone`, or `CanDeleteZone` too.

## Required interface and filters

These signatures are in the root `dnsprovider` package:

```go
type Provider interface {
    Account(context.Context) (AccountInfo, error)
    Zones(context.Context, ZoneFilter) (ZoneSet, error)
    Zone(context.Context, string) (Zone, error)
    Records(context.Context, Zone, RecordFilter) (RecordSet, error)
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
`Zone(ctx, name)` matches an exact name ignoring case and a trailing dot,
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

A Tenant is a Provider-side account. Cloudflare implements `TenantLister`;
`CanListTenants` detects it. `Tenants` lists accessible accounts with or
without a configured Tenant. With TenantID, `Zones` and `Zone` are scoped to
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

Cloudflare can list several Zones of one name. `Zone(name)` prefers Active,
then Pending, then the first listed Zone.

## Optional Zone operations and settings

Cloudflare implements `ZoneCreator`, `ZoneDeleter`, `ZoneStatusReader`,
`ZoneUpdater` and `KeyReader`. GoDaddy and Namecheap implement none of these.

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

`ZoneStatusOf(ctx, p, zone)` returns Unknown settings without a call when
there is no reader. Cloudflare reads DNSSEC, HSTS, and minimum TLS
concurrently. A failed setting read is Unknown; the operation fails only
when all three reads fail. Permission-denied setting reads yield Unknown.

`UpdateZone` processes DNSSEC, HSTS, then MinTLS. Nil fields are read and
left unchanged. A failed write stops the operation, returning earlier
settings as known and the failed and subsequent settings Unknown; earlier
writes remain applied. An empty update delegates to `ZoneStatus`.
HSTS writes preserve existing security-header fields, supplying a six-month
max-age when enabling it without one. MinTLS accepts only `TLSVersions`.

```go
type SigningKey struct {
    DNSKEY string   // "257 3 13 <base64>"
    KeyTag uint16
    DS     []string // "2371 13 2 1F98…", SHA-256 first
}

type KeyReader interface {
    SigningKeys(ctx context.Context, zone Zone) ([]SigningKey, error)
}
```

A Provider whose API returns the keys it signs a Zone with implements
`KeyReader`; `CanReadKeys(p)` detects it. `SigningKeys` returns the Zone's
key-signing keys, none when it is unsigned. `SigningKeysOf(ctx, p, zone)`
returns none without a call when there is no reader. A consumer that gets
none reads the DNSKEY RRset from the Zone's nameservers. DS digests are in
upper case. Cloudflare returns the key of its DNSSEC status while the Zone
is signed, pending or pending-disabled.

## Applying a Changeset

```go
func Apply(ctx context.Context, p Provider, cs Changeset) (ApplyResult, error)

type Batcher interface {
    ApplyChangeset(context.Context, Changeset) (ApplyResult, error)
}
```

Use `Apply` for its common stale check, including on adapters with a Batcher.
Direct CRUD and direct `ApplyChangeset` calls bypass that check. GoDaddy and
Namecheap still require the Before content to exist when updating or deleting;
Cloudflare finds Records by ID and patches their current state.

1. Re-read modifications and deletions. Additions alone need no re-check.
   When all touched Records have one type, filter by that type; if a Before
   ID is missing, read the whole Zone to detect a Record that changed type.
2. Compare each Before with the current Record, including TTL and Extras.
   An absent proxy flag and `proxied=false` are equivalent. If any differs,
   return `*StaleError` (matching `ErrStale`) without writing anything.
3. Use `Batcher` if present. Otherwise run deletions, modifications, then
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

| Operation | Cloudflare (v4 REST) | GoDaddy (v1 REST) | Namecheap (XML API) |
| --- | --- | --- | --- |
| Account / Tenants | account/user token verification; `GET /accounts` | `GET /v1/domains?statuses=ACTIVE` | `users.getBalances` |
| Zones | `GET /zones`, optional account and name filter | marker-paged active domain list, local filter | paged `domains.getList`, SearchTerm and local filter |
| Zone | exact-name list, preferring Active then Pending | domain detail, list fallback on 403/422 | domain list searched to an exact match |
| CreateZone / DeleteZone | `POST /zones`; `DELETE /zones/{id}` | Unsupported | Unsupported |
| ZoneStatus / UpdateZone | DNSSEC, `security_header`, `min_tls_version` reads and PATCHes | Unsupported | Unsupported |
| Records | paged DNS record list with type/name filters | paged records, optional type endpoint, local filters | `domains.dns.getHosts`, local filters |
| Record writes | POST, PATCH (GET + PUT on type change), DELETE by ID | read and replace affected RRsets, DELETE empty RRsets | read and replace all hosts |
| Batcher | None | Changes grouped by RRset | One getHosts and one setHosts |

Cloudflare updates preserve unmodeled fields through PATCH. A type change
uses GET then PUT, preserving comment and tags and the proxy flag when
applicable, while dropping old type-specific settings. A missing proxy flag
in an update leaves the current flag unchanged where the new type can proxy.
Successful writes use the stored Record from the response when decodable;
otherwise they return the sent Record, which may have no ID after a create.
Creates are never retried. A retried record delete treats the specific
record-missing error as success, while other not-found errors remain errors.
Cloudflare currently applies Changesets through individual CRUD calls.

GoDaddy writes whole RRsets (type and name). Its CRUD methods use a
one-change batch; its Batcher groups reads and writes by RRset and reports
per-change failures. Moving a Record between RRsets requires multiple
writes. If only one half succeeds, the adapter attempts to undo it; a failed
undo is reported and can leave a partial change. Successful Records are
constructed from the sent data, without a post-write read. Concurrent writers
of the same RRset can overwrite each other's changes.

Namecheap writes all hosts at once. Its CRUD methods use a one-change batch.
The Batcher preserves untouched hosts and EmailType, refusing the whole
Changeset on validation or preparation failure. It adds and modifies only
A, AAAA, CNAME, MX, TXT, and NS; NS writes must be below the apex. MX additions and modifications
require EmailType `MX` (Custom MX). All API commands use form-encoded POST
and are never retried, including reads. A failed setHosts response can leave
whether the Changeset was applied uncertain. Successful write results are
constructed from the sent hosts; no post-write refresh is performed.

## Errors

Use `errors.Is` for `ErrRateLimited`, `ErrUnauthorized`, `ErrNotFound`,
`ErrNotServed`, `ErrConflict`, `ErrNoTenant`, `ErrStale`, and
`ErrNotImplemented`. `ErrNotServed` is a domain the Account holds but the
Provider serves no DNS for, such as one delegated elsewhere; it also matches
`ErrNotFound`.
`errors.As` exposes `*APIError` or `*StaleError` details.

`APIError` holds Provider, StatusCode, Messages, RetryAfter, and optional
Kind. Kind overrides HTTP classification; otherwise 429 maps to
ErrRateLimited, 401/403 to ErrUnauthorized, and 404 to ErrNotFound. StatusCode
zero represents an error reported inside a successful HTTP response.

Detect absent optional interfaces before offering operations.
`ErrNotImplemented` represents an operation the adapter has not implemented.

## Shared REST client

`rest.Client` provides BaseURL, HTTP, Auth, an optional `rest.Limiter`, an
error Decode callback, and retry/logging/body-size settings. Its request
method is:

```go
func (c *Client) Do(ctx context.Context, method, path string,
    q url.Values, body, out any) error
```

A `url.Values` body is form-encoded; other bodies are JSON. A `*[]byte`
output receives raw bytes for Namecheap's XML decoder. Any 2xx status is a
success. Response bodies default to a 64 MiB limit; Namecheap uses 4 MiB.

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
contains no TUI, vault, cache migrations, or registrar adapter.

Zone writes require consumer confirmation. Consumers must never Offboard
the Live Zone: resolve Delegation and verify that another Zone serves the
domain before deleting the old one. `DeleteZone` does not check Delegation.
Consumers also explain the registrar DS-record dependency when disabling
DNSSEC and the persistent browser effect of enabling HSTS.

A Migration workflow can be built from source `Records`, optional target
`CreateZone`, and `Apply` with additions. The consumer checks target write
types, TTL limits, and Provider-specific Extras before copying, then handles
Delegation separately. There is no Migration API in this module.

## Testing

Adapter tests use `httptest` API responses. Run `go test ./...` for the test
suite and `go vet ./...` for static checks.

`providertest.New()` creates a scriptable fake with call recording, Zones,
Records, account data, failures, withheld results or serials, and Partial
Views (`SetPartialZones`, `SetPartialRecords`). Its
`Factory` builds Providers sharing the script. Configure optional interfaces
before building: `SetTenants`, `SetZoneStatus`, `SetSigningKeys`, `SetBatcher`,
`SetZoneCreator`, `SetZoneUpdater`, and `SetZoneDeleter`. Unscripted Providers
omit those optional interfaces. When any Zone write is scripted, built
Providers expose all three Zone-write interfaces, but unscripted writes
return `ErrNotImplemented`; Factory capabilities declare only scripted writes,
the Factory's `TTL` is the range scripted with `SetTTLRange` and
`SetAutoTTL`, and its `Extras` hold the `ExtraProxied` entry for the types
scripted with `SetProxiableTypes`.

Live tests only read and are skipped when required secret fields are unset.
Factory fields come from `DNSPROVIDER_<PROVIDER>_<FIELD>`:

| Provider | Environment variables |
| --- | --- |
| Cloudflare | `DNSPROVIDER_CLOUDFLARE_TOKEN`, optional `DNSPROVIDER_CLOUDFLARE_TENANT_ID` |
| DigitalOcean | `DNSPROVIDER_DIGITALOCEAN_TOKEN` |
| GoDaddy | `DNSPROVIDER_GODADDY_KEY`, `DNSPROVIDER_GODADDY_SECRET` |
| Hetzner | `DNSPROVIDER_HETZNER_TOKEN` |
| Internet.bs | `DNSPROVIDER_INTERNETBS_KEY`, `DNSPROVIDER_INTERNETBS_PASSWORD` |
| Namecheap | `DNSPROVIDER_NAMECHEAP_USER`, `DNSPROVIDER_NAMECHEAP_KEY`, `DNSPROVIDER_NAMECHEAP_CLIENT_IP` |
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
metadata retention, TTL bounds and uncertain completion. The adapter never
creates Zones implicitly.

## Hetzner

[Hetzner setup and limitations](provider/hetzner.md) cover Cloud API project
tokens, DNS permissions, inherited/shared TTLs, RRset metadata and protection,
and asynchronous action completion. Account verification uses an authenticated
Zone list and works with an empty project. Records have content-derived keys;
retain the complete Before Record. The Batcher plans affected RRsets, preserves
siblings, waits for each write action, and reads back authoritative results.
Uncertain completion and partial moves remain visible as errors.

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
