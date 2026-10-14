# Cloudflare

Import `providers/cloudflare`, or select Registry key `cloudflare`.

## Accounts and Tenants

A Cloudflare token can reach several Tenants (Cloudflare accounts). The
Provider declares `CapTenantLister`, and its `ListTenants(ctx)` works with or
without `TenantID`; `dnsprovider.Can(p, dnsprovider.CapTenantLister)` says
whether a Provider does. With `TenantID` set, a 32-hex-digit account ID, `ListZones` and `GetZone`
list that Tenant's Zones alone. Without it the Provider is unscoped: it
lists every Zone the token reaches, in any account, and `Account` verifies
the token alone, with an empty Tenant. The calls on a Zone work by its ID
either way. An account-owned token is verified only once its Tenant is
set; a token that may not read accounts, such as a DNS-only one, gets an
`Account` Tenant with the ID alone.

## Zones

All adapters expose Zone CRUD through `dnsprovider.Provider`. Cloudflare is
the only built-in adapter declaring support for creation, settings updates,
and deletion in its `Traits`, and the only one whose `ZoneDetails` reads
Zone Status and Signing Keys.

Cloudflare reports Hosting State Active, Pending (also for a Zone still
initializing) and Moved (also for a deactivated Zone). Zone filtering uses
the API's `name=contains:` filter and the common local filter.

Onboarding is `CreateZone`, whose support is declared through
`dnsprovider.Can(p, dnsprovider.CapZoneCreator)`: `CreateZone(ctx, "example.org")` starts DNS
hosting of the name in the Provider's Tenant (it never registers the domain)
and returns the new Zone Pending, with the nameservers Delegation must name
(its name alone, without an ID, when Cloudflare took the create but the Zone
could not be read back). A name the Tenant already has, or that another
account keeps under a zone hold, is `dnsprovider.ErrConflict`; without a
hold, Cloudflare Onboards a name active in another account, pending until
Delegation moves it. A Provider without a Tenant returns
`dnsprovider.ErrNoTenant` without a request. The create is never retried.

Offboarding is `DeleteZone`, whose support is declared
through `dnsprovider.Can(p, dnsprovider.CapZoneDeleter)`: `DeleteZone(ctx, zone)` stops DNS
hosting of the Zone, by its ID, and drops its Records there; it never
touches the registration. It cannot be undone, so a consumer asks first and never
Offboards the Live Zone. The delete is retried like a read: a retry that
finds the Zone gone succeeds when an earlier try was sent and got no
answer or a server error, as that try may have Offboarded it; otherwise
finding no such Zone is `dnsprovider.ErrNotFound`. With a Tenant set, the
Zone is first read by its ID, one more request, and a Zone of another
account is refused without the delete; without a Tenant, the caller owns
that check. A Zone without an ID fails without a request.

Zone Status (DNSSEC, HSTS, minimum TLS) is read with `ZoneDetails`, below.
`UpdateZone`, whose support is declared through
`dnsprovider.Can(p, dnsprovider.CapZoneUpdater)`, changes DNSSEC, HSTS, and minimum TLS:
`UpdateZone(ctx, zone, dnsprovider.ZoneUpdate{DNSSEC: &on})` writes only the
settings it is given and returns the Zone Status after the change, each
setting it was not given as read, Unknown when it could not be. A write that
fails comes with the Zone Status as far as it is known, the settings written
before it as answered. Cloudflare signs and unsigns a Zone over time, so
DNSSEC comes back Pending; HSTS keeps its max-age and other fields, and is
turned on for six months when the Zone has no max-age. An update that sets
nothing reads the Zone Status, failing only when every read fails.

Read Zone Status and Signing Keys with
`dnsprovider.ZoneDetailsOf(ctx, p, name, dnsprovider.ZoneDetailRequest{SigningKeys: true})`,
or `p.ZoneDetails(ctx, zone, request)` with a Zone already read. A Signing
Key is a `SigningKey` with its DNSKEY, key tag and SHA-256 DS; a Zone signed,
pending or pending-disabled has one key, a disabled Zone none. A setting the
API token may not read (HTTP 403) is that property failed with
`ErrUnauthorized`, its value Unknown.
Cloudflare obtains DNSSEC state and requested Signing Keys from one
`GET /zones/{id}/dnssec` response, preserving Unknown, Off, On, and Pending,
including pending signing and pending unsigning. Without requested keys it
still reads DNSSEC state but leaves the key outcome `PropertyNotRequested`.
HSTS and minimum TLS are independent setting reads; the assembled result does
not promise an atomic snapshot across these resources or the Zone identity.

A DNSSEC authorization failure marks DNSSEC and requested Signing Keys failed,
retains the diagnostic and `ErrUnauthorized` classification, and leaves any
successful HSTS and minimum TLS values available. An independent setting
failure likewise preserves the other values. The aggregate error joins failed
reads and keeps cancellation observable. A disabled Zone has a successfully
read empty key list, rather than an unsupported or failed outcome. DS digests
use upper-case presentation. These are Provider Signing Keys, independent of
registrar-held Delegation Signers; reading them does not establish DNSSEC
validity through the parent Zone.

Use canonical `GetZone` and `ListZones` reads; see the
[Zone CRUD migration guide](../zone-crud-migration.md).

## Unconfirmed Writes

A write (a Zone create, delete or setting update, a Record create, update
or delete) whose answer is a server error, is lost, or cannot be decoded
is an Unconfirmed Write matching `dnsprovider.ErrUnconfirmed`: re-read
before retrying. A 4xx answer, or one with `success: false`, refuses the
write and is not. A failing read never is.

## Live tests

Set `DNSPROVIDER_CLOUDFLARE_TOKEN` and optionally
`DNSPROVIDER_CLOUDFLARE_TENANT_ID`; Zones are read only with the Tenant ID set.
`DNSPROVIDER_CLOUDFLARE_BASE_URL` overrides the endpoint. Live tests only read.
