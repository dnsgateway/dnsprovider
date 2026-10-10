# Cloudflare

Import `providers/cloudflare`, or select Registry key `cloudflare`.

## Accounts and Tenants

A Cloudflare token can reach several Tenants (Cloudflare accounts). The
Provider implements `TenantLister`, whose `Tenants(ctx)` works with or
without `TenantID`; `dnsprovider.CanListTenants(p)` says whether a Provider
does. With `TenantID` set, a 32-hex-digit account ID, `Zones` and `Zone`
list that Tenant's Zones alone. Without it the Provider is unscoped: it
lists every Zone the token reaches, in any account, and `Account` verifies
the token alone, with an empty Tenant. The calls on a Zone work by its ID
either way. An account-owned token is verified only once its Tenant is
set; a token that may not read accounts, such as a DNS-only one, gets an
`Account` Tenant with the ID alone.

## Zones

Cloudflare is the only adapter that implements `ZoneCreator`, `ZoneDeleter`,
`ZoneStatusReader`, `ZoneUpdater` and `KeyReader`.

Cloudflare reports Hosting State Active, Pending (also for a Zone still
initializing) and Moved (also for a deactivated Zone). Zone filtering uses
the API's `name=contains:` filter and the common local filter.

Onboarding is the optional `ZoneCreator`, found with
`dnsprovider.CanCreateZone(p)`: `CreateZone(ctx, "example.org")` starts DNS
hosting of the name in the Provider's Tenant (it never registers the domain)
and returns the new Zone Pending, with the nameservers Delegation must name
(its name alone, without an ID, when Cloudflare took the create but the Zone
could not be read back). A name the Tenant already has, or that another
account keeps under a zone hold, is `dnsprovider.ErrConflict`; without a
hold, Cloudflare Onboards a name active in another account, pending until
Delegation moves it. A Provider without a Tenant returns
`dnsprovider.ErrNoTenant` without a request. The create is never retried.

Offboarding is the optional `ZoneDeleter`, found
with `dnsprovider.CanDeleteZone(p)`: `DeleteZone(ctx, zone)` stops DNS
hosting of the Zone, by its ID, and drops its Records there; it never
touches the registration. It cannot be undone, so a consumer asks first and never
Offboards the Live Zone. The delete is retried like a read: a retry that
finds the Zone gone succeeds when an earlier try was sent and got no
answer or a server error, as that try may have Offboarded it; otherwise
finding no such Zone is `dnsprovider.ErrNotFound`. With a Tenant set, the
Zone is first read by its ID, one more request, and a Zone of another
account is refused without the delete; without a Tenant, the caller owns
that check. A Zone without an ID fails without a request.

Zone Status (DNSSEC, HSTS) uses the optional `ZoneStatusReader`.
`dnsprovider.ZoneStatusOf(ctx, p, zone)` reads it, and
reports every setting Unknown, without a call, for a Provider without one.
The optional `ZoneUpdater`, found with
`dnsprovider.CanUpdateZone(p)`, turns DNSSEC and HSTS on or off:
`UpdateZone(ctx, zone, dnsprovider.ZoneUpdate{DNSSEC: &on})` writes only the
settings it is given and returns the Zone Status after the change, each
setting it was not given as read, Unknown when it could not be. A write that
fails comes with the Zone Status as far as it is known, the settings written
before it as answered. Cloudflare signs and unsigns a Zone over time, so
DNSSEC comes back Pending; HSTS keeps its max-age and other fields, and is
turned on for six months when the Zone has no max-age.

The optional `KeyReader`, found with `dnsprovider.CanReadKeys(p)`, returns
the Zone's key-signing keys: `SigningKeys(ctx, zone)` reads the key from the
same `GET /zones/{id}/dnssec` as Zone Status, as a `SigningKey` with its
DNSKEY, key tag and SHA-256 DS. A Zone signed, pending or pending-disabled
has one key; a disabled Zone has none. A token that may not read DNSSEC is
`ErrUnauthorized`.

## Live tests

Set `DNSPROVIDER_CLOUDFLARE_TOKEN` and optionally
`DNSPROVIDER_CLOUDFLARE_TENANT_ID`; Zones are read only with the Tenant ID set.
`DNSPROVIDER_CLOUDFLARE_BASE_URL` overrides the endpoint. Live tests only read.
