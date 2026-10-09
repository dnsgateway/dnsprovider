# dnsprovider

`github.com/dnsgateway/dnsprovider` manages DNS hosting at DNS Providers
(Cloudflare, ClouDNS, GoDaddy, Namecheap) through one Go interface: lean,
provider-neutral Zone and Record types, the record rules every consumer needs
to build valid Records, and Changesets applied to a Zone. It never registers,
renews or cancels a domain.

```
dnsprovider/         root package: Provider, types, record rules, typed errors,
                     Options and Registry
providertest/        fake Provider for consumers' tests
providers/           Registry() of every adapter below
providers/cloudflare
providers/cloudns
providers/godaddy
providers/namecheap
rest/                shared HTTP client of the HTTP adapters:
                     retries, rate limit, error decoding, pagination
```

## Building a Provider

Each provider package builds its Provider from a typed `Config`, without a
network call:

```go
p, err := cloudflare.New(cloudflare.Config{Token: token, TenantID: accountID},
	dnsprovider.WithHTTPClient(client), dnsprovider.WithLogger(logger))
```

A consumer that picks its Provider at run time builds it from a plain field
map instead. Each `Factory` lists its `Fields` (name, label, whether the
field is secret, and whether it holds the Tenant ID), so a form and a
credential store can be built from them, and declares the optional Zone
writes its Providers implement, so a consumer can offer one before it has
the credentials (`f.Can(dnsprovider.CapZoneCreator)`, `CapZoneUpdater`,
`CapZoneDeleter`):

```go
reg := providers.Registry()
p, err := reg.New("namecheap", map[string]string{
	"user": "apiuser", "key": apiKey, "client_ip": "192.0.2.10",
})
```

`WithBaseURL` points a Provider at another endpoint, such as an `httptest`
server or a sandbox.

## Accounts and Tenants

`Account(ctx)` checks the credentials, even for an Account with no Zones, and
returns its Tenant and, where they are the same for every Zone, the
nameservers Delegation must name. A bad token is `ErrUnauthorized`.

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

`Zones(ctx, dnsprovider.ZoneFilter{Contains: "shop"})` lists the Zones whose
names hold the text, ignoring case; the zero filter lists every Zone. Each
adapter pages through the whole list, pushes the filter to the Provider's API
where it can (Cloudflare's `name=contains:`, Namecheap's `SearchTerm`) and
applies the rest with `dnsprovider.MatchZone`, so the result is always
exactly filtered. `Zone(ctx, name)` reads one Zone by its exact name and
fails with `dnsprovider.ErrNotFound` when the Account has none.

Every Zone carries its `HostingState`: Cloudflare reports Active, Pending
(also for a Zone still initializing) and Moved (also for a deactivated
Zone). GoDaddy lists every domain it registers: Active while Delegation
names one of its nameservers, Moved once it names none, Unknown when GoDaddy
does not say. Namecheap lists only the Zones on its DNS, which are Active.

Onboarding is the optional `ZoneCreator`, Cloudflare's alone and found with
`dnsprovider.CanCreateZone(p)`: `CreateZone(ctx, "example.org")` starts DNS
hosting of the name in the Provider's Tenant (it never registers the domain)
and returns the new Zone Pending, with the nameservers Delegation must name
(its name alone, without an ID, when Cloudflare took the create but the Zone
could not be read back). A name the Tenant already has, or that another
account keeps under a zone hold, is `dnsprovider.ErrConflict`; without a
hold, Cloudflare Onboards a name active in another account, pending until
Delegation moves it. A Provider without a Tenant returns
`dnsprovider.ErrNoTenant` without a request. The create is never retried.

Offboarding is the optional `ZoneDeleter`, also Cloudflare's alone and found
with `dnsprovider.CanDeleteZone(p)`: `DeleteZone(ctx, zone)` stops DNS
hosting of the Zone, by its ID, and drops its Records there; it never
touches the registration (GoDaddy's `DELETE /v1/domains`, which cancels it,
is never called). It cannot be undone, so a consumer asks first and never
Offboards the Live Zone. The delete is retried like a read: a retry that
finds the Zone gone succeeds when an earlier try was sent and got no
answer or a server error, as that try may have Offboarded it; otherwise
finding no such Zone is `dnsprovider.ErrNotFound`. With a Tenant set, the
Zone is first read by its ID, one more request, and a Zone of another
account is refused without the delete; without a Tenant, the caller owns
that check. A Zone without an ID fails without a request.

Zone Status (DNSSEC, HSTS) is the optional `ZoneStatusReader`, which only
Cloudflare implements. `dnsprovider.ZoneStatusOf(ctx, p, zone)` reads it, and
reports every setting Unknown, without a call, for a Provider without one.
The optional `ZoneUpdater`, also Cloudflare's alone and found with
`dnsprovider.CanUpdateZone(p)`, turns DNSSEC and HSTS on or off:
`UpdateZone(ctx, zone, dnsprovider.ZoneUpdate{DNSSEC: &on})` writes only the
settings it is given and returns the Zone Status after the change, each
setting it was not given as read, Unknown when it could not be. A write that
fails comes with the Zone Status as far as it is known, the settings written
before it as answered. Cloudflare signs and unsigns a Zone over time, so
DNSSEC comes back Pending; HSTS keeps its max-age and other fields, and is
turned on for six months when the Zone has no max-age.

## ClouDNS

Import `providers/cloudns`, or select Registry key `cloudns`. Typed `Config`
requires `Password` and exactly one of `AuthID`, `SubAuthID`, or `SubAuthUser`.
The equivalent secret field map uses `password` and exactly one of `auth_id`,
`sub_auth_id`, or `sub_auth_user`; IDs must be unsigned integers. Constructors
validate locally. Obtain API credentials in the ClouDNS HTTP API panel and
allow the caller's source IP and appropriate zone/read/write permissions.
Sub-users only discover their accessible Zones. `Account` verifies both login
and DNS-list permission even when the Account has no Zones, returning empty
Tenant/nameserver information because those endpoints do not identify them.

The adapter uses JSON POST form bodies, keeps credentials out of URLs, and
recognizes failed status envelopes even with HTTP 200. Zone IDs are their
normalized names; listing does not establish hosting activity, so hosting
state is Unknown. Nameservers and SOA serial are omitted when unknown.
Zones and Records exhaust 100-row pages and apply the common filters locally.

Record writes support A, AAAA, CNAME, MX, NS, SRV, TXT and CAA. URI writes are
unsupported by the service; unfamiliar Record types are retained when read
and unrelated Records survive edits. TXT Values are the literal text accepted
by the common Record contract. Structured Values put MX preference and SRV
priority/weight/port before the target, and CAA flags/tag before its quoted
value. Native Record IDs identify individual siblings. ClouDNS only permits
Record reads/writes in master Zones (including supported reverse Zones),
and restricted credentials or plans may further limit operations.

TTL bounds are 60–2,592,000 seconds, with no automatic TTL. Supported values
are discrete: 60, 300, 900, 1800, 3600, 21600, 43200, 86400, 172800, 259200,
604800, 1209600 and 2592000; writes verify the Zone-specific available list.
Unsupported TTLs fail instead of being rounded.

ClouDNS cannot modify Record type in place. A type move creates and reads a
replacement before deleting the original; failure reports that partial state.
Supported location/status metadata and notes are preserved. Moving a noted
Record needs main API credentials because the note endpoint documents only
main-user authentication. A move with unfamiliar metadata fails before writes
instead of silently discarding it. Same-type updates retain server metadata.
`dnsprovider.Apply` supplies stale checks and CRUD execution/result ordering;
changes are not atomic. Mutations are never automatically retried. Clients
share a conservative 10 requests/second pace and 600/minute budget per API
endpoint, across credential identities, within the published per-IP quotas
(20/second, 600/minute, 36,000/hour). Processes sharing an IP must also coordinate
their aggregate usage.

See the official [API guide](https://www.cloudns.net/wiki/article/41/),
[authentication](https://www.cloudns.net/wiki/article/42/),
[Zone listing](https://www.cloudns.net/wiki/article/50/),
[Record listing](https://www.cloudns.net/wiki/article/57/),
[add](https://www.cloudns.net/wiki/article/58/) and
[modify](https://www.cloudns.net/wiki/article/60/) contracts.

## Tests

`go test ./...` runs every adapter against recorded API answers. Live tests
against real accounts run only when their credentials are set:

Each Factory field is read from `DNSPROVIDER_<PROVIDER>_<FIELD>`; a live
test is skipped while any required secret field is unset. ClouDNS requires its
password and one alternative identity.

| Provider   | Variables                                                                         |
|------------|-----------------------------------------------------------------------------------|
| Cloudflare | `DNSPROVIDER_CLOUDFLARE_TOKEN`, `DNSPROVIDER_CLOUDFLARE_TENANT_ID` (optional: Zones are read only with it) |
| ClouDNS    | `DNSPROVIDER_CLOUDNS_PASSWORD` and exactly one of `DNSPROVIDER_CLOUDNS_AUTH_ID`, `DNSPROVIDER_CLOUDNS_SUB_AUTH_ID`, `DNSPROVIDER_CLOUDNS_SUB_AUTH_USER` |
| GoDaddy    | `DNSPROVIDER_GODADDY_KEY`, `DNSPROVIDER_GODADDY_SECRET`                           |
| Namecheap  | `DNSPROVIDER_NAMECHEAP_USER`, `DNSPROVIDER_NAMECHEAP_KEY`, `DNSPROVIDER_NAMECHEAP_CLIENT_IP` |

`DNSPROVIDER_<PROVIDER>_BASE_URL` points a live test at another endpoint,
such as the Namecheap sandbox or GoDaddy OTE. Live tests only read.
