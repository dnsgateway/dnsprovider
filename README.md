# dnsprovider

`github.com/dnsgateway/dnsprovider` manages DNS hosting at DNS Providers
(Cloudflare, ClouDNS, DigitalOcean, DNSimple, Gandi, GoDaddy, Internet.bs, Namecheap, Porkbun, Vultr) through one
Go interface: lean, provider-neutral Zone and Record types, the record rules every consumer needs
to build valid Records, and Changesets applied to a Zone. It never registers,
renews or cancels a domain.

```
dnsprovider/         root package: Provider, types, record rules, typed errors,
                     Options and Registry
providertest/        fake Provider for consumers' tests
providers/           Registry() of every adapter below
providers/cloudflare
providers/cloudns
providers/digitalocean
providers/dnsimple
providers/gandi
providers/godaddy
providers/internetbs
providers/namecheap
providers/porkbun
providers/vultr
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

The optional `TenantLister` lists the Tenants a Provider can reach through
`Tenants(ctx)`; `dnsprovider.CanListTenants(p)` reports support. Tenant scoping
and credential requirements depend on the Provider; see its documentation below.

## Zones

`Zones(ctx, dnsprovider.ZoneFilter{Contains: "shop"})` lists the Zones whose
names hold the text, ignoring case; the zero filter lists every Zone. Each
adapter pages through the whole list, pushes the filter to the Provider's API
where it can and
applies the rest with `dnsprovider.MatchZone`, so the result is always
exactly filtered. `Zone(ctx, name)` reads one Zone by its exact name and
fails with `dnsprovider.ErrNotFound` when the Account has none.

Every Zone carries its `HostingState`; the states reported depend on the
Provider.

Onboarding uses the optional `ZoneCreator`, found with
`dnsprovider.CanCreateZone(p)`: `CreateZone(ctx, "example.org")` starts DNS
hosting of the name in the Provider's Tenant; it never registers the domain.

Offboarding uses the optional `ZoneDeleter`, found with
`dnsprovider.CanDeleteZone(p)`: `DeleteZone(ctx, zone)` stops DNS hosting of
the Zone and drops its Records there; it never touches the registration.
It cannot be undone, so a consumer asks first and never Offboards the Live Zone.

Zone Status (DNSSEC, HSTS) uses the optional `ZoneStatusReader`.
`dnsprovider.ZoneStatusOf(ctx, p, zone)` reads it, and reports every setting
Unknown, without a call, for a Provider without one. The optional `ZoneUpdater`,
found with `dnsprovider.CanUpdateZone(p)`, turns DNSSEC and HSTS on or off:
`UpdateZone(ctx, zone, dnsprovider.ZoneUpdate{DNSSEC: &on})` writes only the
settings it is given and returns the Zone Status after the change, each
setting it was not given as read, Unknown when it could not be. A write that
fails comes with the Zone Status as far as it is known, the settings written
before it as answered.

## Providers

Provider setup, behavior, limitations, and live-test credentials:

- [Cloudflare](docs/provider/cloudflare.md)
- [ClouDNS](docs/provider/cloudns.md)
- [DigitalOcean](docs/provider/digitalocean.md)
- [DNSimple](docs/provider/dnsimple.md)
- [Gandi](docs/provider/gandi.md)
- [GoDaddy](docs/provider/godaddy.md)
- [Internet.bs](docs/provider/internetbs.md)
- [Namecheap](docs/provider/namecheap.md)
- [Porkbun](docs/provider/porkbun.md)
- [Vultr](docs/provider/vultr.md)

## Tests

`go test ./...` runs every adapter against recorded API answers. Live tests
against real accounts run only when their credentials are set.

Each Factory field is read from `DNSPROVIDER_<PROVIDER>_<FIELD>`; a live
test is skipped while any required secret field is unset. See the Provider
pages above for credential requirements.

`DNSPROVIDER_<PROVIDER>_BASE_URL` points a live test at another endpoint.
Live tests only read.
