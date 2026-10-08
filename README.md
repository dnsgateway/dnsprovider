# dnsprovider

`github.com/dnsgateway/dnsprovider` manages DNS hosting at DNS Providers
(Cloudflare, GoDaddy, Namecheap) through one Go interface: lean,
provider-neutral Zone and Record types, the record rules every consumer needs
to build valid Records, and Changesets applied to a Zone. It never registers,
renews or cancels a domain.

```
dnsprovider/         root package: Provider, types, record rules, typed errors,
                     Options and Registry
providertest/        fake Provider for consumers' tests
providers/           Registry() of every adapter below
providers/cloudflare
providers/godaddy
providers/namecheap
rest/                shared HTTP client of the GoDaddy and Namecheap adapters:
                     retries, rate limit, error decoding, pagination
```

It started as the Provider layer of [dnscli](https://github.com/sergelogvinov/dnscli),
its first consumer.

## Building a Provider

Each provider package builds its Provider from a typed `Config`, without a
network call:

```go
p, err := cloudflare.New(cloudflare.Config{Token: token, TenantID: accountID},
	dnsprovider.WithHTTPClient(client), dnsprovider.WithLogger(logger))
```

A consumer that picks its Provider at run time builds it from a plain field
map instead. Each `Factory` lists its `Fields` (name, label, and whether the
field is secret), so a form and a credential store can be built from them:

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
Provider implements `TenantLister`, whose `Tenants(ctx)` works before
`TenantID` is set; `dnsprovider.CanListTenants(p)` says whether a Provider
does. Every call but `Account` and `Tenants` is scoped to the configured
Tenant, a 32-hex-digit account ID, and fails with `dnsprovider.ErrNoTenant`
until one is set. An account-owned token is verified only once its Tenant
is set; a token that may not read accounts, such as a DNS-only one, gets
an `Account` Tenant with the ID alone.

## Stability

The module stays at `v0` until dnscli has moved onto it: its API may change
without notice until then. After that, breaking changes need a new major
version.

## Tests

`go test ./...` runs every adapter against recorded API answers. Live tests
against real accounts run only when their credentials are set:

Each Factory field is read from `DNSPROVIDER_<PROVIDER>_<FIELD>`; a live
test is skipped while any secret field is unset.

| Provider   | Variables                                                                         |
|------------|-----------------------------------------------------------------------------------|
| Cloudflare | `DNSPROVIDER_CLOUDFLARE_TOKEN`, `DNSPROVIDER_CLOUDFLARE_TENANT_ID` (optional: Zones are read only with it) |
| GoDaddy    | `DNSPROVIDER_GODADDY_KEY`, `DNSPROVIDER_GODADDY_SECRET`                           |
| Namecheap  | `DNSPROVIDER_NAMECHEAP_USER`, `DNSPROVIDER_NAMECHEAP_KEY`, `DNSPROVIDER_NAMECHEAP_CLIENT_IP` |

`DNSPROVIDER_<PROVIDER>_BASE_URL` points a live test at another endpoint,
such as the Namecheap sandbox or GoDaddy OTE. Live tests only read.
