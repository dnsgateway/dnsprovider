# dnsprovider

`github.com/dnsgateway/dnsprovider` manages DNS hosting at DNS Providers
(Cloudflare, GoDaddy, Namecheap) through one Go interface: lean,
provider-neutral Zone and Record types, the record rules every consumer needs
to build valid Records, and Changesets applied to a Zone. It never registers,
renews or cancels a domain.

```
dnsprovider/         root package: Provider, types, record rules, typed errors
providertest/        fake Provider for consumers' tests
providers/cloudflare
providers/godaddy
providers/namecheap
```

It started as the Provider layer of [dnscli](https://github.com/sergelogvinov/dnscli),
its first consumer.

## Stability

The module stays at `v0` until dnscli has moved onto it: its API may change
without notice until then. After that, breaking changes need a new major
version.

## Tests

`go test ./...` runs every adapter against recorded API answers. Live tests
against real accounts run only when their credentials are set:

| Provider   | Variable                       | Value                     |
|------------|--------------------------------|---------------------------|
| Cloudflare | `DNSPROVIDER_CLOUDFLARE_TOKEN` | API token                 |
| GoDaddy    | `DNSPROVIDER_GODADDY_TOKEN`    | `KEY:SECRET`              |
| Namecheap  | `DNSPROVIDER_NAMECHEAP_TOKEN`  | `APIUSER:APIKEY:CLIENTIP` |

`DNSPROVIDER_<PROVIDER>_BASE_URL` points a live test at another endpoint,
such as the Namecheap sandbox or GoDaddy OTE. Live tests only read.
