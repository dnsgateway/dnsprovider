# DNS Provider

`dnsprovider` is a Go library for managing DNS across different hosting
services. It gives your application one shared interface to read and change
DNS records, whether you use Cloudflare, Gandi, or another supported
provider.

## Why use it?

Each DNS provider has its own API, login fields, and record format. This
library handles those differences so your application can use the same Go
types and methods for each provider.

Use it to build a DNS management tool, an admin panel, or automation that
works with several providers.

## What can it do?

A **Zone** is a set of DNS records for a name such as `example.com`. A
**Record** is one entry in that zone, such as an A record that points
`www.example.com` to an IP address.

The shared interface lets you:

- Check account credentials.
- List zones or find a zone by name.
- List records and filter them by name or type.
- Create, update, and delete records.
- Apply several record changes with a `Changeset`.

The library also provides record validation, shared error types, and a fake
provider for testing your application. Provider adapters handle API details,
such as reading all pages of a record list and following rate limits.

Some features depend on the provider. Cloudflare supports creating and deleting
zones, changing zone settings, and reading Signing Keys for DNSSEC. Porkbun,
Gandi, and Internet.bs support reading and changing DNSSEC Delegation Signer
(DS) records at the registrar. Check the provider documentation for available
features, supported record types, and limits.

The library manages DNS hosting. It does not register, renew, transfer, or
cancel domains. The optional [Delegation workflow](docs/delegation.md) plans and
coordinates explicit hosting and registrar work, reports manual nameserver work,
and verifies replacement hosting before deletion. It requires caller-supplied
DNS observations; automatic nameserver changes also require your own adapter.
Your application stores credentials, selects Accounts, and confirms changes.

## Supported providers

Each link covers setup, features, and limitations.

- [Cloudflare](docs/provider/cloudflare.md)
- [ClouDNS](docs/provider/cloudns.md)
- [DigitalOcean](docs/provider/digitalocean.md)
- [DNSimple](docs/provider/dnsimple.md)
- [Gandi](docs/provider/gandi.md)
- [GoDaddy](docs/provider/godaddy.md)
- [Hetzner](docs/provider/hetzner.md)
- [Internet.bs](docs/provider/internetbs.md)
- [Namecheap](docs/provider/namecheap.md)
- [OVHcloud](docs/provider/ovhcloud.md)
- [Porkbun](docs/provider/porkbun.md)
- [Scaleway](docs/provider/scaleway.md)
- [Vultr](docs/provider/vultr.md)

## Install

Requires Go 1.24 or later. Run this command in your Go project:

```sh
go get github.com/dnsgateway/dnsprovider
```

## Read DNS records

This example reads records from an existing Cloudflare zone. Set
`CLOUDFLARE_API_TOKEN` to an API token with permission to read the zone and its
DNS records. Replace `example.com` with a zone you manage.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

func main() {
	ctx := context.Background()

	p, err := cloudflare.New(cloudflare.Config{
		Token: os.Getenv("CLOUDFLARE_API_TOKEN"),
	})
	if err != nil {
		log.Fatal(err)
	}

	zone, err := p.GetZone(ctx, "example.com")
	if err != nil {
		log.Fatal(err)
	}

	records, err := p.Records(ctx, zone, dnsprovider.RecordFilter{})
	if err != nil {
		log.Fatal(err)
	}

	for _, record := range records.Records {
		fmt.Println(record.Name, record.Type, record.Value, record.TTL)
	}
}
```

An empty `RecordFilter` returns all records. Use
`dnsprovider.RecordFilter{Type: "A"}` to read only A records.

## Create a DNS record

To add a record, put this code inside `main`, after reading the zone. This
writes to your provider account, so the token needs permission to edit DNS
records. Replace the name and IP address with your own values.

```go
record, err := p.CreateRecord(ctx, zone, dnsprovider.Record{
	Type:  "A",
	Name:  "www.example.com",
	Value: "192.0.2.10",
	TTL:   300,
})
if err != nil {
	log.Fatal(err)
}
fmt.Println("Created:", record.Name)
```

Record names are full names without a final dot. TTL is in seconds and tells
DNS caches how long to keep the record. Use `UpdateRecord` or `DeleteRecord`
to change or remove an existing record, passing the record you read from the
provider.

## Choose a provider at runtime

If your application lets users choose a provider, use the registry. It
includes every supported provider and builds one from a map of login fields:

```go
import "github.com/dnsgateway/dnsprovider/providers"

// Inside your function:
p, err := providers.Registry().New("cloudflare", map[string]string{
	"token": token,
})
```

Check `err` before using `p`. The returned provider uses the same methods as
the examples above. If you already know which provider you need, import its
package directly.

## More details

See the [Zone CRUD migration guide](docs/zone-crud-migration.md) when upgrading
consumers or external Provider implementations.

See the [module design](docs/provider.md) for the full interface, record rules,
optional features, and package layout.

For tests in your own application, use the fake provider in
[`providertest`](providertest/).

Run the library's tests with:

```sh
go test ./...
```

Live tests use real accounts and only read data. They run when the required
credentials are set in `DNSPROVIDER_<PROVIDER>_<FIELD>` environment variables.
See each provider's documentation for the required fields. Use
`DNSPROVIDER_<PROVIDER>_BASE_URL` to test against a different API endpoint.
