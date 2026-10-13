# Hetzner

Import `providers/hetzner`, or use Registry key `hetzner`. Typed `Config`
requires `Token`; the equivalent Factory field is `token` (secret).
Construction validates locally without contacting the API.

```go
p, err := hetzner.New(hetzner.Config{Token: token})
// or
p, err := providers.Registry().New("hetzner", map[string]string{"token": token})
```

The adapter uses the current Cloud DNS API at
`https://api.hetzner.cloud/v1`, with Bearer authentication. It does not use
the legacy DNS API or convert legacy credentials. `WithBaseURL` overrides
the entire API prefix. All requests use the supplied `WithHTTPClient` and
context; caller-owned timeouts are retained. `WithLogger` enables shared
retry diagnostics with token text redacted.

## Project scope and access

Create a Cloud API token for the Project containing the existing Zones.
There is no separate Project selector or cross-Project discovery. Read-only
tokens suffice for Account verification and discovery; editing requires
read/write access. `Account` verifies credentials with an authenticated Zone
list, including for an empty Project. Denied access matches `ErrUnauthorized`.
The DNS API supplies no Account identity, so Tenant metadata remains empty.

Discovery returns all accessible Zones, with assigned authoritative
nameservers. Exact lookup returns the same identity and hosting information.
A Zone with status `ok` is Active; other statuses are Unknown. Publication
status does not establish registrar Delegation. Primary Zones expose RRsets;
secondary Zone Record reads and writes are restricted by the service and
return explicit errors. This adapter does not provision or modify Zones,
Delegation, DNSSEC, or cloud reverse DNS.

## Records, metadata and shared TTLs

RRset values expand into individual Records with deterministic content keys,
absolute owners without trailing dots, and effective numeric TTLs. Retain
the complete Before Record: updates and deletions locate values by content.
Apex and wildcard owners are supported. Native types outside the module's
editable set remain visible. Supported writes are A, AAAA, CNAME, NS, MX,
SRV, TXT and CAA; URI and service-managed SOA edits are unsupported.
MX and SRV structured fields remain in the Value. Domain targets use fully
qualified values with trailing dots; relative wire targets are expanded.
TXT preserves quoted zone-file chunks, and new literal text is quoted.
Record Extras expose comments and RRset labels/protection as read-only metadata.

Creates reject identical type, case-insensitive owner and Value regardless
of TTL. Changes group affected source and destination RRsets, preserve
unrequested siblings, comments, labels and protection, and never disable
protection automatically. Protected and managed data cannot be edited.
A move can require several operations and can complete only partly.

## Per-value writes and concurrent Changesets

Writes name only the values a Changeset touches, so concurrent Changesets
on one RRset, such as the two DNS-01 values of a certificate for a name and
its wildcard, keep each other's values:

- An addition is `add_records` with the new value. It creates a missing
  RRset; there is no `POST /rrsets` for it.
- A deletion is `remove_records` with the value as stored. Hetzner deletes
  an RRset it empties; the adapter never deletes a whole RRset to remove
  values.
- A modification adds the new value, then removes the old one, so the
  RRset is never empty in between. A move adds at the destination before
  removing at the source. A move that creates its destination carries the
  source's labels with `POST /rrsets`, which `add_records` cannot set; when
  another writer created the destination first, it adds to it instead.
- A TTL change is `change_ttl`, before any value is added. It applies to
  the whole RRset.
- Comments are read-only: a modification keeps the replaced value's
  comment, and `update_records` is not used.

The RRset's TTL and protection remain last-writer-wins: the API has no
conditional write. Hetzner does not document how `add_records` answers a
value the RRset already holds, nor how `remove_records` answers a value it
does not. The adapter assumes a 4xx error code that maps through the common
sentinels (`uniqueness_error` to `ErrConflict`, `not_found` to
`ErrNotFound`); a live check with a write-capable token should confirm it.

Writable TTLs are 60 through 2147483647 seconds. A null RRset TTL inherits
the Zone default; reads return that effective numeric TTL, and an unchanged
TTL preserves existing inheritance. A new destination RRset also inherits
when all moved values retain inherited TTLs; additions and mixed explicit
sources use an explicit TTL. There is no automatic TTL sentinel.
Every remaining sibling in an RRset must have the same final TTL. Include
all affected siblings consistently to change a shared TTL; conflicting
final TTLs are rejected before any write. TTL action requests always include
the required TTL value.

## Completion and failures

`dnsprovider.Apply` rejects stale Before Records before mutations, orders
deletions before modifications and additions, and returns results in original
Changeset order. The Batcher plans each RRset's values to add and remove
from one read before submitting writes. Empty Changesets submit no write
actions.

Action acknowledgements alone do not confirm writes. The adapter waits for
success or failure through the Cloud DNS action endpoint, then reads stored
Records back and checks only the Changeset's own effects: each value it
added is present with the planned TTL, and each value it removed is absent.
Other values of the same RRset are ignored. A miss returns an error
matching `ErrConflict`, as another write may have replaced the Changeset's;
re-read and retry. Waits are bounded and honor cancellation. A failed action,
lost response, cancellation, or failed readback returns an error that can
leave completion uncertain; re-read before deciding to retry. Cross-RRset
changes are not atomic and do not trigger automatic rollback. Action
completion does not guarantee immediate global DNS propagation.

GET requests use shared bounded retries for 429 and 5xx responses, honoring
Retry-After. Mutation and action submissions are not automatically repeated.
The published default quota is 3600 requests per hour per Project, gradually
replenished; coordinate other clients and handle `ErrRateLimited`. API errors
retain status and redacted messages; authorization, missing-resource,
conflict and rate-limit failures use the common sentinel contracts.

## Read-only live checks

Set `DNSPROVIDER_HETZNER_TOKEN` to a Cloud API Project token, then run:

```sh
go test ./providers/hetzner -run '^TestLive$' -v
```

The check skips without credentials and never writes live DNS.
`DNSPROVIDER_HETZNER_BASE_URL` optionally overrides the API prefix.
Ordinary tests use local protocol fixtures and require no external access.

Protocol references: [Cloud API reference](https://docs.hetzner.cloud/reference/cloud),
[official OpenAPI schema](https://docs.hetzner.cloud/cloud.spec.json),
[official Go client](https://github.com/hetznercloud/hcloud-go/blob/main/hcloud/zone_rrset.go),
[required TTL changelog](https://docs.hetzner.cloud/changelog#september-2026),
and [Console migration differences](https://docs.hetzner.com/networking/dns/migration-to-hetzner-console/features-and-differences/).
The adapter uses shared HTTP infrastructure without an SDK dependency.
