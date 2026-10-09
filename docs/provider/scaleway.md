# Scaleway

Import `providers/scaleway`, or use Registry key `scaleway`. Typed `Config`
requires `SecretKey` and `ProjectID`. Equivalent Factory fields are
`secret_key` (secret) and `project_id` (nonsecret UUID). No access key is
needed. Construction validates locally without contacting Scaleway.

```go
p, err := scaleway.New(scaleway.Config{SecretKey: key, ProjectID: project})
// or
p, err := providers.Registry().New("scaleway", map[string]string{
    "secret_key": key, "project_id": project,
})
```

The Domain DNS v2beta1 endpoint is
`https://api.scaleway.com/domain/v2beta1`, authenticated with `X-Auth-Token`.
`WithBaseURL` overrides this entire prefix; every operation uses it.
`WithHTTPClient` keeps caller timeouts; the default is 30 seconds.
`WithLogger` receives shared retry diagnostics with credential text redacted.

## Project scope and permissions

The domain must already be linked to Scaleway DNS and verified when required
for external domains. Configure an IAM principal with permission to list
DNS Zones and read Records in the chosen Project; writes additionally
require DNS record update permission. `Account` itself uses an authenticated
Project-filtered DNS Zone read, so verification requires Zone list permission,
including for otherwise write-capable credentials. An empty successful list
verifies access; a 401 or 403 matches `ErrUnauthorized`.

The configured Project ID is the Tenant ID. No account name or universal
nameserver metadata is invented. Discovery returns root and sub-Zones by
full name, with the API's nameservers. `active` maps to Active; other statuses
map to Unknown because `pending` denotes an update rather than pending
Delegation. Exact lookups and every Record read/write first establish Project
ownership through discovery. Caller-supplied Zone objects cannot bypass this
check. Record lists also carry `project_id`, and all pages remain on the
configured endpoint. An absent or foreign Zone matches `ErrNotFound`.

## Records and edits

Records carry native IDs, absolute owners without a trailing dot, explicit
stored TTLs and zone-file Values. Apex and wildcard owners are supported.
MX and SRV priority is represented in the Value; wire names are relative.
Target Values are fully qualified with trailing dots. TXT quoted wire chunks
are decoded to their text; writes quote and escape that text. CAA Values
retain their flags, tag and quoted value. Other native Record types remain
visible and untouched but cannot be created or edited through this adapter.
Writable types are A, AAAA, CNAME, NS, MX, SRV, TXT and CAA; URI is unsupported.
SOA serials are returned only when a listed SOA contains a uint32 serial.

Creates reject identical type, case-insensitive owner and Value regardless of
TTL. Updates and deletions select precisely one native Record ID. Comments
and existing geo-IP, HTTP health-check, weighted and view configurations are
copied without changing their contents. Read-only `updated_at` is omitted
from writes. Unknown metadata prevents an edit that might lose it; a type
edit of a dynamic Record is refused. Metadata editing through Extras is
unsupported. Static type/name/Value/TTL edits use ID-targeted `set`, with
old type-specific priority discarded when changing type. Stored IDs may
change; successful writes return the stored identity. Siblings are retained,
including when the last selected Record is deleted.

`dnsprovider.Apply` checks stale Before Records before writing. The Batcher
plans deletions, modifications and additions in that order, checks collisions
before writing, and submits targeted `delete`, `set` and `add` operations in
one PATCH. Results retain original Changeset order. Every request explicitly
sets `disallow_new_zone_creation: true` and `return_all_records: true`.
There are no clear operations or implicit sub-Zone creation.

A batch is not a transaction guarantee. Endpoint failures are whole-Changeset
errors. Successful responses are matched to stored Records, with readback
when insufficient; missing outcomes retain per-change errors and a whole
error indicating the mutation may have completed. Server failures, lost
responses and failed post-write reads also leave completion uncertain. Re-read
Records before retrying; the adapter never automatically repeats PATCH or
requests containing additions. API validation errors retain their status and
message; 409 matches `ErrConflict`. GET uses shared bounded retries for 429
and 5xx, honoring Retry-After. A conservative local limiter allows ten requests
per second; this is not a claimed service quota. Coordinate other API clients
and handle provider throttling through `ErrRateLimited`.

## TTL and live checks

Writable TTLs are 60 through 2592000 seconds, matching the
[official Terraform provider's validation](https://github.com/scaleway/terraform-provider-scaleway/blob/master/internal/services/domain/record.go).
There is no documented automatic TTL sentinel, and no default/inherited TTL
is emitted: callers provide explicit TTLs. Reads retain the stored TTL,
including values outside writable limits; normalization is taken from the
successful API response.

Optional read-only checks use `DNSPROVIDER_SCALEWAY_SECRET_KEY` and
`DNSPROVIDER_SCALEWAY_PROJECT_ID`:

```sh
go test ./providers/scaleway -run '^TestLive$' -v
```

They skip without the secret key and never mutate live DNS.
`DNSPROVIDER_SCALEWAY_BASE_URL` overrides the API prefix.

Protocol references: the [DNS API guide](https://www.scaleway.com/en/developers/api/domains-and-dns)
and [official Go SDK](https://github.com/scaleway/scaleway-sdk-go/blob/master/api/domain/v2beta1/domain_sdk.go).
The adapter uses shared HTTP infrastructure without an SDK dependency.
