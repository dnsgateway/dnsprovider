# DigitalOcean

Import `providers/digitalocean`, or use Registry key `digitalocean`. Typed
`Config` requires `Token`; the equivalent Factory field is `token` (secret).
Use a personal access token (`dop_v1_…`) or an OAuth token. Constructors
validate locally, without network calls, and reject an empty token or one
holding whitespace. There are no optional capabilities: no Zone writes, no
TenantLister and no Batcher.

```go
p, err := digitalocean.New(digitalocean.Config{Token: token})
// or
p, err := providers.Registry().New("digitalocean", map[string]string{"token": token})
```

The adapter uses API v2 at `https://api.digitalocean.com/v2` with Bearer
authentication. `WithBaseURL` replaces that endpoint for every call;
`WithHTTPClient` keeps the caller's timeouts (the default client times out
after 30 seconds); `WithLogger` receives retry diagnostics, never the token.

## Permissions

Account verification and DNS access need separate scopes of a custom-scoped
token. A full-access or read-only token has them all, or the read ones.

| Operation | Endpoint | Scope |
| --- | --- | --- |
| `Account` | `GET /v2/account` | `account:read` |
| `Zones`, `Zone`, `ListRecords` | `GET /v2/domains`, `/v2/domains/{name}`, `/v2/domains/{name}/records` | `domain:read` |
| `CreateRecord` | `POST /v2/domains/{name}/records` | `domain:read`, `domain:create` |
| `UpdateRecord` | `PUT /v2/domains/{name}/records/{id}`; a type change also POSTs and DELETEs | `domain:read`, `domain:update` (`domain:create`, `domain:delete` for a type change) |
| `DeleteRecord` | `DELETE /v2/domains/{name}/records/{id}` | `domain:read`, `domain:delete` |

`Account` reads only the token's own Account, so it succeeds with no Domains
and proves nothing about DNS scopes: a token without `domain:read` verifies,
then fails on `Zones`. Invalid tokens (401) and missing scopes (403) match
`ErrUnauthorized`; a missing Domain or Record (404) matches `ErrNotFound`, so
a denied scope is never reported as an empty or missing resource. The Tenant
is the token's team (`team.uuid`, `team.name`) when the answer names one, or
else the Account's UUID with its name or email. `AccountInfo.Nameservers` are
`ns1.digitalocean.com`, `ns2.digitalocean.com` and `ns3.digitalocean.com`,
which DigitalOcean serves every Domain from.

## Zones

Each DigitalOcean Domain is a Zone. Domains are keyed by name, so a Zone's
ID is its lower-case name. A Domain proves that DigitalOcean holds the Zone,
not that Delegation names its nameservers: the Hosting State is always
`HostingUnknown`, and Zones carry no per-Zone nameservers. `Zone(name)` reads
`GET /v2/domains/{name}` and returns `ErrNotFound` for an absent Domain.
Zone filters are applied locally with the shared case-insensitive rules.

Lists ask for 200 items a page and follow `links.pages.next` until it is
absent. A next link only says that a following page exists: it must name the
same list on the configured or production host and the following page
number, and that page is then read through the configured endpoint, so the
token never goes to a host a link names. A link elsewhere, a repeated or
skipped page, an empty intermediate page, a count disagreeing with
`meta.total`, or a malformed list is an error, never a shorter result.

## Records

`ListRecords` reads the Domain first, for its zone-file SOA serial (zero when
absent) and to tell a missing Zone, then every page of its Domain Records.
A type filter DigitalOcean holds (A, AAAA, CAA, CNAME, MX, NS, SOA, SRV,
TXT) is sent as `type`; any other type finds nothing without a list call.
Name filters are applied locally.

Records carry native numerical IDs as strings and absolute owner names
without trailing dots: `@` is the apex, `*` a wildcard. Values are in
presentation form, built from DigitalOcean's structured fields:

| Type | Value | Wire fields |
| --- | --- | --- |
| A, AAAA | address | `data` |
| CNAME, NS | `host.example.net.` | `data` (`@` is the apex) |
| MX | `10 mail.example.net.` | `priority`, `data` |
| SRV | `0 5 5060 sip.example.net.` | `priority`, `weight`, `port`, `data` |
| TXT | literal text | `data` |
| CAA | `0 issue "letsencrypt.org"` | `flags`, `tag`, `data` |

DigitalOcean answers host names without their trailing dot; the adapter
returns them absolute, with the dot, and sends them with it. A host name
written without the dot is read as absolute and comes back with one. A bare
`issue` or `issuewild` CAA issuer domain is sent with a trailing dot, as
DigitalOcean takes it, and returned without one, whichever form is stored;
CAA values with parameters, `;` alone and `iodef` URLs are sent as given. CAA
values decode `\DDD` escapes, and control characters come back as `\DDD`.
SOA and types unknown to the module stay visible with their native IDs.

## Writes

Writes support A, AAAA, CNAME, MX, NS, SRV, TXT and CAA. URI is not a
DigitalOcean type and is rejected locally, as are CAA tags other than
`issue`, `issuewild` and `iodef`. The SOA Record is managed by DigitalOcean:
updating or deleting it fails locally with `ErrUnauthorized`, without a
write. Other service rules, such as a CNAME at the apex, remain the API's
validation errors.

`CreateRecord` first lists the Zone's Records of the type, and fails with
`ErrConflict` when one has the same name (ignoring case) and Value, whatever
its TTL. It then POSTs once: creates are never retried automatically. A lost
or failed-server answer is reported as an unconfirmed outcome; re-read the
Records before retrying.

`UpdateRecord` finds `before` by its native ID (`ErrNotFound` when absent),
checks that no other Record is identical to `after`, and writes the whole
Record with one PUT, keeping its ID. Name, Value and TTL edits are made in
place; every type-specific field the type does not take is sent null. The
update API does not document a type change, so one creates the new Record,
then deletes the original, and returns the new ID. A CNAME cannot share its
owner name, so a type change to or from CNAME at one owner deletes first.
When that replacement fails, the original is re-created as a best effort
under a new ID. A failure between the writes says which Records may remain:
the replacement and the original, the original restored under its new ID, or
that the original was deleted and could not be restored. `DeleteRecord`
deletes only the Record of the given ID; siblings of the same name and type
remain.

Successful writes return the Record as DigitalOcean answered it. An
acknowledgement without a well-formed Record, empty or malformed, is read
back (by ID, or for a create as the one Record of that content) without
writing again; when that read fails, the error says the write was
acknowledged and may have completed.

`dnsprovider.Apply` works through the common CRUD fallback: its stale check
writes nothing when a modified or deleted Record changed, deletions,
modifications and additions run in that order, and results keep Changeset
order with per-change errors. Changesets are not atomic.

## TTL, quotas and errors

DigitalOcean documents no TTL bounds, so the adapter keeps the shared
`DefaultTTLRange` of 30 to 86400 seconds for writes; Records read keep the
TTL DigitalOcean stored. There is no automatic TTL: TTL 1 is invalid.

DigitalOcean allows 250 requests a minute and 5,000 an hour per token. A
limiter shared by every Provider of one endpoint and token allows 80 calls a
minute, within both. Other users of the token must coordinate. Rate-limit
answers match `ErrRateLimited`, with the wait from `Retry-After` or else from
`ratelimit-reset`. GET, PUT and DELETE are retried within the shared bounded
policy on 429 and 5xx answers; POST never is. Error messages keep the
service's `id` and `message` and its `request_id`, with the token redacted.
Validation failures (such as 422) keep their status and messages in
`APIError` without a sentinel.

## Live tests

Optional read-only live tests run with `DNSPROVIDER_DIGITALOCEAN_TOKEN` set
(`go test ./providers/digitalocean -run '^TestLive$' -v`) and skip without
it. They read the Account, the Zones, one Zone and its Records; they never
write. `DNSPROVIDER_DIGITALOCEAN_BASE_URL` selects another endpoint.

The protocol follows the official
[Account API](https://docs.digitalocean.com/reference/api/reference/account/),
[Domains API](https://docs.digitalocean.com/reference/api/reference/domains/),
[Domain Records API](https://docs.digitalocean.com/reference/api/reference/domain-records/)
and the [OpenAPI specification](https://github.com/digitalocean/openapi).
