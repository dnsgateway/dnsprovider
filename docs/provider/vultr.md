# Vultr

Import `providers/vultr`, or use Registry key `vultr`. Typed `Config`
requires `APIKey`; the equivalent Factory field is `api_key` (secret). Use
the Account's API key or a user's API key. Constructors validate locally,
without network calls, and reject an empty key or one holding whitespace.
There are no optional capabilities: no Zone writes, no TenantLister and no
Batcher.

```go
p, err := vultr.New(vultr.Config{APIKey: key})
// or
p, err := providers.Registry().New("vultr", map[string]string{"api_key": key})
```

The adapter uses API v2 at `https://api.vultr.com/v2` with Bearer
authentication. `WithBaseURL` replaces that endpoint for every call;
`WithHTTPClient` keeps the caller's timeouts (the default client times out
after 30 seconds); `WithLogger` receives retry diagnostics, never the key.

## Access and permissions

API access must be enabled for the key, and the key's access control must
allow the caller's IP address: a call from any other address is refused
with 401 (`Unauthorized IP address`). A user's key acts with that user's
permissions; DNS needs the user's DNS permission (`dns` in the Account's
`acls`).

| Operation | Endpoint | Permission |
| --- | --- | --- |
| `Account` | `GET /v2/account` | a valid key from an allowed address |
| `Zones`, `Zone`, `ListRecords` | `GET /v2/domains`, `/v2/domains/{domain}`, `/v2/domains/{domain}/records` | DNS |
| `CreateRecord` | `GET` the Records, `POST /v2/domains/{domain}/records` | DNS |
| `UpdateRecord` | `GET` the Records, `PATCH /v2/domains/{domain}/records/{id}`, `GET` it back; a type change POSTs and DELETEs | DNS |
| `DeleteRecord` | `DELETE /v2/domains/{domain}/records/{id}` | DNS |

`Account` reads only the key's own Account, so it succeeds with no DNS
Domains and proves nothing about DNS permission: a key without it verifies,
then fails on `Zones`. Invalid keys and refused addresses (401) and missing
permissions (403) match `ErrUnauthorized`; a missing Domain or Record (404)
matches `ErrNotFound`, so a denied permission is never reported as an empty
or missing resource. Vultr's Account answer carries no Account ID: the
Tenant has an empty ID and is named by the Account's name, or else its email.
`AccountInfo.Nameservers` are `ns1.vultr.com` and `ns2.vultr.com`, which
Vultr serves every DNS Domain from.

## Zones

Each Vultr DNS Domain is a Zone. Domains are keyed by name, so a Zone's ID
is its lower-case name. A Domain proves that Vultr holds the Zone, not that
Delegation names its nameservers: the Hosting State is always
`HostingUnknown`, and Zones carry no per-Zone nameservers. `Zone(name)` reads
`GET /v2/domains/{domain}` and returns `ErrNotFound` for an absent Domain.
Zone filters are applied locally with the shared case-insensitive rules.

Lists ask for 500 items a page (`per_page`) and pass `meta.links.next` back
as the `cursor` parameter until it is empty. The cursor is opaque: it is
only ever sent to the configured endpoint, never followed as a link, so the
key goes nowhere else. A repeated cursor, a cursor after an empty page, a
count disagreeing with `meta.total`, or a malformed list is an error, never a
shorter result.

## Records

`ListRecords` reads every page of the Zone's Records; Vultr's list takes no
filter, so type and name filters are applied locally. A missing Zone is
`ErrNotFound`. Vultr reports no SOA serial, so `RecordSet.Serial` is zero.

Records carry native IDs (UUIDs) and absolute owner names without trailing
dots: Vultr's empty name is the apex, `*` a wildcard. Values are in
presentation form, built from Vultr's fields:

| Type | Value | Wire fields |
| --- | --- | --- |
| A, AAAA | address | `data` |
| CNAME, NS | `host.example.net.` | `data` |
| MX | `10 mail.example.net.` (`0 .` is a null MX) | `priority`, `data` |
| SRV | `0 5 5060 sip.example.net.` | `priority`, `data` as `weight port target` |
| TXT | literal text | `data` as one or more strings in double quotes |
| CAA | `0 issue "letsencrypt.org"` | `data` as `flags tag "value"` |

Vultr stores host names without their trailing dot; the adapter returns them
absolute, with the dot, and sends them without it (the root stays `.`).
The priority is sent for MX and SRV alone, where Vultr requires it, and a
zero priority is sent explicitly. TXT data is sent and answered in quotes,
which the adapter adds and removes; backslashes are literal. TXT data of
several quoted strings (`"part1" "part2"`) reads as their concatenation
(`part1part2`), which writes back as one string. CAA values
decode `\DDD` escapes, and control characters come back as `\DDD`; a CAA
value Vultr answers without quotes is read as it is. SSHFP and other types
the module does not edit stay visible with their native IDs and data.
A Record whose data does not parse for its type (an MX without a priority,
say) is listed with that data, as it is, as its Value rather than failing
the listing; only a Record missing its ID, type, name, data or TTL makes the
list a malformed answer.

## Writes

Writes support A, AAAA, CNAME, MX, NS, SRV, TXT and CAA. URI is not a Vultr
type, and SSHFP is not an editable type of the module: both are rejected
locally. A TXT value holding a double quote is rejected locally, as Vultr
refuses quotes inside TXT data. Other service rules, such as a CNAME at the
apex, remain the API's validation errors.

Vultr requires the Records of one name and type to share a TTL and refuses
a write that would mix them. The adapter does not change siblings to make a
write fit: such a create or update fails with Vultr's 400 validation error
and writes nothing. Change the TTL of an RRset by deleting and re-adding its
Records, or by keeping the TTLs equal.

`CreateRecord` first lists the Zone's Records, and fails with `ErrConflict`
when one has the same type, name (ignoring case) and Value, whatever its
TTL. It then POSTs once: creates are never retried automatically. A lost or
failed-server answer is reported as an unconfirmed outcome; re-read the
Records before retrying. A write refused before it was sent, such as one
whose rate-limit wait would pass the context's deadline, and a 4xx answer
are plain failures: nothing was written.

`UpdateRecord` finds `before` by its native ID in one list of the Zone
(`ErrNotFound` when absent), checks that no other Record is identical to
`after`, and edits name, Value and TTL in place with one PATCH, keeping the
ID. PATCH does not take the type. Vultr acknowledges a PATCH with 204 and no
Record, so the stored Record is read back by ID, never written again; when
that read fails, the error says the update was acknowledged and may have
completed. PATCH is not retried automatically. A type change creates the
new Record, then deletes the original, and returns the new ID; the old
type's priority is not carried over. A CNAME cannot share its owner name, so
a type change to or from CNAME at one owner deletes first. Such a move is
refused before any write when the original could not be written back (a
type the module does not write, or a TTL outside the writable range). When
the replacement definitely failed (a 4xx answer, or never sent), the
original is re-created as a best effort under a new ID, even if the
context has ended; when the replacement may have completed (a lost,
server-failed or unreadable answer), the original is not re-created, and
the error says so. A failure between the writes says which Records may
remain: the replacement and the original, the original restored under its
new ID, the original deleted with its replacement unconfirmed, or the
original deleted and not restored. `DeleteRecord`
deletes only the Record of the given ID; siblings of the same name and type
remain. An ID that is not a UUID names no Record (`ErrNotFound`) and is
never sent.

Successful creates return the Record as Vultr answered it. A create
acknowledged without a well-formed Record is read back as the one Record of
that content, without writing again, with the same "may have completed"
error when that read fails.

`dnsprovider.Apply` works through the common CRUD fallback: its stale check
writes nothing when a modified or deleted Record changed, deletions,
modifications and additions run in that order, and results keep Changeset
order with per-change errors. Changesets are not atomic.

## TTL, quotas and errors

Vultr documents no TTL bounds, so the adapter keeps the shared
`DefaultTTLRange` of 30 to 86400 seconds for writes; Records read keep the
TTL Vultr stored. There is no automatic TTL: TTL 1 is invalid.

Vultr allows 30 requests a second per originating IP address. A limiter
shared by every Provider of one endpoint allows 20 calls a second. Other
users of the address must coordinate. Rate-limit answers (429) match
`ErrRateLimited`, with the wait from `Retry-After` when present. GET and
DELETE are retried within the shared bounded policy on 429 and 5xx answers;
POST and PATCH never are. Error messages keep the service's `error` text,
with the key redacted. Validation failures (400) keep their status and
messages in `APIError` without a sentinel.

## Live tests

Optional read-only live tests run with `DNSPROVIDER_VULTR_API_KEY` set
(`go test ./providers/vultr -run '^TestLive$' -v`) and skip without it. They
read the Account, the Zones, one Zone and its Records; they never write.
`DNSPROVIDER_VULTR_BASE_URL` selects another endpoint.

The protocol follows the [Vultr API reference](https://www.vultr.com/api/)
(Account and DNS), the official
[Account client](https://github.com/vultr/govultr/blob/master/account.go),
[DNS Domain client](https://github.com/vultr/govultr/blob/master/domain.go)
and [DNS Record client](https://github.com/vultr/govultr/blob/master/domain_record.go),
the [rate limit](https://docs.vultr.com/support/platform/api/what-rate-limits-apply-to-the-vultr-api)
and [API access control](https://docs.vultr.com/platform/other/api/manage-api-access-control)
documentation. The adapter does not depend on govultr.
