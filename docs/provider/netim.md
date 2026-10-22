# Netim

Import `github.com/dnsgateway/dnsprovider/providers/netim`, or use Registry
key `netim`. Typed `Config` requires `ID` (the reseller ID) and `Secret` (the
API secret); both equivalent Factory fields, `id` and `secret`, are labelled
secrets. Blank credentials and unknown Factory fields fail locally without
echoing their values. Construction makes no network requests.

```go
p, err := netim.New(netim.Config{
    ID: resellerID, Secret: apiSecret,
}, dnsprovider.WithHTTPClient(client))
defer p.Close(context.Background())
```

```go
p, err := providers.Registry().New("netim", map[string]string{
    "id": resellerID, "secret": apiSecret,
})
```

The adapter uses Netim's REST API 3.0, which Netim calls beta. Expect wire
changes.

## Setup and account access

A Netim reseller account has a reseller ID and an API secret. The adapter
sends them only to open a session, as `Authorization: Basic` credentials.

The default endpoint is `https://rest.netim.com/3.0`. Netim's OT&E (test)
environment is reached only through `WithBaseURL`; Netim's docs give it as
`http://oterest.netim.com/3.0` (plain `http`). OT&E needs its own reseller
account, and OT&E domains must use `ns1-ote.netim.net` and
`ns2-ote.netim.net` for any DNS feature; see Netim's
[testing environment](https://support.netim.com/en/docs/resellers/apis/testing-environment).

`WithBaseURL`, `WithHTTPClient`, `WithLogger`, and context cancellation are
honored. Without a supplied HTTP client, requests have the shared 30-second
timeout; supplied clients keep their own timeout settings.

`Account` opens the session, or reuses it, and reads `GET /session/` to prove
access, including when the Account has no domains. Bad credentials are
`ErrUnauthorized`. The Tenant is the reseller ID from the Config; Netim sets
no account-wide nameservers.

## Sessions

The adapter opens a session on the first call that needs one, with
`POST /session/` and the preferences `lang: EN`, `sync: 1` (synchronous
processing) and `notif: 0`. It sends the session's `access_token` as
`Authorization: Bearer` on every later call.

- A Provider holds at most one session and shares it between goroutines.
  Opening is serialized, so concurrent first calls open one session.
- When a call made with the held session gets a 401, the session has expired
  or was revoked: the adapter opens a new one and resends that call once. A
  second 401, or a 401 when opening, is `ErrUnauthorized`.
- `(*netim.Provider).Close(ctx)` sends `DELETE /session/` and forgets the
  session. If a session is being opened when `Close` is called, `Close` waits
  for it and closes it too. A session Netim already ended closes without
  error. A later call opens a new session. `Close` is not part of `dnsprovider.Provider`.

Netim allows 10 concurrent sessions per reseller by default and refuses new
logins once they are in use. Call `Close` on a Provider you no longer need,
and share one Provider rather than building one per request. Netim does not
document a session's lifetime or idle timeout.

The secret, the Basic credentials and the session token are redacted from
every error and log line, including Netim's own messages and transport
errors.

## Zones and records

`ListZones` reads the whole domain list with `POST /domains/` and filters it
locally and exactly, ignoring case. Every list is a Full View. Netim
documents no paging; the adapter assumes one answer holds every domain.
Zone IDs are normalized domain names.

`GetZone` matches a name ignoring case and a trailing dot. It finds the domain
in the list, then reads `GET /domain/{name}/info/` for its nameservers
(`ns`), normalized without trailing dots. A name the list does not hold is
`ErrNotFound`; API failures are returned as they are, never treated as
absence.

Hosting State is Unknown. A domain's status describes its Registration, and
`HasDNS4Service` only says whether the domain uses Netim's nameservers.

`ListRecords` reads `GET /domain/{name}/zone/info/` and filters locally by
type and absolute name.

- Names are absolute, without a trailing dot. An empty `subdomain` and `@`
  are both the apex.
- Types are upper case.
- TTLs are effective, in seconds. A Record with `customTtl` set has its own
  `ttl` and `ttlUnit`; any other has the Zone's `ttl` and `ttlUnit`. The
  units `S`, `M`, `H`, `D` and `W` are converted; a missing unit is seconds.
- MX Values put the `priority` option before the target, and SRV Values the
  `priority`, `weight` and `port` options. An SRV's owner is built from its
  `service` and `protocol` options and its `subdomain`, such as
  `_sip._tcp.example.com`.
- Targets of CNAME, NS, MX and SRV are read without a trailing dot.
- TXT Values are literal text, preserving spaces, quotes and backslashes.
- Types this module does not write, such as TLSA, SVCB and HTTPS, stay
  visible, with `value` as Netim gives it.
- Record options no field carries, such as a TLSA's `certificateUsage`, are
  read-only Extras under `dnsprovider.ExtraOther`, each as its raw JSON.
- Netim reports no Serial; it is zero.

The API gives Records no IDs. Record IDs are derived from the Record's
content and change when the Record changes. A TTL counts only when it is the
Record's own, so a change of the Zone's TTL keeps the IDs of the Records that
inherit it. Keep the whole Record as read.

Numbers in options are read as JSON numbers or numeric strings, and `""` or
`null` as absent. `customTtl` is read as `true`/`false`, `1`/`0` or
`"1"`/`"0"`. Zone info is read as one object, or an array of one, since the
docs describe it both ways.

## Writes

`CreateRecord`, `UpdateRecord` and `DeleteRecord` write A, AAAA, CNAME, MX,
TXT, NS and SRV Records. The Delegation Signer methods are described under
[Registration Signing Keys](#registration-signing-keys).

### Creating

`CreateRecord` reads the Zone first. A Record the Zone holds already, by
`SameRecord` (type, name and Value; TTL does not count), is `ErrConflict`,
and nothing is sent. Otherwise it sends `POST /domain/{name}/zone/` with the
Record's `subdomain`, `type` and `value`, and `options`:

- the TTL, always explicit, as `ttl` with `ttlUnit: "S"`;
- for MX, the preference as `priority`, with the mail host as `value`;
- for SRV, `priority`, `weight` and `port`, and the service and protocol from
  the name's first two labels as `service` (without its `_`) and `protocol`
  (upper case). The rest of the name is the `subdomain`, so
  `_sip._tcp.example.com` is `service: "sip"`, `protocol: "TCP"` and the
  apex. Netim takes the protocols `TCP`, `UDP` and `TLS`.

The apex is sent as an empty `subdomain`. Targets of CNAME, NS, MX and SRV are
sent fully qualified, with a trailing dot. TXT Values are sent as literal
text. Netim's answer does not hold the Record, so once Netim confirms the
create, the adapter reads the Zone again and returns the one Record of that
type, name, Value and TTL.

### Deleting

`DeleteRecord` reads the Zone and finds the Record as last read: by its ID,
which derives from its content, or, without an ID, by `SameRecord` and TTL. A
Record the Zone no longer holds as read is `ErrNotFound`. It then sends
`DELETE /domain/{name}/zone/` with the `subdomain`, `type` and `value` exactly
as Netim gave them. Netim selects a record by those three alone, so a Record
that shares them with another (such as two MX Records for one host with
different preferences, or two SRV Records for one target at one subdomain) is
refused as `ErrConflict` rather than risk deleting both. Nothing is sent for
a missing or ambiguous match.

### Updating and replacing

`UpdateRecord` reads the Zone and finds the Record as last read, as
`DeleteRecord` does: a stale Before is `ErrNotFound`, and one Netim cannot
single out by subdomain, type and value is `ErrConflict`. A destination the
Zone holds already, by `SameRecord`, is `ErrConflict` too. None of these
sends a write.

A change of Value or TTL under the same owner and type is one
`PATCH /domain/{name}/zone/update/`. It selects the Record by its
`subdomain`, `type` and `value` exactly as Netim gave them, and sends the
new target or text as `newValue` and the new `options` in the form a create
sends them, so an MX preference or SRV numbers can change in place. Once Netim
confirms it, the adapter reads the Record back, as for a create. The Record's
ID changes with its content.

A move to another owner or type is a replacement: Netim's update cannot change
the `subdomain` or `type`, and Netim has no atomic move. The adapter sends
`DELETE /domain/{name}/zone/` for the old Record and then
`POST /domain/{name}/zone/` for the new one, and returns the new Record as read
back. For a moment the Zone holds neither. If the delete fails, nothing more is
sent. If the create fails:

- A refusal (a 4xx, `Failed` or `Cancelled`) triggers one attempt to create
  the old Record again, with its TTL as read, now as a custom TTL.
- After an Unconfirmed Write, the adapter reads the Zone first. It restores
  nothing when that read fails or shows the old or the new Record, and
  returns the `ErrUnconfirmed` error. Otherwise it restores the old Record.
- The error always reports the failed create and says whether the old Record
  was restored, the restore failed, or the restore was not confirmed. A
  restore is never retried, and its own Unconfirmed Write is reported as
  `ErrUnconfirmed`.

Netim's other record options (Extras) are kept as they are. An update that
changes them, or moves a Record that has any, is refused after the read and
before any write, since a create would drop them.

### Refused locally

These fail before any request:

- CAA and URI, which Netim does not take, and any other type outside the list
  above, including read-only TLSA, SVCB and HTTPS Records;
- names outside the Zone, and SRV names that do not start with
  `_service._protocol`;
- Values that are not valid for their type;
- Values longer than 150 characters, Netim's documented limit, counted on the
  `value` sent (the target, for MX and SRV) without the trailing dot the
  adapter adds to a target;
- TTLs outside 30–86400 seconds, and the automatic TTL. This range is a
  library default, not a verified Netim bound;
- any Extras on a create: Netim's other record options are read only.

### Operations and Unconfirmed Writes

Every write answers with an operation, whose `STATUS` the adapter reads
ignoring case:

- `Done` confirms the write.
- `Failed` or `Cancelled` is a refusal: a plain `*dnsprovider.APIError` that
  carries Netim's `MESSAGE`. So is a 4xx answer, with its `message`.
- `Pending`, or a status the adapter does not know, is an Unconfirmed Write
  (`ErrUnconfirmed`). A synchronous session should never answer `Pending`.
- A 5xx, a lost answer, or an answer that is not an operation is an
  Unconfirmed Write too.
- A create or update Netim confirmed whose read-back fails, or does not show exactly one
  matching Record, is an Unconfirmed Write.

After an Unconfirmed Write, re-read the Zone before retrying. Writes are never
retried automatically, not even a `DELETE` answered with a 5xx. The one
exception is a 401 on the held session: Netim refuses such a call before
running it, so the adapter opens a new session and sends the write once more.

Zone creation, updates and deletion, batching and Tenant listing are not
supported and return `ErrNotImplemented` without network traffic.

## Errors and quotas

Use `errors.Is` with shared sentinels and `errors.As` with
`*dnsprovider.APIError`, which carries Netim's `message`.

- 401 is `ErrUnauthorized` once a fresh session also fails.
- 429 is `ErrRateLimited`, with `RetryAfter` from a `Retry-After` header.
- 400 and 405 are plain `APIError`s. Netim also answers 405 for a path it does
  not have.

The session-limit refusal is not recognized by its text, which is not known:
it surfaces as an `APIError`, or as `ErrRateLimited` if Netim answers 429.

Reads answered 429 or 5xx are retried by the shared client, except
`POST /domains/`, which is a POST. A shared per-credential, per-endpoint
limiter conservatively paces 60 calls per minute; Netim publishes no rate.
Separate processes still need to coordinate usage.

## Registration Signing Keys

The Traits declare `CapDSRegistrar`. The Delegation Signer methods read and
replace the Signing Keys the registry holds for a Registration whose DNS
Netim does not serve. Each one first reads the domain list and
`GET /domain/{name}/info/`:

- a domain the Account does not register is `ErrNotFound`;
- a domain with `HasDNS4Service = 1`, on Netim's DNS, is `ErrUnsupported`,
  without a write. Netim signs those Zones itself, and its ds-record calls
  cover only domains on other DNS servers.

`ListDelegationSigners` reads `GET /domain/{name}/ds-record/`. Each entry is
DS data (`key`, `type`, `algo`, `digest`) or DNSKEY data (`flags`,
`protocol`, `algo`, `pubKey`). DS entries are grouped into Signing Keys by
key tag and algorithm, SHA-256 first, with the digest in upper case. A
DNSKEY's key tag is computed from its content, as Netim does not send one.

`SetDelegationSigners` checks every key before any request: each needs a
DNSKEY or a DS (`ErrUnsupported` for neither), and each form must carry the
key's tag and one algorithm. A key whose algorithm no registry takes is
`ErrUnsupported`: one that IANA does not assign for zone signing, or that
RFC 8624 says must not sign (1 RSAMD5, 3 DSA, 6 DSA-NSEC3-SHA1, 12 ECC-GOST).
Algorithms 5, 7, 8, 10, 13, 14, 15, 16, 17 and 23 pass. A DS whose digest type
IANA does not assign (0, or above 6) is `ErrUnsupported` too. Netim documents
no algorithm or digest type it refuses. No keys is `ErrNoSigningKeys`. It then
reads the held set. A held entry and a key are the same key when they share a DNSKEY
or a DS, Netim's or one computed from a DNSKEY (SHA-1, SHA-256 or SHA-384),
so an unchanged set sends no write, whichever form Netim holds it in.
Otherwise:

1. It adds the missing keys with `POST /domain/{name}/ds-record/`: a key's
   DNSKEY when it has one, and otherwise its DS records. DNSKEY and DS data go
   in separate calls.
2. Only then it removes the held entries no key wants, with
   `DELETE /domain/{name}/ds-record/` and a `data` list of each entry exactly
   as Netim gave it.

A failure part-way therefore never leaves the Delegation without a key, but
can leave both old and new keys held. A removal is never sent with an empty
`data` list, which Netim could take as delete all.

`DeleteDelegationSigners` sends `DELETE /domain/{name}/ds-record/` with no
body, Netim's delete all.

These writes follow the [Unconfirmed Write](#operations-and-unconfirmed-writes)
rules of Record writes. A write that Netim refuses, with a 4xx or a `Failed`
or `Cancelled` operation, is a plain `APIError` that keeps Netim's message.
Netim documents no refusal codes, so a registry refusing a key's algorithm or
form is not told apart from other refusals. After an Unconfirmed add, nothing
is removed.

Unverified: which form Netim returns for a key sent as a DNSKEY, and whether a
removal must repeat every field of the held entry. The adapter compares keys
across forms and removes entries as they were read.

## Sources and verification limits

Nobody working on this module holds Netim OT&E credentials, so the test
fixtures are not OT&E captures. They come from Netim's
[REST 3.0 reference](https://support.netim.com/en/docs/api-rest-3-0) and its
official [Python](https://github.com/netim-com/netim-apirest-client-for-python)
and [Java](https://github.com/netim-com/netim-apirest-client-for-java) clients,
which target REST 1.0. `providers/netim/testdata/README.md` names each file's
source.

These points are unverified, and the adapter reads tolerantly where they are
open:

- Whether OT&E answers on `https` too.
- Whether the domain list is paged.
- How `ns` entries look in 3.0: the adapter accepts names, objects with a
  `name`, and an object of them keyed by position.
- Whether an SRV's `service` carries a leading `_`, and the case of its
  `protocol`: the adapter accepts both.
- Whether `ttlUnit` comes back on read, whether targets carry a trailing dot,
  whether TXT Values come back quoted, and whether the apex is `""` or `@`.
- On writes: whether Netim expects the apex as `""` or `@` (the adapter sends
  `""`), targets with or without a trailing dot (it sends one), and SRV
  `service` with or without its `_` (it sends none).
- The exact operation answer of a write, including the spelling of its
  statuses, and whether a delete matches a record's value ignoring case or a
  trailing dot.
- The error body beyond `message`, and the session-limit refusal's status and
  text.
- The session lifetime and idle timeout.

Netim's docs have examples that disagree with the reference: a delete example
with a trailing comma, a `PATCH` domain list in the Java client, and a header
spelled `Autorization`. The adapter follows the reference text.

Default tests run offline against a fake Netim server and need no
credentials. The optional live test only reads and requires
`DNSPROVIDER_NETIM_ID` and `DNSPROVIDER_NETIM_SECRET`;
`DNSPROVIDER_NETIM_BASE_URL` may point it at OT&E. It closes its session
when it ends.
