# INWX

Import `github.com/dnsgateway/dnsprovider/providers/inwx`, or use Registry
key `inwx`. Typed `Config` requires `Username` and `Password`, and takes an
optional `SharedSecret` for an account with two-factor authentication. The
equivalent Factory fields, `username`, `password` and `shared_secret`, are
all labelled secrets. A blank username or password, a `shared_secret` that
is not base32 (case, spaces and `=` padding are ignored), and unknown
Factory fields fail locally without echoing their values. Construction
makes no network requests.

```go
p, err := inwx.New(inwx.Config{
    Username: user, Password: password, SharedSecret: totpSecret,
}, dnsprovider.WithHTTPClient(client))
defer p.Close(context.Background())
```

```go
p, err := providers.Registry().New("inwx", map[string]string{
    "username": user, "password": password,
})
```

The adapter uses INWX's DomRobot JSON-RPC API. It reads the Account, its
Zones and their Records, creates, updates and deletes Records, Onboards
and Offboards Zones, reads a Zone's DNSSEC State and Signing Keys, and
switches INWX's automated DNSSEC on or off. As a registrar it reads and
replaces the Registration Signing Keys of a domain whose DNS INWX does not
serve. The Traits declare `CapZoneCreator`, `CapZoneUpdater`,
`CapZoneDeleter` and `CapDSRegistrar`.

## Setup, OT&E and two-factor authentication

The adapter logs in with an INWX account's username and password, or a
sub-user's. The default endpoint is `https://api.domrobot.com/jsonrpc/`.
INWX's OT&E (test) environment, `https://api.ote.domrobot.com/jsonrpc/`, is
reached through `WithBaseURL`; OT&E accounts are registered separately, and
free, at INWX.

For an account with two-factor authentication, give the TOTP shared
secret: the base32 key the INWX web UI shows (or encodes in its QR code)
when 2FA is set up. The adapter computes an RFC 6238 code (HMAC-SHA1,
30-second steps, six digits) from it at each login, so a long-lived
Provider keeps working. A one-off TAN is not a field: it expires within 30
seconds and cannot serve a later login. An account with 2FA and no shared
secret fails its first call with `ErrUnauthorized`, and the message names
`shared_secret`.

`WithBaseURL`, `WithHTTPClient`, `WithLogger`, and context cancellation are
honored. Without a supplied HTTP client, requests have the shared 30-second
timeout; supplied clients keep their own timeout settings. A supplied
client's cookie jar is never used: the adapter holds the session cookie
itself, so a client needs no jar, and the session never goes into one.

`Account` logs in, or reuses the session, and reads `account.info` to prove
access, including when the Account has no domains or Zones. Bad credentials
are `ErrUnauthorized`. The Tenant's ID is the `customerId` (the
`accountId` when INWX gives none) and its Name the `customerNo`; INWX sets
no account-wide nameservers.

## Sessions

Every call is a `POST` of `{"method", "params"}` to the endpoint, with
`lang: "en"`. The adapter logs in with `account.login` (`user`, `pass`) on
the first call that needs a session, and keeps the `domrobot` cookie the
answer sets, sending it as a `Cookie` header on every later call.

- When the login answer's `tfa` is anything but `"0"` or empty (INWX
  documents `"GOOGLE-AUTH"`; a number or bool is read the same way), the
  adapter sends `account.unlock` with a TOTP code computed then. A refused
  unlock is `ErrUnauthorized` with the refusal's code and reason, and the
  locked session is logged out.
- A refusal of `account.login` or `account.unlock`, whatever its 2xxx
  code, is `ErrUnauthorized`: an `APIError` that keeps INWX's code, `msg`
  and `reason`. 2502 ("Session limit exceeded") alone stays
  `ErrRateLimited`.
- A Provider holds at most one session and shares it between goroutines.
  Logging in is serialized, so concurrent first calls log in once.
- When a call made with the held session is refused with 2200, 2201 or 2202,
  the session has expired or was ended: the adapter logs in again and resends
  that call once. INWX refuses such a call before running it, so even a
  write is not repeated. A second refusal is `ErrUnauthorized`.
- `(*inwx.Provider).Close(ctx)` sends `account.logout` and forgets the
  cookie. A login in progress when `Close` is called is waited for and its
  session closed too. A session INWX already ended closes without error. A
  later call logs in again. `Close` is not part of `dnsprovider.Provider`.

INWX documents neither a session's lifetime nor how many sessions an
account may hold; 2502 ("Session limit exceeded") is `ErrRateLimited`. Call
`Close` on a Provider you no longer need, and share one Provider rather
than building one per request.

The password, the shared secret, every TOTP code sent and the session
cookie are redacted from every error and log line, including INWX's own
messages and transport errors.

## Zones

`ListZones` reads every page of `nameserver.list` (`domain: "*"`, `page`,
`pagelimit: 100`) until it holds the answer's `count` of zones, and filters
them locally and exactly. A page that repeats a zone, an empty page, or a
page shorter than the first before `count` is reached is an error, never a
shorter list; so is a list longer than `count`. `count` is read as a number
or a numeric string. Every list is a Full View. Master and slave zones are
both listed.

- The Zone ID is INWX's `roId` as a decimal string. Calls address a zone by
  its name, which every `nameserver.*` method takes.
- Hosting State is Unknown: a zone INWX hosts does not prove Delegation.
- `ListZones` leaves Nameservers nil, which would cost a call per zone.

`GetZone` matches a name ignoring case and a trailing dot. It reads
`nameserver.info` for the name, filtered to `type: NS`, and reports the
apex NS Records as the Zone's nameservers. When INWX answers 2303, the
adapter reads `domain.info`: a domain the Account registers is
`ErrNotServed` (which matches `ErrNotFound`), and any other name
`ErrNotFound`. A failed `domain.info`, and any other failure, is returned
as it is, never treated as absence.

## Onboarding and Offboarding

`CreateZone` and `DeleteZone` start and stop DNS hosting at INWX only.
Neither calls a `domain.*` method: they never register a domain or change
its nameservers at the registry, so Registration and Delegation are
untouched. An empty zone name is `ErrNotFound`, without a request.

- `CreateZone` sends one `nameserver.create` with `domain`, `type: MASTER`
  and INWX's nameservers in `ns` (`ns.inwx.de`, `ns2.inwx.de`,
  `ns3.inwx.eu`), and no `web`, `mail`, URL-redirect or `ignoreExisting`
  options. It returns the Zone with the answer's `roId` as its ID, those
  nameservers, and Hosting State Unknown. A success without a decodable
  `roId` returns the Zone's name alone. A zone INWX already hosts (2302)
  is `ErrConflict`.
- `DeleteZone` reads the zone by name (`nameserver.info`, filtered to its
  SOA). A zone that is gone, or whose `roId` is not the Zone's ID (it was
  deleted and created again), is `ErrNotFound`, without a delete.
  Otherwise it sends one `nameserver.delete` by name, which removes the
  zone and its Records.
- When the delete's outcome is unknown (a lost answer, any non-200
  answer, an undecodable answer, or 2400 and every 25xx code, 2502
  included, which also matches `ErrRateLimited`), the
  zone is read
  once more: gone is success; still there, or unreadable, is
  `ErrUnconfirmed`. A refusal (another 2xxx code) is returned as it is.
- Neither write is ever repeated. An Onboard whose outcome is unknown is
  `ErrUnconfirmed`: read the Zones before trying again.

## Records

`ListRecords` reads one `nameserver.info` for the Zone, by its name, or by
its `roId` for a Zone given with an ID alone. A type INWX serves is pushed
down as `type`; the rest of the filter is applied locally, exactly. The
name is not pushed down: a filter names a substring, and `nameserver.info`'s
`name` matches one name. ErrNotServed and ErrNotFound are as for `GetZone`.

- Names are absolute, without a trailing dot. INWX answers full names; an
  empty name is the apex.
- Types are upper case. IDs are INWX's numeric `id`, which is unique across
  the account, as a decimal string; it is read as a number or a string.
- TTLs are in seconds. The Serial is the zone's `SOAserial`.
- MX, SRV and URI Values put INWX's separate `prio` first: `10
  mail.example.net.`, `10 0 5060 sip.example.net.` (SRV `content` is weight,
  port and target), `10 1 "https://example.com/"` (URI `content` is weight
  and the quoted target).
- Targets of CNAME, NS, MX and SRV get a trailing dot, which INWX stores
  without; the root stays `.`.
- TXT Values are INWX's `content` as literal text, preserving spaces, quotes
  and backslashes. CAA `content` is already in presentation form.
- Types this module does not write, such as SOA, ALIAS, URL redirects,
  HTTPS, SVCB, TLSA, SSHFP and PTR, stay visible, with `content` as their
  Value. URL-redirect fields are not read.
- A record without an `id`, a type or a TTL, or an SRV whose `content` is
  not three fields, fails the read.
- When the answer's `count` is above the records it holds, the list is
  truncated and the read fails. The check is made only for an unfiltered
  read, as INWX does not say whether `count` counts the filtered records.

## Record writes

`CreateRecord` takes A, AAAA, CNAME, MX, TXT, NS, SRV, CAA and URI Records.
It first reads the Zone's Records of that type: one the Zone holds already,
by `SameRecord`, is `ErrConflict` without a write, as is INWX's 2302. It
then sends one `nameserver.createRecord` with the Zone's name as `domain`,
the full `name` without a trailing dot (the zone name for the apex), the
`type`, the `content`, the `ttl` and the `prio`:

- MX, SRV and URI send their priority as `prio` and the rest of the Value as
  `content`: `mail.example.net`, `0 5060 sip.example.net`,
  `1 "https://example.com/"`. Every other type sends `prio` 0.
- Targets of CNAME, NS, MX and SRV lose their trailing dot; the root stays
  `.`.
- TXT `content` is the Value as literal text; CAA `content` is the Value.

It returns the Record read back with `nameserver.info` by the `id` INWX
answers (`recordId`), which must be the Record sent, with its TTL.

`DeleteRecord` deletes by INWX's ID. Record IDs are unique across the
account, so it first reads `nameserver.info` for the Zone with that
`recordId`: an ID the Zone does not hold is `ErrNotFound` without a write,
so a stale or foreign ID never deletes another Zone's Record. It then sends
one `nameserver.deleteRecord` with the `id`; a 2303 refusal is
`ErrNotFound`.

`UpdateRecord` changes the Record of `before`'s ID into `after` with one
`nameserver.updateRecord`, by `id`, sending `name`, `type`, `content`,
`ttl` and `prio` in the same form as a create, whether or not the name or
type changes. A move to another name or type is therefore one write, never
create-then-delete, and is never left half-done. Before writing, it
confirms with `nameserver.info` (`recordId`) that the ID is the Zone's
(`ErrNotFound` otherwise) and reads the Zone's Records of `after`'s type:
another Record the same as `after`, by `SameRecord`, is `ErrConflict`. The
answer carries no Record, so it returns the Record read back by its ID,
which must be `after`, with its TTL.

Refused locally, without a request: a Zone without a name, a type the
adapter does not write (for an update, as `before` or `after`), a Record
with Extras, a name outside the Zone, a Value not in its type's form, a TTL
outside 300–86400 seconds, and an update or delete without a numeric ID.

Every Record write is sent once and never retried, other than once with a
new session when INWX refuses the session (2200–2202), which it does before
running the call. Only code 1000 confirms a write. A refusal, any other
code of 2000 or more but 2400, is a plain `APIError` with INWX's code, `msg`
and `reason`: nothing was applied. These are Unconfirmed Writes, matching
`ErrUnconfirmed`, after which the Zone should be read again before
retrying:

- a lost answer, and any answer other than HTTP 200;
- an answer that cannot be decoded, or without a `code`;
- code 1001 ("action pending"), or any other success code but 1000;
- code 2400 ("Command failed") and every 25xx code, failures on INWX's
  side; 2502 also matches `ErrRateLimited`;
- a create answered without an `id`, and a create or update whose
  read-back fails or does not show the Record sent.

`dnsprovider.Apply` works through these single-record calls, with its stale
check.

## Registration Signing Keys

The adapter declares `CapDSRegistrar`. Its Delegation Signer methods take
the Zone's name, ignoring case and a trailing dot, and first resolve the
domain:

- `domain.info` answering 2303 is `ErrNotFound`: the Account does not
  register the domain.
- A domain INWX hosts a zone of (in `nameserver.list`) is `ErrUnsupported`,
  without a write. INWX signs a zone it hosts itself; the DS of such a
  domain is not the caller's to set here.
- Any other failure is returned as it is.

`ListDelegationSigners` reads `dnssec.listkeys` (`domainName`, `active:
1`). Each entry gives a key's DNSKEY (`flagId`, `algorithmId`,
`publicKey`), its DS (`keyTag`, `algorithmId`, `digestTypeId`, `digest`),
or both, as INWX computes the DS of a DNSKEY it is given. DS records are
grouped with their key by key tag and algorithm, SHA-256 first, with the
digest in upper case; a DNSKEY's key tag is computed from its content.
Numeric fields are read as numbers or strings, and the answer as a bare
array of entries or as an object with them under `dnskey`; an entry INWX
marks inactive or `DELETED` is left out. A registration without keys
lists none.

`SetDelegationSigners` replaces the held keys:

- It checks every key before any request. No key is `ErrNoSigningKeys`. A
  form INWX does not take is `ErrUnsupported`: an algorithm outside the
  documented `dnssecAlgorithm` values (5, 7, 8, 10, 13, 14, 15, 16), and,
  for a key sent as DS records, a digest type other than the documented
  `dnssecDigestType` values 2 and 4.
- It reads the held set. A held entry and a key are the same key when they
  share a DNSKEY or a DS, held or computed from a DNSKEY, so an unchanged
  set in either form sends no write.
- It adds each missing key with one `dnssec.adddnskey` (`domainName`): as
  its DNSKEY (`dnskey: "<domain>. IN DNSKEY <flags> 3 <alg> <key>"`,
  `calculateDigest: true`) when the key has one, and otherwise one call per
  DS (`ds: "<domain>. IN DS <tag> <alg> <type> <digest>"`).
- Only then it removes each held entry no key wants with one
  `dnssec.deletednskey`, by the `id` `listkeys` gave (`key`), sent back as
  INWX typed it.
- A failure part-way is reported with how many forms were added and
  entries removed, and never undone; a failure while adding removes
  nothing, so the Delegation never loses its keys.

`DeleteDelegationSigners` sends one `dnssec.deleteall` (`domainName`),
taking DNSSEC off the Delegation.

Each DNSSEC write is sent once. Code 1001 (pending) counts as taken: INWX
holds the change while the registry catches up, and the next
`ListDelegationSigners` shows what holds. A lost, non-200 or undecodable
answer, and a server-side failure (2400 or any 25xx code), leave the outcome
unknown and match `ErrUnconfirmed`; 2502 also matches `ErrRateLimited`; re-read before retrying. A call INWX
refuses for the session (2200–2202) is sent once more with a fresh
session, as INWX ran none of it. Any other refusal is a plain `APIError`
with INWX's code, message and reason: INWX documents no `reasonCode` for a
registry's refusal of an algorithm, digest type or form, so none is mapped
to `ErrUnsupported` yet.

## Zone details

`ZoneDetails` reads `dnssec.info` with `domains: [name]` and maps the
Zone's entry's `dnssecStatus` (read under goinwx's spelling `dnsSecStatus`
too) to the DNSSEC State:

| `dnssecStatus` | DNSSEC State |
| --- | --- |
| `AUTO` (INWX signs the zone) | On |
| `NONE` | Off |
| `MANUAL` (INWX does not sign; the registrar holds the user's keys) | Off |
| `UPDATE`, `DELETE_ALL` (read as a change in progress) | Pending |
| any other, or no entry for the Zone | Unknown, never Off |

A failed read is the property's failure with its error, and the DNSSEC
State stays Unknown. HSTS and minimum TLS are unsupported, without a call.

Signing Keys, when requested, are read for an `AUTO` Zone alone, from
`dnssec.listkeys` (`domainName`, `active: 1`). Each active entry of flags
257 (a KSK) is one Signing Key: its DNSKEY (`257 3 <algorithm>
<publicKey>`, the key tag computed from it) and its DS (`<keyTag>
<algorithm> <digestType> <digest>`, the digest upper case), grouped by key
tag and algorithm. ZSKs and entries listed inactive or `DELETED` are left out. A Zone
that is not `AUTO` has none: keys INWX holds for it are the registrar's, not
ones INWX signs with. The answer is read as a bare array of entries (as the
Terraform provider reads it) or with the entries under `dnskey` (as the
documentation and goinwx give it); numbers are read as JSON numbers or
strings. A failed key read is that property's failure, with the DNSSEC
State kept.

## DNSSEC switch

`UpdateZone` with DNSSEC set first reads the Zone as `GetZone` does: a Zone
INWX does not host is `ErrNotServed` or `ErrNotFound`, without a write. It
then sends one `dnssec.enablednssec` (`true`) or `dnssec.disablednssec`
(`false`) with `domainName`, once and never replayed, even when the Zone
already reads in the state asked for. 1000 and 1001 ("action pending") are
the switch taken. A lost answer, HTTP 5xx, 2400 and every 25xx code, and an
answer that cannot be decoded or has no `code`, are an
Unconfirmed Write (`ErrUnconfirmed`); 2502 also matches `ErrRateLimited`. Any other refusal, such as 2304 or
2306, is returned as an `APIError`. A refusal of the session (2200–2202) is
sent again once on a fresh session, as INWX refused it before running it.

The DNSSEC State returned is read again from `dnssec.info`: the state asked
for when it shows it, Pending while it shows another (the old state,
`UPDATE` or `DELETE_ALL`), and Unknown, without an error, when the read fails
or answers no known state.

The switch is allowed for any Zone INWX hosts, whether or not the Account
registers its domain. For a domain registered elsewhere, give its registrar
the DS of the Signing Keys `ZoneDetails` reads, as INWX can publish none.

Settings are processed in the order DNSSEC, HSTS, MinTLS. HSTS or MinTLS
set is `ErrUnsupported`, returned with the DNSSEC State as switched (the
switch stays applied) or as read when DNSSEC is nil. A nil DNSSEC is read;
with nothing set, `UpdateZone` returns the DNSSEC State read and fails when
the read fails.

## Errors and rate limits

Every DomRobot answer is HTTP 200 with a result `code`, a `msg`, an optional
`reason` and `reasonCode`, and `resData`. A code below 2000 is success. A
code of 2000 or more is a refusal: an `APIError` with status 0 whose
Messages are the code and `msg`, then the `reason` with its `reasonCode`.
Its kind comes from the code, from the result code table of INWX's API
documentation:

| Code | Documented meaning | Error |
| --- | --- | --- |
| 1000 | Command completed successfully | success |
| 1001 | Command completed successfully; action pending | success for a read, for `CreateZone` and `DeleteZone`, for the DNSSEC switch, and for a DNSSEC key write; an Unconfirmed Write for a Record write |
| 1500 | Command completed successfully; ending session | success (logout) |
| 2200 | Authentication error | `ErrUnauthorized`, after one fresh session |
| 2201 | Authorization error | `ErrUnauthorized`, after one fresh session |
| 2202 | Invalid authorization information | `ErrUnauthorized`, after one fresh session |
| 2302 | Object exists | `ErrConflict` |
| 2303 | Object does not exist | `ErrNotFound` |
| 2502 | Session limit exceeded; server closing connection | `ErrRateLimited`; for a write also `ErrUnconfirmed` |
| 2400, other 25xx | Command failed, and other server-side failures | a plain `APIError` for a read; also `ErrUnconfirmed` for a write |
| other 2xxx | such as 2003, 2004, 2005, 2304, 2305, 2306 | a plain `APIError` |

A refusal at login (`account.login` or `account.unlock`) is
`ErrUnauthorized` whatever its code, but 2502, which stays `ErrRateLimited`.

A non-200 answer, which INWX does not document, is an `APIError` of its
status; HTTP 429 is `ErrRateLimited`, with the wait from `Retry-After`. A
lost or undecodable answer, or one without a `code`, is an error, and for
a write an Unconfirmed Write (`ErrUnconfirmed`), as is any non-200
answer to a write. Every call
is a `POST`, so none is retried.

INWX publishes no general API rate limit. A limiter shared by every
Provider of one endpoint and username allows 60 calls a minute, a
conservative library choice, keyed by a hash of the username.

## TTL

The Traits declare TTLs from 300 to 86400 seconds. The minimum is INWX's,
from its Terraform provider; the maximum is a library bound until a capture
verifies it. There is no automatic TTL.

## Live tests

Optional read-only live tests run with `DNSPROVIDER_INWX_USERNAME` and
`DNSPROVIDER_INWX_PASSWORD` set, and `DNSPROVIDER_INWX_SHARED_SECRET` for
an account with 2FA (`go test ./providers/inwx -run '^TestLive$' -v`); they
skip without a username or password. `DNSPROVIDER_INWX_BASE_URL` points
them at OT&E (`https://api.ote.domrobot.com/jsonrpc/`). They read the
Account, the Zones, one Zone and its Records; they never write, and they
log the session out when done.

## Sources and verification limits

The wire shapes come from INWX's
[API documentation](https://www.inwx.com/en/help/apidoc) (the account,
nameserver, domain and dnssec methods, the data types and the result code table),
the official [Terraform provider](https://github.com/inwx/terraform-provider-inwx)
(a JSON-RPC client: login, TOTP and unlock, records), INWX's
[Python](https://github.com/inwx/python-client) and
[PHP](https://github.com/inwx/php-client) clients, and
[goinwx](https://github.com/nrdcg/goinwx) as lego uses it (an XML-RPC
client, for field names). No answer was captured: the test fixtures are
built from these sources, as `providers/inwx/testdata/README.md` lists. An
OT&E capture (issue #92) is to settle these questions:

1. The code and body of a call made with an expired session; the adapter
   takes 2200–2202 as the session refused, and 2501 ("Authentication error;
   server closing connection") is not among them. The session cap and its
   code, and whether concurrent calls on one session are allowed; the
   Terraform client serializes them, the adapter does not.
2. The 2FA login answer: the documentation and the Python, PHP and lego
   clients read `tfa` from `account.login`, while the Terraform client
   ignores it and takes a 2200 from `account.info` right after login as the
   sign of a locked session. The adapter reads `tfa` (as a string, number
   or bool) only. The refusal of `account.unlock` for a wrong code, and
   whether a code may be reused within its 30-second step (lego waits for
   the next step): a Provider that logs in again within the step of its
   last unlock sends the same code.
3. Whether `account.info` works for a sub-user without the `accounts`
   permission, and whether the Tenant should be `customerId` or
   `accountId`; the adapter takes `customerId`.
4. Whether `nameserver.list` honours `pagelimit: 100`, the JSON type of
   `count` (number or string), whether zone names come back in Unicode for
   IDNs, and whether `nameserver.info` ever pages or truncates a long zone,
   and what its `count` counts under a filter.
5. The record `name` form on read (full name, as assumed, and the apex as
   the zone name or empty), and the JSON type of `id`.
6. TXT quoting and strings longer than 255 bytes; the URI `content` and
   `prio` split; the SRV `content` split; the maximum TTL.
7. Any API rate limit and its code, and whether non-200 statuses ever occur.
8. The `nameserver.create` answer (the JSON type of `roId`), which `ns` set
   it needs (the adapter sends `ns.inwx.de`, `ns2.inwx.de`, `ns3.inwx.eu`),
   whether it adds default Records, and whether it or `nameserver.delete`
   ever answers 1001.
9. The record `name` form on write (the full name and the apex as the zone
   name, as lego sends them), whether `content` takes a trailing dot,
   whether an identical duplicate `createRecord` is refused with 2302, when
   1001 is answered for a Record write, the JSON type of `createRecord`'s
   `id`, and what `nameserver.info` answers for a `recordId` of another
   zone (the adapter takes an empty list or a 2303 as not this Zone's).
10. The `dnssec.info` status vocabulary and field spelling. The
    documentation lists `DELETE_ALL`, `MANUAL` and `UPDATE`
    (`dnssecDomainStatus`); the Terraform provider compares with `AUTO`;
    `NONE` is assumed for an unsigned zone. The adapter reads `UPDATE` and
    `DELETE_ALL` as in progress (Pending). The documentation and the
    Terraform provider spell the field `dnssecStatus`, goinwx (over XML-RPC)
    `dnsSecStatus`; both are read.
11. The shape of `dnssec.listkeys`' answer: the Terraform provider reads
    `resData` as a bare array with string fields, the documentation and
    goinwx as entries under `dnskey` with integer fields; the adapter takes
    both. Whether an entry carries both the DNSKEY and its DS (assumed when
    INWX computed the digest), whether `listkeys` pages, and whether it
    lists INWX's own keys of a zone it signs (if it does not, `ZoneDetails`
    Signing Keys become unsupported).
12. The `dnssec.adddnskey` answer for DS and DNSKEY input, whether a DS
    alone is taken without a `dnskey`, the refusal `reasonCode` for an
    algorithm, digest type or form the registry refuses (none is mapped to
    `ErrUnsupported` yet), and the JSON type `dnssec.deletednskey` wants
    for `key` (the documentation says integer, the Terraform provider sends
    the `listkeys` string; the adapter sends back what `listkeys` gave).
13. Whether automated DNSSEC needs the domain registered at INWX (if it
    does, the switch on a Zone of a domain registered elsewhere becomes
    `ErrUnsupported` without a write), and when `dnssec.enablednssec` and
    `dnssec.disablednssec` answer 1001.
14. When INWX answers 1001 for a DNSSEC key write, and how long the
    registry takes to show it.
