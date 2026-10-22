# Infomaniak

Import `providers/infomaniak`, or use Registry key `infomaniak`. Typed
`Config` requires `Token` and takes an optional `AccountID`; the equivalent
Factory fields are `token` (secret) and `account_id`, the Tenant field.
Constructors validate locally, without network calls: they reject an empty
token or one holding whitespace, and an `account_id` that is not a positive
integer, and their errors never echo the token. The one optional
capability is `CapDSRegistrar`: no Zone writes, no TenantLister and no
Batcher.

```go
p, err := infomaniak.New(infomaniak.Config{Token: token, AccountID: "12345"})
// or
p, err := providers.Registry().New("infomaniak", map[string]string{"token": token})
```

The adapter uses API v2 at `https://api.infomaniak.com` with Bearer
authentication. `WithBaseURL` replaces that endpoint for every call;
`WithHTTPClient` keeps the caller's timeouts (the default client times out
after 30 seconds); `WithLogger` receives retry diagnostics, never the token.

The adapter reads, creates, updates and deletes Records.
`ApplyChangeset` returns `ErrNotImplemented` without a request. `ZoneDetails`
reads the DNSSEC State; see [Zone details](#zone-details). As a registrar
adapter it reads and replaces a Registration's Signing Keys; see
[Registration Signing Keys](#registration-signing-keys).

## Token and scopes

Create a token in the Infomaniak Manager, under the user profile's
[API tokens](https://manager.infomaniak.com/v3/ng/profile/user/token/list).
A token is valid until revoked by default, and Infomaniak deactivates one
left unused for a year. Give it the scopes of the operations it will run:

| Operation | Endpoint | Scope |
| --- | --- | --- |
| `Account` | `GET /2/domains/domains?per_page=1` | `domain:read` |
| `ListZones` | `GET /2/domains/domains`, with `search` for a filter | `domain:read` |
| `GetZone` | `GET /2/zones/{name}`; on a not-found, or with `account_id`, `GET /2/domains/domains?search={name}` | `dns:read`, and `domain:read` to tell `ErrNotServed` or to scope to the Account |
| `ListRecords` | `GET /2/zones/{name}/records`; on a not-found, `GET /2/domains/domains` | `dns:read`, and `domain:read` to tell `ErrNotServed` |
| `CreateRecord` | `GET /2/zones/{name}/records`, then `POST /2/zones/{name}/records` | `dns:read`, `dns:write` |
| `DeleteRecord` | `DELETE /2/zones/{name}/records/{id}` | `dns:write` |
| `ZoneDetails` | `GET /2/zones/{name}` | `dns:read` |
| `ListDelegationSigners` | `GET /2/domains/domains?search={domain}`, `GET /2/zones/{domain}`, `GET /2/domains/domains/{domain}/dnssec/check` | `domain:read`, `dns:read` |
| `SetDelegationSigners` | as `ListDelegationSigners`, then `POST /2/domains/domains/{domain}/dnssec/enable` | `domain:read`, `dns:read`, `domain:write` |
| `DeleteDelegationSigners` | `GET /2/domains/domains?search={domain}`, `GET /2/zones/{domain}`, `POST /2/domains/domains/{domain}/dnssec/disable` | `domain:read`, `dns:read`, `domain:write` |

`Account` proves the token can read the domain list; it succeeds on an
Account without domains and proves nothing about `dns:read`. A bad token
and a missing scope both match `ErrUnauthorized`: Infomaniak answers
`not_authorized` with 401 for either, as far as is known, and a 403 matches
it too.

## Accounts

A token reaches every Account its user belongs to. `account_id`, when set,
scopes the domain list, and so `Account`, `ListZones`, `GetZone` and the
not-served check, to that Account; it is returned as
`AccountInfo.Tenant.ID`. Without it the Tenant is empty. Infomaniak's zone
calls take no Account, so `GetZone` with `account_id` also reads the
domain list, narrowed by a search for the name, and returns `ErrNotFound`
for a Zone that Account does not register. That leaves out a Zone hosted
for a domain registered elsewhere, as `ListZones` does. The record calls
take no Account either and are not checked: a Zone of another Account the
token reaches is still read and written by name. Infomaniak sets no
account-wide nameservers.

## Zones

Each domain of the domain list is a Zone. Its ID is its lower-case name.
The list is of the Account's domain Registrations, which say nothing of
whether Infomaniak serves the Zone: the Hosting State is always
`HostingUnknown`. `ListZones` reads every page. It pushes
`ZoneFilter.Contains`, in lower case without its trailing dot, down as the
domain list's `search`, which the API schema describes as "Filter domains
by name" and which the adapter takes to match a substring of the name; it
then filters locally, exactly, with the shared case-insensitive rules. The
ZoneSet is a Full View. A Zone
Infomaniak hosts for a domain registered elsewhere is not in that list, as
far as is known, so `ListZones` misses it, while `GetZone` and `ListRecords`
read it by name.

`GetZone` reads `GET /2/zones/{name}` and returns the Zone's nameservers as
Infomaniak answers them, lower case and without a trailing dot. When
Infomaniak has no Zone of that name (404), the adapter reads the domain
list: a domain the Account registers is `ErrNotServed`, which also matches
`ErrNotFound`; any other name is `ErrNotFound`. Other failures are returned
as they are.

Lists ask for page after page (`page`, `per_page=100`) until the answer's
`pages`. An answer for another page than the one asked, a page repeating
the one before, a page before the last that is shorter than its
`items_per_page`, a page without paging fields, or a count disagreeing with
`total` is an error, never a shorter result.

## Zone details

`ZoneDetails` reads `GET /2/zones/{name}` and maps its `dnssec.is_enabled`
to the DNSSEC State: `true` is On, `false` is Off. A failed read is
`PropertyFailed` with its error, which matches the shared sentinels (such as
`ErrUnauthorized` or `ErrNotFound`), and the DNSSEC State stays Unknown,
never Off. `dnsprovider.ZoneDetailsOf` reads the Zone with `GetZone` first,
so it makes two requests to the same endpoint.

HSTS and minimum TLS are `PropertyUnsupported`, and so are Signing Keys when
requested: Infomaniak's API answers no key the Zone is signed with. Read
them from the DNSKEY RRset on the Zone's nameservers. None of these fails
the read.

The DNSSEC State is that of the Zone Infomaniak holds. Whether that Zone is
the one the Delegation names is unknown (see below): a domain with an
Infomaniak Zone whose Delegation names other nameservers is read as
Infomaniak-served, and its State says nothing of the Zone those nameservers
serve.

## Records

`ListRecords` reads every page of `GET /2/zones/{name}/records`. A type
filter Infomaniak lists is pushed down as `filter[types][]`; the type and
name filters are then applied locally, exactly. A Zone Infomaniak does not
serve is `ErrNotServed` or `ErrNotFound`, as for `GetZone`. Infomaniak
reports no SOA serial, so `RecordSet.Serial` is zero.

Records carry Infomaniak's native numeric IDs and absolute names without a
trailing dot: Infomaniak's source `.` is the apex, and `*` a wildcard.
Values are in presentation form:

- CNAME, NS, MX and SRV targets come back with a trailing dot, which
  Infomaniak leaves out.
- MX and SRV put their numbers first, as Infomaniak answers them.
- CAA is `flags tag "value"`, its value quoted when Infomaniak answers it bare.
- TXT is the literal text, as Infomaniak answers it. A target made only of
  quoted strings is read as their concatenation.

Types the module can't edit, such as DS, SSHFP, TLSA, DNAME and SOA, are
listed with their target as Infomaniak answers it.

## Writes

The adapter writes A, AAAA, CNAME, MX, TXT, NS, SRV and CAA Records.
Infomaniak takes no URI Records, and the adapter leaves DS, TLSA, SSHFP,
DNAME and SMIMEA read only. The Traits have no field for write types, so
only this page and `EditableTypes` minus URI say so.

### Creating

`CreateRecord` first reads the Zone's records of the type afresh. A Record
the Zone already holds, by `SameRecord` (type, name and Value; the TTL does
not count), is `ErrConflict` without a write. It then sends
`POST /2/zones/{name}/records` once, with `source`, `type`, `target` and the
TTL, and returns the Record as Infomaniak answers it, with its native ID. A
create is never retried.

- `source` is the name relative to the Zone, `.` for the apex, as the API
  schema and Infomaniak's own certbot plugin write it. Names are sent in
  lower case.
- CNAME, NS, MX and SRV targets are sent without their trailing dot; a
  null MX or SRV target stays `.`.
- TXT is sent as its literal text, unquoted. CAA is sent as
  `flags tag "value"`.

### Deleting

`DeleteRecord` sends `DELETE /2/zones/{name}/records/{id}` with the Record's
native ID. A Record without one, from `ListRecords`, fails without a request.
A not-found on the first attempt is `ErrNotFound`. A DELETE answered with a
5xx is retried within the shared policy, and a retry answered not-found
counts as done.

### Updating and moving

`UpdateRecord` reads every record of the Zone afresh and finds `before` by
its native ID. A `before` the Zone no longer holds is `ErrNotFound`, and an
`after` the Zone already holds under another ID, by `SameRecord`, is
`ErrConflict`; neither sends a write. `before` needs its ID from
`ListRecords`, or the update fails without a request.

- A change of Value or TTL, with the same name and type, is one
  `PUT /2/zones/{name}/records/{id}` with `target` and `ttl`, in the form a
  create sends. It keeps the ID and returns the Record as Infomaniak stored
  it. A PUT answered with a 5xx is retried within the shared policy.
- A move to another name or type creates the new Record, as `CreateRecord`
  sends it, then deletes the old one by its ID, and returns the new Record
  with its new ID. A refused or unconfirmed create leaves the old Record
  untouched and sends no delete. A failed delete after a successful create
  returns the new Record with an error saying both may remain. Nothing is
  undone, as for GoDaddy. A move between CNAME and another type at one name
  is likely refused by the create (`dns_record_mutual_exclusion`, which
  matches `ErrConflict`), as the old Record still stands; delete it, then
  create the new one.

`dnsprovider.Apply` works through the common CRUD fallback: it rechecks
every `before` and returns `ErrStale` without a write when one changed,
then deletes, updates and creates, with one result per change in Changeset
order.

### Refused locally

These fail before any request: a type the adapter does not write, a name
outside the Zone, a Value its type does not take, and a TTL outside 60 to
86400 seconds.

### Refusals and Unconfirmed Writes

A 4xx answer, or an answer of success whose `result` is `error`, is a
refusal: an `APIError` with Infomaniak's code and description, which never
matches `ErrUnconfirmed`. `dns_record_already_exists` and
`dns_record_mutual_exclusion` (a CNAME beside other data, for one) also
match `ErrConflict`.

An Unconfirmed Write matches `ErrUnconfirmed`: Infomaniak may or may not have
applied it. These are a lost answer, a 5xx such as `cannot_create_object`
or `cannot_update_object`,
an answer of success that cannot be decoded, a create or update answered
without a Record the adapter can read, and a `result` of `asynchronous`, or any
result the adapter does not know. Infomaniak's API document marks no DNS
operation asynchronous; the rule is a safeguard. Read the Zone again before
deciding whether to repeat a create.

## Errors and rate limits

Infomaniak's error body, `{"result": "error", "error": {"code",
"description", "errors"}}`, becomes an `APIError` whose messages are the
code and description, then each detail's. An answer of success whose
`result` is `error` is a refusal: an `APIError` with status 0. 401 and 403
match `ErrUnauthorized`, 404 `ErrNotFound` and 429 `ErrRateLimited`, with
the wait from `Retry-After` when present; `too_many_requests` is rate
limiting whatever the status. The token is redacted from every error and log
line.

Infomaniak allows 60 requests a minute per token, and does not raise it. A
limiter shared by every Provider of one endpoint and token allows 60 calls a
minute, keyed by a hash of the token, never the token. Reads are retried
within the shared bounded policy on 429 and 5xx answers.

## Registration Signing Keys

The Traits declare `CapDSRegistrar`: the Delegation Signer methods read and
replace the Signing Keys the registry holds for a Registration whose DNS
Infomaniak does not serve. Writing them needs a token with `domain:write`.
The adapter uses the `/2/domains/domains/{domain}/dnssec/` calls; the older
`/2/domains/{domain}/dnssec/` paths are deprecated.

Each method first resolves the domain:

- A domain not in the Account's domain list is `ErrNotFound`.
- A domain Infomaniak holds a Zone of (`GET /2/zones/{domain}` succeeds) is
  `ErrUnsupported`, without a write: Infomaniak signs its own Zones, and
  its enable call takes keys "only when domain has external nameservers".
  A Zone not found (404) means other nameservers.

**Limitation: an Infomaniak Zone counts as Infomaniak-served.** The spec
asks whether the Registration's nameservers are Infomaniak's, but no call
the adapter can make answers that. The domain object has no nameservers,
and the API has no call that reads a Registration's nameservers, only one
that sets them. `GET /2/zones/{domain}` does answer `nameservers`, but the
API schema calls them only "Nameservers for the zone": whether they are
Infomaniak's assigned nameservers or the Delegation's is unknown. Comparing
them with the Zone's NS records, or with a list of Infomaniak hosts, cannot
decide it either. Infomaniak uses several host sets (`ns11/ns12.infomaniak.ch`,
`ns1/ns2.infomaniak.ch`, `ns31/ns32.infomaniak.com`) and documents none, so
the adapter keeps a rule it can decide: a domain with an Infomaniak Zone is
Infomaniak's. A domain that keeps an Infomaniak Zone but delegates to
other nameservers is therefore `ErrUnsupported` here. To manage its keys
through this adapter, delete that Zone at Infomaniak.

`ListDelegationSigners` reads `dnssec/check`. When `has_dnssec` is false it
returns no keys. DS data is grouped into Signing Keys by key tag and
algorithm, SHA-256 first, the digest in upper case; key data becomes a
key's DNSKEY, its key tag computed from its content. Each entry is read by
the fields it has.

`SetDelegationSigners` returns `ErrNoSigningKeys` for no keys, and checks
every key before any request. A key without a DNSKEY or DS, of an
algorithm DNSSEC does not sign zones with (anything but 5, 7, 8, 10, 13,
14, 15, 16, 17 and 23), or with a DS digest type IANA does not assign, is
`ErrUnsupported`; a malformed key, or a form of another key tag or
algorithm, is an error. It then reads the held set: a held entry and a key
are the same key when they share a DNSKEY or a DS, held or computed from a
DNSKEY (SHA-1, SHA-256 or SHA-384), so an unchanged set in either form
sends no write. Otherwise one `POST dnssec/enable` sends the whole new set
as `{"dnssec_data": [...]}`, presentation-form RDATA strings.

**One form per call.** `dnssec/check` reports a single `dnssec_type`,
`dsdata` or `keydata`, for the whole set, so the adapter never mixes DS and
DNSKEY strings in one enable call. It picks the form as follows:

- every key's DS records, when each key has some (a key's DNSKEY is then
  not sent);
- otherwise every key's DNSKEY, when each has one;
- otherwise, for a set mixing keys given only as DS with keys given only
  as a DNSKEY, DS records throughout: each key's own DS records, and for a
  key given only as a DNSKEY its SHA-256 (digest type 2) DS, computed from
  the DNSKEY and the domain name as RFC 4034 section 5.1.4 describes. The
  digest is sent in upper case.

A key's SHA-1 or SHA-384 DS is never computed for sending. Reading the set
back with `ListDelegationSigners` shows the form Infomaniak holds, which
may be the computed DS rather than the DNSKEY given.

`DeleteDelegationSigners` sends `POST dnssec/disable` with `{}`.

Infomaniak documents no refusal code for an algorithm, digest type or form;
the only documented error is `dnssec_management_failed`, a 500. So an
unsupported key is caught locally, as above, and Infomaniak's own refusals
stay `APIError`s. Writes follow the Unconfirmed Write rules and are sent
once: a lost answer, a 5xx (including `dnssec_management_failed`), an
answer that does not decode or a `result` of `asynchronous` is
`ErrUnconfirmed`; a 4xx, or a `result` of `error` in a 2xx, is a refusal.
Read the keys back with `ListDelegationSigners` before trying again.

## TTL

Infomaniak's API schema bounds a record's TTL from 60 to 86400 seconds, so
the Traits declare that range. There is no automatic TTL.

## Live tests

Optional read-only live tests run with `DNSPROVIDER_INFOMANIAK_TOKEN` set,
and `DNSPROVIDER_INFOMANIAK_ACCOUNT_ID` to scope them to one Account
(`go test ./providers/infomaniak -run '^TestLive$' -v`); they skip without a
token. They read the Account, the Zones, one Zone and its Records; they
never write. `DNSPROVIDER_INFOMANIAK_BASE_URL` selects another endpoint.

## Sources and verification limits

The wire shapes come from Infomaniak's
[OpenAPI document](https://developer.infomaniak.com/openapi.json) and
[getting-started guide](https://developer.infomaniak.com/getting-started),
the [API quick-start FAQ](https://www.infomaniak.com/en/support/faq/2581/quick-start-guide-infomaniak-api)
(rate limit) and
[token FAQ](https://infomaniak.com/en/support/faq/2582/generate-and-manage-infomaniak-api-tokens),
and the clients
[certbot-dns-infomaniak](https://github.com/Infomaniak/certbot-dns-infomaniak)
(Infomaniak's own),
[octodns-infomaniak](https://github.com/M0NsTeRRR/octodns-infomaniak),
[lego](https://github.com/go-acme/lego/tree/master/providers/dns/infomaniak)
and [libdns/infomaniak](https://github.com/libdns/infomaniak), all on API
v2. No answer was captured with a token: the test fixtures are built from
these sources, as `providers/infomaniak/testdata/README.md` lists. These
questions stay open:

- The default and largest `per_page`, and whether a list without `page` is
  ever truncated. The adapter always pages.
- The answer for an Account without domains, and whether a Zone hosted for
  a domain registered elsewhere is in the domain list.
- Whether a missing scope is 401 or 403, and the 429 body and its
  `Retry-After`. Unauthenticated calls show `x-ratelimit-limit: 600`, which
  disagrees with the documented 60 a minute; the adapter keeps 60.
- Whether a TXT longer than 255 bytes, or one holding quotes or
  backslashes, comes back as quoted strings or as literal text.
- Whether a Zone's `nameservers` are Infomaniak's assigned nameservers or the
  Delegation's, and so whether a Zone Infomaniak holds is the one served.
  The adapter takes a Zone Infomaniak holds as Infomaniak-served.
- Whether `dnssec.is_enabled` tracks Infomaniak signing the Zone, the DS at
  the registry, or both.
- Whether an unknown name answers `zone_does_not_exists` or
  `object_not_found`; the adapter takes either.
- Whether Infomaniak refuses an identical duplicate create with
  `dns_record_already_exists`, the descriptions of its write refusals, and
  whether a TXT holding quotes is stored as sent.
- The `PUT` answer and refusals: the adapter takes the stored Record as the
  answer's `data`, as the API schema says, without a capture.
- How to tell a Registration on Infomaniak's nameservers from one on other
  nameservers. The adapter takes an Infomaniak Zone of the domain as the
  sign; `dnssec/check`'s `ksk` may be another.
- Whether the domain list's `search` matches a substring of the name, as
  the adapter assumes, or only a prefix or the whole name. A narrower match
  would make a filtered `ListZones` miss Zones.
- Whether `dnssec/enable` replaces the held set or adds to it (the adapter
  assumes it replaces), and which forms each registry takes: the schema's
  example, `"256 3 2 ABCDEFGH1234"`, reads as a DNSKEY.
- The `dnssec/check` answer for a domain not in the Account, what `ksk`
  holds when empty, and the refusal for a key a registry does not take.
