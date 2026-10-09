# DNSimple

Import `providers/dnsimple`, or use Registry key `dnsimple`. Typed `Config`
requires `Token` and `AccountID`; the equivalent Factory fields are `token`
(secret) and `account_id` (nonsecret). Account ID must be a canonical positive
unsigned decimal number. Constructors validate locally, without network calls.
Find the Account ID in the DNSimple application URL `/a/<id>/domains`.

The adapter uses API v2 at `https://api.dnsimple.com/v2` with Bearer tokens.
Account tokens are recommended; user tokens are also supported. Grant the
configured Account Zone-read and Record-write permissions. `Account` verifies
`/whoami`, matches the configured ID in `/accounts`, and reads the Account's
Zones to establish DNS access even when the list is empty. It returns the
selected Account name (or email), never a different Account or user identity.
There is no interactive Tenant selection or TenantLister. Scoped tokens expose
only accessible Zones, and API permission failures remain errors.

All DNS requests include exactly the configured Account ID. Zone discovery and
Record reads follow every documented page and detect repeated pages. Zone IDs
are native numerical IDs represented as strings; Record endpoints use Zone
names as required by DNSimple. Active DNS service is reported as HostingActive
from the Zone's `active` flag; inactive or missing flags are HostingUnknown.
This flag describes provider service, not public Delegation. Nameservers are
omitted; an apex SOA's serial is returned when it can be parsed reliably.

Writes support A, AAAA, CNAME, MX, NS, SRV, TXT and CAA. URI is absent from the
DNSimple Record API's supported types and is rejected locally. CNAME at the
apex is unsupported; DNSimple's separate ALIAS type remains visible in reads.
Unfamiliar types and system Records remain visible with native IDs. Names are
absolute without trailing dots, with apex and wildcard conversion on writes.
MX preference and SRV priority are translated to DNSimple's separate `priority`
field. TXT Values are literal text under the common Record contract; CAA Values
retain flags, tag and quoted data.

`ExtraRegions` exposes the existing placement as a JSON array. `ExtraSystemRecord`
and `ExtraParentID` expose service-management flags. These Extras are read-only:
ordinary edits PATCH only name, content, TTL and priority, retaining regional
placement and other server metadata. Writes explicitly select the `dnsimple`
integrated zone, so they do not propagate edits to separately integrated providers.
System and service-managed child Records cannot be edited or deleted by this
adapter. Service, subscription, secondary-zone and plan restrictions remain
errors, including regional features unavailable to the current plan.

Type changes cannot PATCH `type`. The adapter checks collisions, creates a new
Record with supported regional metadata, then deletes the original. It returns
the new native ID. If deletion fails, the error identifies the replacement and
original IDs, which may both remain. A CNAME cannot coexist with other data at
the same owner: these type moves check siblings, delete first, then create.
If creation fails, the error explicitly reports that the original was deleted;
re-read the Zone before deciding how to recover. A type replacement transfers
supported regional metadata; server-generated metadata and the old native ID
cannot transfer. There is no transaction or automatic rollback. A malformed or
lost mutation response reports an unconfirmed outcome; re-read before retrying.

Duplicates conflict regardless of TTL. Updates and deletes select exactly the
native Record ID; siblings are retained. Successful creates and updates return
the API's stored Record. `dnsprovider.Apply` uses its existing stale-before
check, ordered CRUD fallback and per-change results; the adapter is not a Batcher.
Changesets are not atomic. POST and PATCH mutations are never automatically
retried. The shared transport bounds GET/DELETE retries, including its existing
handling of a retried deletion whose earlier attempt may have succeeded.

The API schema permits TTLs from zero, with no published maximum. Local bounds
are 0 through 4,294,967,295 (the public uint32 ceiling), with the API enforcing
any narrower plan or traffic restrictions. The web editor's documented minimum
is 60 seconds. There is no automatic TTL sentinel: TTL 1 is an ordinary second.
A shared per-endpoint/token sliding limiter conservatively allows 40 calls per
minute within the published 2400 authenticated requests per hour. Other
processes using the token must coordinate total usage. Rate-limit errors retain
`Retry-After`, or the `X-RateLimit-Reset` wait when no retry header is supplied.
Authentication, permission and subscription restrictions match ErrUnauthorized;
missing resources match ErrNotFound (the service may also conceal inaccessible
resources with 404), conflicts match ErrConflict, and throttling matches
ErrRateLimited. Validation restrictions keep their HTTP status and service
messages in APIError.

The protocol follows the official [identity API](https://developer.dnsimple.com/v2/identity/),
[accounts API](https://developer.dnsimple.com/v2/accounts/),
[Zone API](https://developer.dnsimple.com/v2/zones/),
[Record API](https://developer.dnsimple.com/v2/zones/records/),
[OpenAPI schema](https://developer.dnsimple.com/v2/openapi.yml), and
[pagination and quotas](https://developer.dnsimple.com/v2/).
Optional read-only live tests require `DNSPROVIDER_DNSIMPLE_TOKEN` and
`DNSPROVIDER_DNSIMPLE_ACCOUNT_ID`; `DNSPROVIDER_DNSIMPLE_BASE_URL` can select
`https://api.sandbox.dnsimple.com/v2`. Default tests never write live DNS.
