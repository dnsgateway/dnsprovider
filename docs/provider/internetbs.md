# Internet.bs

Import `github.com/dnsgateway/dnsprovider/providers/internetbs`, or use Registry
key `internetbs`. Typed `Config` requires `Key` and `Password`; both equivalent
Factory fields, `key` and `password`, are labelled secrets. Blank credentials
and unknown Factory fields fail locally without echoing their values.
Construction makes no network requests.

```go
p, err := internetbs.New(internetbs.Config{
    Key: apiKey, Password: apiPassword,
}, dnsprovider.WithHTTPClient(client))
```

```go
p, err := providers.Registry().New("internetbs", map[string]string{
    "key": apiKey, "password": apiPassword,
})
```

## Setup and account access

Obtain your [API key](https://faq.internetbs.net/hc/en-gb/articles/4517108121629-Where-can-I-get-the-API-key),
[allowlist the caller's source IP](https://faq.internetbs.net/hc/en-gb/articles/4517045215133-How-to-whitelist-your-server-IP-address-for-API-access),
and configure a [dedicated API password](https://faq.internetbs.net/hc/en-gb/articles/4517044286365-How-to-set-dedicated-password-for-your-API).
Keep the API password separate from application identity and protect both
credentials. The adapter does not discover or configure your source IP.

`Account` verifies access with `Account/Balance/Get`, including when the Account
has no domains or an empty balance list. Balances are not exposed, and this API
does not supply usable Tenant identity or common nameservers. Account verification
does not prove permission to manage a particular domain's DNS. IP restrictions
and DNS access permissions must permit the operations you intend to perform.

The default endpoint is `https://api.internet.bs`. Every command uses a
form-encoded POST with `ResponseFormat=json`, `ApiKey`, and `Password` in the
body. `WithBaseURL`, `WithHTTPClient`, `WithLogger`, and context cancellation
are honored. Without a supplied HTTP client, requests have the shared
30-second timeout; supplied clients keep their own timeout settings.
Credentials, encoded forms, and server echoes are redacted from diagnostics,
including local validation errors.

## Discovery and records

`Domain/List` returns the complete unpaginated inventory. The adapter requests
domain details and nameservers, validates domain names and reported counts, and applies
case-insensitive Zone filtering locally. Zone IDs are normalized names; exact
lookup ignores case and a trailing dot. Local absence from a complete inventory
is `ErrNotFound`; API failures are returned rather than treated as absence.

The inventory lists registered or tracked domains; it does not certify that
Internet.bs serves their DNS or that each domain permits DNS commands. Record
operations require `Domain/DnsRecord/*` access for the selected domain. A domain
held by the Account or delegated elsewhere can therefore still fail DNS access.
Hosting State remains Unknown because registration status does not establish
active hosting. Only returned nameservers are supplied, normalized without
trailing dots; no nameservers are invented. Reads and writes affect the
Internet.bs DNS copy, and do not change Delegation or registration.

Record lists are complete and locally filtered by type and absolute owner-name
substring, ignoring case. Unsupported type filters return an empty result.
Records use absolute names without trailing dots, uppercase types, stored TTL
seconds, and the shared Value representation. MX Values include preference
before the host, while the API carries priority separately. TXT Values contain
literal text, preserving spaces, quotes, and backslashes. Unknown SOA serial is
zero. Unfamiliar readable types remain visible; their visibility does not grant
write support. Malformed owners and address/target Values fail the entire list
rather than producing unsafe mutation selectors; empty stored TXT, valid null MX, and stored TTLs
outside the write defaults remain readable. API metadata using the reserved
`internetbs:wire_value` key is rejected to protect selector identity.

## Writes, selection, and failures

Writes support **A, AAAA, CNAME, MX, TXT, and NS**. SRV, CAA, URI, DYNAMIC,
forwarding records, and registry-side DNS changes through Record operations are excluded. Unsupported
types, out-of-Zone owner names, invalid Values, and unrepresentable TTLs fail
before mutation. Record operations reject empty or invalid Zone names locally,
before sending any request. There is no automatic TTL sentinel. The shared local TTL range
is 30–86400 seconds; this is a library validation default, not a verified
Internet.bs service bound. No provider-specific minimum or maximum is invented.
Every mutation passes an explicit requested TTL; reads preserve stored TTLs.

The API provides no native Record ID. IDs are derived from selectable Record
content and can change after an edit. **Retain the complete Record returned by
reads or successful writes as Before**, including ID, Value, TTL, and Extras.
`internetbs.ExtraWireValue` (`"internetbs:wire_value"`) retains the raw API
Value when target normalization changes it, so later selectors preserve the
original spelling and trailing dot. Keep that Extra on Before Records.
Mutation selectors include the old owner, type, Value, TTL, and MX priority;
removal never selects broadly by owner and type alone. Missing and
indistinguishable selections fail rather than guessing. Siblings, unfamiliar
Records, and unrelated metadata remain untouched. Native updates retain existing
metadata and reject metadata changes. Owner/type replacement is refused before
mutation when unknown metadata cannot be reproduced by Add.

Creates reject a duplicate according to `SameRecord`, including when TTL differs.
Updates locate the source and reject a destination collision before mutation.
Value/TTL edits use native Update with complete current selectors; owner/type
moves require a checked replacement: remove exactly the source, add its
replacement, then read back. A failed removal stops the operation. A definitively
rejected addition triggers an attempt to restore the original; failed restoration
is also reported. After an uncertain outcome, state is read before any
compensation. If state cannot be established, the error reports uncertainty.
Replacement is not atomic and restoration is not guaranteed.

Acknowledged creates and updates are read back because API mutation responses
do not contain the complete stored Record. Returned Records use current
identities and stored data. A failed or ambiguous readback reports that the
write was acknowledged; it never repeats the mutation just to obtain a result.
Refresh the Zone after acknowledged or uncertain failures before attempting
further edits.

`dnsprovider.Apply` provides its common stale-Before check, executes deletions,
modifications, then additions, and returns per-change results in original input
order. Stale modifications/deletions cause no writes. Direct CRUD has no lock or
stronger concurrency guarantee, and Changesets are not transactions. This
adapter implements no Batcher, TenantLister, Zone creation/deletion/settings,
or automatic TTL capability.

## Registration Signing Keys

The Provider implements `dnsprovider.DSRegistrar`. `DelegationSigners` reads
`Domain/Info`, grouping DS records by key tag and algorithm with any returned
DNSKEY, and ordering SHA-256 DS records first. A DNSKEY's tag is computed from
its content. Missing or malformed data fails explicitly; `disabled` means no keys.

`SetDelegationSigners` validates every key before requests, reads the held set,
and skips an unchanged set. It submits all available DS and DNSKEY forms in
one `Domain/Update`, or an explicitly empty `dnssec` to clear the set, following
the [first-party module](https://github.com/centralnicgroup-opensource/rtldev-middleware-whmcs/blob/edee17784da8b39b3d99f7afff9056e74ac96042/whmcs-ibs-registrar-latest.zip).
The wire TTL is 86400 because Signing Keys carry no TTL. The update changes
only the Delegation's Signing Keys. `SUCCESS` and `PENDING` acknowledge it;
neither guarantees propagation. Writes are never retried.

A key without either form is `ErrUnsupported`. Distinct DNSKEYs sharing a tag
and algorithm are refused because their DS cannot be associated unambiguously.
Permission failures remain `ErrUnauthorized` unless an authenticated inventory
proves the Registration absent, when they become `ErrNotFound`. Unknown registry
refusals retain `APIError`; no undocumented refusal codes are guessed.

See [protocol research](internetbs-dnssec-research.md) for sources and verification limits.

## Errors and quotas

Use `errors.Is` with shared sentinels and `errors.As` with `*dnsprovider.APIError`.
Invalid credentials (verified API code 107002) match `ErrUnauthorized`; permission
failures (100005), including unowned domains, remain access failures rather than
being guessed as missing DNS. Provider validation failures remain distinguishable
from authentication, conflict, and quota errors. HTTP success can still contain
an API failure; malformed or incomplete success responses fail explicitly.
Context cancellation and transport causes remain available through error wrapping.

All commands are POST and **never automatically retried**, including reads,
429, 5xx, and transport failures. This avoids replaying uncertain mutations.
Rate-limit errors expose `ErrRateLimited` and server `RetryAfter` when supplied.
A shared per-credential, per-endpoint limiter conservatively paces 60 calls per
minute. Separate processes still need to coordinate usage.

Internet.bs [publishes portfolio-dependent quotas](https://faq.internetbs.net/hc/en-gb/articles/36259311920925-What-Is-the-API-Rate-Limit)
across minute, hour, day, week, and month windows: respectively `60+N`, `500+N`,
`1000+2N`, `2000+2.5N`, and `3000+3N`, where N excludes domains in pending
transfer/trade. The minute limiter does not enforce those wider limits;
in-body quota failures are surfaced to callers.

Protocol fixtures use the [official API reference](https://internetbs.net/internet-bs-api.pdf)
and verified read-only sandbox response shapes. Default tests use local fixtures
and require no credentials. Optional live checks only read and require both
`DNSPROVIDER_INTERNETBS_KEY` and `DNSPROVIDER_INTERNETBS_PASSWORD`;
`DNSPROVIDER_INTERNETBS_BASE_URL` optionally selects another endpoint.
Public sandbox credentials are never used implicitly.
