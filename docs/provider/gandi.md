# Gandi

The `gandi` Registry entry uses Gandi's v5 LiveDNS API. Typed construction is
`gandi.New(gandi.Config{Token: "pat_..."}, opts...)`; the Factory field is `token`
(Personal access token, secret). Constructors validate locally without network
calls. API keys using the deprecated `Apikey` authentication scheme are not supported.

Create a personal access token in the organization's sharing settings with
permission to read LiveDNS domains and records, and to update DNS records when
writes are needed. `Account` authenticates by listing LiveDNS domains even when
none are present; an empty list is distinct from denied access. The LiveDNS
collection normally exposes the personal organization. This adapter uses the
API's default organization visibility and does not select other organizations
through `sharing_id` or implement TenantLister. Tenant identity and account-wide
nameservers are not available from this collection and are left empty.

Zones are domains handled by LiveDNS, identified by their normalized domain
name. Hosting State is Unknown: the API's list does not prove that public
Delegation points at LiveDNS. List and exact lookup use the same identity and
state. Domain registration, renewal, transfer, the Delegation's NS records and
Zone lifecycle or settings changes are outside this adapter. SOA serials are
reported when the record collection contains a valid apex SOA. Unknown record
types remain visible.

Writes support A, AAAA, CNAME, MX, TXT, NS, SRV and CAA. URI writes are unsupported
by the documented LiveDNS type list. Names are absolute without a trailing dot;
apex and wildcard names work. Target values are written as absolute DNS targets.
MX and SRV contain their numeric fields in zone-file presentation form; CAA
retains quoted values. Ordinary single-string TXT values are exposed as literal
text; quoted multi-string TXT presentation is preserved. Single-string DNS
escapes are decoded using decimal `\DDD` escapes, and existing wire strings are
retained unchanged when siblings are edited. New and changed TXT values follow
the common literal text contract: quote characters and backslashes are content,
not presentation syntax. A same-value TXT edit or move retains its original
wire presentation, including chunk boundaries and escapes. Unsupported values and TTLs are
rejected. TTLs range from **300 to 2,592,000 seconds**, without automatic TTL.
Gandi applies additional DNS validity rules and service restrictions server-side.

Gandi writes RRsets: every value at a name and type shares one TTL. Individual
record edits use read-modify-write and retain sibling values and unmodeled
metadata. Deterministic content keys identify public Records, so changing their
name, type or value changes their ID; TTL changes do not. Duplicate content is
rejected regardless of TTL. Before records are located by content, not their ID.

Changesets group every affected RRset, including both ends of a move, and validate
all final TTLs before any write. A shared TTL change must explicitly modify every
remaining sibling to the same TTL. Deletions are planned before modifications
and additions. Use `dnsprovider.Apply` for stale-before checking and
original-order change results.

Writes name only the values a Changeset touches, so concurrent Changesets on
one RRset, such as the two DNS-01 values of a certificate for a name and its
wildcard, keep each other's values:

- An existing RRset takes one `PATCH` with `add_rrset_values`, and
  `remove_rrset_values` holding each removed value exactly as stored, which
  keeps TXT chunking and escapes. A modification within one RRset is a single
  `PATCH` carrying both lists. `rrset_ttl` is sent only when the Changeset
  changes the shared TTL.
- A missing RRset is created with `POST`. When another writer created it
  first (409), the values are added with `PATCH` instead.
- Removing the last value empties the RRset with `PATCH`; LiveDNS answers 204
  and deletes it. The adapter never `PUT`s or `DELETE`s a whole RRset.
- A move adds at the destination before it removes at the source.

TTL is a property of the whole RRset and stays last-writer-wins: LiveDNS has
no conditional write.

Each write is read back from the `PATCH` answer, or with a `GET` after a
`POST`. Only the Changeset's own effects are checked: each value it added is
present with the planned TTL, and each value it removed is absent. Other values
are not compared. A miss is an error matching `ErrConflict`, as another write
may have replaced the Changeset's; re-read and retry. Returned Records are as
stored.

LiveDNS documents neither how `PATCH` answers a missing RRset, nor whether
adding a value already present or removing an absent one is an error. The
adapter avoids the first by creating RRsets with `POST`; it returns any 4xx
from `PATCH` as the mapped API error, without falling back to `DELETE`. A live
check with a write-capable token should confirm these assumptions.

There is **no cross-RRset transaction**. RRsets a move joins are written as a
group, and a failure fails every change of the group, saying it may be partly
applied: a failed destination leaves the source as it was, while a failed
source leaves the value at both ends. Independent RRsets can still succeed.
Read-back failures are reported even after a write succeeded. Mutations are
never automatically retried.

The Provider is a registrar adapter (`dnsprovider.CapDSRegistrar`) through the
Domain API's `dnskeys` routes, at the sibling of the LiveDNS endpoint
(`/v5/domain` next to `/v5/livedns`, or `/domain` appended to a base URL
without `/livedns`). Its token needs permission to manage the domain's
technical configuration, which `Account` does not check.

`ListDelegationSigners` lists every signing key Gandi holds at the registry,
ordered by key tag, each with the DS Gandi computed and its DNSKEY when Gandi
returns the public key: flags 257 for a key of type `ksk`, and 256 for any
other, so a key of type `zsk` or none reads too. Gandi takes only key data and
computes the DS itself, so `SetDelegationSigners` sends each key's DNSKEY
algorithm and public key with type `ksk`; a key without a DNSKEY is
`ErrUnsupported` before any call. It always reads the held keys first, and
writes nothing when they already match; otherwise it replaces the whole set
with one `PUT`. `DeleteDelegationSigners` deletes the held keys one by one by id, as the docs do
not say a replace may hold none, so a delete failing partway through leaves
the keys not yet deleted in place. Gandi answers writes with 202 Accepted and
applies them at the registry asynchronously, so a read right after may still
show the old set.

Gandi documents no 404 or 400 on the `dnskeys` routes, so their mapping is an
assumption: a 404 is `ErrNotFound`, taken as a domain not in the Account, and
a 400 to the replace is `ErrUnsupported`, taken as Gandi or the registry
refusing the key's algorithm or form. Either error keeps Gandi's own
description. A domain another organization holds may come back as 403, which
is `ErrUnauthorized`, rather than `ErrNotFound`.

The client respects context cancellation, supplied HTTP client timeouts,
`WithBaseURL` and `WithLogger`. Its default timeout is 30 seconds. The documented
quota is 1,000 requests per minute per IP; adapter instances share an endpoint
limiter, but other processes using that IP also consume the quota. Rate-limit
errors expose Retry-After when present.

Normal tests use local HTTP servers and require no credentials. Optional live
checks are read-only and skip unless `DNSPROVIDER_GANDI_TOKEN` is set.
`DNSPROVIDER_GANDI_BASE_URL` can override the LiveDNS endpoint for a sandbox.
Run them with `go test ./providers/gandi -run TestLiveReadOnly -v`. No default test
writes live DNS.

References checked for this implementation:

- [LiveDNS contracts](https://api.gandi.net/docs/livedns/)
- [Domain API signing keys](https://api.gandi.net/docs/domains/)
- [DNSSEC at Gandi](https://docs.gandi.net/en/domain_names/advanced_users/dnssec.html)
- [Personal access token authentication](https://api.gandi.net/docs/authentication/)
- [API quotas and sharing](https://api.gandi.net/docs/reference/)
