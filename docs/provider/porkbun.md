# Porkbun

Import `providers/porkbun`, or select Registry key `porkbun`. Typed `Config`
requires `Key` and `Secret`; the equivalent secret field map uses `key` and
`secret`. Constructors validate locally. Enable API access for each domain
(or opt in all domains), grant the key `read` and `dns` scopes or `full`,
plus `domains` for DS writes, and allow the caller's source IP and intended domains in any key restrictions.
`Account` uses authenticated `/ping`, requires confirmed valid credentials
and these scopes even for an empty Account, and returns the account username
as Tenant Name when supplied. It does not invent a Tenant ID or nameservers.

The adapter uses API v3 at `https://api.porkbun.com/api/json/v3`, header
credentials, GET reads, and POST mutations. Discovery exhausts the documented
1000-domain pages and checks DNS access to each matching domain, omitting
API-disabled or domain-restricted domains. Other permission and API failures
remain errors. Zone IDs are normalized domain names. Registration status does
not establish DNS Hosting State, so it is Unknown; nameservers and SOA serial
are omitted. DNS retrieval is unpaginated and excludes SOA and default Porkbun
NS records. Cloudflare-connected domains still expose the Porkbun DNS copy;
editing this copy does not change what Cloudflare serves.

Writes support A, AAAA, CNAME, MX, NS, SRV, TXT and CAA. URI writes are
unsupported; unfamiliar types remain visible in reads. Names are absolute
without trailing dots; writes convert apex and wildcard names to Porkbun's
relative form. MX preference and SRV priority precede the remaining content.
TXT Values are literal text under the common Record contract, and CAA Values
retain flags, tag and quoted content. Native IDs identify individual Records.
Per-ID edits support name/type moves and omit unmodeled fields, retaining
server metadata and siblings; `porkbun.ExtraNotes` exposes optional notes.
A write sends notes only when the Record carries that extra: an update
without it leaves the stored notes as they are, and an empty value clears
them, as Porkbun documents for its edit endpoints.
Creates and updates read the stored Record back. `dnsprovider.Apply` provides
stale checking and ordered CRUD with per-change results; changes are not atomic.
Mutations are never automatically retried, including after an uncertain reply.

The Provider is a registrar adapter (`dnsprovider.CapDSRegistrar`); its DS
writes need the `domains` scope (or `full`), which `Account` does not check. `ListDelegationSigners` reads the registry's DS records with
`getDnssecRecords`, one Signing Key per key tag, without the DNSKEY, which
Porkbun does not return. `SetDelegationSigners` sends each key's SHA-256 DS
(its first DS when it has none), the only form Porkbun takes: a key without
a DS, or two keys of one key tag, is `ErrUnsupported` before any call, as
the module does not compute a DS from a DNSKEY. It reads the held set and
writes only the difference, by key tag: new key tags are added first, so a
rollover keeps a DS in place, then changed and gone key tags are deleted.
`deleteDnssecRecord` takes a key tag, but most registries delete every DS
matching the key data, so the set is read again and each wanted DS it lacks
is added back; a deleted DS the registry still holds is an error. The writes
are not atomic, and a failure stops them, leaving those before it written.
A domain not in the Account (`DOMAIN_NOT_FOUND`, `DOMAIN_NOT_REGISTERED`, or
an `INVALID_DOMAIN` that names the account) is `ErrNotFound` on every
endpoint; `DNSSEC_ALGORITHM_DEPRECATED`, the registry's policy refusing the
algorithm or digest type, is `ErrUnsupported`. `DNSSEC_CREATE_FAILED`, the
registry refusing the DS for any reason, stays a plain `APIError`. Algorithm 8 or 13 with
digest type 2 is accepted by every registry Porkbun serves.

The adapter accepts TTLs from 600 to 4,294,967,295 seconds, without an automatic
TTL sentinel. The documented minimum is account-dependent (typically 600),
and no universal maximum is published: this conservative minimum and Go's
uint32 ceiling are local bounds, while the API enforces each account's actual
limits. Unsupported TTLs are reported, and writes return the stored TTL.
A shared per-endpoint/key limiter paces calls at ten per second within the
published twenty-calls-per-two-seconds generic budget; rate-limit errors
retain `Retry-After`. Processes using the same key must coordinate total usage.

Protocol fixtures follow the official [API v3.62 reference](https://porkbun.com/api/json/v3/spec)
and [setup guide](https://kb.porkbun.com/article/307-getting-started-porkbun-api).
Optional read-only live checks require `DNSPROVIDER_PORKBUN_KEY` and
`DNSPROVIDER_PORKBUN_SECRET`; `DNSPROVIDER_PORKBUN_BASE_URL` overrides the endpoint.
