# Porkbun

Import `providers/porkbun`, or select Registry key `porkbun`. Typed `Config`
requires `Key` and `Secret`; the equivalent secret field map uses `key` and
`secret`. Constructors validate locally. Enable API access for each domain
(or opt in all domains), grant the key `read` and `dns` scopes or `full`, and
allow the caller's source IP and intended domains in any key restrictions.
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
Creates and updates read the stored Record back. `dnsprovider.Apply` provides
stale checking and ordered CRUD with per-change results; changes are not atomic.
Mutations are never automatically retried, including after an uncertain reply.

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
