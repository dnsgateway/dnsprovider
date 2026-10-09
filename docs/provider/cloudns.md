# ClouDNS

Import `providers/cloudns`, or select Registry key `cloudns`. Typed `Config`
requires `Password` and exactly one of `AuthID`, `SubAuthID`, or `SubAuthUser`.
The equivalent secret field map uses `password` and exactly one of `auth_id`,
`sub_auth_id`, or `sub_auth_user`; IDs must be unsigned integers. Constructors
validate locally. Obtain API credentials in the ClouDNS HTTP API panel and
allow the caller's source IP and appropriate zone/read/write permissions.
Sub-users only discover their accessible Zones. `Account` verifies both login
and DNS-list permission even when the Account has no Zones, returning empty
Tenant/nameserver information because those endpoints do not identify them.

The adapter uses JSON POST form bodies, keeps credentials out of URLs, and
recognizes failed status envelopes even with HTTP 200. Zone IDs are their
normalized names; listing does not establish hosting activity, so hosting
state is Unknown. Nameservers and SOA serial are omitted when unknown.
Zones and Records exhaust 100-row pages and apply the common filters locally.

Record writes support A, AAAA, CNAME, MX, NS, SRV, TXT and CAA. URI writes are
unsupported by the service; unfamiliar Record types are retained when read
and unrelated Records survive edits. TXT Values are the literal text accepted
by the common Record contract. Structured Values put MX preference and SRV
priority/weight/port before the target, and CAA flags/tag before its quoted
value. Native Record IDs identify individual siblings. ClouDNS only permits
Record reads/writes in master Zones (including supported reverse Zones),
and restricted credentials or plans may further limit operations.

TTL bounds are 60–2,592,000 seconds, with no automatic TTL. Supported values
are discrete: 60, 300, 900, 1800, 3600, 21600, 43200, 86400, 172800, 259200,
604800, 1209600 and 2592000; writes verify the Zone-specific available list.
Unsupported TTLs fail instead of being rounded.

ClouDNS cannot modify Record type in place. A type move creates and reads a
replacement before deleting the original; failure reports that partial state.
Supported location/status metadata and notes are preserved. Moving a noted
Record needs main API credentials because the note endpoint documents only
main-user authentication. A move with unfamiliar metadata fails before writes
instead of silently discarding it. Same-type updates retain server metadata.
`dnsprovider.Apply` supplies stale checks and CRUD execution/result ordering;
changes are not atomic. Mutations are never automatically retried. Clients
share a conservative 10 requests/second pace and 600/minute budget per API
endpoint, across credential identities, within the published per-IP quotas
(20/second, 600/minute, 36,000/hour). Processes sharing an IP must also coordinate
their aggregate usage.

See the official [API guide](https://www.cloudns.net/wiki/article/41/),
[authentication](https://www.cloudns.net/wiki/article/42/),
[Zone listing](https://www.cloudns.net/wiki/article/50/),
[Record listing](https://www.cloudns.net/wiki/article/57/),
[add](https://www.cloudns.net/wiki/article/58/) and
[modify](https://www.cloudns.net/wiki/article/60/) contracts.

## Live tests

Set `DNSPROVIDER_CLOUDNS_PASSWORD` and exactly one of
`DNSPROVIDER_CLOUDNS_AUTH_ID`, `DNSPROVIDER_CLOUDNS_SUB_AUTH_ID`, or
`DNSPROVIDER_CLOUDNS_SUB_AUTH_USER`. `DNSPROVIDER_CLOUDNS_BASE_URL` overrides
the endpoint. Live tests only read.
