# GoDaddy

Import `providers/godaddy`, or select Registry key `godaddy`.

The adapter uses GoDaddy's [Domains v3 API](https://developer.godaddy.com/docs/api-users/domains)
at `https://api.godaddy.com/v3/domains`. `WithBaseURL` replaces the host,
such as GoDaddy OTE.

## Credentials

`Config.Token`, Factory field `token` (secret), is a personal access token
with the `domains.domain:read` scope, and `domains.dns:update` for writes. The
v3 API takes no API key and secret: GoDaddy's `sso-key` scheme does not work
with it.

Record IDs are GoDaddy's `recordId`, stable across updates.

## Zones

GoDaddy lists every domain it registers. Hosting State is Active while
Delegation names one of its nameservers, Moved once it names none, and Unknown
when GoDaddy does not say. GoDaddy keeps no zone file for a domain it
registers while Delegation names other nameservers: reading its Records is
`ErrNotServed` while the Account holds the domain, and `ErrNotFound` once it
does not.

The adapter never cancels a registration or changes nameservers.

## Records and concurrent writes

Each record has a server-assigned `recordId`, which is the Record's ID. TTLs
range from 600 to 86400 seconds and are set per record; the adapter keeps
every value of an RRset at one TTL, and a shared TTL change must modify
every remaining sibling.

Writes name only the records a Changeset touches, so concurrent Changesets on
one RRset, such as the two DNS-01 values of a certificate for a name and its
wildcard, keep each other's values:

- An addition is a `POST` of the one record. A `POST` is never repeated:
  GoDaddy warns that replaying one after a lost answer can add a duplicate.
- A removal is a `DELETE` by `recordId`. A record another writer deleted first
  (404) is gone as planned.
- A modification adds the new record before it deletes the old one. A move
  that fails partway is reported as possibly partly applied; it is not undone.
- A shared TTL change is a `PUT` of each kept record with the new TTL. TTL
  stays last-writer-wins: the API has no conditional write.

After writing, the adapter reads the touched types back and checks only the
Changeset's own effects: each record it added is present with the planned
TTL, and each it removed is absent. Other records are ignored. A miss is an
error matching both `ErrConflict` and `ErrUnconfirmed`; re-read and retry.
A write answered 5xx, or with its answer lost, or whose read-back fails is an
Unconfirmed Write matching `ErrUnconfirmed`; re-read before retrying. A 4xx
answer is not: GoDaddy refused the write. Host name targets compare ignoring
case and a trailing dot.

GoDaddy's documentation leaves open, and the adapter assumes:

1. A `POST` of a record the RRset already holds answers 409, which is
   `ErrConflict`.
2. A CAA record's `data` is its value alone, with the flag and tag in their
   own fields.
3. v3 lists SRV records with the service and protocol in their own fields and
   the host part as the name, as v1 did.
4. Values of one RRset holding different TTLs: the adapter refuses to leave an
   RRset with mixed TTLs.

A live check with a write-capable token should confirm them.

## Live tests

Set `DNSPROVIDER_GODADDY_TOKEN`. `DNSPROVIDER_GODADDY_BASE_URL` overrides the
endpoint, such as GoDaddy OTE. Live tests only read.
