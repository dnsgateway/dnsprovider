# OVHcloud

Import `providers/ovhcloud`, or use Registry key `ovhcloud`. Typed `Config`
requires `ApplicationKey`, `ApplicationSecret` and `ConsumerKey`, and takes an
optional `Endpoint`. The equivalent Factory fields are `application_key`,
`application_secret`, `consumer_key` (all secret) and `endpoint` (not secret).
Construction validates locally without contacting the API.

```go
p, err := ovhcloud.New(ovhcloud.Config{
	ApplicationKey:    ak,
	ApplicationSecret: as,
	ConsumerKey:       ck,
	Endpoint:          ovhcloud.EndpointEU, // the default
})
// or
p, err := providers.Registry().New("ovhcloud", map[string]string{
	"application_key": ak, "application_secret": as, "consumer_key": ck,
	"endpoint": "ovh-ca",
})
```

## Endpoints and regional restrictions

| Endpoint | API |
| --- | --- |
| `ovh-eu` (default) | `https://eu.api.ovh.com/1.0` |
| `ovh-ca` | `https://ca.api.ovh.com/1.0` |
| `ovh-us` | `https://api.us.ovhcloud.com/1.0` |

These are the identifiers of the official Go client. Each regional API schema
publishes the DNS Zone service paths this adapter uses, but DNS products are
sold per OVHcloud subsidiary: an account can only manage Zones its region
offers, and availability in every region is not promised. Credentials belong
to one region; use the endpoint where they were created. Unknown identifiers,
including the Kimsufi and So you Start brands and raw URLs, are rejected.
`WithBaseURL` overrides the regional URL, for tests, without changing signing.

All requests, including the clock lookup, use the supplied `WithHTTPClient`,
endpoint and context; caller-owned timeouts are retained. `WithLogger`
receives shared retry diagnostics; credentials never appear in errors or logs.

## Authentication and clock

Create an application and a consumer key with the API console (for example
`https://auth.eu.ovhcloud.com/api/createToken`). Each authenticated request carries
`X-Ovh-Application`, `X-Ovh-Consumer`, `X-Ovh-Timestamp` and
`X-Ovh-Signature`: `$1$` and the SHA-1 of the application secret, consumer
key, method, absolute URL with its encoded query, exact body and timestamp,
joined by `+`. The timestamp is the API's time: on first use the adapter reads
the public `GET /auth/time` once and keeps the clock difference for the
Provider. Concurrent first calls share one lookup. A failed or canceled
lookup sends no authenticated request, and the next call tries again. Every
retry is signed again with a fresh timestamp.

The clock difference is re-read when the API refuses a timestamp
(`QUERY_TIME_OUT`), for example after the local clock drifted or jumped:
the call drops the cached difference, reads `GET /auth/time` again and is
sent once more. The API refuses such a request before running it, so this
single retry is safe even for record creation and refresh; a second refusal
is returned as `ErrUnauthorized`. Concurrent calls refused for the same
cached difference share one new lookup. `INVALID_SIGNATURE` does not
trigger a re-read: the signature covers the timestamp that was sent, so a
mismatch means a wrong secret, URL or body, which a new lookup cannot fix.

## Permissions

Account and DNS access are separate. Grant the consumer key:

| Operation | Access rule | IAM action |
| --- | --- | --- |
| `Account` | `GET /me` | `account:apiovh:me/get` |
| Discovery and reads | `GET /domain/zone`, `GET /domain/zone/*` | `dnsZone:apiovh:get`, `record/get`, `soa/get` |
| Record edits | `POST`, `PUT`, `DELETE /domain/zone/*/record*` | `dnsZone:apiovh:record/create`, `record/edit`, `record/delete` |
| Publication | `POST /domain/zone/*/refresh` | `dnsZone:apiovh:refresh` |

`Account` verifies the credentials with the authenticated `GET /me`; the
public time endpoint never counts as verification. It works without Zones,
and denied access matches `ErrUnauthorized`. The Tenant is the account's NIC
handle with its organization name when set; there are no Account-wide
nameservers.

## Zones

Discovery lists DNS Zone services (`GET /domain/zone`), not registrar
domains, and reads the details of each Zone the filter matches. The list is
an unpaged array; repeated names are an error. The Zone ID is its name.
Nameservers come from the Zone service. The API offers no hosting signal, so
the Hosting State is Unknown; deployment on OVHcloud's servers does not
establish Delegation. Exact lookup agrees with discovery and returns
`ErrNotFound` for an absent Zone without hiding other failures. This adapter
does not register domains, change Delegation, DNSSEC, Zone options or
DynHost, and does not provision Zones.

## Records

Records keep their native numeric IDs. The record listing returns an
unpaged array of IDs, which the adapter expands by reading each Record. A
type filter of a native record type is pushed down as `fieldType`; name
filters are applied locally, as the native `subDomain` filter is exact rather
than a substring. The SOA serial comes from the Zone's SOA.

Names are absolute without trailing dots; apex and wildcard owners round-trip.
Values are zone-file presentation: relative host targets become absolute with
a trailing dot, unquoted TXT text is quoted, and MX/SRV keep their numeric
fields. Supported writes are A, AAAA, CNAME, MX, NS, SRV, TXT and CAA; native
types such as SPF, DKIM, DMARC, TLSA or HTTPS remain readable. The API has no
URI type.

Creates reject a Record with the same type, case-insensitive name and Value,
regardless of TTL, as `ErrConflict`; updates reject collisions with another
Record. Updates and deletions find the Record by its ID (or by content when
the ID is empty) and affect only that Record. The update contract cannot
change a type, so a type move creates the new Record, then deletes the old
one; it returns the new ID. If the deletion fails, the error says the move
was only partly staged and names both Records.

Values of the same type are presented alike on reads and writes, from one
type table: A/AAAA addresses are canonical, CNAME, NS, PTR and DNAME hosts
and the MX/SRV target are absolute with a trailing dot, and TXT/SPF text is
quoted. A Record selected by content (no ID) matches the presentation reads
return.

TTLs use the default range of 30 through 86400 seconds; OVHcloud documents no
bounds and the service may reject values it does not accept. A native TTL of
zero inherits the Zone default (the SOA TTL) and reads as that effective
TTL; an update or a type move that keeps that TTL keeps the inheritance.
There is no automatic TTL.

## Staging and publication

Record writes are staged; a Zone refresh (`POST /domain/zone/{zone}/refresh`)
publishes them. CRUD stages the edit, refreshes and only then returns the
stored Record: the create answer, or a read-back after an update.
`dnsprovider.Apply` rejects stale Changesets before any write or refresh,
orders deletions, modifications and additions, and returns results in
Changeset order. The Batcher stages every change and sends one refresh when
any edit was, or may have been, staged, also when other changes failed; an
empty or all-failed Changeset sends none. After a confirmed refresh the
result's `Serial` is the SOA serial read again; it is zero when that read
fails. When nothing was staged it is the serial read before.

When the refresh fails, every change the API took, or may have taken, fails
with `ErrUnpublished` (wrapping the refresh error): confirmed staged
changes, and, joined to their own errors, an update whose read-back failed,
a type move that was only partly staged and a write whose answer was lost.
Changes the API refused keep their own errors, and the Changeset returns a
whole-operation error. Nothing is rolled back or resubmitted: re-read and
refresh again. A confirmed refresh means the service accepted publication,
not that the change has propagated globally.

A write whose answer was lost or a 5xx, a create answer that cannot be
read, an update whose read-back failed, and a failed refresh (with every
`ErrUnpublished` it marks) are Unconfirmed Writes matching
`dnsprovider.ErrUnconfirmed`. An unconfirmed write is never resubmitted; a
Zone refresh still follows it. A write the API refused with a 4xx answer is
a plain failure: nothing was staged.

## Rate limits and retries

OVHcloud publishes no fixed request quota, so the adapter has no client-side
rate limiter. Reads bound their own concurrency instead: a record listing is
expanded with at most four concurrent per-record reads; every other call is
sequential. GET, PUT and DELETE use shared bounded retries for 429 and 5xx
answers, honoring Retry-After, which the error also carries as
`RetryAfter`; record creation and refresh are never retried for these
answers. Handle `ErrRateLimited`. Errors keep the status, the API's class or
error code, missing permissions and query ID, and map to the common
sentinels.

## Read-only live checks

Set `DNSPROVIDER_OVHCLOUD_APPLICATION_KEY`,
`DNSPROVIDER_OVHCLOUD_APPLICATION_SECRET` and
`DNSPROVIDER_OVHCLOUD_CONSUMER_KEY`, optionally
`DNSPROVIDER_OVHCLOUD_ENDPOINT`, then run:

```sh
go test ./providers/ovhcloud -run '^TestLive$' -v
```

The check skips without credentials and never writes live DNS.
`DNSPROVIDER_OVHCLOUD_BASE_URL` optionally overrides the API prefix.
Ordinary tests use local protocol fixtures and require no external access.

Protocol references: [DNS API schema](https://eu.api.ovh.com/1.0/domain.json),
[first steps and signing](https://github.com/ovh/docs/blob/develop/pages/manage_and_operate/api/first-steps/guide.en-gb.md),
and the [official Go client](https://github.com/ovh/go-ovh/blob/master/ovh/ovh.go)
(BSD 3-Clause, Copyright (c) 2015-2025, OVH SAS; no code copied). The adapter
uses shared HTTP infrastructure without an SDK dependency.
