# Infomaniak API v2 fixtures

These JSON bodies are what the `infomaniak` adapter's fake server serves in
tests.

**They are not captures made with a token.** Every body is built from
Infomaniak's public OpenAPI document and getting-started guide, and from
third-party clients' fixtures; only the 401 body was seen on the wire, from
an unauthenticated request. Where Infomaniak's text is unknown, a
description starts with `SYNTHETIC:`. Code must never match on a
description; it matches on `code` alone.

Replace these files with real captures when someone runs them with a token.

| File | Endpoint | Source |
| --- | --- | --- |
| `domains.json` | `GET /2/domains/domains` | OpenAPI schema `api-domain_domain` (required fields only); `contacts` left empty. The fake adds the paging fields `total`, `page`, `pages` and `items_per_page`, which the OpenAPI `Pagination` schema says are "added when using query parameter `page`". |
| `zone.json` | `GET /2/zones/{zone}` | OpenAPI schema `api_dns_zone` (`id`, `fqdn`, `dnssec`, `nameservers`). The nameservers are an assumed pair, one in upper case with a trailing dot to test normalisation. `dnssec.is_enabled` is `true`; the `false` form the ZoneDetails tests script is built the same way. |
| `zone_unsigned.json` | `GET /2/zones/{zone}` | As `zone.json`, with `dnssec.is_enabled` `false`. |
| `records.json` | `GET /2/zones/{zone}/records` | octodns-infomaniak `tests/fixtures/get_example.test.json` at `968f55c`, which looks like a real capture; addresses changed to RFC 5737/3849. The wildcard, quoted multi-string TXT, null MX and `Www` CNAME rows are hand-added: the quoted TXT form is unverified. |
| `not_authorized.json` | any, HTTP 401 | Captured unauthenticated, 2026-10-22, with a bad token. |
| `zone_does_not_exists.json` | `GET /2/zones/{zone}`, HTTP 404 | Code from the OpenAPI document; description `SYNTHETIC:`. |
| `object_not_found.json` | any, HTTP 404 | lego `fixtures/zone_exists_not.json`. |
| `too_many_requests.json` | any, HTTP 429 | Code from the OpenAPI document (other products); description `SYNTHETIC:`. No DNS operation documents a 429. |
| `validation_failed.json` | `POST /2/zones/{zone}/records`, HTTP 422 | libdns/infomaniak issue #1, a real answer. |
| `record_created.json` | `POST /2/zones/{zone}/records`, HTTP 200 | lego `fixtures/record_create.json` shape (OpenAPI: 200, not 201); ID and values changed. |
| `record_updated.json` | `PUT /2/zones/{zone}/records/{record}`, HTTP 200 | OpenAPI: 200 with the record as `data`; shaped as `record_created.json`, hand-built. |
| `cannot_update_object.json` | `PUT /2/zones/{zone}/records/{record}`, HTTP 500 | Code from the OpenAPI document; description `SYNTHETIC:`. |
| `record_deleted.json` | `DELETE /2/zones/{zone}/records/{record}`, HTTP 200 | lego `fixtures/record_delete.json`. |
| `dns_record_already_exists.json` | `POST /2/zones/{zone}/records`, HTTP 400 | Code from the OpenAPI document; description `SYNTHETIC:`. |
| `dns_record_mutual_exclusion.json` | `POST`/`PUT` record, HTTP 400 | Code from the OpenAPI document; description `SYNTHETIC:`. |
| `invalid_dns_record.json` | `POST`/`PUT` record, HTTP 400 | Code from the OpenAPI document; description `SYNTHETIC:`. Also served with HTTP 200, as an error result in a success, which no source shows. |
| `cannot_create_object.json` | `POST /2/zones/{zone}/records`, HTTP 500 | Code from the OpenAPI document; description `SYNTHETIC:`. |
| `asynchronous.json` | any write, HTTP 202 | OpenAPI `AsyncResponse`, hand-built: no DNS operation is asynchronous in the OpenAPI document. |
| `domains_example_net.json` | `GET /2/domains/domains` | As `domains.json`, holding `example.net`, the owner of RFC 6605's example key. |
| `dnssec_check_dsdata.json` | `GET /2/domains/domains/{domain}/dnssec/check` | OpenAPI schema `api-domain_domain_dnssec_record`; string fields. DS of RFC 6605 section 6.1 (digest in lower case to test the upper-casing) and RFC 4034 section 5.4, plus a made-up SHA-1 DS. `ksk` with empty strings is a guess. |
| `dnssec_check_rfc6605_ds.json` | same | As above, the RFC 6605 SHA-256 DS alone. |
| `dnssec_check_keydata.json` | same | Same schema, key data: RFC 6605 section 6.1's DNSKEY, of key tag 55648. |
| `dnssec_check_unsigned.json` | same | Same schema, `has_dnssec` false. |
| `dnssec_done.json` | `POST .../dnssec/enable` and `.../disable` | OpenAPI: `data` `true`. Served for the Signing Key writes and for `UpdateZone`'s empty enable and disable alike. |
| `dnssec_management_failed.json` | DNSSEC calls, HTTP 500 | Code from the OpenAPI document; description `SYNTHETIC:`. |

Domains are `example.ch`, `external-dns.com` (registered, without an
Infomaniak Zone) and `example.org`. The open wire questions are listed in
`docs/provider/infomaniak.md`, "Sources and verification limits".
