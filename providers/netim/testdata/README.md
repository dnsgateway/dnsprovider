# Netim REST 3.0 fixtures

These JSON bodies are what the `netim` adapter's fake server serves in tests.

**They are not OT&E captures.** Nobody working on this module holds Netim OT&E reseller credentials. The bodies come from two places:

- Netim's public REST 3.0 reference.
- Netim's official REST clients:
  - [netim-apirest-client-for-python](https://github.com/netim-com/netim-apirest-client-for-python) (`APIRest.py` at commit `4ab7cc6`)
  - [netim-apirest-client-for-java](https://github.com/netim-com/netim-apirest-client-for-java) (commit `1fc55e6`)

Both clients target REST **1.0** (`conf.xml`: `http://oterest.netim.com/1.0/`). They confirm the session and error handling and the JSON field names that 1.0 and 3.0 share. They do not show 3.0-only endpoints.

Every value is fake:

- domains are `example.com`, `example.net` and `example.org`
- addresses are RFC 5737 / RFC 3849
- contact IDs are `FAKE000n`
- the session token is `00000000000000000000000000fake01`
- DNSSEC keys are made-up bytes

Where Netim's text is unknown, a message starts with `SYNTHETIC:`. Code must never match on that text.

Replace these files with real captures when someone gets OT&E access. Netim calls REST 3.0 beta.

Doc URLs below are relative to `https://support.netim.com/en/docs/api-rest-3-0/`. The page names are shortened.

## Base URLs

| Environment | URL | Source |
| --- | --- | --- |
| Production | `https://rest.netim.com/3.0/` | `get-started` |
| OT&E | `http://oterest.netim.com/3.0/` (the docs print `http`, not `https`) | `get-started`; the clients' `conf.xml` has the 1.0 equivalent `http://oterest.netim.com/1.0/` (Python commit "Fix URL for OTE") |

The OT&E web UI is `https://oteweb.netim.com/direct/`. OT&E domains must use `ns1-ote.netim.net` and `ns2-ote.netim.net` for any DNS feature. Source: [testing environment](https://support.netim.com/en/docs/resellers/apis/testing-environment).

Every 3.0 path ends in `/`, except `operation/{id}`. Every call sends `Content-Type: application/json`.

## Endpoints the adapter uses

All calls after the session is open send `Authorization: Bearer <access_token>`. Several doc examples misspell the header as `Autorization`; the correct spelling is `Authorization`.

| Call | Method and path | Request body | Answer fixture |
| --- | --- | --- | --- |
| Open session | `POST /session/` with `Authorization: Basic base64(id:secret)` and `Accept-Language: EN` | `{"preferences":{"lang":"EN","sync":1,"notif":0}}` (optional) | `session_open.json` |
| Session info | `GET /session/` | none | `session_info.json` (StructSessionInfo) |
| Close session | `DELETE /session/` (Bearer, as in every example and both clients; the header table wrongly says Basic) | none | `session_close.json` |
| Domain list | `POST /domains/` | `{"filters":{...}}` (optional; send none or `{}` for all) | `domains_list.json` (array of StructDomainList) |
| Domain info | `GET /domain/{domain}/info/` | none | `domain_info.json`, `domain_info_external_dns.json` |
| Zone info | `GET /domain/{domain}/zone/info/` | none | `zone_info.json` |
| Create record | `POST /domain/{domain}/zone/` | `{"subdomain","type","value","options":{StructZoneParam + "ttlUnit"}}` | `zone_create_done.json`, `zone_create_srv_done.json`, `zone_create_failed.json` |
| Update record | `PATCH /domain/{domain}/zone/update/` | `{"subdomain","type","value" (current),"newValue","options"}` | `zone_update_done.json` |
| Delete record | `DELETE /domain/{domain}/zone/` | `{"subdomain","type","value"}` | `zone_delete_done.json` |
| List DS | `GET /domain/{domain}/ds-record/` | none | `ds_list_ds.json`, `ds_list_dnskey.json`, `ds_list_empty.json` |
| Create DS | `POST /domain/{domain}/ds-record/` | `{"data":[dsData...]}` or `{"data":[keyData...]}` | `ds_create_done.json` |
| Delete some DS | `DELETE /domain/{domain}/ds-record/` | `{"data":[dsData or keyData...]}` | `ds_delete_done.json` |
| Delete all DS | `DELETE /domain/{domain}/ds-record/` | **no body** | `ds_delete_all_done.json` |

Shapes used in the table:

- **dsData:** `{"key": <tag>, "type": <digest type>, "algo": <alg>, "digest": "<hex>"}`
- **keyData:** `{"flags", "protocol", "algo", "pubKey": "<base64>"}`

Record example:

```json
{"subdomain":"www","type":"A","value":"192.168.0.1",
 "options":{"service":null,"protocol":null,"ttl":365,"ttlUnit":"S","priority":null,"weight":null,"port":null}}
```

The adapter sends `ttlUnit: "S"` always. TTL units are `S`, `M`, `H`, `D` and `W` (Python `APIRest.py:1243`, `domainZoneInitSoa`).

Delete some and delete all share one method and one path. Only the body tells them apart. The adapter must never send delete-some with an empty `data` array: Netim may treat that as delete all.

## Fixture sources

| File | Source |
| --- | --- |
| `session_open.json` | `sessions-management/open-session` (200 body `access_token`); Python `APIRest.call` l.124-152 reads `result['access_token']` |
| `session_info.json` | `api-objects/structsessioninfo` (`idSession`, `timeLogin`, `timeLastActivity`, `lang`, `sync`). The 1.0 Java client names the ID `IDSession`; do not depend on that field |
| `session_close.json` | `sessions-management/close-session` says 200 returns nothing. Python l.137-140 JSON-decodes every answer, so the body is assumed to be JSON. The adapter must ignore it |
| `session_open_limit.json` | **Synthetic.** [sessions management](https://support.netim.com/en/docs/resellers/manage-my-reseller-account/sessions-management) only says that new logins are refused once 10 sessions are open |
| `domains_list.json` | `domain-names/get-domains-list` (POST with `filters`, body is "an array of StructDomainList") and `api-objects/structdomainlist` (`domain`, `dateCreate`, `dateExpiration`) |
| `domain_info.json`, `domain_info_external_dns.json` | `api-objects/structdomaininfo`. `ns` is a list of strings, as Java 1.0 `StructDomainInfo.ns` is `List<String>`. `HasDNS4Service` and `IsSigned` are the integers 0 or 1. `DNSSEC` (present only when `IsSigned = 1`) is left out because its keys are not documented |
| `zone_info.json` | `domain-names/domain-services/get-dns-zone-infos`. It holds zone `ttl`/`ttlUnit` and `records[]` of `{subdomain,type,value,options}`, where options are StructZoneParam plus `customTtl` (bool). `api-objects/structzoneparam` gives the per-type option rules. It holds A, AAAA, CNAME, MX, TXT, NS and SRV, two custom TTLs (300 S and 1 D) and one TLSA as a readable-only type |
| `zone_*_done.json`, `zone_create_failed.json`, `operation_*.json`, `ds_*_done.json` | `api-objects/structoperationresponse` (`ID_OPE` int, `STATUS`, `MESSAGE`, `TYPE`, `DATE`, `DATA`; statuses `Done`, `Pending`, `Failed`, `Cancelled`). The `DATE` format `yyyy-MM-dd HH:mm:ss` comes from Java `StructOperationResponse.java`. The `TYPE` values and the empty `MESSAGE` on success are placeholders |
| `ds_list_ds.json`, `ds_list_dnskey.json`, `ds_list_empty.json` | `domain-names/ds-record-list` (body "an array of dsData or keyData"). Entry fields come from the `ds-record-create` examples and `api-objects/structdsrecord`. Each DS entry is the real SHA-256 digest of the DNSKEY entry at the same index, for `example.net.`, so both files describe the same two Signing Keys, with tags 19095 and 45317 |
| `error_400.json`, `error_401.json`, `error_405.json` | [response codes](https://support.netim.com/en/docs/resellers/apis/rest-api/response-codes) say the body is "an error message". Python l.143-162 and Java `APIRest.java` read `message` from a flat JSON object (Java decodes it as `Map<String,String>`). The message text is synthetic |

## Gaps from #73's Further Notes

1. **OT&E REST base URL.** Answered: `http://oterest.netim.com/3.0/` (`get-started`). Whether `https` also works is unverified.
2. **StructDomainList fields and paging.** The fields are answered (`domain`, `dateCreate`, `dateExpiration`). Paging is **still open**. No page, offset or limit parameter is documented; filters are the only input. Adapter assumption: one `POST /domains/` returns every domain. Filter locally.
3. **StructOperationResponse JSON.**
   - Answered from the docs and the Java client: upper-case keys `ID_OPE`, `STATUS`, `MESSAGE`, `TYPE`, `DATE`, `DATA`, and status values spelled `Done`, `Pending`, `Failed`, `Cancelled`. The Java sample compares `"Pending"`.
   - Not verified on 3.0. Adapter assumption: compare `STATUS` case-insensitively, and treat an unknown status as Unconfirmed.
4. **StructZoneParam in zone info, and SRV service and protocol.**
   - Answered from the docs: options carry `ttl`, `ttlUnit`, `customTtl`, `priority`, `weight`, `port`, `service` and `protocol` (plus the TLSA and SVCB keys). For SRV, `service` and `protocol` travel in `options`, not in `subdomain`: the rules table marks service "List" and protocol "UDP/TCP/TLS" for SRV, and the owner goes in `subdomain`.
   - **Still open:**
     - whether `service` carries a leading `_`
     - the case of `protocol`
     - whether `ttlUnit` comes back on read (StructZoneParam omits it; the create example sends it)
     - whether target values (CNAME, MX, NS, SRV) carry a trailing dot
     - whether TXT values come back quoted
     - whether the apex is `""` or `@`
   - Adapter assumptions:
     - send `service` without `_` and `protocol` upper case
     - on read, strip a leading `_` and accept either case
     - a missing `ttlUnit` means seconds
     - accept targets with or without a trailing dot
     - treat TXT `value` as literal unquoted text
     - accept both `""` and `@` as the apex; `zone_info.json` uses both
5. **Shape of each `ns` entry.** **Still open** for 3.0. StructDomainInfo only says "array". Java 1.0 uses `List<String>`. The 3.0 `Nameservers` input structure is `{"1":{"name":...,"IPv4":...}}`. Adapter assumption: accept a string, an object with `name`, or a map keyed by number. The fixture uses strings.
6. **Delete-DS-records body.** Answered by `domain-names/ds-record-delete`: `{"data":[...]}`, the same shape as create, in DS or DNSKEY form. Delete all is the same `DELETE` with no body. **Still open:** whether delete-some must repeat every field of the stored entry, or matches on fewer.
7. **Error body shape and session-limit message.**
   - Error body: answered as `{"message":"..."}`, from both clients. Other keys are not known. A 406 (body not JSON) documents no body.
   - Session-limit refusal: **still open**, including its status code and text. Adapter assumption: only HTTP 429 (with `Retry-After` when sent) matches `ErrRateLimited`. A session-limit refusal is not recognised by its text, so it surfaces as an `APIError`, or as `ErrUnauthorized` if Netim answers 401. The fake models the cap as 429 with `session_open_limit.json`.

Also still open: the session lifetime and idle timeout (undocumented; the adapter reopens after a 401), and whether `Pending` ever comes back on a `sync: 1` session.

## Doc mistakes to ignore

- **Delete-record example.** It uses the 1.0 URL `https://api.netim.com/rest/1.0/...` and has a trailing comma in its JSON. Follow the 3.0 path above, with strict JSON.
- **Update-record curl example.** It swaps `value` and `newValue` compared with the JSON example. `value` is the current value.
- **`Autorization` header.** Several examples spell it this way; the correct spelling is `Authorization`.
- **Zone-info answer type.** The page says "array", but the listed fields describe one object. The fixture is an object.
- **Python 1.0 domain list.** The Python 1.0 client uses `GET /domains/{filter}`. In 3.0 it is `POST /domains/` with a `filters` body.
