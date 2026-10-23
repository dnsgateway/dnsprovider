# INWX DomRobot JSON-RPC fixtures

These JSON bodies are what the `inwx` adapter's fake DomRobot server serves
in tests.

**They are not OT&E captures.** They are derived from INWX's API
documentation, the official Terraform provider (a JSON-RPC client, so its
type assertions show JSON types) and goinwx (an XML-RPC client, for field
names). Issue #92 is to replace them with OT&E captures.

Every value is fake:

- domains are `example.com`, `example.org`, `example.net` and
  `slave.example.net`
- addresses are RFC 5737 / RFC 3849
- customer, account and object IDs are made up
- the session cookies the fake sets are `fakecookie01`, `fakecookie02`, …

Result messages (`msg`) are the documentation's result code table's. Where
INWX's text is unknown, a `reason` starts with `SYNTHETIC:` and the
`reasonCode` is `SYNTHETIC`. Code must never match on that text; it
matches on `code` alone.

## Transport

Every call is `POST https://api.domrobot.com/jsonrpc/` (OT&E:
`https://api.ote.domrobot.com/jsonrpc/`) with the body
`{"method": "<method>", "params": {..., "lang": "en"}}`. Every answer is
HTTP 200 with `{"code", "msg", "reason"?, "reasonCode"?, "resData"?}`. The
session is the `domrobot` cookie `account.login` sets, sent back as a
`Cookie` header. Sources: the documentation's introduction, the Terraform
provider's `client.go`, the Python client's `Domrobot.py`, and acme.sh's
`dns_inwx.sh` (the cookie name).

## Fixtures

| File | Method | Source |
| --- | --- | --- |
| `account_login.json` | `account.login` | Documentation: resData `customerId`, `customerNo`, `accountId`, `dyndns`, `tfa` (`tfaMethod`: `"0"` or `"GOOGLE-AUTH"`); goinwx adds `builddate`, `version` |
| `account_login_tfa.json` | `account.login`, 2FA account | As above with `tfa: "GOOGLE-AUTH"` (Python, PHP, lego and acme.sh check it) |
| `account_info.json` | `account.info` | Documentation (subset: `accountId`, `customerId`, `customerNo`, `username`, `tfa`, `required2fa`); personal fields left out |
| `account_logout.json` | `account.logout` | Documentation: code 1500 "Command completed successfully; ending session" |
| `ok.json` | `account.unlock`, and calls without resData | Documentation: code 1000 |
| `domain_info.json` | `domain.info` of a domain the Account registers, without an INWX zone | goinwx `domain.go` field names; contact fields left out |
| `nameserver_info_example_com.json` | `nameserver.info` | Documentation (`roId`, `domain`, `type`, `SOAserial` as a string, `count`, `record[]` of `id`, `name`, `type`, `content`, `ttl`, `prio`); Terraform provider (`ttl` a JSON number, apex as `""` or the zone name); lego (full names without a trailing dot). One `id` is a number and one `type` lower case, to test both. SRV `content` as weight, port and target and URI `content` as weight and quoted target are assumptions |
| `nameserver_info_example_org.json` | `nameserver.info` | As above; INWX's nameservers `ns.inwx.de`, `ns2.inwx.de`, `ns3.inwx.eu` are an assumption |
| `dnssec_listkeys_example_net.json` | `dnssec.listkeys` of `example.net` | Terraform provider's shape: `resData` a bare array, fields as strings; field names from the documentation. The key and its SHA-256 DS are RFC 6605 section 6.1's, at `example.net` |
| `dnssec_listkeys_dnskey_form.json` | `dnssec.listkeys` | Documentation and goinwx shape: entries under `resData.dnskey`, fields as numbers; a DS-only entry (RFC 4034 section 5.4's DS) and a DNSKEY-only entry with empty digest fields |
| `nameserver_info_slave_example_net.json` | `nameserver.info` of a slave zone | As above, with `type: SLAVE` and `masterIp` |
| `dnssec_listkeys_example_com.json` | `dnssec.listkeys` of `example.com`, signed by INWX | Documentation and goinwx field names (`id`, `domainId`, `keyTag`, `flagId`, `algorithmId`, `publicKey`, `digestTypeId`, `digest`, `created`, `status`, `active`); Terraform provider (`resData` a bare array, numbers as JSON strings). The KSK is RFC 6605's example key (tag 55648, algorithm 13) with its SHA-256 DS computed for `example.com`, in lower case; the ZSK (flags 256, without a digest) reuses the same key bytes |

The fake builds the other answers itself, from the zones above:

- `nameserver.list` answers `{"count", "domains": [{"roId", "domain", "type", "masterIp"?}]}` a page at a time (documentation; `page` and `pagelimit` params).
- `dnssec.info` answers `{"data": [{"domain", "keyCount", "dnssecStatus"}]}` for each of its `domains` with a status (documentation, Terraform provider); a test also serves goinwx's spelling `dnsSecStatus`. The statuses `AUTO`, `NONE`, `MANUAL`, `UPDATE` and `DELETE_ALL` are the documentation's and the Terraform provider's; their meaning is not captured.
- `dnssec.listkeys` is also served with its entries under `dnskey` (documentation, goinwx), and as no keys (`[]`) for a zone without a fixture.
- `dnssec.enablednssec` and `dnssec.disablednssec` (`domainName`) answer code 1000 and set the zone's status to `AUTO` or `NONE`, or to a status a test chooses; 2303 for a zone the fake does not host.
- `nameserver.create` answers `{"roId"}` as a JSON number (documentation; the Terraform provider asserts a number), 2302 for a zone it holds. **SYNTHETIC:** the new zone holds an SOA and an apex NS record for each `ns` sent; whether INWX adds others is not documented.
- `nameserver.delete` answers without `resData` (documentation), 2303 for an unknown zone.
- `nameserver.createRecord` (in `write_test.go`) stores the record as sent, with the next ID of the account, and answers `{"id": "<id>"}` (documentation: resData `id`; the Terraform provider reads it).
- `nameserver.deleteRecord` (in `write_test.go`) removes the record of `id` and answers code 1000 without resData, or 2303 for an unknown ID (an assumption).
- `nameserver.updateRecord` (in `update_test.go`) changes the sent `name`, `type`, `content`, `ttl` and `prio` of the record of `id`, in whichever zone holds it, and answers code 1000 without resData (documentation: no resData), or 2303 for an unknown ID (an assumption).
- `nameserver.info` with `recordId` answers the zone with only that record, or none when the zone does not hold it (an assumption).
- Refusals are `{"code", "msg"}` with the documentation's message for the code.
- **SYNTHETIC:** a call without a live, unlocked session is refused with 2200. INWX documents no code for an expired session.
- **SYNTHETIC:** a wrong `account.unlock` code is refused with 2200.
- `dnssec.adddnskey` stores an entry from its `dnskey` (with the SHA-256 DS when `calculateDigest` is set) or `ds`, and answers `{"dnskey", "ds"}` with the DS as RDATA (Terraform provider); `dnssec.deletednskey` (`key`) and `dnssec.deleteall` (`domainName`) answer 1000 without resData. Unknown domains or keys are 2303.
- **SYNTHETIC:** a login past the fake's session cap is refused with 2502, the documented "Session limit exceeded" code.
