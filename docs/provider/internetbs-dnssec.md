# Internet.bs DNSSEC registrar research

Reviewed 2026-10-11. Only documentation and first-party source were read; no account requests were made.

## Verified protocol

The official PDF documents optional `Dnssec` on `/Domain/Update`, accepting full RFC 4034 DS or DNSKEY records, including owner, TTL, and class. Credentials and `Domain` are required; `ResponseFormat=JSON` selects JSON. Update responses can report `SUCCESS`, `PENDING`, or `FAILURE`. Direct PDF retrieval returned HTTP 403, so these details were checked against its indexed official excerpts. [Internet.bs API reference](https://internetbs.net/internet-bs-api.pdf).

The official support article links the downloadable first-party WHMCS module. The archive examined is pinned to commit `edee17784da8b39b3d99f7afff9056e74ac96042` (2026-10-09). [Official module documentation](https://faq.internetbs.net/hc/en-gb/articles/13828327871773-WHMCS-Registrar-Module), [module archive](https://github.com/centralnicgroup-opensource/rtldev-middleware-whmcs/blob/edee17784da8b39b3d99f7afff9056e74ac96042/whmcs-ibs-registrar-latest.zip).

Inside that archive, `modules/registrars/ibs/lib/RegistrarModule.php:237` constructs full DNSKEY records; line 251 constructs full DS records. Line 266 joins records with newlines and sends lowercase `dnssec` to `/Domain/Update`. Lines 278–281 clear DNSSEC using an explicitly empty `dnssec` value. Lines 307–315 read `/Domain/Info`: `dnssec` is the string `disabled` or an array of full record strings. No separate DNSSEC list/add/remove command is used. `Registrar.php:240` and `:299` send lowercase `domain` for update and info. `Registrar.php:59` queries `/Domain/Tldinfo`, whose `feature` includes `dnssec` (`YES`/`NO`) and `dnssec_key_type` (`DS` or another form). [Pinned first-party archive](https://github.com/centralnicgroup-opensource/rtldev-middleware-whmcs/blob/edee17784da8b39b3d99f7afff9056e74ac96042/whmcs-ibs-registrar-latest.zip).

## Implementation implications and gaps

A complete desired set can be submitted in one update, following the first-party module. This avoids an intermediate clear/add sequence. The sources do not promise transactional registry atomicity or immediate completion on `PENDING`.

Exact numeric error codes for unowned domains and rejected algorithms were not established. Missing, malformed, or unfamiliar `dnssec` values should not silently become an empty set. TLD support varies; the older PDF's TLD list should not be treated as a current exhaustive capability list. Live account behavior remains unverified.
