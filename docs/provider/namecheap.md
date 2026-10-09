# Namecheap

Import `providers/namecheap`, or select Registry key `namecheap`.

Namecheap lists only the Zones on its DNS, which have Hosting State Active.
Zone filtering uses the API's `SearchTerm` and the common local filter.

## Live tests

Set `DNSPROVIDER_NAMECHEAP_USER`, `DNSPROVIDER_NAMECHEAP_KEY`, and
`DNSPROVIDER_NAMECHEAP_CLIENT_IP`. `DNSPROVIDER_NAMECHEAP_BASE_URL` overrides
the endpoint, such as the Namecheap sandbox. Live tests only read.
