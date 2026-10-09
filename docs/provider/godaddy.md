# GoDaddy

Import `providers/godaddy`, or select Registry key `godaddy`.

GoDaddy lists every domain it registers. Hosting State is Active while
Delegation names one of its nameservers, Moved once it names none, and Unknown
when GoDaddy does not say. GoDaddy keeps no zone file for a domain it
registers while Delegation names other nameservers: reading its Records is
`ErrNotServed` while the Account holds the domain, and `ErrNotFound` once it
does not.

The adapter never calls `DELETE /v1/domains`, which cancels registration.

## Live tests

Set `DNSPROVIDER_GODADDY_KEY` and `DNSPROVIDER_GODADDY_SECRET`.
`DNSPROVIDER_GODADDY_BASE_URL` overrides the endpoint, such as GoDaddy OTE.
Live tests only read.
