# Namecheap

Import `providers/namecheap`, or select Registry key `namecheap`.

Namecheap lists only the Zones on its DNS, which have Hosting State Active.
Zone filtering uses the API's `SearchTerm` and the common local filter.

## Concurrent writes

Every write replaces the domain's whole host list (`setHosts`). The API has
no append, remove-one or conditional write, so concurrent writers to the
same domain can lose each other's changes, on any record of the domain.

After each write the adapter reads the hosts back and checks the
Changeset's own effects: hosts it added or modified are present with their
TTL, and hosts it deleted are gone. Hosts it did not touch are not
compared. A miss fails the Changeset with an error matching `ErrConflict`:
re-read the Zone and retry. The read-back catches only some losses: a write
that replaces ours after our read-back goes undetected.

Callers that need safe concurrent writes serialize them per Zone, for
example with a lock in the Gateway.

## Live tests

Set `DNSPROVIDER_NAMECHEAP_USER`, `DNSPROVIDER_NAMECHEAP_KEY`, and
`DNSPROVIDER_NAMECHEAP_CLIENT_IP`. `DNSPROVIDER_NAMECHEAP_BASE_URL` overrides
the endpoint, such as the Namecheap sandbox. Live tests only read.
