# dnsprovider

One vocabulary for reading and writing DNS Zones and Records across DNS
hosting services, each reached as a Provider.

## Language

**Partial View**:
A list of Zones, or of a Zone's Records, that the caller's access does not
cover in full: some Zones, or some names and types in the Zone, are outside
it. It says what the access covers, not that anything was left out.
_Avoid_: filtered view, incomplete list, subset

**Full View**:
A list of Zones, or of a Zone's Records, that the caller's access covers in
full.
_Avoid_: complete list

**Signing Key**:
A key-signing key of a Zone: its DNSKEY, and the Delegation Signer (DS)
records that fix it at the parent zone. It is one notion for the key a
Provider signs the Zone with and the key a registrar holds.
_Avoid_: DNSSEC key, KSK, zone-signing key

**Registration**:
A Zone whose domain the Account registers, as well as or instead of
hosting its DNS. Its registrar holds the Signing Keys published by the registry
as Delegation Signer records, separately from the Provider signing the Zone.
_Avoid_: registrar zone, domain

**Zone Status**:
The state of a Zone's DNSSEC signing and security settings, including HSTS
and minimum TLS, separate from whether the Provider serves its DNS.
_Avoid_: Hosting State, DNS status

**DNSSEC State**:
Whether a Provider's Zone signing is Unknown, Off, On, or Pending. Pending
includes both signing and unsigning in progress; Unknown does not establish Off.
_Avoid_: DNSSEC validity, Delegation state

**Delegation**:
The parent zone's Nameservers and Delegation Signer records that direct queries
and establish trust for a Zone.
_Avoid_: nameserver settings, DNS routing

**Onboarding**:
Establishing DNS hosting for a Zone and, when requested, coordinating its
Delegation to that hosting.
_Avoid_: domain registration, provisioning

**Offboarding**:
Removing DNS hosting after replacement hosting serves the name and Delegation
has left every old Nameserver. The Registration remains intact.
_Avoid_: domain cancellation, unregistering

**Trust Path**:
The parent Delegation Signers and the authoritative Zone's Signing Keys that
allow DNSSEC validation of that Zone.
_Avoid_: matching key tags, signed status
