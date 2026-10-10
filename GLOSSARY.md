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
