package dnsprovider

// Zone is a DNS zone hosted in one Account at a Provider.
type Zone struct {
	ID    string // Provider-assigned, opaque
	Name  string // e.g. "example.com"
	State HostingState
	// Nameservers are the nameservers the Provider assigned to the Zone,
	// which Delegation must name; nil when not known.
	Nameservers []string
}

// Record is a single DNS resource record inside a Zone.
type Record struct {
	// ID is Provider-assigned; a key built from the Record's content where
	// the Provider has no record IDs, which changes when the Record does.
	ID   string
	Type string
	// Name is absolute, without a trailing dot: "www.example.com".
	Name string
	// Value is in zone-file presentation form; see EditableTypes.
	Value string
	TTL   uint32
	// Extras holds Provider-specific fields, such as Cloudflare's proxy
	// flag. Each provider package exports its keys.
	Extras map[string]string
}

// HostingState is whether the Provider is serving a Zone.
type HostingState int8

// Hosting States. The zero value is Unknown.
const (
	HostingUnknown HostingState = iota
	// HostingActive is a Zone the Provider serves.
	HostingActive
	// HostingPending is a Zone Onboarded and waiting for Delegation to
	// name its nameservers.
	HostingPending
	// HostingMoved is a Zone whose Delegation left the Provider; it is no
	// longer served.
	HostingMoved
)

// ChangeKind says what a Change does to a Record.
type ChangeKind int

// Change kinds.
const (
	ChangeAdd ChangeKind = iota + 1
	ChangeModify
	ChangeDelete
)

// Change is one Record addition, modification or deletion.
type Change struct {
	Kind ChangeKind
	// Before is the Record as the Changeset was built from it; empty for an addition.
	Before Record
	// After is the Record as it should become; empty for a deletion.
	After Record
}

// Changeset is a set of Record additions, modifications and deletions for
// one Zone, applied to the Provider as one operation.
type Changeset struct {
	Zone    Zone
	Changes []Change
}

// ZoneStatus is the Provider-side summary of a Zone shown in the status bar.
// Mail records and the Live Zone marker are left to the consumer.
type ZoneStatus struct {
	DNSSEC Setting
	HSTS   Setting
}

// Setting is a Zone setting that is on, off, pending a change between
// the two, or unknown, such as when the API token may not read it.
type Setting int8

// Settings. The zero value is Unknown. The values are stored in the cache:
// append new ones, never renumber.
const (
	Unknown Setting = iota
	Off
	On
	// Pending is a setting the Provider is still turning on or off, such
	// as DNSSEC waiting for its DS record at the registrar.
	Pending
)

// String is "on", "off", "pending" or "?".
func (s Setting) String() string {
	switch s {
	case On:
		return "on"
	case Off:
		return "off"
	case Pending:
		return "pending"
	}

	return "?"
}
