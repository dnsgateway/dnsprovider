package dnsprovider

import "strings"

// ZoneFilter narrows Zones. The zero value matches every Zone. One exact
// Zone is read with Zone(name), not with a filter.
type ZoneFilter struct {
	// Contains matches zone names holding this text, ignoring case.
	Contains string
}

// MatchZone reports whether a Zone matches the filter. An adapter applies
// it to what it could not push down to the Provider's API, so a filtered
// list is always exactly filtered.
func MatchZone(f ZoneFilter, z Zone) bool {
	return strings.Contains(strings.ToLower(z.Name), strings.ToLower(f.Contains))
}
