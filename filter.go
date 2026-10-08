package dnsprovider

import "strings"

// ZoneFilter narrows Zones. The zero value matches every Zone. One exact
// Zone is read with Zone(name), not with a filter.
type ZoneFilter struct {
	// Contains matches zone names holding this text, ignoring case. The
	// names are matched in absolute form, so a trailing dot ends one:
	// "example.com." matches example.com and shop.example.com, not
	// example.community.
	Contains string
}

// MatchZone reports whether a Zone matches the filter. An adapter applies
// it to what it could not push down to the Provider's API, so a filtered
// list is always exactly filtered. The text an adapter pushes down is
// Contains in lower case without its trailing dot, which matches at least
// what MatchZone does.
func MatchZone(f ZoneFilter, z Zone) bool {
	name := strings.ToLower(strings.TrimSuffix(z.Name, ".")) + "."

	return strings.Contains(name, strings.ToLower(f.Contains))
}
