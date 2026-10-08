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
	return holds(z.Name, f.Contains)
}

// RecordFilter narrows Records. The zero value matches every Record.
type RecordFilter struct {
	// Type matches one Record type, such as "MX", ignoring case.
	Type string
	// Contains matches Record names holding this text, ignoring case. The
	// names are matched in absolute form, as ZoneFilter's are.
	Contains string
}

// MatchRecord reports whether a Record matches the filter. An adapter
// applies it to what it could not push down to the Provider's API, so a
// filtered list is always exactly filtered. The text an adapter pushes
// down is Contains in lower case without its trailing dot, and the type
// in upper case.
func MatchRecord(f RecordFilter, r Record) bool {
	if f.Type != "" && !strings.EqualFold(f.Type, r.Type) {
		return false
	}

	return holds(r.Name, f.Contains)
}

// holds reports whether a name, in absolute form, holds the text,
// ignoring case.
func holds(name, text string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, ".")) + "."

	return strings.Contains(name, strings.ToLower(text))
}
