// Package names converts Record names between the absolute form the module
// uses and the zone-relative form GoDaddy and Namecheap write on the wire.
//
// The wire form differs from dnsprovider.QualifyName and
// dnsprovider.RelativeName, which serve UIs: a wire name outside the Zone
// has no trailing dot, and AbsoluteName trusts the Provider's names rather
// than checking them, since a Record a Provider returns must not be lost.
package names

import (
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// AbsoluteName turns a name relative to a Zone, as GoDaddy and Namecheap
// write it, into an absolute one: "@" or "" is the apex, and a ".@" suffix
// stands for the Zone.
func AbsoluteName(zone, name string) string {
	switch {
	case name == "@" || name == "":
		return zone
	case strings.HasSuffix(name, ".@"):
		return strings.TrimSuffix(name, "@") + zone
	}

	return name + "." + zone
}

// RelativeName is AbsoluteName undone for GoDaddy and Namecheap: it is
// dnsprovider.RelativeName, except that a name outside the Zone is returned
// without a trailing dot.
func RelativeName(zone, name string) string {
	return strings.TrimSuffix(dnsprovider.RelativeName(zone, name), ".")
}
