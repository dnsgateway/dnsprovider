package ovhcloud

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider/internal/charstr"
)

// shape is how a record type's value is presented.
type shape int

const (
	opaque   shape = iota // kept as is, trimmed
	address               // an IP address
	hostName              // one host name
	hostLast              // numeric fields, then a host name
	text                  // character-strings
)

// shapes is the one type table for reads and writes, so both present a
// type alike.
var shapes = map[string]shape{
	"A": address, "AAAA": address,
	"CNAME": hostName, "NS": hostName, "PTR": hostName, "DNAME": hostName,
	"MX": hostLast, "SRV": hostLast,
	"TXT": text, "SPF": text,
}

// presentValue puts a value of typ in zone-file presentation; host makes
// a host name absolute.
func presentValue(typ, value string, host func(string) string) string {
	value = strings.TrimSpace(value)

	switch shapes[typ] {
	case address:
		if a, err := netip.ParseAddr(value); err == nil {
			return a.String()
		}
	case hostName:
		return host(value)
	case hostLast:
		f := strings.Fields(value)
		if len(f) > 1 {
			for i := range len(f) - 1 {
				if n, err := strconv.ParseUint(f[i], 10, 16); err == nil {
					f[i] = strconv.FormatUint(n, 10)
				}
			}

			f[len(f)-1] = host(f[len(f)-1])

			return strings.Join(f, " ")
		}
	case text:
		if !strings.HasPrefix(value, `"`) {
			return charstr.Quote(value)
		}
	case opaque:
	}

	return value
}
