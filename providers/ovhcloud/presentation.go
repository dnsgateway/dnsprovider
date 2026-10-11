package ovhcloud

import (
	"net/netip"
	"slices"
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

// equivalentValue compares RDATA while retaining the authoritative presentation
// in returned Records. TXT character-string boundaries remain significant.
func equivalentValue(typ, a, b string) bool {
	if a == b {
		return true
	}
	switch typ {
	case "TXT":
		aa, errA := charstr.Parse(a, " \t\r\n")
		bb, errB := charstr.Parse(b, " \t\r\n")
		return errA == nil && errB == nil && len(aa) > 0 && len(bb) > 0 && slices.Equal(aa, bb)
	case "CAA":
		parse := func(v string) (uint64, string, []string, bool) {
			fields := strings.Fields(v)
			if len(fields) < 3 {
				return 0, "", nil, false
			}
			flags, err := strconv.ParseUint(fields[0], 10, 8)
			remainder := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), fields[0]))
			remainder = strings.TrimSpace(strings.TrimPrefix(remainder, fields[1]))
			values, errText := charstr.Parse(remainder, " \t\r\n")
			return flags, strings.ToLower(fields[1]), values, err == nil && errText == nil && len(values) == 1
		}
		fa, ta, va, oka := parse(a)
		fb, tb, vb, okb := parse(b)
		return oka && okb && fa == fb && ta == tb && slices.Equal(va, vb)
	}
	return false
}
