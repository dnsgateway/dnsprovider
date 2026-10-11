package hetzner

import (
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider/internal/charstr"
)

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
