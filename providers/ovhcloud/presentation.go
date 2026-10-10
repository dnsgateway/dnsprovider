package ovhcloud

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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
			return quoteText(value)
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
		aa, okA := characterStrings(a)
		bb, okB := characterStrings(b)
		return okA && okB && slices.Equal(aa, bb)
	case "CAA":
		parse := func(v string) (uint64, string, []string, bool) {
			fields := strings.Fields(v)
			if len(fields) < 3 {
				return 0, "", nil, false
			}
			flags, err := strconv.ParseUint(fields[0], 10, 8)
			remainder := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), fields[0]))
			remainder = strings.TrimSpace(strings.TrimPrefix(remainder, fields[1]))
			values, ok := characterStrings(remainder)
			return flags, strings.ToLower(fields[1]), values, err == nil && ok && len(values) == 1
		}
		fa, ta, va, oka := parse(a)
		fb, tb, vb, okb := parse(b)
		return oka && okb && fa == fb && ta == tb && slices.Equal(va, vb)
	}
	return false
}

// characterStrings decodes quoted zone-file strings, including escaped decimal
// octets. Invalid or unquoted presentations are never treated as equivalent.
func characterStrings(text string) ([]string, bool) {
	var values []string
	for text = strings.TrimSpace(text); text != ""; text = strings.TrimSpace(text) {
		if text[0] != '"' {
			return nil, false
		}
		text = text[1:]
		var value strings.Builder
		closed := false
		for len(text) > 0 {
			c := text[0]
			text = text[1:]
			if c == '"' {
				closed = true
				break
			}
			if c == '\\' {
				if len(text) == 0 {
					return nil, false
				}
				c = text[0]
				text = text[1:]
				if c >= '0' && c <= '9' {
					if len(text) < 2 || text[0] < '0' || text[0] > '9' || text[1] < '0' || text[1] > '9' {
						return nil, false
					}
					n := int(c-'0')*100 + int(text[0]-'0')*10 + int(text[1]-'0')
					if n > 255 {
						return nil, false
					}
					c = byte(n)
					text = text[2:]
				}
			}
			value.WriteByte(c)
		}
		if !closed {
			return nil, false
		}
		values = append(values, value.String())
		if text != "" && text[0] != ' ' && text[0] != '\t' && text[0] != '\r' && text[0] != '\n' {
			return nil, false
		}
	}
	return values, len(values) > 0
}

// quoteText makes literal text one quoted zone-file string.
func quoteText(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := range len(value) {
		c := value[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 32 || c == 127:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
