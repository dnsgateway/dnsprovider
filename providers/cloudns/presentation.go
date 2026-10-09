package cloudns

import (
	"errors"
	"fmt"
	"strings"
)

// unquoteDNS decodes DNS character-string escapes: \DDD is decimal,
// and a backslash before any other character quotes that character.
func unquoteDNS(s string) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", errors.New("cloudns: malformed quoted CAA value")
	}
	var b strings.Builder
	for i := 1; i < len(s)-1; i++ {
		c := s[i]
		if c == '"' {
			return "", errors.New("cloudns: unescaped quote in CAA value")
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(s)-1 {
			return "", errors.New("cloudns: incomplete CAA escape")
		}
		if s[i] >= '0' && s[i] <= '9' {
			if i+2 >= len(s)-1 || s[i+1] < '0' || s[i+1] > '9' || s[i+2] < '0' || s[i+2] > '9' {
				return "", errors.New("cloudns: CAA decimal escapes require three digits")
			}
			n := int(s[i]-'0')*100 + int(s[i+1]-'0')*10 + int(s[i+2]-'0')
			if n > 255 {
				return "", errors.New("cloudns: CAA decimal escape exceeds 255")
			}
			b.WriteByte(byte(n))
			i += 2
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String(), nil
}

func quoteDNS(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
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
