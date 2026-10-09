package scaleway

import (
	"errors"
	"fmt"
	"strings"
)

// unquoteDNS decodes DNS character-string escapes: \DDD is decimal,
// and a backslash before any other character quotes that character.
func unquoteDNS(s string) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", errors.New("scaleway: malformed quoted TXT value")
	}
	var b strings.Builder
	for i := 1; i < len(s)-1; i++ {
		c := s[i]
		if c == '"' {
			return "", errors.New("scaleway: unescaped quote in TXT value")
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(s)-1 {
			return "", errors.New("scaleway: incomplete TXT escape")
		}
		if s[i] >= '0' && s[i] <= '9' {
			if i+2 >= len(s)-1 || s[i+1] < '0' || s[i+1] > '9' || s[i+2] < '0' || s[i+2] > '9' {
				return "", errors.New("scaleway: TXT decimal escapes require three digits")
			}
			n := int(s[i]-'0')*100 + int(s[i+1]-'0')*10 + int(s[i+2]-'0')
			if n > 255 {
				return "", errors.New("scaleway: TXT decimal escape exceeds 255")
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

// txtValue joins the quoted character strings of one TXT record.
func txtValue(s string) (string, error) {
	var out strings.Builder
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		if s[0] != '"' {
			return "", errors.New("scaleway: malformed TXT data")
		}
		end := -1
		for i := 1; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if s[i] == '"' {
				end = i
				break
			}
		}
		if end < 0 {
			return "", errors.New("scaleway: unclosed TXT data")
		}
		value, err := unquoteDNS(s[:end+1])
		if err != nil {
			return "", err
		}
		out.WriteString(value)
		s = s[end+1:]
		if s != "" && s[0] != ' ' && s[0] != '\t' {
			return "", errors.New("scaleway: malformed TXT separator")
		}
	}
	return out.String(), nil
}
