// Package charstr encodes and decodes DNS character-string presentation.
// Adapters decide whether to join decoded strings or retain their chunks.
package charstr

import (
	"errors"
	"fmt"
	"strings"
)

// Quote presents literal bytes as one quoted character-string. Quotes and
// backslashes are escaped; control bytes use three-digit decimal escapes.
func Quote(value string) string {
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

// Unquote decodes exactly one quoted character-string, without surrounding
// whitespace. A decimal escape requires three digits and a value at most 255;
// a backslash before any other byte quotes that byte.
func Unquote(text string) (string, error) {
	value, rest, err := take(text)
	if err != nil {
		return "", err
	}
	if rest != "" {
		return "", errors.New("trailing data after character-string")
	}
	return value, nil
}

// Parse decodes quoted character-strings, preserving each chunk. Separators
// names the bytes allowed immediately after a chunk (usually space and tab,
// optionally carriage return and newline). Surrounding whitespace is ignored.
// Empty text yields no chunks; malformed text yields an error and no chunks.
func Parse(text, separators string) ([]string, error) {
	var values []string
	for text = strings.TrimSpace(text); text != ""; text = strings.TrimSpace(text) {
		value, rest, err := take(text)
		if err != nil {
			return nil, err
		}
		if rest != "" && !strings.ContainsRune(separators, rune(rest[0])) {
			return nil, errors.New("malformed character-string separator")
		}
		values = append(values, value)
		text = rest
	}
	return values, nil
}

// take reads the first quoted character-string and leaves the rest untouched.
func take(text string) (string, string, error) {
	if len(text) == 0 || text[0] != '"' {
		return "", "", errors.New("malformed quoted character-string")
	}
	var value strings.Builder
	for i := 1; i < len(text); i++ {
		c := text[i]
		if c == '"' {
			return value.String(), text[i+1:], nil
		}
		if c == '\\' {
			i++
			if i >= len(text) {
				return "", "", errors.New("incomplete character-string escape")
			}
			c = text[i]
			if c >= '0' && c <= '9' {
				if i+2 >= len(text) || text[i+1] < '0' || text[i+1] > '9' || text[i+2] < '0' || text[i+2] > '9' {
					return "", "", errors.New("decimal escapes require three digits")
				}
				n := int(c-'0')*100 + int(text[i+1]-'0')*10 + int(text[i+2]-'0')
				if n > 255 {
					return "", "", errors.New("decimal escape exceeds 255")
				}
				c = byte(n)
				i += 2
			}
		}
		value.WriteByte(c)
	}
	return "", "", errors.New("unclosed character-string")
}
