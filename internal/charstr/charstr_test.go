package charstr_test

import (
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/charstr"
)

func TestQuotePreservesLiteralBytes(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"", `""`},
		{"ordinary text", `"ordinary text"`},
		{"a \"quote\" and a \\ slash", `"a \"quote\" and a \\ slash"`},
		{"\x00\t\n\r\x1f\x7f", `"\000\009\010\013\031\127"`},
		{"caf\u00e9\xff", "\"caf\u00e9\xff\""},
	} {
		if got := charstr.Quote(tc.value); got != tc.want {
			t.Errorf("Quote(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
	var all []byte
	for i := range 256 {
		all = append(all, byte(i))
	}
	value := string(all)
	got, err := charstr.Unquote(charstr.Quote(value))
	if err != nil || got != value {
		t.Fatalf("all bytes round trip = %q, %v", got, err)
	}
}

func TestUnquoteDecodesExactlyOneString(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{`""`, ""},
		{`"\065\032\255"`, "A \xff"},
		{`"a\"b\\c\qd"`, "a\"b\\cqd"},
		{`"\0001"`, "\x001"},
	} {
		got, err := charstr.Unquote(tc.text)
		if err != nil || got != tc.want {
			t.Errorf("Unquote(%q) = %q, %v, want %q", tc.text, got, err, tc.want)
		}
	}
	for _, text := range []string{"", "plain", `"`, `"unclosed`, `"\"`, `"\1"`, `"\12"`, `"\1x3"`, `"\256"`, `"\999"`, `"a" "b"`, ` "a"`, `"a" `, `"a"tail`} {
		if got, err := charstr.Unquote(text); err == nil || got != "" {
			t.Errorf("Unquote(%q) = %q, %v, want no value and an error", text, got, err)
		}
	}
}

func TestParsePreservesChunksAndSeparatorPolicy(t *testing.T) {
	for _, tc := range []struct {
		text, separators string
		want             []string
	}{
		{" \t\n", " \t", nil},
		{`""`, " \t", []string{""}},
		{`"ab" "cd"`, " \t", []string{"ab", "cd"}},
		{`"abcd"`, " \t", []string{"abcd"}},
		{" \"a\\032b\"\t\"c\\\"d\" \n", " \t", []string{"a b", "c\"d"}},
		{"\"a\"\r\n\"b\"", " \t\r\n", []string{"a", "b"}},
	} {
		got, err := charstr.Parse(tc.text, tc.separators)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("Parse(%q, %q) = %q, %v, want %q", tc.text, tc.separators, got, err, tc.want)
		}
	}
	for _, text := range []string{`plain`, `"a""b"`, `"a" garbage`, `"a" "\256"`, `"a" "unclosed`, "\"a\"\n\"b\""} {
		if got, err := charstr.Parse(text, " \t"); err == nil || got != nil {
			t.Errorf("Parse(%q) = %q, %v, want no chunks and an error", text, got, err)
		}
	}
}
