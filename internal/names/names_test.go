package names_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/names"
)

func TestRelativeName(t *testing.T) {
	cases := []struct{ zone, name, want string }{
		{"example.com", "example.com", "@"},
		{"example.com", "Example.COM.", "@"},
		{"example.com", "WWW.example.com", "WWW"},
		{"example.com", "a.b.example.com", "a.b"},
		// Lowercasing "Ⱥ" (2 bytes) gives "ⱥ" (3 bytes): the cut must not shift.
		{"example.com", "Ⱥ.example.com", "Ⱥ"},
		{"example.com", "ȺȺȺ.example.com", "ȺȺȺ"},
		// Outside the Zone: as given, without a trailing dot.
		{"example.com", "www.other.org.", "www.other.org"},
	}

	for _, c := range cases {
		if got := names.RelativeName(c.zone, c.name); got != c.want {
			t.Errorf("RelativeName(%q, %q) = %q, want %q", c.zone, c.name, got, c.want)
		}
	}
}

func TestAbsoluteNameUndoesRelativeName(t *testing.T) {
	for _, abs := range []string{"example.com", "www.example.com", "a.b.example.com", "Ⱥ.example.com"} {
		if got := names.AbsoluteName("example.com", names.RelativeName("example.com", abs)); got != abs {
			t.Errorf("AbsoluteName(RelativeName(%q)) = %q", abs, got)
		}
	}
}

func TestZoneNameIsLowerCaseWithoutATrailingDot(t *testing.T) {
	for in, want := range map[string]string{"Example.COM.": "example.com", "example.com": "example.com", "": ""} {
		if got := names.ZoneName(in); got != want {
			t.Errorf("ZoneName(%q) = %q, want %q", in, got, want)
		}
	}
}
