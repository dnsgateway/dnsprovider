package dnsprovider_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestMatchZoneMatchesNamesHoldingTheTextIgnoringCase(t *testing.T) {
	cases := []struct {
		contains, name string
		want           bool
	}{
		{"", "example.com", true},
		{"ample", "example.com", true},
		{"AMPLE", "Example.COM", true},
		{"example.org", "example.com", false},
		{"shop.", "shop.example.com", true},
	}

	for _, c := range cases {
		z := dnsprovider.Zone{ID: "z1", Name: c.name}
		if got := dnsprovider.MatchZone(dnsprovider.ZoneFilter{Contains: c.contains}, z); got != c.want {
			t.Errorf("MatchZone(%q, %q) = %v, want %v", c.contains, c.name, got, c.want)
		}
	}
}
