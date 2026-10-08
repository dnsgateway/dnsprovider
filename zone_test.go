package dnsprovider_test

import (
	"context"
	"errors"
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

// statusReader is a Provider that reads Zone Status.
type statusReader struct {
	dnsprovider.Provider
	status dnsprovider.ZoneStatus
	err    error
}

func (r statusReader) ZoneStatus(context.Context, dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	return r.status, r.err
}

func TestZoneStatusOfAProviderWithoutAReaderIsUnknown(t *testing.T) {
	got, err := dnsprovider.ZoneStatusOf(context.Background(), oneTenant{}, dnsprovider.Zone{ID: "z1", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Unknown, HSTS: dnsprovider.Unknown}); got != want {
		t.Errorf("ZoneStatusOf = %+v, want %+v", got, want)
	}
}

func TestZoneStatusOfAReaderIsWhatItReads(t *testing.T) {
	p := statusReader{status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.Off}}

	got, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{ID: "z1", Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if got != p.status {
		t.Errorf("ZoneStatusOf = %+v, want %+v", got, p.status)
	}

	p.err = dnsprovider.ErrUnauthorized
	if _, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{ID: "z1"}); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("ZoneStatusOf error = %v, want ErrUnauthorized", err)
	}
}
