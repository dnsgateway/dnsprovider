package infomaniak_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

const (
	servedEnablePath  = "/2/domains/domains/example.ch/dnssec/enable"
	servedDisablePath = "/2/domains/domains/example.ch/dnssec/disable"
)

// updateFake is the fake with the DNSSEC switch of example.ch, which the
// Account registers and Infomaniak serves, signed as zone.json says.
func updateFake(t *testing.T) *fake {
	t.Helper()

	f := newFake(t)
	f.serveFile("POST "+servedEnablePath, "dnssec_done.json")
	f.serveFile("POST "+servedDisablePath, "dnssec_done.json")

	return f
}

func updateZone(f *fake, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	return f.provider().UpdateZone(context.Background(), served, u)
}

func TestUpdateZoneTurnsDNSSECOnWithOneEmptyEnableCall(t *testing.T) {
	f := updateFake(t)
	on := true

	got, err := updateZone(f, dnsprovider.ZoneUpdate{DNSSEC: &on})
	if err != nil {
		t.Fatal(err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}

	if w := f.writes(); len(w) != 1 || len(w[servedEnablePath]) != 1 || w[servedEnablePath][0] != "{}" {
		t.Fatalf("writes = %v, want one enable call with {}", w)
	}
}

func TestUpdateZoneSwitchesDNSSECOnlyForADomainTheAccountRegistersAndInfomaniakServes(t *testing.T) {
	hosted := dnsprovider.Zone{ID: "hosted.net", Name: "hosted.net"}

	for _, tc := range []struct {
		zone dnsprovider.Zone
		want error
	}{
		{stranger, dnsprovider.ErrNotFound},  // neither registered nor served
		{external, dnsprovider.ErrNotFound},  // registered, on other nameservers
		{hosted, dnsprovider.ErrUnsupported}, // served, registered elsewhere
	} {
		for _, on := range []bool{true, false} {
			f := updateFake(t)
			f.serveFile("GET /2/zones/hosted.net", "zone.json")

			got, err := f.provider().UpdateZone(context.Background(), tc.zone, dnsprovider.ZoneUpdate{DNSSEC: &on})
			if !errors.Is(err, tc.want) || got != (dnsprovider.ZoneStatus{}) {
				t.Errorf("%s %v: UpdateZone = %+v, %v; want %v and every setting Unknown", tc.zone.Name, on, got, err, tc.want)
			}

			if w := f.writes(); len(w) != 0 {
				t.Errorf("%s %v: writes = %v, want none", tc.zone.Name, on, w)
			}
		}
	}
}

func TestUpdateZoneTurnsDNSSECOffWithOneEmptyDisableCall(t *testing.T) {
	f := updateFake(t)
	f.serveFile("GET /2/zones/example.ch", "zone_unsigned.json")

	off := false

	got, err := updateZone(f, dnsprovider.ZoneUpdate{DNSSEC: &off})
	if err != nil {
		t.Fatal(err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Off}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}

	if w := f.writes(); len(w) != 1 || len(w[servedDisablePath]) != 1 || w[servedDisablePath][0] != "{}" {
		t.Fatalf("writes = %v, want one disable call with {}", w)
	}
}

func TestUpdateZoneWritesEvenWhenTheZoneIsAlreadyInTheWantedState(t *testing.T) {
	f := updateFake(t) // zone.json: DNSSEC enabled
	on := true

	if _, err := updateZone(f, dnsprovider.ZoneUpdate{DNSSEC: &on}); err != nil {
		t.Fatal(err)
	}

	if n := len(f.writes()[servedEnablePath]); n != 1 {
		t.Fatalf("%d enable calls, want one", n)
	}
}

func TestUpdateZoneReportsDNSSECPendingWhileTheReReadShowsTheOldState(t *testing.T) {
	for _, tc := range []struct {
		on   bool
		zone string
	}{{true, "zone_unsigned.json"}, {false, "zone.json"}} {
		f := updateFake(t)
		f.serveFile("GET /2/zones/example.ch", tc.zone)

		got, err := updateZone(f, dnsprovider.ZoneUpdate{DNSSEC: &tc.on})
		if err != nil {
			t.Fatal(err)
		}

		if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending}); got != want {
			t.Errorf("%v: UpdateZone = %+v, want %+v", tc.on, got, want)
		}
	}
}

func TestUpdateZoneWhoseReReadFailsTakesTheWriteWithDNSSECUnknown(t *testing.T) {
	f := updateFake(t)
	f.script("GET /2/zones/example.ch", http.StatusOK, fixture(t, "zone.json"))
	f.script("GET /2/zones/example.ch", http.StatusUnauthorized, fixture(t, "not_authorized.json"))

	on := true

	got, err := updateZone(f, dnsprovider.ZoneUpdate{DNSSEC: &on})
	if err != nil || got != (dnsprovider.ZoneStatus{}) {
		t.Fatalf("UpdateZone = %+v, %v; want DNSSEC Unknown and no error", got, err)
	}

	if n := len(f.writes()[servedEnablePath]); n != 1 {
		t.Fatalf("%d enable calls, want one", n)
	}
}

func TestUpdateZoneRefusesHSTSAndMinTLSAfterTheSettingsBefore(t *testing.T) {
	on, tls := true, dnsprovider.TLS12

	for _, tc := range []struct {
		name   string
		u      dnsprovider.ZoneUpdate
		writes int
	}{
		{"HSTS", dnsprovider.ZoneUpdate{HSTS: &on}, 0},
		{"MinTLS", dnsprovider.ZoneUpdate{MinTLS: &tls}, 0},
		{"DNSSEC then HSTS", dnsprovider.ZoneUpdate{DNSSEC: &on, HSTS: &on}, 1},
		{"DNSSEC then MinTLS", dnsprovider.ZoneUpdate{DNSSEC: &on, MinTLS: &tls}, 1},
	} {
		f := updateFake(t)

		got, err := updateZone(f, tc.u)
		if !errors.Is(err, dnsprovider.ErrUnsupported) {
			t.Errorf("%s: err = %v, want ErrUnsupported", tc.name, err)
		}

		// DNSSEC, written or read before, stays as it is known.
		if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On}); got != want {
			t.Errorf("%s: status = %+v, want %+v", tc.name, got, want)
		}

		if n := len(f.writes()[servedEnablePath]); n != tc.writes || len(f.writes()) > 1 {
			t.Errorf("%s: writes = %v, want %d enable calls", tc.name, f.writes(), tc.writes)
		}
	}
}

func TestUpdateZoneWithNothingSetReadsDNSSECAndWritesNothing(t *testing.T) {
	f := updateFake(t)

	got, err := updateZone(f, dnsprovider.ZoneUpdate{})
	if err != nil || got != (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On}) {
		t.Fatalf("UpdateZone = %+v, %v; want DNSSEC On", got, err)
	}

	if w := f.writes(); len(w) != 0 {
		t.Fatalf("writes = %v, want none", w)
	}
}

func TestUpdateZoneWithNothingSetFailsWhenTheReadFails(t *testing.T) {
	f := updateFake(t)
	f.script("GET /2/zones/example.ch", http.StatusUnauthorized, fixture(t, "not_authorized.json"))

	if got, err := updateZone(f, dnsprovider.ZoneUpdate{}); !errors.Is(err, dnsprovider.ErrUnauthorized) || got != (dnsprovider.ZoneStatus{}) {
		t.Fatalf("UpdateZone = %+v, %v; want ErrUnauthorized and every setting Unknown", got, err)
	}
}

func TestUpdateZoneDNSSECWritesFollowTheUnconfirmedWriteRules(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		unconfirmed bool
	}{
		{"500 dnssec_management_failed", http.StatusInternalServerError, fixture(t, "dnssec_management_failed.json"), true},
		{"lost", lost, "", true},
		{"asynchronous", http.StatusAccepted, fixture(t, "asynchronous.json"), true},
		{"undecodable success", http.StatusOK, `{"result":`, true},
		{"error in a 2xx", http.StatusOK, fixture(t, "dnssec_management_failed.json"), false},
		{"422 refusal", http.StatusUnprocessableEntity, fixture(t, "validation_failed.json"), false},
	} {
		for _, on := range []bool{true, false} {
			path := servedDisablePath
			if on {
				path = servedEnablePath
			}

			f := updateFake(t)
			f.script("POST "+path, tc.status, tc.body)

			got, err := updateZone(f, dnsprovider.ZoneUpdate{DNSSEC: &on})

			var apiErr *dnsprovider.APIError

			switch {
			case err == nil:
				t.Errorf("%s %v: no error", tc.name, on)
			case errors.Is(err, dnsprovider.ErrUnconfirmed) != tc.unconfirmed:
				t.Errorf("%s %v: %v, unconfirmed = %v", tc.name, on, err, !tc.unconfirmed)
			case !tc.unconfirmed && !errors.As(err, &apiErr):
				t.Errorf("%s %v: %v, want an APIError", tc.name, on, err)
			case strings.Count(err.Error(), "infomaniak:") < 1:
				t.Errorf("%s %v: %v, want the provider named", tc.name, on, err)
			}

			if got != (dnsprovider.ZoneStatus{}) {
				t.Errorf("%s %v: status = %+v, want every setting Unknown", tc.name, on, got)
			}

			if n := len(f.writes()[path]); n != 1 {
				t.Errorf("%s %v: %d writes, want exactly one", tc.name, on, n)
			}
		}
	}
}
