package cloudflare_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

var z1 = dnsprovider.Zone{ID: "z1", Name: "example.com"}

// updateZone changes z1's settings through the Provider's ZoneUpdater.
func updateZone(t *testing.T, p dnsprovider.Provider, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	t.Helper()

	return p.UpdateZone(context.Background(), z1, u)
}

func TestCloudflareUpdatesZones(t *testing.T) {
	if !dnsprovider.CanUpdateZone(newProvider(t, &cfAPI{})) {
		t.Error("Cloudflare does not update Zones")
	}
}

func TestUpdateZoneTurnsDNSSECOnOrOffAndWritesNothingElse(t *testing.T) {
	tests := []struct {
		on         bool
		wantStatus string
		want       dnsprovider.ZoneStatus
	}{
		// Cloudflare signs and unsigns over time: the change is pending.
		{true, "active", dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.On}},
		{false, "disabled", dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.On}},
	}

	for _, tt := range tests {
		t.Run(tt.wantStatus, func(t *testing.T) {
			api := &cfAPI{dnssec: map[string]string{"z1": "disabled"}, hsts: map[string]bool{"z1": true}}

			got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{DNSSEC: &tt.on})
			if err != nil {
				t.Fatalf("UpdateZone: %v", err)
			}

			if got != tt.want {
				t.Errorf("UpdateZone = %+v, want %+v", got, tt.want)
			}

			assertWrites(t, api, []write{{Method: "PATCH", Path: "/client/v4/zones/z1/dnssec", Body: map[string]any{"status": tt.wantStatus}}})
		})
	}
}

func TestUpdateZoneTurnsHSTSOnOrOffKeepingTheRestOfItsSettings(t *testing.T) {
	for _, on := range []bool{true, false} {
		api := &cfAPI{dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": !on}}

		got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{HSTS: &on})
		if err != nil {
			t.Fatalf("UpdateZone: %v", err)
		}

		want := dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.Off}
		if on {
			want.HSTS = dnsprovider.On
		}

		if got != want {
			t.Errorf("HSTS %v: UpdateZone = %+v, want %+v", on, got, want)
		}

		assertWrites(t, api, []write{{
			Method: "PATCH",
			Path:   "/client/v4/zones/z1/settings/security_header",
			Body: map[string]any{"value": map[string]any{"strict_transport_security": map[string]any{
				"enabled": on, "max_age": 86400.0, "include_subdomains": true, "preload": false, "nosniff": true,
			}}},
		}})
	}
}

func TestUpdateZoneTurnsHSTSOnForSixMonthsWhenTheZoneHasNoMaxAge(t *testing.T) {
	api := &cfAPI{sts: map[string]map[string]any{"z1": {"enabled": false, "max_age": 0, "include_subdomains": false, "preload": false, "nosniff": false}}}
	on := true

	if _, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{HSTS: &on}); err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}

	assertWrites(t, api, []write{{
		Method: "PATCH",
		Path:   "/client/v4/zones/z1/settings/security_header",
		Body: map[string]any{"value": map[string]any{"strict_transport_security": map[string]any{
			"enabled": true, "max_age": 15552000.0, "include_subdomains": false, "preload": false, "nosniff": false,
		}}},
	}})
}

func TestUpdateZoneWritesBothSettingsWhenBothAreSet(t *testing.T) {
	api := &cfAPI{dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": false}}
	off, on := false, true

	got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{DNSSEC: &off, HSTS: &on})
	if err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.On}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}

	var paths []string
	for _, w := range api.Writes() {
		paths = append(paths, w.Method+" "+w.Path)
	}

	if want := []string{"PATCH /client/v4/zones/z1/dnssec", "PATCH /client/v4/zones/z1/settings/security_header"}; !slices.Equal(paths, want) {
		t.Errorf("writes = %q, want %q", paths, want)
	}
}

func TestUpdateZoneWithNothingSetReadsTheZoneStatusAndWritesNothing(t *testing.T) {
	api := &cfAPI{dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": true}}

	got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{})
	if err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.On}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}

	assertWrites(t, api, nil)
}

func TestUpdateZoneLeavesASettingItCannotReadUnknown(t *testing.T) {
	api := &cfAPI{
		dnssec:    map[string]string{"z1": "disabled"},
		forbidden: []string{"/client/v4/zones/z1/settings/security_header"},
	}
	on := true

	got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{DNSSEC: &on})
	if err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.Unknown}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}
}

func TestUpdateZoneThatCloudflareRefusesIsATypedError(t *testing.T) {
	api := &cfAPI{
		dnssec: map[string]string{"z1": "disabled"},
		intercept: func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodPatch {
				return false
			}

			writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")

			return true
		},
	}
	on := true

	for _, u := range []dnsprovider.ZoneUpdate{{DNSSEC: &on}, {HSTS: &on}} {
		if _, err := updateZone(t, newProvider(t, api), u); !errors.Is(err, dnsprovider.ErrUnauthorized) {
			t.Errorf("UpdateZone(%+v) error = %v, want ErrUnauthorized", u, err)
		}
	}
}

func TestUpdateZoneThatCloudflareDoesNotMarkAsSuccessFails(t *testing.T) {
	api := &cfAPI{
		intercept: func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodPatch {
				return false
			}

			writeJSON(w, http.StatusOK, map[string]any{"success": false, "errors": []map[string]any{{"code": 1000, "message": "no"}}, "result": nil})

			return true
		},
	}
	on := true

	var apiErr *dnsprovider.APIError
	if _, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{DNSSEC: &on}); !errors.As(err, &apiErr) {
		t.Errorf("UpdateZone error = %v, want an APIError", err)
	}
}

func TestUpdateZoneThatFailsAfterASettingIsWrittenReturnsThatSettingWithTheError(t *testing.T) {
	api := &cfAPI{
		dnssec: map[string]string{"z1": "disabled"},
		hsts:   map[string]bool{"z1": false},
		intercept: func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodPatch || r.URL.Path != "/client/v4/zones/z1/settings/security_header" {
				return false
			}

			writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")

			return true
		},
	}
	on := true

	got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{DNSSEC: &on, HSTS: &on})
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("UpdateZone error = %v, want ErrUnauthorized", err)
	}

	// DNSSEC was written, as Cloudflare answered; HSTS was not.
	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.Unknown}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}
}

func TestUpdateZoneThatFailsBeforeWritingReturnsEverySettingUnknown(t *testing.T) {
	api := &cfAPI{
		dnssec:    map[string]string{"z1": "disabled"},
		hsts:      map[string]bool{"z1": true},
		forbidden: []string{"/client/v4/zones/z1/dnssec"},
	}
	on := true

	got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{DNSSEC: &on})
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("UpdateZone error = %v, want ErrUnauthorized", err)
	}

	if got != (dnsprovider.ZoneStatus{}) {
		t.Errorf("UpdateZone = %+v, want every setting Unknown", got)
	}
}

func TestUpdateZoneKeepsTheSecurityHeaderFieldsItDoesNotKnow(t *testing.T) {
	api := &cfAPI{}
	api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodGet || r.URL.Path != "/client/v4/zones/z1/settings/security_header" {
			return false
		}

		writeResult(w, map[string]any{
			"id": "security_header",
			"value": map[string]any{
				"strict_transport_security": map[string]any{"enabled": false, "max_age": 86400, "preload": true, "future_field": "kept"},
				"future_header":             map[string]any{"enabled": true},
			},
			"editable": true,
		})

		return true
	}
	on := true

	if _, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{HSTS: &on}); err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}

	assertWrites(t, api, []write{{
		Method: "PATCH",
		Path:   "/client/v4/zones/z1/settings/security_header",
		Body: map[string]any{"value": map[string]any{
			"strict_transport_security": map[string]any{"enabled": true, "max_age": 86400.0, "preload": true, "future_field": "kept"},
			"future_header":             map[string]any{"enabled": true},
		}},
	}})
}

func TestUpdateZoneSetsTheMinimumTLSVersionAndWritesNothingElse(t *testing.T) {
	api := &cfAPI{dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": true}, minTLS: map[string]string{"z1": "1.0"}}
	v := dnsprovider.TLS12

	got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{MinTLS: &v})
	if err != nil {
		t.Fatalf("UpdateZone: %v", err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.On, MinTLS: dnsprovider.TLS12}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}

	assertWrites(t, api, []write{{Method: "PATCH", Path: "/client/v4/zones/z1/settings/min_tls_version", Body: map[string]any{"value": "1.2"}}})
}

func TestUpdateZoneRefusesATLSVersionItDoesNotKnowWritingNothing(t *testing.T) {
	api := &cfAPI{minTLS: map[string]string{"z1": "1.0"}}
	v := dnsprovider.TLSVersion("1.4")

	if _, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{MinTLS: &v}); err == nil {
		t.Error("UpdateZone of TLS 1.4 succeeded")
	}

	assertWrites(t, api, nil)
}

func TestUpdateZoneWhoseMinimumTLSVersionFailsKeepsTheSettingsWrittenBefore(t *testing.T) {
	api := &cfAPI{
		dnssec: map[string]string{"z1": "disabled"},
		hsts:   map[string]bool{"z1": false},
		minTLS: map[string]string{"z1": "1.0"},
		intercept: func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method != http.MethodPatch || r.URL.Path != "/client/v4/zones/z1/settings/min_tls_version" {
				return false
			}

			writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")

			return true
		},
	}
	on, v := true, dnsprovider.TLS13

	got, err := updateZone(t, newProvider(t, api), dnsprovider.ZoneUpdate{DNSSEC: &on, HSTS: &on, MinTLS: &v})
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("UpdateZone error = %v, want ErrUnauthorized", err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.On}); got != want {
		t.Errorf("UpdateZone = %+v, want %+v", got, want)
	}
}
