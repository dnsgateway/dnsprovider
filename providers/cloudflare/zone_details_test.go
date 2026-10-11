package cloudflare_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

func TestZoneDetailsUseOneDNSSECResponseForStateAndKeys(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}, dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": true}, minTLS: map[string]string{"z1": "1.2"}}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), newProvider(t, api), "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := []dnsprovider.SigningKey{{DNSKEY: "257 3 13 " + testPublicKey, KeyTag: 16953, DS: []string{"16953 13 2 " + testDigest}}}
	if got.Zone.ID != "z1" || got.Status != (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.On, MinTLS: dnsprovider.TLS12}) || !reflect.DeepEqual(got.SigningKeys, wantKeys) {
		t.Fatalf("details=%+v", got)
	}
	count := 0
	for _, req := range api.Requests() {
		if strings.Contains(req, "/dnssec?") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("DNSSEC requests=%d, want one", count)
	}
}

func TestZoneDetailsRetainAuthorizationDiagnosticsForEachFailedProperty(t *testing.T) {
	for _, path := range []string{"/dnssec", "/settings/security_header", "/settings/min_tls_version"} {
		t.Run(path, func(t *testing.T) {
			api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}, dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": true}, minTLS: map[string]string{"z1": "1.3"}, forbidden: []string{"/client/v4/zones/z1" + path}}
			got, err := dnsprovider.ZoneDetailsOf(context.Background(), newProvider(t, api), "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
			if !errors.Is(err, dnsprovider.ErrUnauthorized) || got.Zone.ID != "z1" {
				t.Fatalf("details=%+v err=%v", got, err)
			}
			outcomes := map[string]dnsprovider.PropertyResult{"/dnssec": got.Properties.DNSSEC, "/settings/security_header": got.Properties.HSTS, "/settings/min_tls_version": got.Properties.MinTLS}
			for property, outcome := range outcomes {
				if property == path {
					var diagnostic *dnsprovider.APIError
					if outcome.State != dnsprovider.PropertyFailed || !errors.As(outcome.Err, &diagnostic) || diagnostic.StatusCode != http.StatusForbidden {
						t.Errorf("failed property=%+v", outcome)
					}
				} else if outcome.State != dnsprovider.PropertyRead || outcome.Err != nil {
					t.Errorf("known property=%+v", outcome)
				}
			}
			if path == "/dnssec" && (got.Properties.SigningKeys.State != dnsprovider.PropertyFailed || !errors.Is(got.Properties.SigningKeys.Err, dnsprovider.ErrUnauthorized)) {
				t.Errorf("keys=%+v", got.Properties.SigningKeys)
			}
		})
	}
}

func TestZoneDetailsPreserveDNSSECStatesAndOptionalKeys(t *testing.T) {
	for _, tt := range []struct {
		state string
		want  dnsprovider.Setting
		keys  int
	}{
		{"disabled", dnsprovider.Off, 0}, {"active", dnsprovider.On, 1}, {"pending", dnsprovider.Pending, 1}, {"pending-disabled", dnsprovider.Pending, 1}, {"error", dnsprovider.Unknown, 1},
	} {
		for _, keys := range []bool{false, true} {
			t.Run(tt.state+map[bool]string{false: "-status", true: "-keys"}[keys], func(t *testing.T) {
				api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}, dnssec: map[string]string{"z1": tt.state}, hsts: map[string]bool{"z1": true}, minTLS: map[string]string{"z1": "1.2"}}
				got, err := dnsprovider.ZoneDetailsOf(context.Background(), newProvider(t, api), "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: keys})
				if err != nil || got.Status.DNSSEC != tt.want || got.Properties.DNSSEC.State != dnsprovider.PropertyRead {
					t.Fatalf("details=%+v err=%v", got, err)
				}
				if keys {
					if len(got.SigningKeys) != tt.keys || got.Properties.SigningKeys.State != dnsprovider.PropertyRead {
						t.Errorf("keys=%+v", got)
					}
				} else if len(got.SigningKeys) != 0 || got.Properties.SigningKeys.State != dnsprovider.PropertyNotRequested {
					t.Errorf("unrequested keys=%+v", got)
				}
			})
		}
	}
}

func TestZoneDetailsAllFailedPropertiesKeepIdentityAndDiagnostics(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}, forbidden: []string{"/client/v4/zones/z1/dnssec", "/client/v4/zones/z1/settings/security_header", "/client/v4/zones/z1/settings/min_tls_version"}}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), newProvider(t, api), "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if got.Zone.ID != "z1" || got.Status != (dnsprovider.ZoneStatus{}) || !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("details=%+v err=%v", got, err)
	}
	for _, outcome := range []dnsprovider.PropertyResult{got.Properties.DNSSEC, got.Properties.HSTS, got.Properties.MinTLS, got.Properties.SigningKeys} {
		if outcome.State != dnsprovider.PropertyFailed || !errors.Is(outcome.Err, dnsprovider.ErrUnauthorized) {
			t.Errorf("failed property=%+v", outcome)
		}
	}
}

func TestZoneDetailsMissingIdentityDoesNotReadProperties(t *testing.T) {
	api := &cfAPI{}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), newProvider(t, api), "missing.example", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if !errors.Is(err, dnsprovider.ErrNotFound) || !reflect.DeepEqual(got, dnsprovider.ZoneDetails{}) {
		t.Fatalf("missing details=%+v err=%v", got, err)
	}
	for _, req := range api.Requests() {
		if strings.Contains(req, "/dnssec") || strings.Contains(req, "/settings/") {
			t.Fatalf("detail request=%s", req)
		}
	}
}

func TestZoneDetailsCancellationRetainsIdentityAndPropertyFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}, dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": true}, intercept: func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/settings/min_tls_version") {
			close(started)
			<-r.Context().Done()
			return true
		}
		return false
	}}
	p := newProvider(t, api)
	done := make(chan struct{})
	var got dnsprovider.ZoneDetails
	var err error
	go func() {
		got, err = dnsprovider.ZoneDetailsOf(ctx, p, "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("detail read did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("detail read did not cancel")
	}
	if got.Zone.ID != "z1" || !errors.Is(err, context.Canceled) || got.Properties.MinTLS.State != dnsprovider.PropertyFailed || !errors.Is(got.Properties.MinTLS.Err, context.Canceled) {
		t.Fatalf("canceled details=%+v err=%v", got, err)
	}
}

func TestZoneListsRemainLightweightWithCombinedDetailSupport(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com"), cfZone("z2", "example.net")}}
	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil || set.Partial || len(set.Zones) != 2 {
		t.Fatalf("list=%+v err=%v", set, err)
	}
	for _, req := range api.Requests() {
		if strings.Contains(req, "/dnssec") || strings.Contains(req, "/settings/") {
			t.Fatalf("list enriched zones with %s", req)
		}
	}
}

func TestZoneDetailsPreserveKnownPropertiesOnOtherTypedFailure(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}, dnssec: map[string]string{"z1": "active"}, minTLS: map[string]string{"z1": "1.2"}, intercept: func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/settings/security_header") {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1015,"message":"rate limited"}]}`))
			return true
		}
		return false
	}}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), newProvider(t, api), "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if !errors.Is(err, dnsprovider.ErrRateLimited) || got.Status.DNSSEC != dnsprovider.On || got.Status.MinTLS != dnsprovider.TLS12 || len(got.SigningKeys) != 1 || got.Properties.HSTS.State != dnsprovider.PropertyFailed || !errors.Is(got.Properties.HSTS.Err, dnsprovider.ErrRateLimited) {
		t.Fatalf("partial details=%+v err=%v", got, err)
	}
}

func TestZoneDetailsSigningKeyDigestsRemainUpperCase(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}, intercept: func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, "/dnssec") {
			res := dnssecResult("active")
			res["digest"] = strings.ToLower(testDigest)
			writeResult(w, res)
			return true
		}
		return false
	}}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), newProvider(t, api), "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil || len(got.SigningKeys) != 1 || !reflect.DeepEqual(got.SigningKeys[0].DS, []string{"16953 13 2 " + testDigest}) {
		t.Fatalf("keys=%+v err=%v", got.SigningKeys, err)
	}
}
