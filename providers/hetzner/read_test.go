package hetzner_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/hetzner"
	"github.com/dnsgateway/dnsprovider/rest"
)

func discoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/zones" && r.URL.Query().Get("per_page") != "50" {
			t.Error("Zone page exceeds documented limit")
		}
		switch r.URL.Path {
		case "/zones":
			if r.URL.Query().Get("page") == "1" {
				_, _ = w.Write([]byte(`{"zones":[{"id":1,"name":"example.com","ttl":300,"mode":"primary","status":"ok","authoritative_nameservers":{"assigned":["hydrogen.ns.hetzner.com."]}}],"meta":{"pagination":{"page":1,"next_page":2}}}`))
			} else {
				_, _ = w.Write([]byte(`{"zones":[{"id":2,"name":"example.net","ttl":300,"status":"updating"}],"meta":{"pagination":{"page":2,"next_page":null}}}`))
			}
		case "/zones/1", "/zones/example.com":
			_, _ = w.Write([]byte(`{"zone":{"id":1,"name":"example.com","ttl":300,"mode":"primary","status":"ok","authoritative_nameservers":{"assigned":["hydrogen.ns.hetzner.com."]}}}`))
		case "/zones/1/rrsets":
			_, _ = w.Write([]byte(`{"rrsets":[{"name":"@","type":"A","ttl":null,"labels":{"team":"dns"},"protection":{"change":true},"records":[{"value":"192.0.2.1","comment":"first"},{"value":"192.0.2.2"}]},{"name":"*.sub","type":"MX","ttl":600,"records":[{"value":"10 mail"}]},{"name":"@","type":"SOA","ttl":null,"records":[{"value":"ns. hostmaster. 123 3600 600 86400 60"}]},{"name":"_svc","type":"HTTPS","ttl":300,"records":[{"value":"1 . alpn=\"h2\""}]}],"meta":{"pagination":{"page":1,"next_page":null}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"missing"}}`))
		}
	}))
}

func TestDiscoveryAndRecordExpansion(t *testing.T) {
	s := discoveryServer(t)
	defer s.Close()
	p, _ := hetzner.New(hetzner.Config{Token: "secret"}, dnsprovider.WithBaseURL(s.URL))
	set, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."})
	zones := set.Zones

	if err != nil || len(zones) != 1 {
		t.Fatalf("Zones = %+v,%v", zones, err)
	}

	if set.Partial {
		t.Error("Zones is a Partial View, want a full view")
	}

	z, err := p.Zone(context.Background(), "EXAMPLE.COM.")
	if err != nil || z.State != dnsprovider.HostingActive || z.Nameservers[0] != "hydrogen.ns.hetzner.com" {
		t.Fatalf("Zone = %+v,%v", z, err)
	}
	if zones[0].ID != z.ID || zones[0].State != z.State {
		t.Fatal("discovery differs from lookup")
	}
	rs, err := p.Records(context.Background(), z, dnsprovider.RecordFilter{})
	if err != nil || len(rs.Records) != 5 || rs.Serial != 123 {
		t.Fatalf("Records = %+v,%v", rs, err)
	}

	if rs.Partial {
		t.Error("Records is a Partial View, want a full view")
	}

	if rs.Records[0].Name != "example.com" || rs.Records[0].TTL != 300 || rs.Records[0].ID == rs.Records[1].ID || rs.Records[0].Extras[hetzner.ExtraComment] != "first" || rs.Records[0].Extras[hetzner.ExtraLabels] != `{"team":"dns"}` {
		t.Fatalf("expanded = %+v", rs.Records)
	}
	for _, r := range rs.Records {
		if err := hetzner.Factory().CheckExtras(r); err != nil {
			t.Errorf("Factory does not declare the extras of %+v: %v", r, err)
		}
	}
	if rs.Records[2].Name != "*.sub.example.com" || rs.Records[2].Value != "10 mail.example.com." || rs.Records[2].TTL != 600 {
		t.Fatalf("MX = %+v", rs.Records[2])
	}
	filtered, err := p.Records(context.Background(), z, dnsprovider.RecordFilter{Type: "mx", Contains: "SUB.EXAMPLE.COM."})
	if err != nil || len(filtered.Records) != 1 {
		t.Fatalf("filtered=%+v,%v", filtered, err)
	}
	unknown, err := p.Records(context.Background(), z, dnsprovider.RecordFilter{Type: "NOSUCHTYPE"})
	if err != nil || len(unknown.Records) != 0 {
		t.Fatalf("unsupported filter=%+v,%v", unknown, err)
	}
	_, err = p.Zone(context.Background(), "absent.com")
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("missing=%v", err)
	}
}

func TestPaginationAndMalformedResponses(t *testing.T) {
	for _, body := range []string{`{}`, `{"zones":null,"meta":{"pagination":{"page":1}}}`, `{"zones":[],"meta":{"pagination":{"page":1,"next_page":3}}}`, `{"zones":[],"meta":{"pagination":{"page":1,"next_page":1}}}`, `{"zones":[{}],"meta":{"pagination":{"page":1,"next_page":null}}}`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer s.Close()
			p, _ := hetzner.New(hetzner.Config{Token: "secret"}, dnsprovider.WithBaseURL(s.URL))
			if _, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
				t.Fatal("malformed listing accepted")
			}
			if _, err := p.Account(context.Background()); err == nil {
				t.Fatal("malformed Account accepted")
			}
		})
	}
	t.Run("repeated inventory", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			var next any
			if page == 1 {
				next = 2
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"zones": []map[string]any{{"id": 1, "name": "example.com", "ttl": 300}}, "meta": map[string]any{"pagination": map[string]any{"page": page, "next_page": next}}})
		}))
		defer s.Close()
		p, _ := hetzner.New(hetzner.Config{Token: "secret"}, dnsprovider.WithBaseURL(s.URL))
		_, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
		if !errors.Is(err, rest.ErrSamePage) {
			t.Fatalf("repeated page=%v", err)
		}
	})
}

func TestRecordsExhaustPaginationAndRejectMissingValues(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"complete", `{"rrsets":[{"name":"two","type":"TXT","ttl":null,"records":[{"value":"\"text\""}]}],"meta":{"pagination":{"page":2,"next_page":null,"total_entries":2}}}`, 2},
		{"missing value", `{"rrsets":[{"name":"two","type":"TXT","records":[{}]}],"meta":{"pagination":{"page":2,"next_page":null}}}`, 0},
		{"truncated", `{"rrsets":[],"meta":{"pagination":{"page":2,"next_page":null,"total_entries":2}}}`, 0},
		{"repeated", `{"rrsets":[{"name":"one","type":"A","records":[{"value":"192.0.2.1"}]}],"meta":{"pagination":{"page":2,"next_page":3}}}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/zones/1" {
					_, _ = w.Write([]byte(`{"zone":{"id":1,"name":"example.com","ttl":300,"mode":"primary"}}`))
					return
				}
				if r.URL.Query().Get("per_page") != "100" {
					t.Error("RRset page size")
				}
				if r.URL.Query().Get("page") == "1" {
					_, _ = w.Write([]byte(`{"rrsets":[{"name":"one","type":"A","ttl":null,"records":[{"value":"192.0.2.1"}]}],"meta":{"pagination":{"page":1,"next_page":2,"total_entries":2}}}`))
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer s.Close()
			p, _ := hetzner.New(hetzner.Config{Token: "secret"}, dnsprovider.WithBaseURL(s.URL))
			rs, err := p.Records(context.Background(), testZone, dnsprovider.RecordFilter{})
			if tc.want > 0 {
				if err != nil || len(rs.Records) != tc.want {
					t.Fatalf("inventory=%+v,%v", rs, err)
				}
			} else if err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
}
