package gandi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
	"github.com/dnsgateway/dnsprovider/rest"
)

func TestZoneDiscoveryExhaustsShortPagesAndSharesLookupState(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/domains" {
			_, _ = w.Write([]byte(`{"fqdn":"example.org"}`))
			return
		}
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(`[{"fqdn":"unrelated.net"}]`))
		case "2":
			_, _ = w.Write([]byte(`[{"fqdn":"example.org"}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer s.Close()
	p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	zones, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE.ORG."})
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0].State != dnsprovider.HostingUnknown {
		t.Fatalf("Zones = %+v", zones)
	}
	exact, err := p.Zone(context.Background(), "EXAMPLE.ORG.")
	if err != nil || exact.ID != zones[0].ID || exact.State != zones[0].State {
		t.Fatalf("lookup = %+v %v", exact, err)
	}
}

func TestReadFailuresHaveTypedErrorsAndRedactToken(t *testing.T) {
	for _, status := range []int{401, 403, 404, 409, 429} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]any{"code": status, "message": "echo pat_test"})
			}))
			defer s.Close()
			p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Account(context.Background())
			var api *dnsprovider.APIError
			if !errors.As(err, &api) || strings.Contains(err.Error(), "pat_test") {
				t.Fatalf("error = %v", err)
			}
			want := map[int]error{401: dnsprovider.ErrUnauthorized, 403: dnsprovider.ErrUnauthorized, 404: dnsprovider.ErrNotFound, 409: dnsprovider.ErrConflict, 429: dnsprovider.ErrRateLimited}[status]
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			if status == 429 && api.RetryAfter == 0 {
				t.Fatal("lost retry interval")
			}
		})
	}
}

func TestMalformedAndFailedSuccessResponsesAreRejected(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `[{"fqdn":""}]`, `{"code":403,"message":"denied"}`, `not-json`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer s.Close()
			p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.Account(context.Background()); err == nil {
				t.Fatal("accepted malformed/error body")
			}
		})
	}
}

func TestEmptyAccountVerifiesAccessAndRepeatedPagesFail(t *testing.T) {
	for _, body := range []string{`[]`, `[{"fqdn":"example.org"}]`} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; _, _ = w.Write([]byte(body)) }))
			defer s.Close()
			p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
			if err != nil {
				t.Fatal(err)
			}
			info, err := p.Account(context.Background())
			if body == `[]` {
				if err != nil || calls != 1 || info.Tenant.ID != "" {
					t.Fatalf("empty Account = %+v %v (%d calls)", info, err, calls)
				}
			} else if !errors.Is(err, rest.ErrSamePage) || calls != 2 {
				t.Fatalf("repeat = %v (%d calls)", err, calls)
			}
		})
	}
}

func TestRecordFiltersAndSOASerial(t *testing.T) {
	_, p := newService(t, aSet("*", 300, "192.0.2.1"), map[string]any{"rrset_name": "@", "rrset_type": "SOA", "rrset_ttl": 300, "rrset_values": []string{"ns.example.org. hostmaster.example.org. 123 10800 3600 604800 300"}})
	for _, filter := range []dnsprovider.RecordFilter{{Type: "a", Contains: "EXAMPLE.ORG."}, {Type: "a"}, {Contains: "*.EXAMPLE.ORG."}, {Type: "NOSUCHTYPE"}} {
		rs, err := p.Records(context.Background(), testZone, filter)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if filter.Type == "NOSUCHTYPE" {
			want = 0
		}
		if len(rs.Records) != want || rs.Serial != 123 {
			t.Fatalf("filter %+v = %+v", filter, rs)
		}
	}
}

func TestSupportedTypesRoundTrip(t *testing.T) {
	fixtures := []dnsprovider.Record{
		{Name: "@", Type: "A", Value: "192.0.2.1", TTL: 300},
		{Name: "*", Type: "AAAA", Value: "2001:db8::1", TTL: 300},
		{Name: "alias", Type: "CNAME", Value: "target.example.net", TTL: 300},
		{Name: "@", Type: "MX", Value: "10 mail.example.net", TTL: 300},
		{Name: "@", Type: "TXT", Value: "v=spf1 -all", TTL: 300},
		{Name: "delegation", Type: "NS", Value: "ns.example.net", TTL: 300},
		{Name: "_sip._tcp", Type: "SRV", Value: "10 5 443 host.example.net", TTL: 300},
		{Name: "@", Type: "CAA", Value: `0 issue "letsencrypt.org"`, TTL: 300},
	}
	_, p := newService(t)
	for _, r := range fixtures {
		got, err := p.CreateRecord(context.Background(), testZone, r)
		if err != nil {
			t.Fatal(err)
		}
		if got.ID == "" || got.Type != r.Type || got.TTL != r.TTL {
			t.Fatalf("roundtrip = %+v", got)
		}
	}
	if len(read(t, p)) != len(fixtures) {
		t.Fatal("missing roundtrip records")
	}
}

func TestFailedSuccessEnvelopeKeepsHTTPStatusAbsent(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":403,"message":"denied"}`))
	}))
	defer s.Close()
	p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Account(context.Background())
	var api *dnsprovider.APIError
	if !errors.As(err, &api) || !errors.Is(err, dnsprovider.ErrUnauthorized) || api.StatusCode != 0 {
		t.Fatalf("success envelope = %v", err)
	}
}
