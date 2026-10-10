package porkbun_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
)

func TestAccountVerifiesCredentialsForEmptyAccount(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "test-key" || r.Header.Get("X-Secret-Api-Key") != "test-secret" {
			t.Error("missing header credentials")
		}
		if r.URL.Path != "/ping" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "credentialsValid": true, "account": "alice", "scopes": []string{"full"}})
	}))
	defer s.Close()
	p, err := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Account(context.Background())
	if err != nil || a.Tenant.Name != "alice" || len(a.Nameservers) != 0 {
		t.Fatalf("Account()=%+v,%v", a, err)
	}
}

func TestZonesRespectAPIAccessAndNameBoundaries(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/domain/listAll":
			if r.URL.Query().Get("apiAccess") != "yes" {
				t.Error("discovery must request API-access domains")
			}
			w.Write([]byte(`{"status":"SUCCESS","domains":[{"domain":"Example.COM","apiAccess":1,"status":"ACTIVE"},{"domain":"example.community","apiAccess":1},{"domain":"disabled.example.com","apiAccess":0},{"domain":"restricted.example.com","apiAccess":1}]}`))
		case "/dns/retrieve/restricted.example.com":
			w.Write([]byte(`{"status":"ERROR","code":"DOMAIN_NOT_ALLOWED","message":"restricted key"}`))
		default:
			w.Write([]byte(`{"status":"SUCCESS","records":[]}`))
		}
	}))
	defer s.Close()
	p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
	set, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."})
	zs := set.Zones

	if err != nil || len(zs) != 1 || zs[0].ID != "example.com" || zs[0].State != dnsprovider.HostingUnknown {
		t.Fatalf("Zones=%+v,%v", zs, err)
	}

	if set.Partial {
		t.Error("Zones is a Partial View, want a full view")
	}

	z, err := p.Zone(context.Background(), "EXAMPLE.COM.")
	if err != nil || z.ID != zs[0].ID || z.State != zs[0].State {
		t.Fatalf("Zone=%+v,%v", z, err)
	}
}

func TestRecordsRetainNativeIDsAndPresentation(t *testing.T) {
	// Frozen against the official v3.62 DnsRecordsResponse schema.
	fixture, err := os.ReadFile("testdata/records.json")
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixture)
	}))
	defer s.Close()
	p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
	set, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 5 {
		t.Fatalf("Records=%+v,%v", set, err)
	}

	if set.Partial {
		t.Error("Records is a Partial View, want a full view")
	}

	if set.Records[0].ID != "101" || set.Records[0].Name != "Example.COM" || set.Records[0].Value != "10 mail.example.net." || set.Records[0].Extras[porkbun.ExtraNotes] != "keep" {
		t.Errorf("MX=%+v", set.Records[0])
	}
	for _, r := range set.Records {
		if err := porkbun.Factory().CheckExtras(r); err != nil {
			t.Errorf("Factory does not declare the extras of %+v: %v", r, err)
		}
	}
	if set.Records[1].Value != "20 5 443 sip.example.net." || set.Records[2].Value != `hello "world"` || set.Records[4].Value != "1 . alpn=h2" {
		t.Errorf("values=%+v", set.Records)
	}
	filtered, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{Type: "https", Contains: "EXAMPLE.COM."})
	if err != nil || len(filtered.Records) != 1 {
		t.Fatalf("filtered=%+v,%v", filtered, err)
	}
}

func TestRecordFiltersCombineTypeAndTrailingDotBoundary(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"SUCCESS","records":[{"id":"1","name":"WWW.Example.COM.","type":"A","content":"192.0.2.1","ttl":"600"},{"id":"2","name":"www.example.community","type":"A","content":"192.0.2.2","ttl":"600"},{"id":"3","name":"www.example.com","type":"AAAA","content":"2001:db8::1","ttl":"600"}]}`))
	}))
	defer s.Close()
	p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
	set, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{Type: "a", Contains: "EXAMPLE.COM."})
	if err != nil || len(set.Records) != 1 || set.Records[0].ID != "1" {
		t.Fatalf("combined filters=%+v,%v", set, err)
	}
	set, err = p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{Type: "URI"})
	if err != nil || len(set.Records) != 0 {
		t.Fatalf("unsupported type filter=%+v,%v", set, err)
	}
}
