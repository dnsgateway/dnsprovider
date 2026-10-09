package hetzner_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/hetzner"
)

func TestConstructionAndEmptyAccount(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer project-token" {
			t.Error("missing project bearer token")
		}
		if r.URL.Path != "/zones" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"zones":[],"meta":{"pagination":{"page":1,"next_page":null}}}`))
	}))
	defer s.Close()
	p, err := hetzner.New(hetzner.Config{Token: "project-token"}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	f := hetzner.Factory()
	if len(f.Fields) != 1 || f.Fields[0].Name != "token" || !f.Fields[0].Secret {
		t.Fatalf("credentials: %+v", f.Fields)
	}
	q, err := f.New(map[string]string{"token": "project-token"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("construction made network requests")
	}
	for _, provider := range []dnsprovider.Provider{p, q} {
		a, err := provider.Account(context.Background())
		if err != nil || a.Tenant.ID != "" || a.Tenant.Name != "" || len(a.Nameservers) != 0 {
			t.Fatalf("Account = %+v, %v", a, err)
		}
	}
	if _, err := hetzner.New(hetzner.Config{}); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, err := f.New(map[string]string{"token": "project-token", "project": "1"}); err == nil {
		t.Fatal("unknown field accepted")
	}
}
