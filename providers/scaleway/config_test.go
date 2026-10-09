package scaleway_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/scaleway"
)

const project = "11111111-1111-4111-8111-111111111111"

func TestConstructionIsLocalAndFactoryEquivalent(t *testing.T) {
	for _, cfg := range []scaleway.Config{{}, {SecretKey: "secret"}, {SecretKey: "secret", ProjectID: "bad"}, {SecretKey: "secret\n", ProjectID: project}} {
		if _, err := scaleway.New(cfg); err == nil {
			t.Fatalf("accepted invalid config %+v", cfg)
		}
	}
	if _, err := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}); err != nil {
		t.Fatal(err)
	}
	f := scaleway.Factory()
	if len(f.Fields) != 2 || !f.Fields[0].Secret || f.Fields[1].Secret {
		t.Fatalf("fields: %+v", f.Fields)
	}
	if _, err := f.New(map[string]string{"secret_key": "secret", "project_id": project}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.New(map[string]string{"secret_key": "secret", "project_id": project, "access_key": "unused"}); err == nil {
		t.Fatal("accepted unknown field")
	}
}

func TestOptionsAndConstructorPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prefix/dns-zones" || r.Header.Get("X-Auth-Token") != "secret" {
			t.Errorf("options request: %s", r.URL)
		}
		fmt.Fprint(w, `{"total_count":0,"dns_zones":[]}`)
	}))
	defer srv.Close()
	client := srv.Client()
	client.Timeout = 2 * time.Second
	opts := []dnsprovider.Option{dnsprovider.WithBaseURL(srv.URL + "/prefix/"), dnsprovider.WithHTTPClient(client)}
	typed, err := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := scaleway.Factory().New(map[string]string{"secret_key": "secret", "project_id": project}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []dnsprovider.Provider{typed, factory} {
		got, err := p.Account(context.Background())
		if err != nil || got.Tenant.ID != project {
			t.Fatalf("construction: %+v %v", got, err)
		}
	}
	if client.Timeout != 2*time.Second {
		t.Fatal("modified caller timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := typed.Account(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if _, err := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, dnsprovider.WithHTTPClient(nonet.Client(t))); err != nil {
		t.Fatal(err)
	}
}
