package cloudflare_test

import (
	"context"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

func TestNewMakesNoNetworkCall(t *testing.T) {
	client := nonet.Client(t)

	if _, err := cloudflare.New(cloudflare.Config{Token: testToken}, dnsprovider.WithHTTPClient(client)); err != nil {
		t.Fatal(err)
	}

	if _, err := cloudflare.Factory().New(map[string]string{"token": testToken}, dnsprovider.WithHTTPClient(client)); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesAConfigWithoutAToken(t *testing.T) {
	if _, err := cloudflare.New(cloudflare.Config{TenantID: acc1}); err == nil {
		t.Fatal("New built a Provider without a token")
	}
}

func TestNewRefusesATenantIDThatIsNotACloudflareAccountID(t *testing.T) {
	for _, id := range []string{"acc1", acc1[:31], acc1 + "0", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef0123456789abcdeg", " " + acc1} {
		if _, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: id}); err == nil {
			t.Errorf("New took Tenant ID %q", id)
		}

		if _, err := cloudflare.Factory().New(map[string]string{"token": testToken, "tenant_id": id}); err == nil {
			t.Errorf("Factory took Tenant ID %q", id)
		}
	}

	if _, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: acc1}); err != nil {
		t.Errorf("New refused Tenant ID %q: %v", acc1, err)
	}
}

func TestFactoryFieldsNameEveryConfigFieldAndMarkTheTokenSecretAndTheTenant(t *testing.T) {
	want := []dnsprovider.Field{
		{Name: "token", Label: "API token", Secret: true},
		{Name: "tenant_id", Label: "Account ID", Tenant: true},
	}

	got := cloudflare.Factory().Fields
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Fields = %+v, want %+v", got, want)
	}

	if n := reflect.TypeFor[cloudflare.Config]().NumField(); n != len(got) {
		t.Errorf("Config has %d fields, Factory names %d", n, len(got))
	}
}

func TestFactoryRefusesMissingAndUnknownFields(t *testing.T) {
	for name, fields := range map[string]map[string]string{
		"no token":      {"tenant_id": acc1},
		"empty token":   {"token": ""},
		"unknown field": {"token": testToken, "secret": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := cloudflare.Factory().New(fields); err == nil {
				t.Fatalf("Factory built a Provider from %v", fields)
			}
		})
	}
}

func TestFactoryBuildsTheSameProviderAsTheTypedConfig(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}}

	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)

	typed, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: acc1}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatal(err)
	}

	built, err := cloudflare.Factory().New(map[string]string{"token": testToken, "tenant_id": acc1}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatal(err)
	}

	want, err := typed.Zones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}

	got, err := built.Zones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, want) || len(got) != 1 {
		t.Fatalf("Zones from the field map = %+v, from the Config = %+v", got, want)
	}
}
