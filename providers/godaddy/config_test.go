package godaddy_test

import (
	"context"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/godaddy"
)

func TestNewMakesNoNetworkCall(t *testing.T) {
	client := nonet.Client(t)

	if _, err := godaddy.New(testConfig, dnsprovider.WithHTTPClient(client)); err != nil {
		t.Fatal(err)
	}

	if _, err := godaddy.Factory().New(map[string]string{"token": testToken}, dnsprovider.WithHTTPClient(client)); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesAConfigWithoutAToken(t *testing.T) {
	if _, err := godaddy.New(godaddy.Config{}); err == nil {
		t.Error("New built a Provider without a token")
	}
}

func TestFactoryFieldsNameEveryConfigFieldAndMarkTheSecrets(t *testing.T) {
	want := []dnsprovider.Field{{Name: "token", Label: "Personal access token", Secret: true}}

	got := godaddy.Factory().Fields
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Fields = %+v, want %+v", got, want)
	}

	if n := reflect.TypeFor[godaddy.Config]().NumField(); n != len(got) {
		t.Errorf("Config has %d fields, Factory names %d", n, len(got))
	}
}

func TestFactoryRefusesMissingAndUnknownFields(t *testing.T) {
	for name, fields := range map[string]map[string]string{
		"no token": {},
		// The v1 API key and secret are gone: the v3 API takes neither.
		"v1 key and secret": {"key": "k", "secret": "s"},
		"unknown field":     {"token": testToken, "key": "k"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := godaddy.Factory().New(fields); err == nil {
				t.Fatalf("Factory built a Provider from %v", fields)
			}
		})
	}
}

func TestFactoryBuildsTheSameProviderAsTheTypedConfig(t *testing.T) {
	api := &gdAPI{}

	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)

	typed, err := godaddy.New(testConfig, dnsprovider.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	built, err := godaddy.Factory().New(map[string]string{"token": testToken}, dnsprovider.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(built, dnsprovider.Provider(typed)) {
		t.Fatalf("Provider from the field map = %+v, from the Config = %+v", built, typed)
	}

	// The handler checks each request carries the token.
	if _, err := built.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err != nil {
		t.Fatal(err)
	}
}
