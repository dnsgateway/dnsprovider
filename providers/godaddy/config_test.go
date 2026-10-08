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

	if _, err := godaddy.Factory().New(map[string]string{"key": testKey, "secret": testSecret}, dnsprovider.WithHTTPClient(client)); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesAConfigWithoutKeyOrSecret(t *testing.T) {
	for _, cfg := range []godaddy.Config{{}, {Key: testKey}, {Secret: testSecret}, {Key: "a:b", Secret: testSecret}} {
		if _, err := godaddy.New(cfg); err == nil {
			t.Errorf("New(%+v) built a Provider", cfg)
		}
	}
}

func TestFactoryFieldsNameEveryConfigFieldAndMarkTheSecrets(t *testing.T) {
	want := []dnsprovider.Field{
		{Name: "key", Label: "API key", Secret: true},
		{Name: "secret", Label: "API secret", Secret: true},
	}

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
		"no secret":     {"key": testKey},
		"no key":        {"secret": testSecret},
		"unknown field": {"key": testKey, "secret": testSecret, "token": "x"},
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

	built, err := godaddy.Factory().New(map[string]string{"key": testKey, "secret": testSecret}, dnsprovider.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(built, dnsprovider.Provider(typed)) {
		t.Fatalf("Provider from the field map = %+v, from the Config = %+v", built, typed)
	}

	// The handler checks each request carries the key and secret.
	if _, err := built.Zones(context.Background()); err != nil {
		t.Fatal(err)
	}
}
