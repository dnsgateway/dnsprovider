package namecheap_test

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/namecheap"
)

// noNetwork is a transport that fails the test on any request.
type noNetwork struct{ t *testing.T }

func (n noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	n.t.Errorf("building the Provider sent %s %s", r.Method, r.URL)

	return nil, errors.New("no network")
}

var testFields = map[string]string{"user": "apiuser", "key": "apikey", "client_ip": "192.0.2.10"}

func TestNewMakesNoNetworkCall(t *testing.T) {
	client := &http.Client{Transport: noNetwork{t}}

	if _, err := namecheap.New(testConfig, dnsprovider.WithHTTPClient(client)); err != nil {
		t.Fatal(err)
	}

	if _, err := namecheap.Factory().New(testFields, dnsprovider.WithHTTPClient(client)); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesAConfigWithoutUserKeyAndIPv4ClientIP(t *testing.T) {
	for _, cfg := range []namecheap.Config{
		{},
		{Key: "apikey", ClientIP: "192.0.2.10"},
		{User: "apiuser", ClientIP: "192.0.2.10"},
		{User: "apiuser", Key: "apikey"},
		{User: "apiuser", Key: "apikey", ClientIP: "not-an-ip"},
		{User: "apiuser", Key: "apikey", ClientIP: "2001:db8::1"},
		{User: "apiuser", Key: "apikey", ClientIP: "::ffff:192.0.2.10"},
		{User: "apiuser", Key: "apikey", ClientIP: "192.0.2"},
	} {
		_, err := namecheap.New(cfg)
		if err == nil {
			t.Errorf("New(%+v) built a Provider", cfg)

			continue
		}

		if strings.Contains(err.Error(), "apikey") {
			t.Errorf("New(%+v) = %q, want an error without the API key", cfg, err)
		}
	}
}

func TestFactoryFieldsNameEveryConfigFieldAndMarkTheKeySecret(t *testing.T) {
	want := []dnsprovider.Field{
		{Name: "user", Label: "API user"},
		{Name: "key", Label: "API key", Secret: true},
		{Name: "client_ip", Label: "Whitelisted client IPv4"},
	}

	got := namecheap.Factory().Fields
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Fields = %+v, want %+v", got, want)
	}

	if n := reflect.TypeFor[namecheap.Config]().NumField(); n != len(got) {
		t.Errorf("Config has %d fields, Factory names %d", n, len(got))
	}
}

func TestFactoryRefusesMissingAndUnknownFields(t *testing.T) {
	for name, fields := range map[string]map[string]string{
		"no client IP":  {"user": "apiuser", "key": "apikey"},
		"unknown field": {"user": "apiuser", "key": "apikey", "client_ip": "192.0.2.10", "token": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := namecheap.Factory().New(fields); err == nil {
				t.Fatalf("Factory built a Provider from %v", fields)
			}
		})
	}
}

func TestFactoryBuildsTheSameProviderAsTheTypedConfig(t *testing.T) {
	typed, err := namecheap.New(testConfig, dnsprovider.WithBaseURL("http://127.0.0.1:1/xml.response"))
	if err != nil {
		t.Fatal(err)
	}

	built, err := namecheap.Factory().New(testFields, dnsprovider.WithBaseURL("http://127.0.0.1:1/xml.response"))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(built, dnsprovider.Provider(typed)) {
		t.Fatalf("Provider from the field map = %+v, from the Config = %+v", built, typed)
	}
}
