package fields_test

import (
	"errors"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/providertest"
)

var testFields = []dnsprovider.Field{{Name: "token", Label: "API token", Secret: true}}

func TestFactoryRefusesAnUnknownFieldBeforeBuilding(t *testing.T) {
	f := fields.Factory("test", testFields, func(map[string]string, ...dnsprovider.Option) (*providertest.Provider, error) {
		t.Error("built the Provider from a field map with an unknown field")

		return providertest.New(), nil
	})

	_, err := f.New(map[string]string{"token": "t", "tokne": "x"})
	if err == nil {
		t.Fatal("New accepted an unknown field")
	}
}

func TestFactoryReturnsANilProviderWhenBuildingFails(t *testing.T) {
	boom := errors.New("boom")
	f := fields.Factory("test", testFields, func(map[string]string, ...dnsprovider.Option) (*providertest.Provider, error) {
		return nil, boom
	})

	p, err := f.New(map[string]string{"token": "t"})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}

	if p != nil {
		t.Errorf("Provider = %#v, want a nil interface", p)
	}
}

func TestFactoryPassesTheFieldsAndOptionsThrough(t *testing.T) {
	var gotToken string

	var gotOpts int

	f := fields.Factory("test", testFields, func(m map[string]string, opts ...dnsprovider.Option) (*providertest.Provider, error) {
		gotToken, gotOpts = m["token"], len(opts)

		return providertest.New(), nil
	})

	if f.Fields[0] != testFields[0] || len(f.Fields) != 1 {
		t.Errorf("Fields = %+v, want %+v", f.Fields, testFields)
	}

	p, err := f.New(map[string]string{"token": "t1"}, dnsprovider.WithBaseURL("http://x"))
	if err != nil || p == nil {
		t.Fatalf("New = %v, %v", p, err)
	}

	if gotToken != "t1" || gotOpts != 1 {
		t.Errorf("built from token %q with %d options, want t1 with 1", gotToken, gotOpts)
	}
}
