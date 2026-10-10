package fields_test

import (
	"errors"
	"maps"
	"slices"
	"strings"
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

	if !slices.EqualFunc(f.Fields, testFields, func(a, b dnsprovider.Field) bool { return a.Name == b.Name }) {
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

var egressFields = []dnsprovider.Field{
	{Name: "token", Label: "API token", Secret: true},
	{Name: "egress", Label: "Egress", Default: "auto", Choices: []string{"auto", "gateway", "agent"}},
}

func TestFactoryFillsInAMissingFieldWithItsDefault(t *testing.T) {
	var got map[string]string

	f := fields.Factory("test", egressFields, func(m map[string]string, _ ...dnsprovider.Option) (*providertest.Provider, error) {
		got = m

		return providertest.New(), nil
	})

	for _, m := range []map[string]string{{"token": "t"}, {"token": "t", "egress": ""}} {
		before := maps.Clone(m)

		if _, err := f.New(m); err != nil {
			t.Fatalf("New(%v) = %v", m, err)
		}

		if got["egress"] != "auto" {
			t.Errorf("New(%v) built with egress %q, want auto", m, got["egress"])
		}

		if !maps.Equal(m, before) {
			t.Errorf("New changed the caller's map to %v", m)
		}
	}
}

func TestFactoryRefusesAValueNotAmongTheChoices(t *testing.T) {
	f := fields.Factory("test", egressFields, func(map[string]string, ...dnsprovider.Option) (*providertest.Provider, error) {
		return providertest.New(), nil
	})

	if _, err := f.New(map[string]string{"token": "t", "egress": "gateway"}); err != nil {
		t.Errorf("New refused a listed choice: %v", err)
	}

	_, err := f.New(map[string]string{"token": "t", "egress": "proxy"})
	if err == nil {
		t.Fatal("New accepted a value not among the choices")
	}

	if strings.Contains(err.Error(), "proxy") {
		t.Errorf("error %q names the value", err)
	}
}

func TestFactoryRefusesADefaultNotAmongTheChoices(t *testing.T) {
	bad := []dnsprovider.Field{
		{Name: "token", Label: "API token", Secret: true},
		{Name: "egress", Label: "Egress", Default: "proxy", Choices: []string{"auto", "gateway", "agent"}},
	}
	f := fields.Factory("test", bad, func(map[string]string, ...dnsprovider.Option) (*providertest.Provider, error) {
		t.Error("built the Provider from a Factory whose Default is not among its Choices")

		return providertest.New(), nil
	})

	for _, m := range []map[string]string{{"token": "t"}, {"token": "t", "egress": "gateway"}} {
		if _, err := f.New(m); err == nil {
			t.Errorf("New(%v) accepted a Factory whose Default is not among its Choices", m)
		}
	}
}
