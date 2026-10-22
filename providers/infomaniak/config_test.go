package infomaniak_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/infomaniak"
)

func TestNewRefusesABlankOrMalformedTokenWithoutEchoingIt(t *testing.T) {
	for _, tok := range []string{"", " ", "\t", "tok-value secret", "tok-value\n"} {
		p, err := infomaniak.New(infomaniak.Config{Token: tok}, dnsprovider.WithHTTPClient(nonet.Client(t)))
		if p != nil || err == nil {
			t.Fatalf("New accepted token %q", tok)
		}

		if strings.Contains(err.Error(), "tok-value") {
			t.Fatalf("error echoes the token: %v", err)
		}
	}
}

func TestNewRefusesAnAccountIDThatIsNotAPositiveInteger(t *testing.T) {
	for _, id := range []string{"0", "-1", "abc", "012", "1.5", " 12", "+12", "99999999999999999999999"} {
		p, err := infomaniak.New(infomaniak.Config{Token: "tok-value", AccountID: id}, dnsprovider.WithHTTPClient(nonet.Client(t)))
		if p != nil || err == nil {
			t.Fatalf("New accepted account_id %q", id)
		}

		if strings.Contains(err.Error(), "tok-value") {
			t.Fatalf("error echoes the token: %v", err)
		}
	}
}

func TestBuildingAProviderSendsNoRequest(t *testing.T) {
	for _, cfg := range []infomaniak.Config{{Token: "t"}, {Token: "t", AccountID: "12345"}} {
		if _, err := infomaniak.New(cfg, dnsprovider.WithHTTPClient(nonet.Client(t))); err != nil {
			t.Fatal(err)
		}
	}

	for _, m := range []map[string]string{{"token": "t"}, {"token": "t", "account_id": "12345"}, {"token": "t", "account_id": ""}} {
		if _, err := infomaniak.Factory().New(m, dnsprovider.WithHTTPClient(nonet.Client(t))); err != nil {
			t.Fatalf("Factory().New(%v) = %v", m, err)
		}
	}
}

func TestFactoryHasASecretTokenAndAnOptionalTenantAccountID(t *testing.T) {
	f := infomaniak.Factory()

	want := []dnsprovider.Field{
		{Name: infomaniak.FieldToken, Label: "API token", Secret: true},
		{Name: infomaniak.FieldAccountID, Label: "Account ID", Tenant: true},
	}
	if len(f.Fields) != len(want) || f.Fields[0].Name != want[0].Name || !f.Fields[0].Secret || f.Fields[0].Tenant ||
		f.Fields[1].Name != want[1].Name || f.Fields[1].Secret || !f.Fields[1].Tenant || f.Fields[1].Default != "" {
		t.Fatalf("Fields = %+v, want %+v", f.Fields, want)
	}
}

func TestFactoryRefusesUnknownFieldsAndABadAccountIDWithoutEchoingThem(t *testing.T) {
	f := infomaniak.Factory()

	for _, m := range []map[string]string{
		{"token": "tok-value", "tokn": "typo-value"},
		{"token": "tok-value", "account_id": "nope"},
		{"account_id": "12345"},
		{"token": " "},
	} {
		p, err := f.New(m, dnsprovider.WithHTTPClient(nonet.Client(t)))
		if p != nil || err == nil {
			t.Fatalf("Factory().New(%v) built a Provider", m)
		}

		if strings.Contains(err.Error(), "tok-value") || strings.Contains(err.Error(), "typo-value") {
			t.Fatalf("error echoes a value: %v", err)
		}
	}
}

func TestTraitsDeclareDSRegistrarAndATTLRangeOf60To86400(t *testing.T) {
	p, err := infomaniak.New(infomaniak.Config{Token: "t"})
	if err != nil {
		t.Fatal(err)
	}

	tr := p.Traits()
	if !slices.Equal(tr.Capabilities, []dnsprovider.Capability{dnsprovider.CapDSRegistrar}) || len(tr.Extras) != 0 {
		t.Fatalf("Traits = %+v, want CapDSRegistrar alone and no Extras", tr)
	}

	if !dnsprovider.Can(p, dnsprovider.CapDSRegistrar) {
		t.Fatal("Can(p, CapDSRegistrar) = false")
	}

	if got, want := tr.TTLRange(), (dnsprovider.TTLRange{Min: 60, Max: 86400}); got != want {
		t.Fatalf("TTL range = %+v, want %+v", got, want)
	}
}
