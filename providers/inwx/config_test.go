package inwx_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/inwx"
)

func TestNewRefusesBlankCredentialsWithoutEchoingThem(t *testing.T) {
	for _, cfg := range []inwx.Config{
		{},
		{Username: "user"},
		{Password: "pw-value"},
		{Username: " ", Password: "pw-value"},
		{Username: "user", Password: "\t"},
	} {
		p, err := inwx.New(cfg, dnsprovider.WithHTTPClient(nonet.Client(t)))
		if p != nil || err == nil {
			t.Fatalf("New(%+v) accepted blank credentials", cfg)
		}

		if strings.Contains(err.Error(), "pw-value") {
			t.Fatalf("error echoes the password: %v", err)
		}
	}
}

func TestNewRefusesASharedSecretThatIsNotBase32WithoutEchoingIt(t *testing.T) {
	for _, secret := range []string{"not base32 at all!", "JBSWY3DP1", "0000"} {
		p, err := inwx.New(inwx.Config{Username: "user", Password: "pw", SharedSecret: secret}, dnsprovider.WithHTTPClient(nonet.Client(t)))
		if p != nil || err == nil {
			t.Fatalf("New accepted the shared secret %q", secret)
		}

		if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "shared_secret") {
			t.Fatalf("error = %v, want one naming shared_secret without its value", err)
		}
	}
}

func TestNewTakesASharedSecretInAnyCaseWithOrWithoutPadding(t *testing.T) {
	for _, secret := range []string{"JBSWY3DPEHPK3PXP", "jbswy3dpehpk3pxp", "JBSWY3DPEE======", "jbsw y3dp ee"} {
		if _, err := inwx.New(inwx.Config{Username: "user", Password: "pw", SharedSecret: secret}, dnsprovider.WithHTTPClient(nonet.Client(t))); err != nil {
			t.Fatalf("New refused the shared secret %q: %v", secret, err)
		}
	}
}

func TestBuildingAProviderSendsNoRequest(t *testing.T) {
	if _, err := inwx.New(inwx.Config{Username: "user", Password: "pw", SharedSecret: "JBSWY3DPEHPK3PXP"}, dnsprovider.WithHTTPClient(nonet.Client(t))); err != nil {
		t.Fatal(err)
	}

	if _, err := inwx.Factory().New(map[string]string{"username": "user", "password": "pw"}, dnsprovider.WithHTTPClient(nonet.Client(t))); err != nil {
		t.Fatal(err)
	}
}

func TestFactoryLabelsEveryFieldSecretAndRefusesUnknownOnes(t *testing.T) {
	f := inwx.Factory()

	var names []string

	for _, fd := range f.Fields {
		if !fd.Secret {
			t.Errorf("field %s is not secret", fd.Name)
		}

		names = append(names, fd.Name)
	}

	if !slices.Equal(names, []string{inwx.FieldUsername, inwx.FieldPassword, inwx.FieldSharedSecret}) {
		t.Fatalf("Fields = %v, want username, password, shared_secret", names)
	}

	_, err := f.New(map[string]string{"username": "u", "password": "p", "pasword": "typo-value"}, dnsprovider.WithHTTPClient(nonet.Client(t)))
	if err == nil {
		t.Fatal("built a Provider with an unknown field")
	}

	if strings.Contains(err.Error(), "typo-value") {
		t.Fatalf("error echoes a value: %v", err)
	}

	if _, err := f.New(map[string]string{"username": "u"}, dnsprovider.WithHTTPClient(nonet.Client(t))); err == nil {
		t.Fatal("built a Provider without a password")
	}
}

func TestTraitsDeclareTheTTLRangeAndNoExtras(t *testing.T) {
	p, err := inwx.New(inwx.Config{Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}

	tr := p.Traits()
	if tr.TTLRange() != (dnsprovider.TTLRange{Min: 300, Max: 86400}) || tr.Extras != nil {
		t.Fatalf("Traits = %+v", tr)
	}
}
