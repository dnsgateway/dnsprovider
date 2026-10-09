package porkbun_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
)

func TestConstructorsValidateLocallyAndFactoryMatchesTypedConfig(t *testing.T) {
	f := porkbun.Factory()
	if len(f.Fields) != 2 {
		t.Fatalf("Fields=%+v", f.Fields)
	}
	for _, fd := range f.Fields {
		if !fd.Secret || fd.Label == "" || (fd.Name != "key" && fd.Name != "secret") {
			t.Fatalf("field=%+v", fd)
		}
	}
	for _, m := range []map[string]string{nil, {"key": "test-key"}, {"secret": "test-secret"}, {"key": "test-key", "secret": "test-secret", "typo": "credential-value"}} {
		p, err := f.New(m, dnsprovider.WithBaseURL(":invalid endpoint"))
		if err == nil || p != nil || strings.Contains(err.Error(), "credential-value") || strings.Contains(err.Error(), "test-secret") {
			t.Fatalf("New=%v,%v", p, err)
		}
	}
	for _, cfg := range []porkbun.Config{{}, {Key: "k"}, {Secret: "s"}, {Key: "  ", Secret: "s"}} {
		if _, err := porkbun.New(cfg); err == nil {
			t.Errorf("accepted missing configuration")
		}
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"SUCCESS","credentialsValid":true,"account":"alice","scopes":["read","dns"]}`))
	}))
	defer s.Close()
	opts := []dnsprovider.Option{dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client())}
	typed, err := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := f.New(map[string]string{"key": "test-key", "secret": "test-secret"}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := typed.Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := mapped.Account(context.Background())
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("constructors disagree: %+v %+v %v", a, b, err)
	}
}

func TestAccountRequiresValidatedCredentialsAndDNSPermission(t *testing.T) {
	for _, body := range []string{`{"status":"SUCCESS","yourIp":"192.0.2.1"}`, `{"status":"SUCCESS","credentialsValid":true,"scopes":["read"]}`, `{"status":"ERROR","code":"INVALID_API_KEYS_002","message":"wrong credentials"}`, `{"status":"ERROR","code":"IP_NOT_ALLOWED","message":"wrong source"}`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer s.Close()
			p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
			_, err := p.Account(context.Background())
			if !errors.Is(err, dnsprovider.ErrUnauthorized) {
				t.Fatalf("Account error=%v", err)
			}
		})
	}
}
