package cloudns_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudns"
)

func TestConfigRequiresPasswordAndExactlyOneIdentity(t *testing.T) {
	for _, cfg := range []cloudns.Config{{}, {Password: "secret"}, {AuthID: "123"}, {Password: "secret", AuthID: "123", SubAuthID: "456"}} {
		if _, err := cloudns.New(cfg); err == nil {
			t.Fatalf("accepted invalid configuration")
		}
	}
	for _, cfg := range []cloudns.Config{{Password: "secret", AuthID: "123"}, {Password: "secret", SubAuthID: "456"}, {Password: "secret", SubAuthUser: "user"}} {
		if _, err := cloudns.New(cfg); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAccountAuthenticatesAllModesWithFormBody(t *testing.T) {
	for key, cfg := range map[string]cloudns.Config{"auth-id": {Password: "secret", AuthID: "123"}, "sub-auth-id": {Password: "secret", SubAuthID: "456"}, "sub-auth-user": {Password: "secret", SubAuthUser: "user"}} {
		t.Run(key, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RawQuery != "" || r.Method != http.MethodPost {
					t.Error("credentials must use POST form")
				}
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.PostForm.Get("auth-password") != "secret" || r.PostForm.Get(key) == "" {
					t.Error("missing auth")
				}
				switch r.URL.Path {
				case "/login/login.json":
					fmt.Fprint(w, `{"status":"Success","statusDescription":"Success login."}`)
				case "/dns/list-zones.json":
					fmt.Fprint(w, `[]`)
				default:
					t.Error(r.URL.Path)
				}
			}))
			defer s.Close()
			p, err := cloudns.New(cfg, dnsprovider.WithBaseURL(s.URL))
			if err != nil {
				t.Fatal(err)
			}
			info, err := p.Account(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if info.Tenant.ID != "" || len(info.Nameservers) > 0 {
				t.Errorf("unknown account info invented: %+v", info)
			}
		})
	}
}

func TestFactoryMatchesTypedConstructorAndValidatesSecretFields(t *testing.T) {
	f := cloudns.Factory()
	if len(f.Fields) != 4 {
		t.Fatal(f.Fields)
	}
	for _, fd := range f.Fields {
		if !fd.Secret || fd.Label == "" {
			t.Fatal(fd)
		}
	}
	for _, m := range []map[string]string{nil, {"password": "secret"}, {"password": "secret", "auth_id": "123", "sub_auth_user": "other"}, {"password": "secret", "auth_id": "123", "unknown": "hidden"}} {
		if p, err := f.New(m); err == nil || p != nil {
			t.Fatal("accepted invalid fields")
		}
	}
	for _, mode := range []string{"auth_id", "sub_auth_id", "sub_auth_user"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				if r.PostForm.Get(strings.ReplaceAll(mode, "_", "-")) != "123" || r.PostForm.Get("auth-password") != "secret" {
					t.Error("constructor authentication differs")
				}
				if r.URL.Path == "/login/login.json" {
					fmt.Fprint(w, `{"status":"Success"}`)
				} else {
					fmt.Fprint(w, `[]`)
				}
			}))
			defer s.Close()
			cfg := cloudns.Config{Password: "secret"}
			switch mode {
			case "auth_id":
				cfg.AuthID = "123"
			case "sub_auth_id":
				cfg.SubAuthID = "123"
			default:
				cfg.SubAuthUser = "123"
			}
			typed, err := cloudns.New(cfg, dnsprovider.WithBaseURL(s.URL))
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := f.New(map[string]string{"password": "secret", mode: "123"}, dnsprovider.WithBaseURL(s.URL))
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []dnsprovider.Provider{typed, mapped} {
				info, err := p.Account(context.Background())
				if err != nil || info.Tenant.ID != "" || len(info.Nameservers) != 0 {
					t.Fatalf("Account = %+v, %v", info, err)
				}
			}
		})
	}
}
