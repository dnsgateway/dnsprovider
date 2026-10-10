package ovhcloud_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/ovhcloud"
)

var validFields = map[string]string{"application_key": appKey, "application_secret": appSecret, "consumer_key": consumerKey}

func TestFactoryDescribesCredentialsAndEndpoint(t *testing.T) {
	f := ovhcloud.Factory()

	want := []struct {
		name   string
		secret bool
	}{{"application_key", true}, {"application_secret", true}, {"consumer_key", true}, {"endpoint", false}}
	if len(f.Fields) != len(want) {
		t.Fatalf("Fields = %+v", f.Fields)
	}

	for i, w := range want {
		if f.Fields[i].Name != w.name || f.Fields[i].Secret != w.secret || f.Fields[i].Label == "" {
			t.Errorf("Field %d = %+v, want %s secret=%v", i, f.Fields[i], w.name, w.secret)
		}
	}

	if len(f.Capabilities) != 0 {
		t.Errorf("Capabilities = %v; no Zone writes are implemented", f.Capabilities)
	}
}

func TestConstructionValidatesWithoutNetwork(t *testing.T) {
	client := nonet.Client(t)

	for _, endpoint := range []string{"", "ovh-eu", "ovh-ca", "ovh-us"} {
		cfg := ovhcloud.Config{ApplicationKey: appKey, ApplicationSecret: appSecret, ConsumerKey: consumerKey, Endpoint: endpoint}
		if _, err := ovhcloud.New(cfg, dnsprovider.WithHTTPClient(client)); err != nil {
			t.Errorf("New(endpoint %q) = %v", endpoint, err)
		}

		fields := map[string]string{"application_key": appKey, "application_secret": appSecret, "consumer_key": consumerKey}
		if endpoint != "" {
			fields["endpoint"] = endpoint
		}

		if _, err := ovhcloud.Factory().New(fields, dnsprovider.WithHTTPClient(client)); err != nil {
			t.Errorf("Factory().New(endpoint %q) = %v", endpoint, err)
		}
	}

	for name, cfg := range map[string]ovhcloud.Config{
		"no application key":    {ApplicationSecret: appSecret, ConsumerKey: consumerKey},
		"no application secret": {ApplicationKey: appKey, ConsumerKey: consumerKey},
		"no consumer key":       {ApplicationKey: appKey, ApplicationSecret: appSecret},
		"blank consumer key":    {ApplicationKey: appKey, ApplicationSecret: appSecret, ConsumerKey: " \t"},
		"unknown endpoint":      {ApplicationKey: appKey, ApplicationSecret: appSecret, ConsumerKey: consumerKey, Endpoint: "kimsufi-eu"},
		"endpoint URL":          {ApplicationKey: appKey, ApplicationSecret: appSecret, ConsumerKey: consumerKey, Endpoint: "https://eu.api.ovh.com/1.0"},
	} {
		_, err := ovhcloud.New(cfg, dnsprovider.WithHTTPClient(client))
		if err == nil {
			t.Errorf("%s: accepted", name)

			continue
		}

		for _, secret := range []string{appSecret, consumerKey} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: error %q holds a credential", name, err)
			}
		}
	}

	extra := map[string]string{"application_key": appKey, "application_secret": appSecret, "consumer_key": consumerKey, "region": "eu"}
	if _, err := ovhcloud.Factory().New(extra, dnsprovider.WithHTTPClient(client)); err == nil || !strings.Contains(err.Error(), "region") {
		t.Errorf("unknown field: %v", err)
	}

	if _, err := ovhcloud.Factory().New(map[string]string{"application_key": appKey}, dnsprovider.WithHTTPClient(client)); err == nil {
		t.Error("missing secrets accepted")
	}
}

func TestTypedAndFactoryProvidersBehaveAlike(t *testing.T) {
	f := newFake(t)
	typed := f.provider(t)

	built, err := ovhcloud.Factory().New(validFields, dnsprovider.WithBaseURL(f.srv.URL), dnsprovider.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range []dnsprovider.Provider{typed, built} {
		a, err := p.Account(context.Background())
		if err != nil || a.Tenant.ID != "ab12345-ovh" || a.Tenant.Name != "Example SAS" || a.Nameservers != nil {
			t.Fatalf("Account = %+v, %v", a, err)
		}
	}
}

func TestDefaultEndpointIsEurope(t *testing.T) {
	for endpoint, host := range map[string]string{"": "eu.api.ovh.com", "ovh-eu": "eu.api.ovh.com", "ovh-ca": "ca.api.ovh.com", "ovh-us": "api.us.ovhcloud.com"} {
		var seen []string

		client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			seen = append(seen, r.URL.String())

			return nil, errors.New("offline")
		})}

		p, err := ovhcloud.New(ovhcloud.Config{ApplicationKey: appKey, ApplicationSecret: appSecret, ConsumerKey: consumerKey, Endpoint: endpoint}, dnsprovider.WithHTTPClient(client))
		if err != nil {
			t.Fatal(err)
		}

		if _, err := p.Account(context.Background()); err == nil {
			t.Fatal("offline Account succeeded")
		}

		if len(seen) == 0 || seen[0] != "https://"+host+"/1.0/auth/time" {
			t.Errorf("endpoint %q sent %v, want the time API of %s first", endpoint, seen, host)
		}

		for _, u := range seen {
			if strings.Contains(u, "/me") {
				t.Errorf("endpoint %q sent an authenticated call %s without a clock", endpoint, u)
			}
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientTimeoutCancellationAndRedactedLogs(t *testing.T) {
	f := newFake(t)
	f.fail["GET /me"] = []int{http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable}

	var logs bytes.Buffer

	client := f.srv.Client()
	client.Timeout = 5 * time.Second
	p := f.provider(t, dnsprovider.WithHTTPClient(client), dnsprovider.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))))

	_, err := p.Account(context.Background())
	if err == nil || client.Timeout != 5*time.Second {
		t.Fatalf("Account = %v", err)
	}

	for _, secret := range []string{appSecret, consumerKey} {
		if strings.Contains(err.Error(), secret) || strings.Contains(logs.String(), secret) {
			t.Fatalf("credential leaked: %v\n%s", err, logs.String())
		}
	}

	if !strings.Contains(logs.String(), "retry") {
		t.Fatalf("no retry diagnostics: %s", logs.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := p.Account(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Account = %v", err)
	}
}
