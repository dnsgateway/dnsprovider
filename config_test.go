package dnsprovider_test

import (
	"log/slog"
	"net/http"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestOptionsCarryWhatTheConsumerOwns(t *testing.T) {
	client := &http.Client{}
	logger := slog.New(slog.DiscardHandler)

	o := dnsprovider.NewOptions(
		dnsprovider.WithHTTPClient(client),
		dnsprovider.WithBaseURL("http://127.0.0.1:8080/api"),
		dnsprovider.WithLogger(logger),
	)

	if o.HTTPClient != client {
		t.Errorf("HTTPClient = %p, want %p", o.HTTPClient, client)
	}

	if o.BaseURL != "http://127.0.0.1:8080/api" {
		t.Errorf("BaseURL = %q", o.BaseURL)
	}

	if o.Logger != logger {
		t.Errorf("Logger = %p, want %p", o.Logger, logger)
	}
}

func TestOptionsLeftOutAreEmptyButTheLoggerIsUsable(t *testing.T) {
	o := dnsprovider.NewOptions()

	if o.HTTPClient != nil || o.BaseURL != "" {
		t.Errorf("options = %+v, want no HTTP client and no base URL", o)
	}

	if o.Logger == nil {
		t.Fatal("Logger is nil")
	}

	o.Logger.Info("discarded") // must not panic
}

func TestRegistryListsItsProviderTypesSorted(t *testing.T) {
	newFake := func(map[string]string, ...dnsprovider.Option) (dnsprovider.Provider, error) {
		return nil, nil
	}

	r := dnsprovider.Registry{
		"namecheap":  {New: newFake},
		"cloudflare": {New: newFake},
		"godaddy":    {New: newFake},
	}

	if got, want := r.Types(), []string{"cloudflare", "godaddy", "namecheap"}; !slices.Equal(got, want) {
		t.Fatalf("Types() = %v, want %v", got, want)
	}
}

func TestRegistryBuildsAProviderFromItsFields(t *testing.T) {
	var got map[string]string

	r := dnsprovider.Registry{
		"fake": {
			Fields: []dnsprovider.Field{{Name: "token", Label: "API token", Secret: true}},
			New: func(fields map[string]string, _ ...dnsprovider.Option) (dnsprovider.Provider, error) {
				got = fields

				return nil, nil
			},
		},
	}

	if _, err := r.New("fake", map[string]string{"token": "t"}); err != nil {
		t.Fatal(err)
	}

	if got["token"] != "t" {
		t.Errorf("fields = %v, want token t", got)
	}

	if _, err := r.New("other", nil); err == nil {
		t.Error("an unregistered Provider type built a Provider")
	}
}
