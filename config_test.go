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

func TestFactoryWithoutATTLRangeTakesTheDefault(t *testing.T) {
	if got, want := (dnsprovider.Factory{}).TTLRange(), (dnsprovider.TTLRange{Min: 30, Max: 86400}); got != want {
		t.Errorf("TTLRange() = %+v, want %+v", got, want)
	}

	declared := dnsprovider.TTLRange{Min: 0, Max: 600, Auto: true}
	if got := (dnsprovider.Traits{TTL: declared}).TTLRange(); got != declared {
		t.Errorf("TTLRange() = %+v, want %+v", got, declared)
	}
}

func TestFactoryLooksUpTheRecordExtrasItDeclares(t *testing.T) {
	f := dnsprovider.Traits{Extras: []dnsprovider.ExtraSpec{
		{Key: "proxied", Label: "Proxied", Kind: dnsprovider.ExtraBool, Writable: true, Types: []string{"A", "AAAA", "CNAME"}},
		{Key: "comment", Label: "Comment", Kind: dnsprovider.ExtraString},
	}}

	proxied, ok := f.Extra("proxied")
	if !ok || !proxied.Writable || proxied.Kind != dnsprovider.ExtraBool {
		t.Errorf("Extra(proxied) = %+v, %v", proxied, ok)
	}

	if !proxied.AppliesTo("aaaa") || proxied.AppliesTo("TXT") {
		t.Errorf("proxied applies to AAAA %v, to TXT %v; want true, false", proxied.AppliesTo("aaaa"), proxied.AppliesTo("TXT"))
	}

	if comment, ok := f.Extra("comment"); !ok || !comment.AppliesTo("MX") {
		t.Errorf("Extra(comment) = %+v, %v; want one for every type", comment, ok)
	}

	if _, ok := f.Extra("labels"); ok {
		t.Error("found an extra the Factory does not declare")
	}
}

func TestFactoryOtherExtrasStandForEveryUnnamedKey(t *testing.T) {
	f := dnsprovider.Traits{Extras: []dnsprovider.ExtraSpec{
		{Key: "wire", Label: "Wire value", Kind: dnsprovider.ExtraString},
		{Key: dnsprovider.ExtraOther, Label: "Other fields", Kind: dnsprovider.ExtraJSON},
	}}

	if got, ok := f.Extra("wire"); !ok || got.Key != "wire" {
		t.Errorf("Extra(wire) = %+v, %v", got, ok)
	}

	if got, ok := f.Extra("comment"); !ok || got.Key != dnsprovider.ExtraOther {
		t.Errorf("Extra(comment) = %+v, %v; want the ExtraOther entry", got, ok)
	}
}

func TestFactoryChecksARecordCarriesOnlyTheExtrasItDeclares(t *testing.T) {
	f := dnsprovider.Traits{Extras: []dnsprovider.ExtraSpec{
		{Key: "proxied", Label: "Proxied", Kind: dnsprovider.ExtraBool, Writable: true, Types: []string{"A"}},
		{Key: "comment", Label: "Comment", Kind: dnsprovider.ExtraString},
	}}

	for _, tc := range []struct {
		r  dnsprovider.Record
		ok bool
	}{
		{dnsprovider.Record{Type: "TXT"}, true},
		{dnsprovider.Record{Type: "a", Extras: map[string]string{"proxied": "true", "comment": "x"}}, true},
		{dnsprovider.Record{Type: "TXT", Extras: map[string]string{"proxied": "true"}}, false},
		{dnsprovider.Record{Type: "A", Extras: map[string]string{"labels": "{}"}}, false},
		{dnsprovider.Record{Type: "A", Extras: map[string]string{"proxied": "false"}}, true},
		{dnsprovider.Record{Type: "A", Extras: map[string]string{"proxied": "yes"}}, false},
		{dnsprovider.Record{Type: "A", Extras: map[string]string{"proxied": ""}}, false},
		{dnsprovider.Record{Type: "A", Extras: map[string]string{"comment": "yes"}}, true},
	} {
		if err := f.CheckExtras(tc.r); (err == nil) != tc.ok {
			t.Errorf("CheckExtras(%+v) = %v, want ok %v", tc.r, err, tc.ok)
		}
	}
}

func TestFactoryProxiableTypesComeFromItsProxiedExtra(t *testing.T) {
	if got := (dnsprovider.Factory{}).ProxiableTypes(); got != nil {
		t.Errorf("ProxiableTypes() = %v, want none", got)
	}

	f := dnsprovider.Traits{Extras: []dnsprovider.ExtraSpec{
		{Key: dnsprovider.ExtraOther, Label: "Other", Kind: dnsprovider.ExtraString},
		{Key: dnsprovider.ExtraProxied, Label: "Proxied", Kind: dnsprovider.ExtraBool, Writable: true, Types: []string{"A", "CNAME"}},
	}}
	if got, want := f.ProxiableTypes(), []string{"A", "CNAME"}; !slices.Equal(got, want) {
		t.Errorf("ProxiableTypes() = %v, want %v", got, want)
	}
}
