package netim_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/netim"
)

func TestNewRefusesBlankCredentialsWithoutEchoingThem(t *testing.T) {
	for _, cfg := range []netim.Config{{}, {ID: "id"}, {Secret: "pw-value"}, {ID: " ", Secret: "pw-value"}, {ID: "id", Secret: "\t"}} {
		p, err := netim.New(cfg, dnsprovider.WithHTTPClient(nonet.Client(t)))
		if p != nil || err == nil {
			t.Fatalf("New(%+v) accepted blank credentials", cfg)
		}

		if strings.Contains(err.Error(), "pw-value") {
			t.Fatalf("error echoes the secret: %v", err)
		}
	}
}

func TestBuildingAProviderSendsNoRequest(t *testing.T) {
	if _, err := netim.New(netim.Config{ID: "id", Secret: "s"}, dnsprovider.WithHTTPClient(nonet.Client(t))); err != nil {
		t.Fatal(err)
	}

	if _, err := netim.Factory().New(map[string]string{"id": "id", "secret": "s"}, dnsprovider.WithHTTPClient(nonet.Client(t))); err != nil {
		t.Fatal(err)
	}
}

func TestFactoryLabelsBothFieldsSecretAndRefusesUnknownOnes(t *testing.T) {
	f := netim.Factory()
	if len(f.Fields) != 2 || f.Fields[0].Name != netim.FieldID || f.Fields[1].Name != netim.FieldSecret || !f.Fields[0].Secret || !f.Fields[1].Secret {
		t.Fatalf("Fields = %+v, want secret id and secret", f.Fields)
	}

	_, err := f.New(map[string]string{"id": "id", "secret": "s", "pasword": "typo-value"}, dnsprovider.WithHTTPClient(nonet.Client(t)))
	if err == nil {
		t.Fatal("built a Provider with an unknown field")
	}

	if strings.Contains(err.Error(), "typo-value") {
		t.Fatalf("error echoes a value: %v", err)
	}

	if _, err := f.New(map[string]string{"id": "id"}, dnsprovider.WithHTTPClient(nonet.Client(t))); err == nil {
		t.Fatal("built a Provider without a secret")
	}
}

func TestTraitsDeclareDSRegistrarOnly(t *testing.T) {
	p, err := netim.New(netim.Config{ID: "id", Secret: "s"})
	if err != nil {
		t.Fatal(err)
	}

	tr := p.Traits()
	if !slices.Equal(tr.Capabilities, []dnsprovider.Capability{dnsprovider.CapDSRegistrar}) || tr.TTLRange() != dnsprovider.DefaultTTLRange {
		t.Fatalf("Traits = %+v", tr)
	}

	if s, ok := tr.Extra("certificateUsage"); !ok || s.Writable {
		t.Fatalf("other record options are not read-only extras: %+v %v", s, ok)
	}
}
