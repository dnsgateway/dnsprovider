package infomaniak_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/infomaniak"
)

func TestZoneDetailsReadsAnEnabledZoneAsDNSSECOn(t *testing.T) {
	f := newFake(t)

	got, err := f.provider().ZoneDetails(context.Background(), exampleCH, dnsprovider.ZoneDetailRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if got.Status.DNSSEC != dnsprovider.On || got.Properties.DNSSEC != (dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}) {
		t.Fatalf("DNSSEC = %v, %+v; want On, read", got.Status.DNSSEC, got.Properties.DNSSEC)
	}
}

func TestZoneDetailsResolvesTheZoneAsRecordCallsDo(t *testing.T) {
	for _, zone := range []dnsprovider.Zone{{ID: "example.ch"}, {Name: "Example.CH."}} {
		got, err := newFake(t).provider().ZoneDetails(context.Background(), zone, dnsprovider.ZoneDetailRequest{})
		if err != nil || got.Status.DNSSEC != dnsprovider.On {
			t.Errorf("%+v: ZoneDetails = %+v, %v; want DNSSEC On", zone, got, err)
		}
	}
}

func TestZoneDetailsReadsADisabledZoneAsDNSSECOff(t *testing.T) {
	f := newFake(t)
	f.script("GET /2/zones/example.ch", http.StatusOK,
		`{"result":"success","data":{"id":4242,"fqdn":"example.ch","dnssec":{"is_enabled":false},"nameservers":["ns11.infomaniak.ch"]}}`)

	got, err := f.provider().ZoneDetails(context.Background(), exampleCH, dnsprovider.ZoneDetailRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if got.Status.DNSSEC != dnsprovider.Off || got.Properties.DNSSEC != (dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}) {
		t.Fatalf("DNSSEC = %v, %+v; want Off, read", got.Status.DNSSEC, got.Properties.DNSSEC)
	}
}

func TestZoneDetailsReportsHSTSMinTLSAndSigningKeysUnsupported(t *testing.T) {
	unsupported := dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported}

	for _, request := range []dnsprovider.ZoneDetailRequest{{}, {SigningKeys: true}} {
		got, err := newFake(t).provider().ZoneDetails(context.Background(), exampleCH, request)
		if err != nil {
			t.Fatalf("%+v: %v", request, err)
		}

		want := dnsprovider.ZoneDetailProperties{DNSSEC: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}, HSTS: unsupported, MinTLS: unsupported}
		if request.SigningKeys {
			want.SigningKeys = unsupported
		}

		if got.Properties != want || got.SigningKeys != nil || got.Status.DNSSEC != dnsprovider.On {
			t.Errorf("%+v: details = %+v, want properties %+v and DNSSEC On", request, got, want)
		}
	}
}

func TestZoneDetailsOfReturnsTheZoneWithItsDNSSECState(t *testing.T) {
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), newFake(t).provider(), "Example.CH.", dnsprovider.ZoneDetailRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if got.Zone.ID != "example.ch" || got.Zone.Name != "example.ch" || !slices.Equal(got.Zone.Nameservers, []string{"ns11.infomaniak.ch", "ns12.infomaniak.ch"}) {
		t.Errorf("Zone = %+v, want example.ch with its nameservers", got.Zone)
	}

	if got.Status.DNSSEC != dnsprovider.On || got.Properties.DNSSEC.State != dnsprovider.PropertyRead {
		t.Errorf("DNSSEC = %v, %+v; want On, read", got.Status.DNSSEC, got.Properties.DNSSEC)
	}
}

func TestZoneDetailsReportsAFailedReadAsFailedAndUnknown(t *testing.T) {
	f := newFake(t)

	got, err := f.providerFor(infomaniak.Config{Token: "wrong"}).ZoneDetails(context.Background(), exampleCH, dnsprovider.ZoneDetailRequest{})
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}

	if got.Zone.Name != exampleCH.Name || got.Status.DNSSEC != dnsprovider.Unknown {
		t.Errorf("details = %+v, want the Zone with DNSSEC Unknown", got)
	}

	if got.Properties.DNSSEC.State != dnsprovider.PropertyFailed || !errors.Is(got.Properties.DNSSEC.Err, dnsprovider.ErrUnauthorized) {
		t.Errorf("DNSSEC property = %+v, want failed with ErrUnauthorized", got.Properties.DNSSEC)
	}
}
