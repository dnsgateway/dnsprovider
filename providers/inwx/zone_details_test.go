package inwx_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

var (
	signed   = dnsprovider.Zone{ID: "1001", Name: "example.com"}
	unsigned = dnsprovider.Zone{ID: "1002", Name: "example.org"}
)

func TestZoneDetailsReadsAnAutomaticallySignedZoneAsOn(t *testing.T) {
	d := newDNSSECFake(t)

	got, err := d.provider().ZoneDetails(context.Background(), signed, dnsprovider.ZoneDetailRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if got.Status.DNSSEC != dnsprovider.On || got.Properties.DNSSEC.State != dnsprovider.PropertyRead {
		t.Fatalf("DNSSEC = %v (%+v), want on, read", got.Status.DNSSEC, got.Properties.DNSSEC)
	}

	if p := d.params("dnssec.info"); p == nil || len(p["domains"].([]any)) != 1 || p["domains"].([]any)[0] != "example.com" {
		t.Fatalf("dnssec.info params = %v, want domains [example.com]", p)
	}
}

// signedKey is example.com's KSK: RFC 6605's example key, with its
// SHA-256 DS for example.com.
var signedKey = dnsprovider.SigningKey{
	DNSKEY: "257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
	KeyTag: 55648,
	DS:     []string{"55648 13 2 5CF0895FFC0F5544C1260E1F35ED9B80A648D87B8AA335312B552EC003D1D830"},
}

func TestZoneDetailsReturnsTheActiveKSKsOfAnAutomaticallySignedZone(t *testing.T) {
	for _, form := range []string{"array", "dnskey"} {
		d := newDNSSECFake(t)
		if form == "dnskey" {
			d.script("dnssec.listkeys", http.StatusOK, dnskeyForm(t, "dnssec_listkeys_example_com.json"))
		}

		got, err := d.provider().ZoneDetails(context.Background(), signed, dnsprovider.ZoneDetailRequest{SigningKeys: true})
		if err != nil {
			t.Fatalf("%s: %v", form, err)
		}

		if !reflect.DeepEqual(got.SigningKeys, []dnsprovider.SigningKey{signedKey}) || got.Properties.SigningKeys.State != dnsprovider.PropertyRead {
			t.Errorf("%s: Signing Keys = %+v (%+v), want %+v, read", form, got.SigningKeys, got.Properties.SigningKeys, signedKey)
		}

		if p := d.params("dnssec.listkeys"); p["domainName"] != "example.com" || number(p["active"], 0) != 1 {
			t.Errorf("%s: dnssec.listkeys params = %v, want domainName example.com, active 1", form, p)
		}
	}
}

func TestZoneDetailsLeavesOutKeysListedInactive(t *testing.T) {
	d := newDNSSECFake(t)
	d.script("dnssec.listkeys", http.StatusOK, answer(1000, []any{map[string]any{
		"id": 7003, "keyTag": 55648, "flagId": 257, "algorithmId": 13, "publicKey": "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
		"digestTypeId": 2, "digest": "5CF0895FFC0F5544C1260E1F35ED9B80A648D87B8AA335312B552EC003D1D830", "status": "DELETED", "active": 0,
	}}))

	got, err := d.provider().ZoneDetails(context.Background(), signed, dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil {
		t.Fatal(err)
	}

	if len(got.SigningKeys) != 0 || got.Properties.SigningKeys.State != dnsprovider.PropertyRead {
		t.Fatalf("Signing Keys = %+v (%+v), want none, read", got.SigningKeys, got.Properties.SigningKeys)
	}
}

func TestZoneDetailsReturnsNoSigningKeysForAZoneINWXDoesNotSign(t *testing.T) {
	d := newDNSSECFake(t)
	d.setStatus("example.org", "MANUAL")
	d.keys["example.org"] = "dnssec_listkeys_example_com.json" // the registrar's keys, not INWX's

	got, err := d.provider().ZoneDetails(context.Background(), unsigned, dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil {
		t.Fatal(err)
	}

	if len(got.SigningKeys) != 0 || got.Properties.SigningKeys.State != dnsprovider.PropertyRead {
		t.Fatalf("Signing Keys = %+v (%+v), want none, read", got.SigningKeys, got.Properties.SigningKeys)
	}

	if d.count("dnssec.listkeys") != 0 {
		t.Error("dnssec.listkeys was read for a zone INWX does not sign")
	}
}

func TestZoneDetailsReportsAFailedKeyReadAsAFailedProperty(t *testing.T) {
	d := newDNSSECFake(t)
	d.script("dnssec.listkeys", lost, "")

	got, err := d.provider().ZoneDetails(context.Background(), signed, dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err == nil {
		t.Fatal("ZoneDetails succeeded with its keys' answer lost")
	}

	if got.Status.DNSSEC != dnsprovider.On || got.Properties.DNSSEC.State != dnsprovider.PropertyRead {
		t.Errorf("DNSSEC = %v (%+v), want on, read", got.Status.DNSSEC, got.Properties.DNSSEC)
	}

	if got.Properties.SigningKeys.State != dnsprovider.PropertyFailed || !errors.Is(got.Properties.SigningKeys.Err, err) || got.SigningKeys != nil {
		t.Errorf("Signing Keys = %+v (%+v), want none, failed with %v", got.SigningKeys, got.Properties.SigningKeys, err)
	}
}

func TestZoneDetailsMapsINWXsDNSSECStatus(t *testing.T) {
	for _, tc := range []struct {
		status, field string
		want          dnsprovider.Setting
	}{
		{"AUTO", "dnssecStatus", dnsprovider.On},
		{"AUTO", "dnsSecStatus", dnsprovider.On}, // goinwx's spelling
		{"NONE", "dnssecStatus", dnsprovider.Off},
		{"MANUAL", "dnssecStatus", dnsprovider.Off}, // the registrar holds the user's keys; INWX does not sign
		{"UPDATE", "dnssecStatus", dnsprovider.Pending},
		{"DELETE_ALL", "dnssecStatus", dnsprovider.Pending},
		{"SOMETHING_NEW", "dnssecStatus", dnsprovider.Unknown},
		{"", "dnssecStatus", dnsprovider.Unknown}, // no entry for the zone
	} {
		d := newDNSSECFake(t)
		d.field = tc.field
		d.setStatus("example.org", tc.status)

		got, err := d.provider().ZoneDetails(context.Background(), unsigned, dnsprovider.ZoneDetailRequest{})
		if err != nil {
			t.Fatalf("%s %q: %v", tc.field, tc.status, err)
		}

		if got.Status.DNSSEC != tc.want || got.Properties.DNSSEC.State != dnsprovider.PropertyRead {
			t.Errorf("%s %q: DNSSEC = %v (%+v), want %v, read", tc.field, tc.status, got.Status.DNSSEC, got.Properties.DNSSEC, tc.want)
		}
	}
}

func TestZoneDetailsReportsAFailedReadAsAFailedPropertyNeverOff(t *testing.T) {
	d := newDNSSECFake(t)
	d.scriptCode("dnssec.info", 2400, "SYNTHETIC: internal error")

	got, err := d.provider().ZoneDetails(context.Background(), signed, dnsprovider.ZoneDetailRequest{SigningKeys: true})

	if _, ok := errors.AsType[*dnsprovider.APIError](err); !ok {
		t.Fatalf("err = %v, want the APIError", err)
	}

	if got.Status.DNSSEC != dnsprovider.Unknown || got.Properties.DNSSEC.State != dnsprovider.PropertyFailed || !errors.Is(got.Properties.DNSSEC.Err, err) {
		t.Fatalf("DNSSEC = %v (%+v), want unknown, failed with %v", got.Status.DNSSEC, got.Properties.DNSSEC, err)
	}

	if got.Properties.SigningKeys.State != dnsprovider.PropertyFailed {
		t.Errorf("Signing Keys = %+v, want failed", got.Properties.SigningKeys)
	}

	if d.count("dnssec.listkeys") != 0 {
		t.Error("dnssec.listkeys was read after dnssec.info failed")
	}
}

func TestZoneDetailsReportsHSTSAndMinTLSUnsupportedWithoutACall(t *testing.T) {
	d := newDNSSECFake(t)

	got, err := d.provider().ZoneDetails(context.Background(), unsigned, dnsprovider.ZoneDetailRequest{})
	if err != nil {
		t.Fatal(err)
	}

	unsupported := dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported}
	if got.Properties.HSTS != unsupported || got.Properties.MinTLS != unsupported {
		t.Fatalf("HSTS = %+v, MinTLS = %+v, want unsupported", got.Properties.HSTS, got.Properties.MinTLS)
	}

	if got.Properties.SigningKeys.State != dnsprovider.PropertyNotRequested {
		t.Errorf("Signing Keys = %+v, want not requested", got.Properties.SigningKeys)
	}

	if want := []string{"account.login", "dnssec.info"}; !slices.Equal(d.methodsCalled(), want) {
		t.Errorf("calls = %v, want %v", d.methodsCalled(), want)
	}
}
