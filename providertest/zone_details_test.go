package providertest_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

func TestScriptedZoneDetailsReturnsPartialResults(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "example.org", State: dnsprovider.HostingActive, Nameservers: []string{"ns.example.org"}}
	fake := providertest.New().AddZone(z)
	failure := &dnsprovider.APIError{StatusCode: 403, Provider: "script"}
	fake.SetZoneDetails(z.ID, dnsprovider.ZoneDetails{
		Status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.Off},
		Properties: dnsprovider.ZoneDetailProperties{
			DNSSEC:      dnsprovider.PropertyResult{State: dnsprovider.PropertyRead},
			HSTS:        dnsprovider.PropertyResult{State: dnsprovider.PropertyRead},
			MinTLS:      dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported},
			SigningKeys: dnsprovider.PropertyResult{State: dnsprovider.PropertyFailed, Err: failure},
		},
	})
	p := newFake(t, fake)
	request := dnsprovider.ZoneDetailRequest{SigningKeys: true}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, request)
	if !errors.Is(err, dnsprovider.ErrUnauthorized) || !reflect.DeepEqual(got.Zone, z) || got.Status.DNSSEC != dnsprovider.On || got.Properties.SigningKeys.Err != failure {
		t.Fatalf("partial details = %+v, %v", got, err)
	}
	calls := fake.Calls()
	if len(calls) != 3 || calls[1].Op != providertest.OpGetZone || calls[2].Op != providertest.OpZoneDetails || calls[2].ZoneDetailRequest != request {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestScriptedZoneDetailsTakePrecedenceOverZoneStatusAndKeys(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "example.org"}
	fake := providertest.New().AddZone(z)
	fake.SetZoneStatus(z.ID, dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Off})
	fake.SetSigningKeys(z.ID)
	fake.SetRegistration(z.ID, dnsprovider.SigningKey{DS: []string{"1 13 2 AA"}})
	fake.SetZoneDetails(z.ID, dnsprovider.ZoneDetails{Status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending}, Properties: dnsprovider.ZoneDetailProperties{DNSSEC: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}}})
	p := newFake(t, fake)
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, dnsprovider.ZoneDetailRequest{})
	if err != nil || got.Status.DNSSEC != dnsprovider.Pending || len(got.SigningKeys) != 0 || got.Properties.SigningKeys.State != dnsprovider.PropertyNotRequested {
		t.Fatalf("details = %+v, %v", got, err)
	}
	if !dnsprovider.Can(p, dnsprovider.CapDSRegistrar) {
		t.Fatal("missing registrar reader")
	}
}

func TestScriptedZoneDetailsCopiesAndClearsHosting(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "example.org", Nameservers: []string{"ns.example.org"}}
	key := dnsprovider.SigningKey{DS: []string{"1 13 2 AA"}}
	fake := providertest.New().AddZone(z)
	scripted := dnsprovider.ZoneDetails{SigningKeys: []dnsprovider.SigningKey{key}, Properties: dnsprovider.ZoneDetailProperties{SigningKeys: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}}}
	fake.SetZoneDetails(z.ID, scripted)
	fake.SetRegistration(z.ID, key)
	scripted.SigningKeys[0].DS[0] = "changed input"
	p := newFake(t, fake)
	request := dnsprovider.ZoneDetailRequest{SigningKeys: true}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, request)
	if err != nil || got.SigningKeys[0].DS[0] != "1 13 2 AA" {
		t.Fatalf("script copy = %+v, %v", got, err)
	}
	got.SigningKeys[0].DS[0] = "changed output"
	got.Zone.Nameservers[0] = "changed zone"
	again, err := dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, request)
	if err != nil || again.SigningKeys[0].DS[0] != "1 13 2 AA" || again.Zone.Nameservers[0] != "ns.example.org" {
		t.Fatalf("result copy = %+v, %v", again, err)
	}
	calls := fake.Calls()
	calls[2].Zone.Nameservers[0] = "changed call"
	if fake.Calls()[2].Zone.Nameservers[0] != "ns.example.org" {
		t.Fatal("recorded call aliases Calls result")
	}
	fake.RemoveZone(z.ID)
	fake.AddZone(z)
	again, err = dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, request)
	if err != nil || again.Properties.SigningKeys.State != dnsprovider.PropertyUnsupported || len(again.SigningKeys) != 0 {
		t.Fatalf("re-added zone details = %+v, %v", again, err)
	}
}

func TestZoneDetailsSupportIsExplicitAndRegistrationIsSeparate(t *testing.T) {
	z := dnsprovider.Zone{ID: "z1", Name: "example.org"}
	fake := providertest.New().AddZone(z)
	fake.SetRegistration(z.ID, dnsprovider.SigningKey{DS: []string{"1 13 2 AA"}})
	p := newFake(t, fake)
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil || got.Properties.SigningKeys.State != dnsprovider.PropertyUnsupported || len(got.SigningKeys) != 0 {
		t.Fatalf("provider details substituted Registration = %+v, %v", got, err)
	}
	fake.SetZoneDetails(z.ID, dnsprovider.ZoneDetails{Properties: dnsprovider.ZoneDetailProperties{SigningKeys: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}}})
	p = newFake(t, fake)
	got, err = dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil || got.Properties.SigningKeys.State != dnsprovider.PropertyRead || len(got.SigningKeys) != 0 {
		t.Fatalf("unsigned keys = %+v, %v", got, err)
	}
	fake.Fail(providertest.OpZoneDetails, context.Canceled)
	got, err = dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, dnsprovider.ZoneDetailRequest{})
	if !errors.Is(err, context.Canceled) || got.Zone.ID != z.ID {
		t.Fatalf("canceled partial result = %+v, %v", got, err)
	}
	fake.Fail(providertest.OpGetZone, dnsprovider.ErrNotFound)
	got, err = dnsprovider.ZoneDetailsOf(context.Background(), p, z.Name, dnsprovider.ZoneDetailRequest{})
	if !errors.Is(err, dnsprovider.ErrNotFound) || got.Zone.ID != "" {
		t.Fatalf("identity failure = %+v, %v", got, err)
	}
}
