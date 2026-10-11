package providertest_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providertest"
)

func TestDeleteZoneLeavesRegistrationAndDelegationSignersIntact(t *testing.T) {
	ctx := context.Background()
	z := dnsprovider.Zone{ID: "z1", Name: "example.com"}
	key := dnsprovider.SigningKey{DNSKEY: "257 3 13 public-key", KeyTag: 1, DS: []string{"1 13 2 AA"}}
	fake := providertest.New().AddZone(z)
	fake.SetRegistration(z.ID, key)
	fake.SetZoneDeleter(true)
	p := newFake(t, fake)

	if err := p.DeleteZone(ctx, z); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetZone(ctx, z.Name); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone after Offboarding: %v, want ErrNotFound", err)
	}
	registrar := p.(dnsprovider.DSRegistrar)
	got, err := registrar.ListDelegationSigners(ctx, z)
	if err != nil || !reflect.DeepEqual(got, []dnsprovider.SigningKey{key}) {
		t.Fatalf("DelegationSigners after Offboarding = %+v, %v; want Registration's key retained", got, err)
	}
}
