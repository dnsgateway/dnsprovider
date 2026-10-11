package dnsprovider_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

type detailHost struct {
	dnsprovider.Provider

	zone dnsprovider.Zone
	err  error
}

func (p detailHost) GetZone(context.Context, string) (dnsprovider.Zone, error) { return p.zone, p.err }

func (p detailHost) ZoneDetails(ctx context.Context, z dnsprovider.Zone, r dnsprovider.ZoneDetailRequest) (dnsprovider.ZoneDetails, error) {
	return dnsprovider.UnimplementedZoneDetails{}.ZoneDetails(ctx, z, r)
}

func TestUnimplementedZoneDetailsAreUnsupportedAndKeepIdentity(t *testing.T) {
	zone := dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingPending, Nameservers: []string{"ns.example.net"}}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), detailHost{zone: zone}, zone.Name, dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil || !reflect.DeepEqual(got.Zone, zone) {
		t.Fatalf("details = %+v, %v", got, err)
	}
	for _, property := range []dnsprovider.PropertyResult{got.Properties.DNSSEC, got.Properties.HSTS, got.Properties.MinTLS, got.Properties.SigningKeys} {
		if property.State != dnsprovider.PropertyUnsupported || property.Err != nil {
			t.Errorf("unsupported property = %+v", property)
		}
	}
	got, err = dnsprovider.ZoneDetailsOf(context.Background(), detailHost{zone: zone}, zone.Name, dnsprovider.ZoneDetailRequest{})
	if err != nil || got.Properties.SigningKeys.State != dnsprovider.PropertyNotRequested {
		t.Errorf("unrequested keys = %+v, %v", got.Properties.SigningKeys, err)
	}
}

func TestZoneDetailsIdentityFailureReturnsNoDetails(t *testing.T) {
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), detailHost{err: dnsprovider.ErrNotFound}, "missing.example", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("missing zone=%+v err=%v", got, err)
	}
	assertZoneDetailsEqual(t, got, dnsprovider.ZoneDetails{})
}

func TestZoneDetailsCancellationIsObservableEvenWhenTheProviderIgnoresIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := dnsprovider.ZoneDetailsOf(ctx, detailHost{zone: dnsprovider.Zone{ID: "z1"}}, "example.com", dnsprovider.ZoneDetailRequest{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read=%+v err=%v", got, err)
	}
	assertZoneDetailsEqual(t, got, dnsprovider.ZoneDetails{})
}

type combinedDetailHost struct {
	detailHost

	details   dnsprovider.ZoneDetails
	detailErr error
	cancel    context.CancelFunc
}

func (p combinedDetailHost) ZoneDetails(context.Context, dnsprovider.Zone, dnsprovider.ZoneDetailRequest) (dnsprovider.ZoneDetails, error) {
	if p.cancel != nil {
		p.cancel()
	}
	return p.details, p.detailErr
}

func TestZoneDetailsAreTheProvidersWithAuthoritativeIdentity(t *testing.T) {
	p := combinedDetailHost{detailHost: detailHost{zone: dnsprovider.Zone{ID: "z1", Name: "example.com"}}, details: dnsprovider.ZoneDetails{Status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.On}, SigningKeys: []dnsprovider.SigningKey{{KeyTag: 2371}}, Properties: dnsprovider.ZoneDetailProperties{DNSSEC: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}, HSTS: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}, MinTLS: dnsprovider.PropertyResult{State: dnsprovider.PropertyFailed, Err: dnsprovider.ErrUnauthorized}, SigningKeys: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}}}, detailErr: dnsprovider.ErrUnauthorized}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	want := p.details
	want.Zone = p.zone
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("details=%+v err=%v", got, err)
	}
	assertZoneDetailsEqual(t, got, want)
}

func TestZoneDetailsCancellationRetainsCompletedProperties(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := combinedDetailHost{detailHost: detailHost{zone: dnsprovider.Zone{ID: "z1"}}, details: dnsprovider.ZoneDetails{Status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On}, Properties: dnsprovider.ZoneDetailProperties{DNSSEC: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}}}, cancel: cancel}
	got, err := dnsprovider.ZoneDetailsOf(ctx, p, "example.com", dnsprovider.ZoneDetailRequest{})
	if !errors.Is(err, context.Canceled) || got.Zone.ID != "z1" || got.Status.DNSSEC != dnsprovider.On {
		t.Fatalf("canceled details=%+v err=%v", got, err)
	}
}

type registrationDetailHost struct{ detailHost }

func (registrationDetailHost) ListDelegationSigners(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	panic("provider details never consult registration")
}

func (registrationDetailHost) SetDelegationSigners(context.Context, dnsprovider.Zone, []dnsprovider.SigningKey) error {
	panic("provider details never write registration")
}

func (registrationDetailHost) DeleteDelegationSigners(context.Context, dnsprovider.Zone) error {
	panic("provider details never write registration")
}

func TestZoneDetailsDoNotSubstituteRegistrarSigningKeys(t *testing.T) {
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), registrationDetailHost{detailHost{zone: dnsprovider.Zone{ID: "z1"}}}, "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil || len(got.SigningKeys) != 0 || got.Properties.SigningKeys.State != dnsprovider.PropertyUnsupported {
		t.Fatalf("provider keys=%+v err=%v", got, err)
	}
}

type canceledIdentityHost struct {
	dnsprovider.Provider

	cancel context.CancelFunc
}

func (p canceledIdentityHost) GetZone(context.Context, string) (dnsprovider.Zone, error) {
	p.cancel()
	return dnsprovider.Zone{}, dnsprovider.ErrNotFound
}

func TestZoneDetailsIdentityFailureRetainsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, err := dnsprovider.ZoneDetailsOf(ctx, canceledIdentityHost{cancel: cancel}, "missing.example", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if !errors.Is(err, dnsprovider.ErrNotFound) || !errors.Is(err, context.Canceled) {
		t.Fatalf("failed identity=%+v err=%v", got, err)
	}
	assertZoneDetailsEqual(t, got, dnsprovider.ZoneDetails{})
}

func assertZoneDetailsEqual(t *testing.T, got, want dnsprovider.ZoneDetails) {
	t.Helper()
	if !reflect.DeepEqual(got.Zone, want.Zone) || got.Status != want.Status || !reflect.DeepEqual(got.SigningKeys, want.SigningKeys) {
		t.Errorf("details = %+v, want %+v", got, want)
	}
	for _, property := range []struct {
		name string
		got  dnsprovider.PropertyResult
		want dnsprovider.PropertyResult
	}{
		{"DNSSEC", got.Properties.DNSSEC, want.Properties.DNSSEC},
		{"HSTS", got.Properties.HSTS, want.Properties.HSTS},
		{"MinTLS", got.Properties.MinTLS, want.Properties.MinTLS},
		{"SigningKeys", got.Properties.SigningKeys, want.Properties.SigningKeys},
	} {
		if property.got.State != property.want.State || !errors.Is(property.got.Err, property.want.Err) {
			t.Errorf("%s = %+v, want %+v", property.name, property.got, property.want)
		}
	}
}
