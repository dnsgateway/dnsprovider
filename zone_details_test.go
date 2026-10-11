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

func TestZoneDetailsRetainIdentityWithoutOptionalReaders(t *testing.T) {
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
}

type statusDetailHost struct {
	detailHost
	status    dnsprovider.ZoneStatus
	statusErr error
}

func (p statusDetailHost) ZoneStatus(context.Context, dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	return p.status, p.statusErr
}

type keyDetailHost struct {
	statusDetailHost
	keys   []dnsprovider.SigningKey
	keyErr error
}

func (p keyDetailHost) SigningKeys(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	return p.keys, p.keyErr
}

func TestZoneDetailsFallbackPreservesStatusAndRequestedKeys(t *testing.T) {
	for _, state := range []dnsprovider.Setting{dnsprovider.Unknown, dnsprovider.Off, dnsprovider.On, dnsprovider.Pending} {
		p := keyDetailHost{statusDetailHost: statusDetailHost{detailHost: detailHost{zone: dnsprovider.Zone{ID: "z1", Name: "example.com"}}, status: dnsprovider.ZoneStatus{DNSSEC: state, HSTS: dnsprovider.On, MinTLS: dnsprovider.TLS12}}, keys: []dnsprovider.SigningKey{{KeyTag: 2371, DS: []string{"2371 13 2 ABCDEF"}}}}
		got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
		if err != nil || got.Status != p.status || !reflect.DeepEqual(got.SigningKeys, p.keys) {
			t.Fatalf("state %v: details=%+v err=%v", state, got, err)
		}
		for _, property := range []dnsprovider.PropertyResult{got.Properties.DNSSEC, got.Properties.HSTS, got.Properties.MinTLS, got.Properties.SigningKeys} {
			if property.State != dnsprovider.PropertyRead || property.Err != nil {
				t.Errorf("successful property=%+v", property)
			}
		}
	}
}

func TestZoneDetailsRetainKnownPropertiesAndTypedFailures(t *testing.T) {
	keyError := &dnsprovider.APIError{Provider: "test", StatusCode: 403, Messages: []string{"key permission missing"}}
	p := keyDetailHost{statusDetailHost: statusDetailHost{detailHost: detailHost{zone: dnsprovider.Zone{ID: "z1"}}, status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, MinTLS: dnsprovider.TLS13}, statusErr: dnsprovider.ErrRateLimited}, keyErr: keyError}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if !errors.Is(err, dnsprovider.ErrRateLimited) || !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("aggregate=%v", err)
	}
	if got.Status.DNSSEC != dnsprovider.On || got.Status.MinTLS != dnsprovider.TLS13 || got.Properties.DNSSEC.State != dnsprovider.PropertyRead || got.Properties.MinTLS.State != dnsprovider.PropertyRead {
		t.Fatalf("known properties=%+v", got)
	}
	if got.Properties.HSTS.State != dnsprovider.PropertyFailed || !errors.Is(got.Properties.HSTS.Err, dnsprovider.ErrRateLimited) {
		t.Errorf("HSTS=%+v", got.Properties.HSTS)
	}
	var diagnostic *dnsprovider.APIError
	if got.Properties.SigningKeys.State != dnsprovider.PropertyFailed || !errors.As(got.Properties.SigningKeys.Err, &diagnostic) || diagnostic != keyError {
		t.Errorf("keys=%+v", got.Properties.SigningKeys)
	}
}

func TestZoneDetailsKeysAreExplicitAndEmptyKeysAreSuccessful(t *testing.T) {
	p := keyDetailHost{statusDetailHost: statusDetailHost{detailHost: detailHost{zone: dnsprovider.Zone{ID: "z1"}}}, keyErr: dnsprovider.ErrUnauthorized}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, "example.com", dnsprovider.ZoneDetailRequest{})
	if err != nil || got.Properties.SigningKeys.State != dnsprovider.PropertyNotRequested {
		t.Fatalf("unrequested keys=%+v err=%v", got, err)
	}
	p.keyErr = nil
	got, err = dnsprovider.ZoneDetailsOf(context.Background(), p, "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if err != nil || len(got.SigningKeys) != 0 || got.Properties.SigningKeys.State != dnsprovider.PropertyRead {
		t.Fatalf("unsigned details=%+v err=%v", got, err)
	}
}

func TestZoneDetailsIdentityFailureReturnsNoDetails(t *testing.T) {
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), detailHost{err: dnsprovider.ErrNotFound}, "missing.example", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if !errors.Is(err, dnsprovider.ErrNotFound) || !reflect.DeepEqual(got, dnsprovider.ZoneDetails{}) {
		t.Fatalf("missing zone=%+v err=%v", got, err)
	}
}

func TestZoneDetailsCancellationIsObservableEvenWhenReaderIgnoresIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := dnsprovider.ZoneDetailsOf(ctx, detailHost{zone: dnsprovider.Zone{ID: "z1"}}, "example.com", dnsprovider.ZoneDetailRequest{})
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, dnsprovider.ZoneDetails{}) {
		t.Fatalf("canceled read=%+v err=%v", got, err)
	}
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

func (p combinedDetailHost) ZoneStatus(context.Context, dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	panic("combined reader must supply status")
}

func (p combinedDetailHost) SigningKeys(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	panic("combined reader must supply keys")
}

func TestZoneDetailsPreferCombinedReaderAndRetainAuthoritativeIdentity(t *testing.T) {
	p := combinedDetailHost{detailHost: detailHost{zone: dnsprovider.Zone{ID: "z1", Name: "example.com"}}, details: dnsprovider.ZoneDetails{Status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.On}, SigningKeys: []dnsprovider.SigningKey{{KeyTag: 2371}}, Properties: dnsprovider.ZoneDetailProperties{DNSSEC: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}, HSTS: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}, MinTLS: dnsprovider.PropertyResult{State: dnsprovider.PropertyFailed, Err: dnsprovider.ErrUnauthorized}, SigningKeys: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}}}, detailErr: dnsprovider.ErrUnauthorized}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	want := p.details
	want.Zone = p.zone
	if !reflect.DeepEqual(got, want) || !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("combined details=%+v err=%v", got, err)
	}
}

func TestZoneDetailsCancellationRetainsCompletedProperties(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := combinedDetailHost{detailHost: detailHost{zone: dnsprovider.Zone{ID: "z1"}}, details: dnsprovider.ZoneDetails{Status: dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On}, Properties: dnsprovider.ZoneDetailProperties{DNSSEC: dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}}}, cancel: cancel}
	got, err := dnsprovider.ZoneDetailsOf(ctx, p, "example.com", dnsprovider.ZoneDetailRequest{})
	if !errors.Is(err, context.Canceled) || got.Zone.ID != "z1" || got.Status.DNSSEC != dnsprovider.On {
		t.Fatalf("canceled details=%+v err=%v", got, err)
	}
}

func TestZoneDetailsAllFailedPropertiesKeepIdentity(t *testing.T) {
	p := keyDetailHost{statusDetailHost: statusDetailHost{detailHost: detailHost{zone: dnsprovider.Zone{ID: "z1"}}, statusErr: dnsprovider.ErrRateLimited}, keyErr: dnsprovider.ErrUnauthorized}
	got, err := dnsprovider.ZoneDetailsOf(context.Background(), p, "example.com", dnsprovider.ZoneDetailRequest{SigningKeys: true})
	if got.Zone.ID != "z1" || !errors.Is(err, dnsprovider.ErrRateLimited) || !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("failed details=%+v err=%v", got, err)
	}
	for _, property := range []dnsprovider.PropertyResult{got.Properties.DNSSEC, got.Properties.HSTS, got.Properties.MinTLS, got.Properties.SigningKeys} {
		if property.State != dnsprovider.PropertyFailed || property.Err == nil {
			t.Errorf("failed property=%+v", property)
		}
	}
}

type registrationDetailHost struct{ detailHost }

func (registrationDetailHost) DelegationSigners(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	panic("provider details never consult registration")
}

func (registrationDetailHost) SetDelegationSigners(context.Context, dnsprovider.Zone, []dnsprovider.SigningKey) error {
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
	if !errors.Is(err, dnsprovider.ErrNotFound) || !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, dnsprovider.ZoneDetails{}) {
		t.Fatalf("failed identity=%+v err=%v", got, err)
	}
}
