package dnsprovider

import (
	"context"
	"errors"
)

// ZoneDetailRequest selects additional work for a detailed Zone read.
// Zone Status is always requested; Signing Keys are opt-in.
type ZoneDetailRequest struct {
	SigningKeys bool
}

// PropertyReadState distinguishes an unrequested property, missing adapter
// support, a successful read (possibly Unknown or empty), and a failed read.
type PropertyReadState uint8

const (
	PropertyNotRequested PropertyReadState = iota
	PropertyUnsupported
	PropertyRead
	PropertyFailed
)

// PropertyResult describes one property read. Err retains the original
// diagnostic on failure, including errors.Is and errors.As classification.
type PropertyResult struct {
	State PropertyReadState
	Err   error
}

// ZoneDetailProperties holds outcomes for the properties in ZoneDetails.
type ZoneDetailProperties struct {
	DNSSEC      PropertyResult
	HSTS        PropertyResult
	MinTLS      PropertyResult
	SigningKeys PropertyResult
}

// ZoneDetails assembles Provider-side Zone identity and properties. SigningKeys
// are keys the Provider signs with, never registrar-held Delegation Signers.
// Independent properties need not be an atomic snapshot.
type ZoneDetails struct {
	Zone        Zone
	Status      ZoneStatus
	SigningKeys []SigningKey
	Properties  ZoneDetailProperties
}

// ZoneDetailsOf reads a Zone by its name with GetZone, then its requested
// properties with the Provider's ZoneDetails. Identity failure returns no
// details. Property failures return the details known and a joined
// error; cancellation remains observable in the returned error.
func ZoneDetailsOf(ctx context.Context, p Provider, name string, request ZoneDetailRequest) (ZoneDetails, error) {
	if err := ctx.Err(); err != nil {
		return ZoneDetails{}, err
	}
	zone, err := p.GetZone(ctx, name)
	if err != nil {
		return ZoneDetails{}, errors.Join(err, ctx.Err())
	}
	details, detailErr := p.ZoneDetails(ctx, zone, request)
	details.Zone = zone
	return details, errors.Join(detailErr, ctx.Err())
}

// UnimplementedZoneDetails is embedded by an adapter whose Provider reads
// no Zone property: every requested property is PropertyUnsupported,
// without a call or an error.
type UnimplementedZoneDetails struct{}

// ZoneDetails reports every requested property unsupported.
func (UnimplementedZoneDetails) ZoneDetails(_ context.Context, zone Zone, request ZoneDetailRequest) (ZoneDetails, error) {
	unsupported := PropertyResult{State: PropertyUnsupported}
	details := ZoneDetails{Zone: zone, Properties: ZoneDetailProperties{DNSSEC: unsupported, HSTS: unsupported, MinTLS: unsupported}}
	if request.SigningKeys {
		details.Properties.SigningKeys = unsupported
	}
	return details, nil
}
