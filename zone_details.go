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

// ZoneDetailsReader is an optional combined property reader. ZoneDetailsOf
// supplies a successfully read Zone. Implementations report each requested
// property's outcome and return the joined property errors. Unsupported
// properties carry no error. Unrequested keys remain PropertyNotRequested.
// Implementations can read related properties from one response for consistency.
type ZoneDetailsReader interface {
	ZoneDetails(ctx context.Context, zone Zone, request ZoneDetailRequest) (ZoneDetails, error)
}

// ZoneDetailsOf reads identity first, then requested properties, preferring a
// combined reader and otherwise using ZoneStatusReader and KeyReader. Missing
// optional readers report PropertyUnsupported without failing the read.
// Identity failure returns no details. Property failures return known details
// and a joined error; cancellation remains observable in the returned error.
// Legacy status readers expose one error for all settings: known values are
// retained and unknown values carry that error. If a legacy reader suppresses
// failures, an Unknown value is a successful observation with no diagnostic;
// only a combined reader can distinguish those suppressed failures.
func ZoneDetailsOf(ctx context.Context, p Provider, name string, request ZoneDetailRequest) (ZoneDetails, error) {
	if err := ctx.Err(); err != nil {
		return ZoneDetails{}, err
	}
	zone, err := p.GetZone(ctx, name)
	if err != nil {
		return ZoneDetails{}, errors.Join(err, ctx.Err())
	}
	if reader, ok := p.(ZoneDetailsReader); ok {
		details, detailErr := reader.ZoneDetails(ctx, zone, request)
		details.Zone = zone
		return details, errors.Join(detailErr, ctx.Err())
	}
	details := ZoneDetails{Zone: zone, Properties: ZoneDetailProperties{
		DNSSEC: PropertyResult{State: PropertyUnsupported},
		HSTS:   PropertyResult{State: PropertyUnsupported},
		MinTLS: PropertyResult{State: PropertyUnsupported},
	}}
	if request.SigningKeys {
		details.Properties.SigningKeys.State = PropertyUnsupported
	}
	var readErrors []error
	if reader, ok := p.(ZoneStatusReader); ok {
		status, statusErr := reader.ZoneStatus(ctx, zone)
		details.Status = status
		details.Properties.DNSSEC = legacyPropertyResult(status.DNSSEC != Unknown, statusErr)
		details.Properties.HSTS = legacyPropertyResult(status.HSTS != Unknown, statusErr)
		details.Properties.MinTLS = legacyPropertyResult(status.MinTLS != TLSUnknown, statusErr)
		readErrors = append(readErrors, statusErr)
	}
	if request.SigningKeys {
		if reader, ok := p.(KeyReader); ok {
			keys, keyErr := reader.SigningKeys(ctx, zone)
			details.SigningKeys = keys
			details.Properties.SigningKeys = legacyPropertyResult(false, keyErr)
			readErrors = append(readErrors, keyErr)
		}
	}
	readErrors = append(readErrors, ctx.Err())
	return details, errors.Join(readErrors...)
}

func legacyPropertyResult(known bool, err error) PropertyResult {
	if err != nil && !known {
		return PropertyResult{State: PropertyFailed, Err: err}
	}
	return PropertyResult{State: PropertyRead}
}
