package providertest

import (
	"context"
	"errors"
	"slices"

	"github.com/dnsgateway/dnsprovider"
)

// SetZoneDetails scripts a Zone's whole ZoneDetails answer, its Properties
// saying which are read, unsupported or failed. Identity still comes from
// GetZone. Errors on failed properties are joined; Fail(OpZoneDetails, err)
// adds a read error. A Zone it does not script answers from SetZoneStatus
// and SetSigningKeys.
func (p *Provider) SetZoneDetails(zoneID string, details dnsprovider.ZoneDetails) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.details[zoneID] = cloneDetails(details)
}

func cloneDetails(details dnsprovider.ZoneDetails) dnsprovider.ZoneDetails {
	details.Zone.Nameservers = slices.Clone(details.Zone.Nameservers)
	details.SigningKeys = cloneKeys(details.SigningKeys)
	return details
}

// ZoneDetails implements dnsprovider.Provider, recorded as OpZoneDetails:
// the details SetZoneDetails scripted for the Zone, else the Zone Status
// and signing keys SetZoneStatus and SetSigningKeys scripted, each
// property unsupported when it is not.
func (p *Provider) ZoneDetails(ctx context.Context, z dnsprovider.Zone, request dnsprovider.ZoneDetailRequest) (dnsprovider.ZoneDetails, error) {
	readErr := p.record(Call{Op: OpZoneDetails, Zone: cloneZone(z), ZoneDetailRequest: request})
	p.mu.Lock()
	details, ok := p.details[z.ID]
	if ok {
		details = cloneDetails(details)
	} else {
		details = p.scriptedDetails(z.ID)
	}
	p.mu.Unlock()
	details.Zone = cloneZone(z)
	if !request.SigningKeys {
		details.SigningKeys = nil
		details.Properties.SigningKeys = dnsprovider.PropertyResult{}
	}
	return details, errors.Join(readErr, details.Properties.DNSSEC.Err, details.Properties.HSTS.Err,
		details.Properties.MinTLS.Err, details.Properties.SigningKeys.Err, ctx.Err())
}

// scriptedDetails are a Zone's details from SetZoneStatus and
// SetSigningKeys. The caller holds p.mu.
func (p *Provider) scriptedDetails(zoneID string) dnsprovider.ZoneDetails {
	unsupported := dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported}
	read := dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}
	details := dnsprovider.ZoneDetails{Properties: dnsprovider.ZoneDetailProperties{
		DNSSEC: unsupported, HSTS: unsupported, MinTLS: unsupported, SigningKeys: unsupported,
	}}
	if p.readStatus {
		details.Status = p.status[zoneID]
		details.Properties.DNSSEC, details.Properties.HSTS, details.Properties.MinTLS = read, read, read
	}
	if p.readKeys {
		details.SigningKeys = cloneKeys(p.keys[zoneID])
		details.Properties.SigningKeys = read
	}
	return details
}

func cloneZone(z dnsprovider.Zone) dnsprovider.Zone {
	z.Nameservers = slices.Clone(z.Nameservers)
	return z
}
