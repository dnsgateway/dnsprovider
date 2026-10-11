package providertest

import (
	"context"
	"errors"
	"slices"

	"github.com/dnsgateway/dnsprovider"
)

// SetZoneDetails scripts a combined property read and enables ZoneDetailsReader
// for subsequently built Providers. Identity still comes from GetZone. Errors
// on failed properties are joined; Fail(OpZoneDetails, err) adds a read error.
// Unscripted Zones report unsupported properties. Legacy optional readers remain
// controlled independently by SetZoneStatus and SetSigningKeys.
func (p *Provider) SetZoneDetails(zoneID string, details dnsprovider.ZoneDetails) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.details[zoneID] = cloneDetails(details)
	p.readDetails = true
}

func cloneDetails(details dnsprovider.ZoneDetails) dnsprovider.ZoneDetails {
	details.Zone.Nameservers = slices.Clone(details.Zone.Nameservers)
	details.SigningKeys = cloneKeys(details.SigningKeys)
	return details
}

func (p *Provider) zoneDetails(ctx context.Context, z dnsprovider.Zone, request dnsprovider.ZoneDetailRequest) (dnsprovider.ZoneDetails, error) {
	readErr := p.record(Call{Op: OpZoneDetails, Zone: cloneZone(z), ZoneDetailRequest: request})
	p.mu.Lock()
	details, ok := p.details[z.ID]
	details = cloneDetails(details)
	p.mu.Unlock()
	details.Zone = cloneZone(z)
	if !ok {
		details.Properties = dnsprovider.ZoneDetailProperties{
			DNSSEC:      dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported},
			HSTS:        dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported},
			MinTLS:      dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported},
			SigningKeys: dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported},
		}
	}
	if !request.SigningKeys {
		details.SigningKeys = nil
		details.Properties.SigningKeys = dnsprovider.PropertyResult{}
	}
	return details, errors.Join(readErr, details.Properties.DNSSEC.Err, details.Properties.HSTS.Err,
		details.Properties.MinTLS.Err, details.Properties.SigningKeys.Err, ctx.Err())
}

func cloneZone(z dnsprovider.Zone) dnsprovider.Zone {
	z.Nameservers = slices.Clone(z.Nameservers)
	return z
}
