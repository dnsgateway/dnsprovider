package infomaniak

import (
	"context"

	"github.com/dnsgateway/dnsprovider"
)

// ZoneDetails implements dnsprovider.Provider: the DNSSEC State is the
// Zone's dnssec.is_enabled, read with GET /2/zones/{zone}. A failed read
// is the property's error, its state Unknown and never Off. HSTS,
// minimum TLS and Signing Keys are unsupported: Infomaniak's API
// answers no Signing Key, which the DNSKEY RRset on the nameservers
// holds.
func (p *Provider) ZoneDetails(ctx context.Context, zone dnsprovider.Zone, request dnsprovider.ZoneDetailRequest) (dnsprovider.ZoneDetails, error) {
	unsupported := dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported}
	details := dnsprovider.ZoneDetails{Zone: zone, Properties: dnsprovider.ZoneDetailProperties{HSTS: unsupported, MinTLS: unsupported}}

	if request.SigningKeys {
		details.Properties.SigningKeys = unsupported
	}

	var wire struct {
		DNSSEC struct {
			IsEnabled bool `json:"is_enabled"`
		} `json:"dnssec"`
	}

	name, err := zoneOf(zone)
	if err == nil {
		_, err = p.get(ctx, zonePath(name), nil, &wire)
	}

	if err != nil {
		details.Properties.DNSSEC = dnsprovider.PropertyResult{State: dnsprovider.PropertyFailed, Err: err}

		return details, err
	}

	details.Status.DNSSEC = dnsprovider.Off
	if wire.DNSSEC.IsEnabled {
		details.Status.DNSSEC = dnsprovider.On
	}

	details.Properties.DNSSEC = dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}

	return details, nil
}
