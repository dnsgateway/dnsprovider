package cloudflare

import (
	"context"
	"errors"
	"sync"

	"github.com/dnsgateway/dnsprovider"
)

// ZoneDetails implements dnsprovider.Provider: DNSSEC and the requested
// Signing Keys come from one read of the Zone's DNSSEC status, HSTS and
// minimum TLS from independent reads of its settings, made concurrently.
// Each failed read is its property's error, a setting the API token may
// not read (HTTP 403) among them, as ErrUnauthorized.
func (p *Provider) ZoneDetails(ctx context.Context, zone dnsprovider.Zone, request dnsprovider.ZoneDetailRequest) (dnsprovider.ZoneDetails, error) {
	details := dnsprovider.ZoneDetails{Zone: zone}
	var hstsErr, tlsErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); details.Status.HSTS, hstsErr = p.readHSTS(ctx, zone) }()
	go func() { defer wg.Done(); details.Status.MinTLS, tlsErr = p.readMinTLS(ctx, zone) }()
	res, err := p.readDNSSEC(ctx, zone)
	if err == nil {
		details.Status.DNSSEC = dnssecSetting(res.Status)
		if request.SigningKeys {
			details.SigningKeys = dnssecSigningKeys(res)
		}
	}
	wg.Wait()
	details.Properties.DNSSEC = detailPropertyResult(err)
	details.Properties.HSTS = detailPropertyResult(hstsErr)
	details.Properties.MinTLS = detailPropertyResult(tlsErr)
	if request.SigningKeys {
		details.Properties.SigningKeys = detailPropertyResult(err)
	}
	return details, errors.Join(err, hstsErr, tlsErr, ctx.Err())
}

func detailPropertyResult(err error) dnsprovider.PropertyResult {
	if err != nil {
		return dnsprovider.PropertyResult{State: dnsprovider.PropertyFailed, Err: err}
	}
	return dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}
}
