package cloudflare

import (
	"context"
	"errors"
	"net/http"
	"sync"

	cfdns "github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/dnsgateway/dnsprovider"
)

var _ dnsprovider.ZoneDetailsReader = (*Provider)(nil)

// ZoneDetails reads DNSSEC state and requested Signing Keys from one response.
// HSTS and minimum TLS are independent reads, with individual diagnostics.
func (p *Provider) ZoneDetails(ctx context.Context, zone dnsprovider.Zone, request dnsprovider.ZoneDetailRequest) (dnsprovider.ZoneDetails, error) {
	details := dnsprovider.ZoneDetails{Zone: zone}
	var hstsErr, tlsErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); details.Status.HSTS, hstsErr = p.readHSTS(ctx, zone, true) }()
	go func() { defer wg.Done(); details.Status.MinTLS, tlsErr = p.readMinTLS(ctx, zone, true) }()
	var params cfdns.DNSSECGetParams
	params.ZoneID.Value, params.ZoneID.Present = zone.ID, true
	var raw *http.Response
	res, err := p.dnssec.Get(ctx, params, option.WithResponseInto(&raw))
	if err != nil {
		err = apiError(err, raw, nil)
	} else {
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
