package inwx

import (
	"context"
	"fmt"

	"github.com/dnsgateway/dnsprovider"
)

// UpdateZone implements dnsprovider.Provider (CapZoneUpdater): it
// switches DNSSEC, INWX's automated signing of a zone it hosts, then
// refuses HSTS, then minimum TLS, as the contract orders them. DNSSEC is
// switched with one dnssec.enablednssec or dnssec.disablednssec, sent
// once and whatever the zone's state, and returned as dnssec.info reads
// after it. Left nil, it is read. HSTS or MinTLS set is ErrUnsupported,
// returned with DNSSEC as switched or read before it; with nothing set,
// UpdateZone reads DNSSEC and fails when that fails.
func (p *Provider) UpdateZone(ctx context.Context, zone dnsprovider.Zone, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	var status dnsprovider.ZoneStatus

	switch {
	case u.DNSSEC != nil:
		// A zone INWX does not host is ErrNotServed or ErrNotFound, as
		// for GetZone, without a write.
		z, err := p.GetZone(ctx, zone.Name)
		if err != nil {
			return dnsprovider.ZoneStatus{}, err
		}

		method := "dnssec.disablednssec"
		if *u.DNSSEC {
			method = "dnssec.enablednssec"
		}

		if _, err := p.write(ctx, method, map[string]any{"domainName": z.Name}, pendingTaken); err != nil {
			return dnsprovider.ZoneStatus{}, err
		}

		status.DNSSEC = p.switched(ctx, z, *u.DNSSEC)
	case u.HSTS == nil && u.MinTLS == nil:
		d, err := p.ZoneDetails(ctx, zone, dnsprovider.ZoneDetailRequest{})
		if err != nil {
			return dnsprovider.ZoneStatus{}, err
		}

		return d.Status, nil
	default:
		d, _ := p.ZoneDetails(ctx, zone, dnsprovider.ZoneDetailRequest{})
		status.DNSSEC = d.Status.DNSSEC
	}

	// HSTS, then MinTLS, fail in turn: DNSSEC, switched or read before,
	// stays as it is known.
	if u.HSTS != nil {
		return status, fmt.Errorf("inwx: INWX has no HSTS setting: %w", dnsprovider.ErrUnsupported)
	}

	if u.MinTLS != nil {
		return status, fmt.Errorf("inwx: INWX has no minimum TLS setting: %w", dnsprovider.ErrUnsupported)
	}

	return status, nil
}

// switched is DNSSEC after a switch INWX took. Its answer holds no
// state, so dnssec.info is read again: the state asked for when it shows
// it, Pending while it shows any other, and Unknown when the read fails
// or answers no known state, as the switch was taken all the same.
func (p *Provider) switched(ctx context.Context, zone dnsprovider.Zone, on bool) dnsprovider.Setting {
	d, err := p.ZoneDetails(ctx, zone, dnsprovider.ZoneDetailRequest{})
	if err != nil {
		return dnsprovider.Unknown
	}

	want := dnsprovider.Off
	if on {
		want = dnsprovider.On
	}

	switch d.Status.DNSSEC {
	case want, dnsprovider.Unknown:
		return d.Status.DNSSEC
	}

	return dnsprovider.Pending
}
