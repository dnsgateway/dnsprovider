package infomaniak

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dnsgateway/dnsprovider"
)

// UpdateZone implements dnsprovider.Provider (CapZoneUpdater): it
// switches DNSSEC, the one Zone setting Infomaniak has, then refuses
// HSTS, then minimum TLS, as the contract orders them. DNSSEC is switched
// for a domain the Account registers and Infomaniak serves, with one
// POST of {} to the registrar's dnssec/enable or dnssec/disable call,
// sent once and whatever the Zone's state, and returned as the Zone
// reads after it. Left nil, it is read. HSTS or MinTLS set is
// ErrUnsupported, returned with DNSSEC as written or read before it;
// with nothing set, UpdateZone reads DNSSEC and fails when that fails.
func (p *Provider) UpdateZone(ctx context.Context, zone dnsprovider.Zone, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	var status dnsprovider.ZoneStatus

	switch {
	case u.DNSSEC != nil:
		domain, err := p.signable(ctx, zone)
		if err != nil {
			return dnsprovider.ZoneStatus{}, err
		}

		action := "disable"
		if *u.DNSSEC {
			action = "enable"
		}

		if _, err := p.write(ctx, http.MethodPost, dnssecPath(domain, action), struct{}{}); err != nil {
			return dnsprovider.ZoneStatus{}, fmt.Errorf("infomaniak: %s DNSSEC: %w", action, err)
		}

		status.DNSSEC = p.switched(ctx, zone, *u.DNSSEC)
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

	// HSTS, then MinTLS, fail in turn: DNSSEC, written or read before,
	// stays as it is known.
	if u.HSTS != nil {
		return status, fmt.Errorf("infomaniak: Infomaniak has no HSTS setting: %w", dnsprovider.ErrUnsupported)
	}

	if u.MinTLS != nil {
		return status, fmt.Errorf("infomaniak: Infomaniak has no minimum TLS setting: %w", dnsprovider.ErrUnsupported)
	}

	return status, nil
}

// switched is DNSSEC after a switch Infomaniak took. Its answer, data
// true, holds no state, so the Zone is read again: the state asked for
// when the Zone shows it, Pending while it shows the old one, and
// Unknown when the read fails, as the write was taken all the same.
func (p *Provider) switched(ctx context.Context, zone dnsprovider.Zone, on bool) dnsprovider.Setting {
	d, err := p.ZoneDetails(ctx, zone, dnsprovider.ZoneDetailRequest{})
	if err != nil {
		return dnsprovider.Unknown
	}

	if (d.Status.DNSSEC == dnsprovider.On) != on {
		return dnsprovider.Pending
	}

	return d.Status.DNSSEC
}

// signable is the Zone's domain, once Infomaniak is known to serve it
// and the Account to register it: the inverse of registration. A Zone
// Infomaniak does not hold is ErrNotServed or ErrNotFound, as for
// GetZone, and one of a domain the Account does not register is
// ErrUnsupported, as only the registrar's DNSSEC call switches signing.
func (p *Provider) signable(ctx context.Context, zone dnsprovider.Zone) (string, error) {
	domain, err := zoneOf(zone)
	if err != nil {
		return "", err
	}

	if _, err := p.get(ctx, zonePath(domain), nil, nil); err != nil {
		return "", p.notServed(ctx, domain, err)
	}

	held, err := p.registers(ctx, domain)
	if err != nil {
		return "", err
	}

	if !held {
		return "", fmt.Errorf("infomaniak: the Account does not register %s; Infomaniak switches DNSSEC only for its own Registrations: %w", domain, dnsprovider.ErrUnsupported)
	}

	return domain, nil
}
