package inwx

import (
	"context"
	"fmt"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/dnssec"
)

// dnssecStatus values of dnssec.info. INWX's documentation lists
// DELETE_ALL, MANUAL and UPDATE (dnssecDomainStatus); its Terraform
// provider compares with AUTO, and NONE is the spec's word for a zone
// without keys. No capture confirms the vocabulary yet.
const (
	statusAuto      = "AUTO"
	statusNone      = "NONE"
	statusManual    = "MANUAL"
	statusUpdate    = "UPDATE"
	statusDeleteAll = "DELETE_ALL"
)

// setting is the DNSSEC State of a dnssecStatus: AUTO, INWX signing the
// zone, is On; NONE and MANUAL, where INWX does not sign and the
// registrar holds the user's own keys, are Off; UPDATE and DELETE_ALL,
// read as a change in progress, are Pending. Any other status is
// Unknown, never Off.
func setting(status string) dnsprovider.Setting {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case statusAuto:
		return dnsprovider.On
	case statusNone, statusManual:
		return dnsprovider.Off
	case statusUpdate, statusDeleteAll:
		return dnsprovider.Pending
	}

	return dnsprovider.Unknown
}

// dnssecEntry is a zone's entry of dnssec.info. The documentation and
// the Terraform provider spell its status dnssecStatus, goinwx (over
// XML-RPC) dnsSecStatus; both are read.
type dnssecEntry struct {
	Domain       string `json:"domain"`
	DNSSECStatus string `json:"dnssecStatus"`
	DNSSecStatus string `json:"dnsSecStatus"`
}

func (e dnssecEntry) status() string {
	if e.DNSSECStatus != "" {
		return e.DNSSECStatus
	}

	return e.DNSSecStatus
}

// dnssecStatus is the zone's dnssecStatus from dnssec.info; empty when
// INWX answers no entry for it.
func (p *Provider) dnssecStatus(ctx context.Context, name string) (string, error) {
	var res struct {
		Data []dnssecEntry `json:"data"`
	}

	if err := p.read(ctx, "dnssec.info", map[string]any{"domains": []string{name}}, &res); err != nil {
		return "", err
	}

	for _, e := range res.Data {
		if zoneName(e.Domain) == name {
			return e.status(), nil
		}
	}

	return "", nil
}

// signingKeys are the Signing Keys INWX signs the domain with: the
// active KSKs of dnssec.listkeys, grouped by key tag and algorithm.
func (p *Provider) signingKeys(ctx context.Context, domain string) ([]dnsprovider.SigningKey, error) {
	keys, err := p.activeKeys(ctx, domain)
	if err != nil {
		return nil, err
	}

	var signers []dnssec.Signer

	for _, k := range keys {
		if !k.ksk() {
			continue
		}

		s, err := k.signers()
		if err != nil {
			return nil, err
		}

		signers = append(signers, s...)
	}

	out, err := dnssec.Group(signers)
	if err != nil {
		return nil, fmt.Errorf("inwx: dnssec.listkeys for %s: %w", domain, err)
	}

	return out, nil
}

// ZoneDetails implements dnsprovider.Provider: the DNSSEC State is the
// zone's dnssecStatus of dnssec.info (see setting); no entry for the
// zone is Unknown. Signing Keys, when requested, are the active KSKs
// dnssec.listkeys answers for a zone INWX signs (AUTO), and none for
// any other. A failed read is the property's error, its state Unknown
// and never Off. HSTS and minimum TLS are unsupported.
func (p *Provider) ZoneDetails(ctx context.Context, zone dnsprovider.Zone, request dnsprovider.ZoneDetailRequest) (dnsprovider.ZoneDetails, error) {
	unsupported := dnsprovider.PropertyResult{State: dnsprovider.PropertyUnsupported}
	details := dnsprovider.ZoneDetails{Zone: zone, Properties: dnsprovider.ZoneDetailProperties{HSTS: unsupported, MinTLS: unsupported}}

	var status string

	name, err := namedZone(zone.Name)
	if err == nil {
		status, err = p.dnssecStatus(ctx, name)
	}

	if err != nil {
		failed := dnsprovider.PropertyResult{State: dnsprovider.PropertyFailed, Err: err}

		details.Properties.DNSSEC = failed
		if request.SigningKeys {
			details.Properties.SigningKeys = failed
		}

		return details, err
	}

	details.Status.DNSSEC = setting(status)
	details.Properties.DNSSEC = dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}

	if !request.SigningKeys {
		return details, nil
	}

	if details.Status.DNSSEC == dnsprovider.On {
		keys, err := p.signingKeys(ctx, name)
		if err != nil {
			details.Properties.SigningKeys = dnsprovider.PropertyResult{State: dnsprovider.PropertyFailed, Err: err}

			return details, err
		}

		details.SigningKeys = keys
	}

	details.Properties.SigningKeys = dnsprovider.PropertyResult{State: dnsprovider.PropertyRead}

	return details, nil
}
