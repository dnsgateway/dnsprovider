package infomaniak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/dnssec"
)

// text is a string field of the DNSSEC answer, which the schema types as
// a string; a number is taken too.
type text string

func (t *text) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*t = text(s)

		return nil
	}

	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}

	*t = text(n)

	return nil
}

// wireSigner is one entry of dnssec_data: DS data, with key, algorithm,
// digest_type and digest, or key data, with flags, protocol, algorithm
// and public_key.
type wireSigner struct {
	Key        text `json:"key"`
	Algorithm  text `json:"algorithm"`
	DigestType text `json:"digest_type"`
	Digest     text `json:"digest"`
	Flags      text `json:"flags"`
	Protocol   text `json:"protocol"`
	PublicKey  text `json:"public_key"`
}

// signer reads an entry by the fields it has, as each entry is one form
// whatever the answer's dnssec_type says.
func (w wireSigner) signer() (dnssec.Signer, error) {
	var (
		form  dnssec.Form
		value string
	)

	switch {
	case w.Digest != "" && w.PublicKey == "":
		form, value = dnssec.DS, fmt.Sprintf("%s %s %s %s", w.Key, w.Algorithm, w.DigestType, w.Digest)
	case w.PublicKey != "" && w.Digest == "":
		form, value = dnssec.DNSKEY, fmt.Sprintf("%s %s %s %s", w.Flags, w.Protocol, w.Algorithm, w.PublicKey)
	default:
		return dnssec.Signer{}, errors.New("infomaniak: a dnssec_data entry is neither DS nor key data")
	}

	s, err := dnssec.Parse(form, value)
	if err != nil {
		return dnssec.Signer{}, fmt.Errorf("infomaniak: %w", err)
	}

	return s, nil
}

// dnssecPath is the path of a domain's DNSSEC call, such as
// /2/domains/domains/example.com/dnssec/check.
func dnssecPath(domain, action string) string {
	return "/2/domains/domains/" + url.PathEscape(domain) + "/dnssec/" + action
}

// registration is the Zone's domain, once the Account is known to register
// it, and Infomaniak not to serve its DNS: ErrNotFound when the domain is
// not in the Account's domain list, and ErrUnsupported when Infomaniak
// holds a Zone of it. Infomaniak's DNSSEC calls set the registry's keys
// only for a domain on other nameservers; for its own Zones it signs them
// itself. A domain with an Infomaniak Zone but a Delegation to other
// nameservers is taken as Infomaniak's: its answers do not tell the two
// apart.
func (p *Provider) registration(ctx context.Context, zone dnsprovider.Zone) (string, error) {
	domain, err := zoneOf(zone)
	if err != nil {
		return "", err
	}

	held, err := p.registers(ctx, domain)
	if err != nil {
		return "", err
	}

	if !held {
		return "", fmt.Errorf("infomaniak: the Account does not register %s: %w", domain, dnsprovider.ErrNotFound)
	}

	switch _, err := p.get(ctx, zonePath(domain), nil, nil); {
	case err == nil:
		return "", fmt.Errorf("infomaniak: Infomaniak serves and signs %s; its Signing Keys are not the registry's to set: %w", domain, dnsprovider.ErrUnsupported)
	case !errors.Is(err, dnsprovider.ErrNotFound):
		return "", err
	}

	return domain, nil
}

// held reads the DS and DNSKEY entries the registry holds for the domain;
// none when it reports no DNSSEC.
func (p *Provider) held(ctx context.Context, domain string) ([]dnssec.Signer, error) {
	var check struct {
		HasDNSSEC bool         `json:"has_dnssec"`
		Data      []wireSigner `json:"dnssec_data"`
	}

	if _, err := p.get(ctx, dnssecPath(domain, "check"), nil, &check); err != nil {
		return nil, err
	}

	if !check.HasDNSSEC {
		return nil, nil
	}

	out := make([]dnssec.Signer, 0, len(check.Data))

	for _, w := range check.Data {
		s, err := w.signer()
		if err != nil {
			return nil, err
		}

		out = append(out, s)
	}

	return out, nil
}

// ListDelegationSigners implements dnsprovider.Provider
// (CapDSRegistrar): the Signing Keys the registry holds for a domain on
// other nameservers, none when it is unsigned. DS data is grouped by key
// tag and algorithm, SHA-256 first, the digest in upper case; key data's
// tag is computed from its content.
func (p *Provider) ListDelegationSigners(ctx context.Context, zone dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	domain, err := p.registration(ctx, zone)
	if err != nil {
		return nil, err
	}

	hs, err := p.held(ctx, domain)
	if err != nil {
		return nil, err
	}

	keys, err := dnssec.Group(hs)
	if err != nil {
		return nil, fmt.Errorf("infomaniak: %w", err)
	}

	return keys, nil
}

// dnssecData is the whole set in one form, as the check call reports one
// form for a set: every key's DS records when each key has some, else
// every key's DNSKEY when each has one, else each key's DS records or,
// for a key with a DNSKEY alone, its SHA-256 DS computed for the domain.
func dnssecData(domain string, want []dnssec.Key) []string {
	allDS := !slices.ContainsFunc(want, func(w dnssec.Key) bool { return len(w.DS) == 0 })
	allKeys := !slices.ContainsFunc(want, func(w dnssec.Key) bool { return w.DNSKEY == nil })

	var out []string

	add := func(v string) {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}

	for _, w := range want {
		switch {
		case allDS || (!allKeys && len(w.DS) > 0):
			for _, s := range w.DS {
				add(s.Value)
			}
		case allKeys:
			add(w.DNSKEY.Value)
		default:
			// The key passed the checks, so its digest is computed.
			digest, _ := dnssec.Digest(domain, w.DNSKEY.RDATA, 2)
			add(fmt.Sprintf("%d %d 2 %s", w.DNSKEY.Tag, w.DNSKEY.Algorithm, digest))
		}
	}

	return out
}

// SetDelegationSigners implements dnsprovider.Provider (CapDSRegistrar):
// it replaces the Signing Keys the registry holds for a domain on other
// nameservers with keys. It checks every key before any request, then
// reads the held set: a held entry and a key are the same key when they
// share a DNSKEY or a DS, held or computed from a DNSKEY, so an unchanged
// set in either form sends no write. Otherwise one enable call sends the
// whole set in dnssec_data, which replaces the held set. A key of an
// algorithm or digest type no registry takes is ErrUnsupported before
// any request; Infomaniak's own refusals are APIErrors.
func (p *Provider) SetDelegationSigners(ctx context.Context, zone dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	if len(keys) == 0 {
		return dnsprovider.ErrNoSigningKeys
	}

	want, err := dnssec.CheckKeys(keys)
	if err != nil {
		return fmt.Errorf("infomaniak: %w", err)
	}

	domain, err := p.registration(ctx, zone)
	if err != nil {
		return err
	}

	hs, err := p.held(ctx, domain)
	if err != nil {
		return err
	}

	if dnssec.Diff(domain, hs, func(s dnssec.Signer) []dnssec.Signer { return []dnssec.Signer{s} }, want).Same() {
		return nil
	}

	body := map[string][]string{"dnssec_data": dnssecData(domain, want)}
	if _, err := p.write(ctx, http.MethodPost, dnssecPath(domain, "enable"), body); err != nil {
		return fmt.Errorf("infomaniak: set Signing Keys: %w", err)
	}

	return nil
}

// DeleteDelegationSigners implements dnsprovider.Provider
// (CapDSRegistrar): it removes every Signing Key the registry holds for
// a domain on other nameservers, with the disable call.
func (p *Provider) DeleteDelegationSigners(ctx context.Context, zone dnsprovider.Zone) error {
	domain, err := p.registration(ctx, zone)
	if err != nil {
		return err
	}

	if _, err := p.write(ctx, http.MethodPost, dnssecPath(domain, "disable"), struct{}{}); err != nil {
		return fmt.Errorf("infomaniak: delete Signing Keys: %w", err)
	}

	return nil
}
