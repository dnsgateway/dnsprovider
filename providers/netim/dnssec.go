package netim

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/dnssec"
)

// wireSigner is one entry of a domain's ds-record list: a dsData, with
// key, type, algo and digest, or a keyData, with flags, protocol, algo
// and pubKey.
type wireSigner struct {
	Key      number  `json:"key"`
	Type     number  `json:"type"`
	Algo     number  `json:"algo"`
	Digest   *string `json:"digest"`
	Flags    number  `json:"flags"`
	Protocol number  `json:"protocol"`
	PubKey   *string `json:"pubKey"`
}

// signerOf reads a ds-record entry; dnssec.Parse checks its ranges.
func signerOf(w wireSigner) (dnssec.Signer, error) {
	var (
		form  dnssec.Form
		value string
	)

	switch {
	case w.Digest != nil && w.PubKey == nil:
		if !w.Key.set || !w.Type.set || !w.Algo.set {
			return dnssec.Signer{}, errors.New("netim: malformed DS record")
		}

		form, value = dnssec.DS, fmt.Sprintf("%d %d %d %s", w.Key.value, w.Algo.value, w.Type.value, *w.Digest)
	case w.PubKey != nil && w.Digest == nil:
		if !w.Flags.set || !w.Protocol.set || !w.Algo.set {
			return dnssec.Signer{}, errors.New("netim: malformed DNSKEY record")
		}

		form, value = dnssec.DNSKEY, fmt.Sprintf("%d %d %d %s", w.Flags.value, w.Protocol.value, w.Algo.value, *w.PubKey)
	default:
		return dnssec.Signer{}, errors.New("netim: a ds-record entry is neither DS nor DNSKEY data")
	}

	s, err := dnssec.Parse(form, value)
	if err != nil {
		return dnssec.Signer{}, fmt.Errorf("netim: %w", err)
	}

	return s, nil
}

// registration reads the domain's info: ErrNotFound when the Account
// does not register it, and ErrUnsupported when Netim serves its DNS, as
// Netim's ds-record calls cover only domains on other DNS servers.
func (p *Provider) registration(ctx context.Context, zone dnsprovider.Zone) (string, error) {
	domain, err := zoneName(zone)
	if err != nil {
		return "", err
	}

	var info struct {
		HasDNS4Service flag `json:"HasDNS4Service"`
	}
	if _, err := p.domainInfo(ctx, domain, &info); err != nil {
		return "", err
	}

	if info.HasDNS4Service {
		return "", fmt.Errorf("netim: %s uses Netim's DNS, which signs it; its Signing Keys are not the registry's to set: %w", domain, dnsprovider.ErrUnsupported)
	}

	return domain, nil
}

// heldSigner is a DS or DNSKEY the registry holds for a domain, with the
// entry Netim gave for it.
type heldSigner struct {
	dnssec.Signer

	raw json.RawMessage
}

// heldSigners reads the DS and DNSKEY entries the registry holds.
func (p *Provider) heldSigners(ctx context.Context, domain string) ([]heldSigner, error) {
	var entries []json.RawMessage
	if err := p.read(ctx, http.MethodGet, domainPath(domain, "ds-record"), nil, &entries); err != nil {
		return nil, err
	}

	out := make([]heldSigner, 0, len(entries))

	for _, e := range entries {
		var w wireSigner
		if err := json.Unmarshal(e, &w); err != nil {
			return nil, fmt.Errorf("netim: malformed ds-record entry: %w", err)
		}

		s, err := signerOf(w)
		if err != nil {
			return nil, err
		}

		out = append(out, heldSigner{s, e})
	}

	return out, nil
}

// ListDelegationSigners implements dnsprovider.Provider
// (CapDSRegistrar): the Signing Keys the registry holds for a domain on
// other DNS servers. DS entries are grouped by key tag and algorithm,
// SHA-256 first; a DNSKEY entry's tag is computed from its content.
func (p *Provider) ListDelegationSigners(ctx context.Context, zone dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	domain, err := p.registration(ctx, zone)
	if err != nil {
		return nil, err
	}

	hs, err := p.heldSigners(ctx, domain)
	if err != nil {
		return nil, err
	}

	signers := make([]dnssec.Signer, 0, len(hs))
	for _, h := range hs {
		signers = append(signers, h.Signer)
	}

	keys, err := dnssec.Group(signers)
	if err != nil {
		return nil, fmt.Errorf("netim: %w", err)
	}

	return keys, nil
}

// dsData and keyData are the wire forms of a DS and a DNSKEY.
type dsData struct {
	Key    uint16 `json:"key"`
	Type   uint8  `json:"type"`
	Algo   uint8  `json:"algo"`
	Digest string `json:"digest"`
}

type keyData struct {
	Flags    uint16 `json:"flags"`
	Protocol uint8  `json:"protocol"`
	Algo     uint8  `json:"algo"`
	PubKey   string `json:"pubKey"`
}

// wire is a Signer as Netim takes it.
func wire(s dnssec.Signer) any {
	f := strings.Fields(s.Value)
	if s.Form == dnssec.DS {
		return dsData{Key: s.Tag, Type: s.DigestType, Algo: s.Algorithm, Digest: strings.ToLower(f[3])}
	}

	return keyData{Flags: binary.BigEndian.Uint16(s.RDATA), Protocol: 3, Algo: s.Algorithm, PubKey: f[3]}
}

// SetDelegationSigners implements dnsprovider.Provider (CapDSRegistrar):
// it replaces the Signing Keys the registry holds for a domain on other
// DNS servers with keys. It checks every key before any request, then
// reads the held set. A held entry and a key are the same key when they
// share a DNSKEY or a DS, Netim's or one computed from a DNSKEY, so an
// unchanged set in either form sends no write. Otherwise it first adds
// each missing key, as its DNSKEY when it has one and else as its DS
// records, and only then removes the held entries no key wants, each as
// Netim gave it: a failure part-way never leaves the Delegation without
// a key. A key of an algorithm or digest type no registry takes is
// ErrUnsupported before any request; Netim's own refusals are APIErrors.
func (p *Provider) SetDelegationSigners(ctx context.Context, zone dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	if len(keys) == 0 {
		return dnsprovider.ErrNoSigningKeys
	}

	want, err := dnssec.CheckKeys(keys)
	if err != nil {
		return fmt.Errorf("netim: %w", err)
	}

	domain, err := p.registration(ctx, zone)
	if err != nil {
		return err
	}

	hs, err := p.heldSigners(ctx, domain)
	if err != nil {
		return err
	}

	heldIDs := map[string]bool{}
	for _, h := range hs {
		for _, id := range h.Identities(domain) {
			heldIDs[id] = true
		}
	}

	wantIDs := map[string]bool{}
	added := map[dnssec.Form][]any{} // by form, in key order

	for _, w := range want {
		ids := w.Identities(domain)

		if !slices.ContainsFunc(ids, func(id string) bool { return heldIDs[id] }) {
			if w.DNSKEY != nil {
				added[dnssec.DNSKEY] = appendNew(added[dnssec.DNSKEY], wire(*w.DNSKEY))
			} else {
				for _, s := range w.DS {
					added[dnssec.DS] = appendNew(added[dnssec.DS], wire(s))
				}
			}
		}

		for _, id := range ids {
			wantIDs[id] = true
		}
	}

	removed := map[dnssec.Form][]json.RawMessage{}

	for _, h := range hs {
		if !slices.ContainsFunc(h.Identities(domain), func(id string) bool { return wantIDs[id] }) {
			removed[h.Form] = append(removed[h.Form], h.raw)
		}
	}

	path := domainPath(domain, "ds-record")

	for _, form := range []dnssec.Form{dnssec.DNSKEY, dnssec.DS} {
		if data := added[form]; len(data) > 0 {
			if err := p.write(ctx, http.MethodPost, path, map[string]any{"data": data}); err != nil {
				return fmt.Errorf("netim: add Signing Keys: %w", err)
			}
		}
	}

	for _, form := range []dnssec.Form{dnssec.DNSKEY, dnssec.DS} {
		// A delete with an empty data list could delete every key.
		if data := removed[form]; len(data) > 0 {
			if err := p.write(ctx, http.MethodDelete, path, map[string]any{"data": data}); err != nil {
				return fmt.Errorf("netim: remove Signing Keys: %w", err)
			}
		}
	}

	return nil
}

// appendNew appends v unless list holds it.
func appendNew(list []any, v any) []any {
	if slices.Contains(list, v) {
		return list
	}

	return append(list, v)
}

// DeleteDelegationSigners implements dnsprovider.Provider
// (CapDSRegistrar): it removes every Signing Key the registry holds for
// a domain on other DNS servers, with Netim's delete-all call, a DELETE
// with no body.
func (p *Provider) DeleteDelegationSigners(ctx context.Context, zone dnsprovider.Zone) error {
	domain, err := p.registration(ctx, zone)
	if err != nil {
		return err
	}

	if err := p.write(ctx, http.MethodDelete, domainPath(domain, "ds-record"), nil); err != nil {
		return fmt.Errorf("netim: delete Signing Keys: %w", err)
	}

	return nil
}
