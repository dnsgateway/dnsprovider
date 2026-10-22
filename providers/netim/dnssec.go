package netim

import (
	"cmp"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// signer is one DS or DNSKEY, checked, in presentation form after its
// type: a DS's digest in upper case, a DNSKEY's key in base64.
type signer struct {
	typ        string // "DS" or "DNSKEY"
	value      string
	tag        uint16
	algorithm  uint8
	digestType uint8  // a DS's
	rdata      []byte // a DNSKEY's RDATA
}

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

// signerOf reads a ds-record entry; parseSigner checks its ranges.
func signerOf(w wireSigner) (signer, error) {
	switch {
	case w.Digest != nil && w.PubKey == nil:
		if !w.Key.set || !w.Type.set || !w.Algo.set {
			return signer{}, errors.New("netim: malformed DS record")
		}

		return parseSigner("DS", fmt.Sprintf("%d %d %d %s", w.Key.value, w.Algo.value, w.Type.value, *w.Digest))
	case w.PubKey != nil && w.Digest == nil:
		if !w.Flags.set || !w.Protocol.set || !w.Algo.set {
			return signer{}, errors.New("netim: malformed DNSKEY record")
		}

		return parseSigner("DNSKEY", fmt.Sprintf("%d %d %d %s", w.Flags.value, w.Protocol.value, w.Algo.value, *w.PubKey))
	}

	return signer{}, errors.New("netim: a ds-record entry is neither DS nor DNSKEY data")
}

// parseSigner checks a DS or DNSKEY in presentation form after its type.
// A DNSKEY's key tag is computed from its RDATA, as RFC 4034 Appendix B
// does.
func parseSigner(typ, value string) (signer, error) {
	f := strings.Fields(value)
	if len(f) < 4 {
		return signer{}, fmt.Errorf("netim: malformed %s record %q", typ, value)
	}

	var n [3]uint64

	for i, bits := range []int{16, 8, 8} {
		var err error
		if n[i], err = parseUint(f[i], bits); err != nil {
			return signer{}, fmt.Errorf("netim: malformed %s record %q", typ, value)
		}
	}

	s := signer{typ: typ}

	switch typ {
	case "DS":
		digest, err := hex.DecodeString(strings.Join(f[3:], ""))
		if err != nil || len(digest) == 0 {
			return signer{}, fmt.Errorf("netim: malformed DS digest in %q", value)
		}

		s.tag, s.algorithm, s.digestType = uint16(n[0]), uint8(n[1]), uint8(n[2])
		s.value = fmt.Sprintf("%d %d %d %s", n[0], n[1], n[2], strings.ToUpper(hex.EncodeToString(digest)))
	case "DNSKEY":
		pub, err := base64.StdEncoding.DecodeString(strings.Join(f[3:], ""))
		if err != nil || len(pub) == 0 || n[1] != 3 {
			return signer{}, fmt.Errorf("netim: malformed DNSKEY %q", value)
		}

		s.algorithm = uint8(n[2])
		s.value = fmt.Sprintf("%d 3 %d %s", n[0], n[2], base64.StdEncoding.EncodeToString(pub))
		s.rdata = append(binary.BigEndian.AppendUint16(nil, uint16(n[0])), 3, s.algorithm)
		s.rdata = append(s.rdata, pub...)

		if s.tag, err = keyTag(s.algorithm, s.rdata); err != nil {
			return signer{}, err
		}
	default:
		return signer{}, fmt.Errorf("netim: unexpected signing record type %s", typ)
	}

	return s, nil
}

func parseUint(s string, bits int) (uint64, error) {
	var n number
	if err := n.UnmarshalJSON([]byte(s)); err != nil || !n.set || n.value >= 1<<bits {
		return 0, errors.New("out of range")
	}

	return n.value, nil
}

// keyTag is a DNSKEY's key tag, from its RDATA (RFC 4034 Appendix B).
func keyTag(algorithm uint8, rdata []byte) (uint16, error) {
	if algorithm == 1 {
		if len(rdata) < 7 {
			return 0, errors.New("netim: malformed RSA/MD5 DNSKEY")
		}

		return binary.BigEndian.Uint16(rdata[len(rdata)-3:]), nil
	}

	var sum uint32

	for i, b := range rdata {
		if i%2 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}

	sum += sum >> 16 & 0xFFFF

	return uint16(sum), nil //nolint:gosec // the key tag is the low 16 bits
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
	signer

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

	rank := func(s signer) int {
		if s.digestType == 2 {
			return -1
		}

		return int(s.digestType)
	}

	slices.SortStableFunc(hs, func(a, b heldSigner) int {
		return cmp.Or(cmp.Compare(a.tag, b.tag), cmp.Compare(a.algorithm, b.algorithm), cmp.Compare(rank(a.signer), rank(b.signer)), strings.Compare(a.value, b.value))
	})

	keys := []dnsprovider.SigningKey{}

	for i, h := range hs {
		if i == 0 || h.tag != hs[i-1].tag || h.algorithm != hs[i-1].algorithm {
			keys = append(keys, dnsprovider.SigningKey{KeyTag: h.tag})
		}

		k := &keys[len(keys)-1]

		switch {
		case h.typ == "DS" && !slices.Contains(k.DS, h.value):
			k.DS = append(k.DS, h.value)
		case h.typ == "DNSKEY" && k.DNSKEY != "" && k.DNSKEY != h.value:
			return nil, fmt.Errorf("netim: distinct DNSKEYs share key tag %d and algorithm %d", h.tag, h.algorithm)
		case h.typ == "DNSKEY":
			k.DNSKEY = h.value
		}
	}

	return keys, nil
}

// wanted is a Signing Key to set, checked: its DNSKEY, when it has one,
// and its DS records.
type wanted struct {
	dnskey *signer
	ds     []signer
}

// checkKeys checks every key: each needs a DNSKEY or a DS of an
// algorithm and digest type a registry can take (sendable), and every
// form of a key must have its key tag and one algorithm.
func checkKeys(keys []dnsprovider.SigningKey) ([]wanted, error) {
	out := make([]wanted, 0, len(keys))

	for _, k := range keys {
		if k.DNSKEY == "" && len(k.DS) == 0 {
			return nil, fmt.Errorf("netim: key tag %d has no DNSKEY or DS: %w", k.KeyTag, dnsprovider.ErrUnsupported)
		}

		var (
			w     wanted
			forms []signer
		)

		if k.DNSKEY != "" {
			s, err := parseSigner("DNSKEY", k.DNSKEY)
			if err == nil {
				err = s.sendable()
			}

			if err != nil {
				return nil, err
			}

			w.dnskey = &s
			forms = append(forms, s)
		}

		for _, v := range k.DS {
			s, err := parseSigner("DS", v)
			if err == nil {
				err = s.sendable()
			}

			if err != nil {
				return nil, err
			}

			w.ds = append(w.ds, s)
			forms = append(forms, s)
		}

		for _, s := range forms {
			if s.tag != k.KeyTag || s.algorithm != forms[0].algorithm {
				return nil, fmt.Errorf("netim: the %s %q is not of key tag %d and algorithm %d", s.typ, s.value, k.KeyTag, forms[0].algorithm)
			}
		}

		out = append(out, w)
	}

	return out, nil
}

// sendable reports ErrUnsupported for a signer no registry takes: an
// algorithm that IANA's DNS Security Algorithm Numbers registry does not
// assign for zone signing, or that RFC 8624 says MUST NOT sign (RSAMD5,
// DSA, DSA-NSEC3-SHA1, ECC-GOST); or a DS digest type that IANA's DS
// RR Type Digest Algorithms registry does not assign. Netim documents no
// algorithm it refuses, nor a refusal code for one, so its own refusals
// stay APIErrors.
func (s signer) sendable() error {
	switch s.algorithm {
	case 5, 7, 8, 10, 13, 14, 15, 16, 17, 23:
	default:
		return fmt.Errorf("netim: the %s %q has algorithm %d, which DNSSEC does not sign with: %w", s.typ, s.value, s.algorithm, dnsprovider.ErrUnsupported)
	}

	if s.typ == "DS" && (s.digestType < 1 || s.digestType > 6) {
		return fmt.Errorf("netim: the DS %q has digest type %d, which is not assigned: %w", s.value, s.digestType, dnsprovider.ErrUnsupported)
	}

	return nil
}

// identities are the forms a signer is known by: a DNSKEY's own, and the
// DS records of a DNSKEY, held or computed for the domain. Two signers
// are one key when they share one.
func (s signer) identities(domain string) []string {
	if s.typ == "DS" {
		return []string{"DS " + s.value}
	}

	owner := []byte{}
	for label := range strings.SplitSeq(strings.ToLower(domain), ".") {
		owner = append(append(owner, byte(len(label))), label...)
	}

	data := append(append(owner, 0), s.rdata...)
	sha1Sum, sha256Sum, sha384Sum := sha1.Sum(data), sha256.Sum256(data), sha512.Sum384(data) //nolint:gosec // SHA-1 is DS digest type 1

	out := []string{"DNSKEY " + s.value}
	for digestType, sum := range map[int][]byte{1: sha1Sum[:], 2: sha256Sum[:], 4: sha384Sum[:]} {
		out = append(out, fmt.Sprintf("DS %d %d %d %s", s.tag, s.algorithm, digestType, strings.ToUpper(hex.EncodeToString(sum))))
	}

	return out
}

// identities are the forms a wanted key is known by.
func (w wanted) identities(domain string) []string {
	var out []string
	if w.dnskey != nil {
		out = w.dnskey.identities(domain)
	}

	for _, s := range w.ds {
		out = append(out, s.identities(domain)...)
	}

	return out
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

// wire is a signer as Netim takes it.
func (s signer) wire() any {
	f := strings.Fields(s.value)
	if s.typ == "DS" {
		return dsData{Key: s.tag, Type: s.digestType, Algo: s.algorithm, Digest: strings.ToLower(f[3])}
	}

	return keyData{Flags: binary.BigEndian.Uint16(s.rdata), Protocol: 3, Algo: s.algorithm, PubKey: f[3]}
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

	want, err := checkKeys(keys)
	if err != nil {
		return err
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
		for _, id := range h.identities(domain) {
			heldIDs[id] = true
		}
	}

	wantIDs := map[string]bool{}
	added := map[string][]any{} // by form, in key order

	for _, w := range want {
		ids := w.identities(domain)

		if !slices.ContainsFunc(ids, func(id string) bool { return heldIDs[id] }) {
			if w.dnskey != nil {
				added["DNSKEY"] = appendNew(added["DNSKEY"], w.dnskey.wire())
			} else {
				for _, s := range w.ds {
					added["DS"] = appendNew(added["DS"], s.wire())
				}
			}
		}

		for _, id := range ids {
			wantIDs[id] = true
		}
	}

	removed := map[string][]json.RawMessage{}

	for _, h := range hs {
		if !slices.ContainsFunc(h.identities(domain), func(id string) bool { return wantIDs[id] }) {
			removed[h.typ] = append(removed[h.typ], h.raw)
		}
	}

	path := domainPath(domain, "ds-record")

	for _, form := range []string{"DNSKEY", "DS"} {
		if data := added[form]; len(data) > 0 {
			if err := p.write(ctx, http.MethodPost, path, map[string]any{"data": data}); err != nil {
				return fmt.Errorf("netim: add Signing Keys: %w", err)
			}
		}
	}

	for _, form := range []string{"DNSKEY", "DS"} {
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
