// Package dnssec holds the DNSSEC handling registrar adapters share: a
// DNSKEY's key tag and DS digests, the algorithms and digest types a
// registry can take, and the parsing, checking and grouping of the DS
// and DNSKEY records of Signing Keys.
package dnssec

import (
	"cmp"
	"crypto/sha1" //nolint:gosec // SHA-1 is DS digest type 1
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// KeyTag is a DNSKEY's key tag, from its RDATA: flags, protocol,
// algorithm and key (RFC 4034 Appendix B).
func KeyTag(rdata []byte) (uint16, error) {
	if len(rdata) < 4 {
		return 0, errors.New("malformed DNSKEY")
	}

	if rdata[3] == 1 {
		if len(rdata) < 7 {
			return 0, errors.New("malformed RSA/MD5 DNSKEY")
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

// Digest is the digest, in upper-case hex, of a DS of digest type 1
// (SHA-1), 2 (SHA-256) or 4 (SHA-384) for the DNSKEY of that RDATA at
// owner (RFC 4034 section 5.1.4).
func Digest(owner string, rdata []byte, digestType uint8) (string, error) {
	var wire []byte

	for label := range strings.SplitSeq(strings.TrimSuffix(strings.ToLower(owner), "."), ".") {
		if label != "" {
			wire = append(append(wire, byte(len(label))), label...)
		}
	}

	data := append(append(wire, 0), rdata...)

	var sum []byte

	switch digestType {
	case 1:
		s := sha1.Sum(data) //nolint:gosec // SHA-1 is DS digest type 1
		sum = s[:]
	case 2:
		s := sha256.Sum256(data)
		sum = s[:]
	case 4:
		s := sha512.Sum384(data)
		sum = s[:]
	default:
		return "", fmt.Errorf("DS digest type %d is not computed", digestType)
	}

	return strings.ToUpper(hex.EncodeToString(sum)), nil
}

// Signable reports whether a zone may be signed with algorithm: one that
// IANA's DNS Security Algorithm Numbers registry assigns for zone
// signing, other than those RFC 8624 says MUST NOT sign (RSAMD5, DSA,
// DSA-NSEC3-SHA1, ECC-GOST).
func Signable(algorithm uint8) bool {
	switch algorithm {
	case 5, 7, 8, 10, 13, 14, 15, 16, 17, 23:
		return true
	}

	return false
}

// DigestAssigned reports whether IANA's DS RR Type Digest Algorithms
// registry assigns digestType.
func DigestAssigned(digestType uint8) bool {
	return digestType >= 1 && digestType <= 6
}

// Form is the record type a Signer is written in: a DS or a DNSKEY.
type Form uint8

// The forms of a Signer.
const (
	DS Form = iota + 1
	DNSKEY
)

// String is the form's record type.
func (f Form) String() string {
	switch f {
	case DS:
		return "DS"
	case DNSKEY:
		return "DNSKEY"
	}

	return "Form(" + strconv.Itoa(int(f)) + ")"
}

// Signer is one DS or DNSKEY, checked, in presentation form after its
// type: a DS's digest in upper case, a DNSKEY's key in base64.
type Signer struct {
	Form       Form
	Value      string
	Tag        uint16
	Algorithm  uint8
	DigestType uint8  // a DS's
	RDATA      []byte // a DNSKEY's
}

// Parse checks a DS or DNSKEY in presentation form after its type. A
// DNSKEY's key tag is computed from its RDATA.
func Parse(form Form, value string) (Signer, error) {
	f := strings.Fields(value)
	if len(f) < 4 {
		return Signer{}, fmt.Errorf("malformed %s record %q", form, value)
	}

	var n [3]uint64

	for i, bits := range []int{16, 8, 8} {
		var err error
		if n[i], err = strconv.ParseUint(f[i], 10, bits); err != nil {
			return Signer{}, fmt.Errorf("malformed %s record %q", form, value)
		}
	}

	s := Signer{Form: form}

	switch form {
	case DS:
		digest, err := hex.DecodeString(strings.Join(f[3:], ""))
		if err != nil || len(digest) == 0 {
			return Signer{}, fmt.Errorf("malformed DS digest in %q", value)
		}

		s.Tag, s.Algorithm, s.DigestType = uint16(n[0]), uint8(n[1]), uint8(n[2])
		s.Value = fmt.Sprintf("%d %d %d %s", n[0], n[1], n[2], strings.ToUpper(hex.EncodeToString(digest)))
	case DNSKEY:
		pub, err := base64.StdEncoding.DecodeString(strings.Join(f[3:], ""))
		if err != nil || len(pub) == 0 || n[1] != 3 {
			return Signer{}, fmt.Errorf("malformed DNSKEY %q", value)
		}

		s.Algorithm = uint8(n[2])
		s.Value = fmt.Sprintf("%d 3 %d %s", n[0], n[2], base64.StdEncoding.EncodeToString(pub))
		s.RDATA = append(binary.BigEndian.AppendUint16(nil, uint16(n[0])), 3, s.Algorithm)
		s.RDATA = append(s.RDATA, pub...)

		if s.Tag, err = KeyTag(s.RDATA); err != nil {
			return Signer{}, err
		}
	default:
		return Signer{}, fmt.Errorf("unexpected signing record type %s", form)
	}

	return s, nil
}

// Sendable reports dnsprovider.ErrUnsupported for a Signer no registry
// takes: an algorithm DNSSEC does not sign zones with (Signable), or a DS
// digest type IANA does not assign (DigestAssigned). Registrars document
// neither the algorithms they refuse nor a refusal code for one, so
// adapters check them before any request.
func (s Signer) Sendable() error {
	if !Signable(s.Algorithm) {
		return fmt.Errorf("the %s %q has algorithm %d, which DNSSEC does not sign with: %w", s.Form, s.Value, s.Algorithm, dnsprovider.ErrUnsupported)
	}

	if s.Form == DS && !DigestAssigned(s.DigestType) {
		return fmt.Errorf("the DS %q has digest type %d, which is not assigned: %w", s.Value, s.DigestType, dnsprovider.ErrUnsupported)
	}

	return nil
}

// Identities are the forms a Signer is known by: a DS's own, or a
// DNSKEY's own and the DS records of digest types 1, 2 and 4 computed
// from it for the domain. Two Signers are one key when they share one.
func (s Signer) Identities(domain string) []string {
	if s.Form == DS {
		return []string{"DS " + s.Value}
	}

	out := []string{"DNSKEY " + s.Value}

	for _, digestType := range []uint8{1, 2, 4} {
		if digest, err := Digest(domain, s.RDATA, digestType); err == nil {
			out = append(out, fmt.Sprintf("DS %d %d %d %s", s.Tag, s.Algorithm, digestType, digest))
		}
	}

	return out
}

// Group makes the Signing Keys of the Signers a registry holds: one per
// key tag and algorithm, its DS records SHA-256 first, then by digest
// type. Distinct DNSKEYs of one key tag and algorithm are an error.
func Group(signers []Signer) ([]dnsprovider.SigningKey, error) {
	rank := func(s Signer) int {
		if s.DigestType == 2 {
			return -1
		}

		return int(s.DigestType)
	}

	hs := slices.Clone(signers)
	slices.SortStableFunc(hs, func(a, b Signer) int {
		return cmp.Or(cmp.Compare(a.Tag, b.Tag), cmp.Compare(a.Algorithm, b.Algorithm), cmp.Compare(rank(a), rank(b)), strings.Compare(a.Value, b.Value))
	})

	keys := []dnsprovider.SigningKey{}

	for i, h := range hs {
		if i == 0 || h.Tag != hs[i-1].Tag || h.Algorithm != hs[i-1].Algorithm {
			keys = append(keys, dnsprovider.SigningKey{KeyTag: h.Tag})
		}

		k := &keys[len(keys)-1]

		switch {
		case h.Form == DS && !slices.Contains(k.DS, h.Value):
			k.DS = append(k.DS, h.Value)
		case h.Form == DNSKEY && k.DNSKEY != "" && k.DNSKEY != h.Value:
			return nil, fmt.Errorf("distinct DNSKEYs share key tag %d and algorithm %d", h.Tag, h.Algorithm)
		case h.Form == DNSKEY:
			k.DNSKEY = h.Value
		}
	}

	return keys, nil
}

// Key is a Signing Key to set, checked: its DNSKEY, when it has one, and
// its DS records.
type Key struct {
	DNSKEY *Signer
	DS     []Signer
}

// Identities are the forms a Key is known by: those of its DNSKEY and of
// its DS records.
func (k Key) Identities(domain string) []string {
	var out []string
	if k.DNSKEY != nil {
		out = k.DNSKEY.Identities(domain)
	}

	for _, s := range k.DS {
		out = append(out, s.Identities(domain)...)
	}

	return out
}

// CheckKeys checks every Signing Key before any request: each needs a
// DNSKEY or a DS that is Sendable, else dnsprovider.ErrUnsupported, and
// every form of a key must have its key tag and one algorithm.
func CheckKeys(keys []dnsprovider.SigningKey) ([]Key, error) {
	out := make([]Key, 0, len(keys))

	for _, k := range keys {
		if k.DNSKEY == "" && len(k.DS) == 0 {
			return nil, fmt.Errorf("key tag %d has no DNSKEY or DS: %w", k.KeyTag, dnsprovider.ErrUnsupported)
		}

		var (
			w     Key
			forms []Signer
		)

		check := func(form Form, value string) (Signer, error) {
			s, err := Parse(form, value)
			if err == nil {
				err = s.Sendable()
			}

			return s, err
		}

		if k.DNSKEY != "" {
			s, err := check(DNSKEY, k.DNSKEY)
			if err != nil {
				return nil, err
			}

			w.DNSKEY = &s
			forms = append(forms, s)
		}

		for _, v := range k.DS {
			s, err := check(DS, v)
			if err != nil {
				return nil, err
			}

			w.DS = append(w.DS, s)
			forms = append(forms, s)
		}

		for _, s := range forms {
			if s.Tag != k.KeyTag || s.Algorithm != forms[0].Algorithm {
				return nil, fmt.Errorf("the %s %q is not of key tag %d and algorithm %d", s.Form, s.Value, k.KeyTag, forms[0].Algorithm)
			}
		}

		out = append(out, w)
	}

	return out, nil
}
