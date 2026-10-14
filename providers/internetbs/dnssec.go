package internetbs

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// signingRecord is a checked DS or DNSKEY in presentation form after its type.
// TTL is not part of SigningKey, so comparison ignores the wire TTL.
type signingRecord struct {
	typ, value string
	tag        uint16
	algorithm  uint8
	digestType uint8
}

func parseSigningRecord(typ, value string) (signingRecord, error) {
	f := strings.Fields(value)
	if len(f) < 4 {
		return signingRecord{}, errors.New("internetbs: malformed signing record")
	}
	first, errFirst := strconv.ParseUint(f[0], 10, 16)
	second, errSecond := strconv.ParseUint(f[1], 10, 8)
	third, errThird := strconv.ParseUint(f[2], 10, 8)
	if errors.Join(errFirst, errSecond, errThird) != nil {
		return signingRecord{}, errors.New("internetbs: malformed signing record numbers")
	}
	r := signingRecord{typ: typ, tag: uint16(first)}
	switch typ {
	case "DS":
		digest, err := hex.DecodeString(strings.Join(f[3:], ""))
		if err != nil || len(digest) == 0 {
			return signingRecord{}, errors.New("internetbs: malformed DS digest")
		}
		r.algorithm, r.digestType = uint8(second), uint8(third)
		r.value = fmt.Sprintf("%d %d %d %s", first, second, third, strings.ToUpper(hex.EncodeToString(digest)))
	case "DNSKEY":
		pub, err := base64.StdEncoding.DecodeString(strings.Join(f[3:], ""))
		if err != nil || len(pub) == 0 || second != 3 {
			return signingRecord{}, errors.New("internetbs: malformed DNSKEY")
		}
		r.algorithm = uint8(third)
		r.value = fmt.Sprintf("%d 3 %d %s", first, third, base64.StdEncoding.EncodeToString(pub))
		// RFC 4034 Appendix B: the key tag is computed from DNSKEY RDATA.
		data := binary.BigEndian.AppendUint16(nil, uint16(first))
		data = append(data, 3, r.algorithm)
		data = append(data, pub...)
		if r.algorithm == 1 {
			if len(pub) < 3 {
				return signingRecord{}, errors.New("internetbs: malformed RSA/MD5 DNSKEY")
			}
			r.tag = uint16(pub[len(pub)-3])<<8 | uint16(pub[len(pub)-2])
		} else {
			var sum uint32
			for i, b := range data {
				if i%2 == 0 {
					sum += uint32(b) << 8
				} else {
					sum += uint32(b)
				}
			}
			sum += (sum >> 16) & 0xffff
			r.tag = uint16(sum)
		}
	default:
		return signingRecord{}, errors.New("internetbs: unexpected signing record type")
	}
	return r, nil
}

// registryKeys reads only Registration data, never the hosted Zone's Records.
func (p *Provider) registryKeys(ctx context.Context, z dnsprovider.Zone) ([]signingRecord, error) {
	if err := checkZone(z); err != nil {
		return nil, p.api.RedactError(err)
	}
	body, err := p.call(ctx, "Domain/Info", url.Values{"Domain": {names.ZoneName(z.Name)}})
	if err != nil {
		// Permission code 100005 also covers unowned domains. A successful
		// inventory lookup can distinguish absence without guessing from it.
		if errors.Is(err, dnsprovider.ErrUnauthorized) {
			if _, lookup := p.GetZone(ctx, z.Name); errors.Is(lookup, dnsprovider.ErrNotFound) {
				var api *dnsprovider.APIError
				if errors.As(err, &api) {
					copyErr := *api
					copyErr.Kind = dnsprovider.ErrNotFound
					return nil, &copyErr
				}
			}
		}
		return nil, err
	}
	var state string
	if json.Unmarshal(body["dnssec"], &state) == nil && state == "disabled" {
		return nil, nil
	}
	var wire []string
	if err := requiredList(body, "dnssec", &wire); err != nil {
		return nil, err
	}
	var records []signingRecord
	for _, line := range wire {
		// Parentheses and comments are allowed in the documented RFC 4034
		// presentation. They carry no Signing Key data.
		var text strings.Builder
		for part := range strings.SplitSeq(line, "\n") {
			part, _, _ = strings.Cut(part, ";")
			text.WriteString(part)
			text.WriteByte(' ')
		}
		presentation := text.String()
		depth, opened := 0, false
		for _, c := range presentation {
			switch c {
			case '(':
				if depth != 0 || opened {
					return nil, errors.New("internetbs: malformed signing record parentheses")
				}
				depth, opened = 1, true
			case ')':
				if depth != 1 {
					return nil, errors.New("internetbs: malformed signing record parentheses")
				}
				depth = 0
			}
		}
		if depth != 0 {
			return nil, errors.New("internetbs: unclosed signing record parentheses")
		}
		f := strings.Fields(strings.NewReplacer("(", " ", ")", " ").Replace(presentation))
		if len(f) < 8 || names.ZoneName(f[0]) != names.ZoneName(z.Name) || !strings.EqualFold(f[2], "IN") {
			return nil, errors.New("internetbs: malformed registry signing record")
		}
		if _, err := strconv.ParseUint(f[1], 10, 32); err != nil {
			return nil, errors.New("internetbs: malformed signing record TTL")
		}
		r, err := parseSigningRecord(strings.ToUpper(f[3]), strings.Join(f[4:], " "))
		if err != nil {
			return nil, err
		}
		if !slices.Contains(records, r) {
			records = append(records, r)
		}
	}
	return records, nil
}

// ListDelegationSigners implements dnsprovider.Provider (CapDSRegistrar). DS records are grouped
// by key tag and algorithm, SHA-256 first, with a DNSKEY when returned. A
// DNSKEY's tag is computed because Internet.bs does not return it separately.
func (p *Provider) ListDelegationSigners(ctx context.Context, z dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	records, err := p.registryKeys(ctx, z)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(records, func(a, b signingRecord) int {
		rank := func(d uint8) int {
			if d == 2 {
				return -1
			}
			return int(d)
		}
		return cmp.Or(cmp.Compare(a.tag, b.tag), cmp.Compare(a.algorithm, b.algorithm), cmp.Compare(rank(a.digestType), rank(b.digestType)), strings.Compare(a.value, b.value))
	})
	var keys []dnsprovider.SigningKey
	for i, r := range records {
		if i == 0 || r.tag != records[i-1].tag || r.algorithm != records[i-1].algorithm {
			keys = append(keys, dnsprovider.SigningKey{KeyTag: r.tag})
		}
		k := &keys[len(keys)-1]
		if r.typ == "DS" {
			k.DS = append(k.DS, r.value)
		} else {
			if k.DNSKEY != "" && k.DNSKEY != r.value {
				return nil, errors.New("internetbs: distinct DNSKEYs share a key tag and algorithm")
			}
			k.DNSKEY = r.value
		}
	}
	return keys, nil
}

// SetDelegationSigners implements dnsprovider.Provider (CapDSRegistrar) through
// replaceDelegationSigners.
func (p *Provider) SetDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	if len(keys) == 0 {
		return dnsprovider.ErrNoSigningKeys
	}

	return p.replaceDelegationSigners(ctx, z, keys)
}

// DeleteDelegationSigners implements dnsprovider.Provider (CapDSRegistrar) through
// replaceDelegationSigners with no keys.
func (p *Provider) DeleteDelegationSigners(ctx context.Context, z dnsprovider.Zone) error {
	return p.replaceDelegationSigners(ctx, z, nil)
}

// replaceDelegationSigners replaces Registration Signing Keys in one Domain/Update.
// Each key's available DS and DNSKEY forms are sent, as the first-party module
// does, allowing the registry to take the form it needs. An empty dnssec clears
// the set. SUCCESS or PENDING acknowledges the update, not DNS propagation.
func (p *Provider) replaceDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	if err := checkZone(z); err != nil {
		return p.api.RedactError(err)
	}
	var want []signingRecord
	for _, k := range keys {
		if k.DNSKEY == "" && len(k.DS) == 0 {
			return fmt.Errorf("internetbs: key tag %d has no DNSKEY or DS: %w", k.KeyTag, dnsprovider.ErrUnsupported)
		}
		values := make([]signingRecord, 0, len(k.DS)+1)
		for _, value := range k.DS {
			r, err := parseSigningRecord("DS", value)
			if err != nil {
				return err
			}
			values = append(values, r)
		}
		if k.DNSKEY != "" {
			r, err := parseSigningRecord("DNSKEY", k.DNSKEY)
			if err != nil {
				return err
			}
			values = append(values, r)
		}
		for _, r := range values {
			if r.tag != k.KeyTag || r.algorithm != values[0].algorithm {
				return fmt.Errorf("internetbs: inconsistent Signing Key with key tag %d", k.KeyTag)
			}
			if r.typ == "DNSKEY" && slices.ContainsFunc(want, func(w signingRecord) bool {
				return w.typ == "DNSKEY" && w.tag == r.tag && w.algorithm == r.algorithm && w.value != r.value
			}) {
				return fmt.Errorf("internetbs: cannot associate DS with distinct DNSKEYs sharing a key tag and algorithm: %w", dnsprovider.ErrUnsupported)
			}
			if !slices.Contains(want, r) {
				want = append(want, r)
			}
		}
	}
	held, err := p.registryKeys(ctx, z)
	if err != nil {
		return err
	}
	byRecord := func(a, b signingRecord) int {
		return cmp.Or(strings.Compare(a.typ, b.typ), strings.Compare(a.value, b.value))
	}
	slices.SortFunc(want, byRecord)
	slices.SortFunc(held, byRecord)
	if slices.Equal(want, held) {
		return nil
	}
	lines := make([]string, 0, len(want))
	for _, r := range want {
		// SigningKey does not carry a TTL; use the reference's example TTL.
		lines = append(lines, fmt.Sprintf("%s. 86400 IN %s %s", names.ZoneName(z.Name), r.typ, r.value))
	}
	_, err = p.command(ctx, "Domain/Update", url.Values{"Domain": {names.ZoneName(z.Name)}, "dnssec": {strings.Join(lines, "\n")}}, true, true)
	return err
}
