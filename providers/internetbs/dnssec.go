package internetbs

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/dnssec"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// sameSigner reports whether two checked records are one: TTL is not
// part of SigningKey, so comparison ignores the wire TTL.
func sameSigner(a, b dnssec.Signer) bool {
	return a.Form == b.Form && a.Value == b.Value
}

func bySigner(a, b dnssec.Signer) int {
	return cmp.Or(strings.Compare(a.Form.String(), b.Form.String()), strings.Compare(a.Value, b.Value))
}

// registryKeys reads only Registration data, never the hosted Zone's Records.
func (p *Provider) registryKeys(ctx context.Context, z dnsprovider.Zone) ([]dnssec.Signer, error) {
	if err := checkZone(z); err != nil {
		return nil, p.api.RedactError(err)
	}
	body, err := p.call(ctx, "Domain/Info", url.Values{"Domain": {names.ZoneName(z.Name)}})
	if err != nil {
		// Permission code 100005 also covers unowned domains. A successful
		// inventory lookup can distinguish absence without guessing from it.
		if errors.Is(err, dnsprovider.ErrUnauthorized) {
			if _, lookup := p.GetZone(ctx, z.Name); errors.Is(lookup, dnsprovider.ErrNotFound) {
				if api, ok := errors.AsType[*dnsprovider.APIError](err); ok {
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
	var records []dnssec.Signer
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
		var form dnssec.Form
		switch strings.ToUpper(f[3]) {
		case "DS":
			form = dnssec.DS
		case "DNSKEY":
			form = dnssec.DNSKEY
		default:
			return nil, errors.New("internetbs: unexpected signing record type")
		}
		r, err := dnssec.Parse(form, strings.Join(f[4:], " "))
		if err != nil {
			return nil, fmt.Errorf("internetbs: %w", err)
		}
		if !slices.ContainsFunc(records, func(h dnssec.Signer) bool { return sameSigner(h, r) }) {
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
	keys, err := dnssec.Group(records)
	if err != nil {
		return nil, fmt.Errorf("internetbs: %w", err)
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
	checked, err := dnssec.CheckKeys(keys)
	if err != nil {
		return fmt.Errorf("internetbs: %w", err)
	}
	var want []dnssec.Signer
	for _, k := range checked {
		forms := k.DS
		if d := k.DNSKEY; d != nil {
			if slices.ContainsFunc(want, func(w dnssec.Signer) bool {
				return w.Form == dnssec.DNSKEY && w.Tag == d.Tag && w.Algorithm == d.Algorithm && w.Value != d.Value
			}) {
				return fmt.Errorf("internetbs: cannot associate DS with distinct DNSKEYs sharing a key tag and algorithm: %w", dnsprovider.ErrUnsupported)
			}
			forms = append(slices.Clone(k.DS), *d)
		}
		for _, r := range forms {
			if !slices.ContainsFunc(want, func(w dnssec.Signer) bool { return sameSigner(w, r) }) {
				want = append(want, r)
			}
		}
	}
	held, err := p.registryKeys(ctx, z)
	if err != nil {
		return err
	}
	slices.SortFunc(want, bySigner)
	slices.SortFunc(held, bySigner)
	if slices.EqualFunc(want, held, sameSigner) {
		return nil
	}
	lines := make([]string, 0, len(want))
	for _, r := range want {
		// SigningKey does not carry a TTL; use the reference's example TTL.
		lines = append(lines, fmt.Sprintf("%s. 86400 IN %s %s", names.ZoneName(z.Name), r.Form, r.Value))
	}
	_, err = p.command(ctx, "Domain/Update", url.Values{"Domain": {names.ZoneName(z.Name)}, "dnssec": {strings.Join(lines, "\n")}}, true, true)
	return err
}
