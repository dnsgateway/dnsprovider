package porkbun

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// dsWire is one DS record as the Porkbun DNSSEC API carries it, every
// field a decimal or hex string.
type dsWire struct {
	KeyTag     string `json:"keyTag"`
	Alg        string `json:"alg"`
	DigestType string `json:"digestType"`
	Digest     string `json:"digest"`
}

// dsValue is a normalized DS record: two are the same DS when equal.
type dsValue struct {
	keyTag     uint16
	alg        uint8
	digestType uint8
	// digest is upper-case hex.
	digest string
}

// parseDS reads a DS from its fields as text, from the API or from a
// SigningKey.
func parseDS(tag, alg, digestType, digest string) (dsValue, error) {
	t, errT := strconv.ParseUint(tag, 10, 16)
	a, errA := strconv.ParseUint(alg, 10, 8)
	d, errD := strconv.ParseUint(digestType, 10, 8)
	b, errH := hex.DecodeString(digest)
	if errors.Join(errT, errA, errD, errH) != nil || len(b) == 0 {
		return dsValue{}, errors.New("porkbun: malformed DS record")
	}
	return dsValue{keyTag: uint16(t), alg: uint8(a), digestType: uint8(d), digest: strings.ToUpper(hex.EncodeToString(b))}, nil
}

// String is the DS in presentation form after the type.
func (d dsValue) String() string {
	return fmt.Sprintf("%d %d %d %s", d.keyTag, d.alg, d.digestType, d.digest)
}

func (d dsValue) wire() dsWire {
	return dsWire{
		KeyTag: strconv.Itoa(int(d.keyTag)), Alg: strconv.Itoa(int(d.alg)),
		DigestType: strconv.Itoa(int(d.digestType)), Digest: d.digest,
	}
}

func byKeyTag(a, b dsValue) int { return cmp.Compare(a.keyTag, b.keyTag) }

// registryDS reads the DS records the registry holds for the Zone's
// domain, ordered by key tag.
func (p *Provider) registryDS(ctx context.Context, z dnsprovider.Zone) ([]dsValue, error) {
	var env struct{ Records json.RawMessage }
	if err := p.call(ctx, http.MethodGet, "/dns/getDnssecRecords/"+zonePath(z), nil, nil, &env); err != nil {
		return nil, err
	}
	// An empty set comes as an empty JSON array, not an object.
	if bytes.Equal(bytes.TrimSpace(env.Records), []byte("[]")) {
		return nil, nil
	}
	var byTag map[string]dsWire
	if json.Unmarshal(env.Records, &byTag) != nil || byTag == nil {
		return nil, errors.New("porkbun: missing DNSSEC records")
	}
	out := make([]dsValue, 0, len(byTag))
	for tag, rec := range byTag {
		d, err := parseDS(rec.KeyTag, rec.Alg, rec.DigestType, rec.Digest)
		if err != nil {
			return nil, err
		}
		if tag != strconv.Itoa(int(d.keyTag)) {
			return nil, fmt.Errorf("porkbun: DNSSEC record under key tag %q has key tag %d", tag, d.keyTag)
		}
		out = append(out, d)
	}
	slices.SortFunc(out, byKeyTag)
	return out, nil
}

// ListDelegationSigners implements dnsprovider.Provider (CapDSRegistrar): the DS records
// the registry holds for the Zone's domain, one Signing Key per key tag,
// without its DNSKEY, which Porkbun does not return.
func (p *Provider) ListDelegationSigners(ctx context.Context, z dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	ds, err := p.registryDS(ctx, z)
	if err != nil {
		return nil, err
	}
	keys := make([]dnsprovider.SigningKey, 0, len(ds))
	for _, d := range ds {
		keys = append(keys, dnsprovider.SigningKey{KeyTag: d.keyTag, DS: []string{d.String()}})
	}
	return keys, nil
}

// dsToSend is the DS Porkbun is sent for a key: its SHA-256 one, or its
// first when it has none. Porkbun takes only a DS, one per key tag, and
// this module has no way to compute one from a DNSKEY.
func dsToSend(k dnsprovider.SigningKey) (dsValue, error) {
	var ds []dsValue
	for _, s := range k.DS {
		f := strings.Fields(s)
		if len(f) < 4 {
			return dsValue{}, fmt.Errorf("porkbun: malformed DS record %q", s)
		}
		d, err := parseDS(f[0], f[1], f[2], strings.Join(f[3:], ""))
		if err != nil {
			return dsValue{}, err
		}
		if d.keyTag != k.KeyTag {
			return dsValue{}, fmt.Errorf("porkbun: DS record %q is not of key tag %d", s, k.KeyTag)
		}
		ds = append(ds, d)
	}
	if len(ds) == 0 {
		return dsValue{}, fmt.Errorf("porkbun: key tag %d has no DS record, the only form Porkbun takes: %w", k.KeyTag, dnsprovider.ErrUnsupported)
	}
	if i := slices.IndexFunc(ds, func(d dsValue) bool { return d.digestType == 2 }); i >= 0 {
		return ds[i], nil
	}
	return ds[0], nil
}

// diffDS plans a replace by key tag, each list ordered by key tag: added
// are wanted DS of key tags not held, changed are wanted DS whose key tag
// holds another, and gone are held DS of key tags not wanted.
func diffDS(want, held []dsValue) (added, changed, gone []dsValue) {
	heldByTag := map[uint16]dsValue{}
	for _, h := range held {
		heldByTag[h.keyTag] = h
	}
	wanted := map[uint16]bool{}
	for _, w := range want {
		wanted[w.keyTag] = true
		if h, ok := heldByTag[w.keyTag]; !ok {
			added = append(added, w)
		} else if h != w {
			changed = append(changed, w)
		}
	}
	for _, h := range held {
		if !wanted[h.keyTag] {
			gone = append(gone, h)
		}
	}
	for _, ds := range [][]dsValue{added, changed, gone} {
		slices.SortFunc(ds, byKeyTag)
	}
	return added, changed, gone
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

// replaceDelegationSigners replaces the Signing Keys the registry holds
// with keys, none deleting them all: it reads the
// DS records the registry holds, then writes only those that differ from
// the keys' DS. New key tags are added first, so a key rollover keeps a
// DS in place. Then the changed and gone key tags are deleted. Porkbun
// deletes by key tag, but most registries delete every DS matching the
// key data, so after deleting it reads the set again and adds back every
// wanted DS it lacks, the changed ones among them; a deleted DS still
// held is an error. A failed write stops it, leaving those before it
// written.
func (p *Provider) replaceDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	want := make([]dsValue, 0, len(keys))
	for _, k := range keys {
		d, err := dsToSend(k)
		if err != nil {
			return err
		}
		if i := slices.IndexFunc(want, func(w dsValue) bool { return w.keyTag == d.keyTag }); i >= 0 {
			if want[i] != d {
				return fmt.Errorf("porkbun: two keys share key tag %d, and Porkbun holds one DS per key tag: %w", d.keyTag, dnsprovider.ErrUnsupported)
			}
			continue
		}
		want = append(want, d)
	}
	held, err := p.registryDS(ctx, z)
	if err != nil {
		return err
	}
	added, changed, gone := diffDS(want, held)
	for _, d := range added {
		if err := p.createDS(ctx, z, d); err != nil {
			return err
		}
	}
	if len(changed)+len(gone) == 0 {
		return nil
	}
	for _, d := range slices.Concat(changed, gone) {
		if err := p.deleteDS(ctx, z, d.keyTag); err != nil {
			return err
		}
	}
	if held, err = p.registryDS(ctx, z); err != nil {
		return err
	}
	missing, changed, gone := diffDS(want, held)
	if stays := slices.Concat(changed, gone); len(stays) > 0 {
		return fmt.Errorf("porkbun: the registry still holds DS %s after deleting its key tag", stays[0])
	}
	for _, d := range missing {
		if err := p.createDS(ctx, z, d); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) createDS(ctx context.Context, z dnsprovider.Zone, d dsValue) error {
	return p.write(ctx, http.MethodPost, "/dns/createDnssecRecord/"+zonePath(z), nil, d.wire(), nil)
}

// deleteDS deletes the registry's DS of a key tag; Porkbun answers
// success when it holds none.
func (p *Provider) deleteDS(ctx context.Context, z dnsprovider.Zone, tag uint16) error {
	return p.write(ctx, http.MethodPost, "/dns/deleteDnssecRecord/"+zonePath(z)+"/"+strconv.Itoa(int(tag)), nil, map[string]any{}, nil)
}
