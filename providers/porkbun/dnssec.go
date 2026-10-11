package porkbun

import (
	"bytes"
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

// dsRecord is one DS record as the Porkbun DNSSEC API carries it, every
// field a decimal or hex string.
type dsRecord struct {
	KeyTag     string `json:"keyTag"`
	Alg        string `json:"alg"`
	DigestType string `json:"digestType"`
	Digest     string `json:"digest"`
}

// String is the DS in presentation form after the type, the digest in
// upper case.
func (d dsRecord) String() string {
	return d.KeyTag + " " + d.Alg + " " + d.DigestType + " " + d.Digest
}

// parseDS reads a DS, from the API or from a SigningKey, normalizing its
// numbers and its digest to upper case.
func parseDS(tag, alg, digestType, digest string) (dsRecord, uint16, error) {
	t, errT := strconv.ParseUint(tag, 10, 16)
	a, errA := strconv.ParseUint(alg, 10, 8)
	d, errD := strconv.ParseUint(digestType, 10, 8)
	b, errH := hex.DecodeString(digest)
	if errors.Join(errT, errA, errD, errH) != nil || len(b) == 0 {
		return dsRecord{}, 0, errors.New("porkbun: malformed DS record")
	}
	return dsRecord{
		KeyTag: strconv.FormatUint(t, 10), Alg: strconv.FormatUint(a, 10), DigestType: strconv.FormatUint(d, 10),
		Digest: strings.ToUpper(hex.EncodeToString(b)),
	}, uint16(t), nil
}

// registryDS reads the DS records the registry holds for the Zone's
// domain, ordered by key tag.
func (p *Provider) registryDS(ctx context.Context, z dnsprovider.Zone) ([]dsRecord, error) {
	var env struct{ Records json.RawMessage }
	if err := p.call(ctx, http.MethodGet, "/dns/getDnssecRecords/"+zonePath(z), nil, nil, &env); err != nil {
		return nil, err
	}
	// An empty set comes as an empty JSON array, not an object.
	if bytes.Equal(bytes.TrimSpace(env.Records), []byte("[]")) {
		return nil, nil
	}
	var byTag map[string]dsRecord
	if json.Unmarshal(env.Records, &byTag) != nil || byTag == nil {
		return nil, errors.New("porkbun: missing DNSSEC records")
	}
	out := make([]dsRecord, 0, len(byTag))
	for _, w := range byTag {
		d, _, err := parseDS(w.KeyTag, w.Alg, w.DigestType, w.Digest)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	sortByTag(out)
	return out, nil
}

// DelegationSigners implements dnsprovider.DSRegistrar: the DS records
// the registry holds for the Zone's domain, one Signing Key per key tag,
// without its DNSKEY, which Porkbun does not return.
func (p *Provider) DelegationSigners(ctx context.Context, z dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	ds, err := p.registryDS(ctx, z)
	if err != nil {
		return nil, err
	}
	keys := make([]dnsprovider.SigningKey, 0, len(ds))
	for _, d := range ds {
		tag, _ := strconv.ParseUint(d.KeyTag, 10, 16)
		keys = append(keys, dnsprovider.SigningKey{KeyTag: uint16(tag), DS: []string{d.String()}})
	}
	return keys, nil
}

// sentDS is the DS Porkbun is sent for a key: its SHA-256 one, or its
// first when it has none. Porkbun takes only a DS, one per key tag.
func sentDS(k dnsprovider.SigningKey) (dsRecord, error) {
	var ds []dsRecord
	for _, s := range k.DS {
		f := strings.Fields(s)
		if len(f) < 4 {
			return dsRecord{}, fmt.Errorf("porkbun: malformed DS record %q", s)
		}
		d, tag, err := parseDS(f[0], f[1], f[2], strings.Join(f[3:], ""))
		if err != nil {
			return dsRecord{}, err
		}
		if tag != k.KeyTag {
			return dsRecord{}, fmt.Errorf("porkbun: DS record %q is not of key tag %d", s, k.KeyTag)
		}
		ds = append(ds, d)
	}
	if len(ds) == 0 {
		return dsRecord{}, fmt.Errorf("porkbun: key tag %d has no DS record, the only form Porkbun takes: %w", k.KeyTag, dnsprovider.ErrUnsupported)
	}
	if i := slices.IndexFunc(ds, func(d dsRecord) bool { return d.DigestType == "2" }); i >= 0 {
		return ds[i], nil
	}
	return ds[0], nil
}

// SetDelegationSigners implements dnsprovider.DSRegistrar: it reads the
// DS records the registry holds, then writes only those that differ from
// the keys' DS. Porkbun deletes by key tag, so a new key tag is added
// first, a changed one is deleted and added again, and a gone one is
// deleted last: a key rollover keeps a DS in place throughout. A failed
// write stops it, leaving those before it written.
func (p *Provider) SetDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	want := map[string]dsRecord{}
	for _, k := range keys {
		d, err := sentDS(k)
		if err != nil {
			return err
		}
		if w, ok := want[d.KeyTag]; ok && w != d {
			return fmt.Errorf("porkbun: two keys share key tag %s, and Porkbun holds one DS per key tag: %w", d.KeyTag, dnsprovider.ErrUnsupported)
		}
		want[d.KeyTag] = d
	}
	heldDS, err := p.registryDS(ctx, z)
	if err != nil {
		return err
	}
	held := map[string]dsRecord{}
	for _, d := range heldDS {
		held[d.KeyTag] = d
	}
	var added, changed, gone []dsRecord
	for tag, d := range want {
		if h, ok := held[tag]; !ok {
			added = append(added, d)
		} else if h != d {
			changed = append(changed, d)
		}
	}
	for tag, h := range held {
		if _, ok := want[tag]; !ok {
			gone = append(gone, h)
		}
	}
	for _, ds := range [][]dsRecord{added, changed, gone} {
		sortByTag(ds)
	}
	for _, d := range added {
		if err := p.createDS(ctx, z, d); err != nil {
			return err
		}
	}
	for _, d := range changed {
		if err := p.deleteDS(ctx, z, d); err != nil {
			return err
		}
		if err := p.createDS(ctx, z, d); err != nil {
			return err
		}
	}
	for _, d := range gone {
		if err := p.deleteDS(ctx, z, d); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provider) createDS(ctx context.Context, z dnsprovider.Zone, d dsRecord) error {
	return p.call(ctx, http.MethodPost, "/dns/createDnssecRecord/"+zonePath(z), nil, d, nil)
}

// deleteDS deletes the registry's DS of d's key tag; Porkbun answers
// success when it holds none.
func (p *Provider) deleteDS(ctx context.Context, z dnsprovider.Zone, d dsRecord) error {
	return p.call(ctx, http.MethodPost, "/dns/deleteDnssecRecord/"+zonePath(z)+"/"+d.KeyTag, nil, map[string]any{}, nil)
}

func sortByTag(ds []dsRecord) {
	slices.SortFunc(ds, func(a, b dsRecord) int {
		ta, _ := strconv.Atoi(a.KeyTag)
		tb, _ := strconv.Atoi(b.KeyTag)
		return ta - tb
	})
}

var _ dnsprovider.DSRegistrar = (*Provider)(nil)
