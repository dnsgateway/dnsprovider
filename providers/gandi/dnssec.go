package gandi

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/dnssec"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// gandiKSK is Gandi's wire value for the type of a key the DS of a
// Delegation names: a signing key is sent with it, and a held key with it
// reads with flags 257.
const gandiKSK = "ksk"

// wireKey is one signing key as the Gandi Domain API key list returns it:
// the key Gandi sent the registry and the DS it computed from it.
type wireKey struct {
	// ID is a number in the docs' key list but a string in their delete
	// path, so either is taken.
	ID         json.RawMessage `json:"id"`
	KeyTag     *int            `json:"keytag"`
	Algorithm  *int            `json:"algorithm"`
	Type       string          `json:"type"`
	PublicKey  string          `json:"public_key"`
	DigestType *int            `json:"digest_type"`
	Digest     string          `json:"digest"`
}

func dnskeysPath(z dnsprovider.Zone) string {
	return "/domains/" + url.PathEscape(names.ZoneName(z.Name)) + "/dnskeys"
}

// signingKey is the Signing Key of a held key: its DNSKEY when Gandi
// returns its public key, flags 257 for a key of type gandiKSK and 256
// for any other, and its DS.
func (w wireKey) signingKey() (dnsprovider.SigningKey, error) {
	if w.KeyTag == nil || w.Algorithm == nil || w.DigestType == nil {
		return dnsprovider.SigningKey{}, errors.New("gandi: malformed signing key")
	}
	ds, err := dnssec.Parse(dnssec.DS, fmt.Sprintf("%d %d %d %s", *w.KeyTag, *w.Algorithm, *w.DigestType, w.Digest))
	if err != nil {
		return dnsprovider.SigningKey{}, fmt.Errorf("gandi: malformed signing key: %w", err)
	}
	k := dnsprovider.SigningKey{KeyTag: ds.Tag, DS: []string{ds.Value}}
	if w.PublicKey != "" {
		flags := 256
		if w.Type == gandiKSK {
			flags = 257
		}
		k.DNSKEY = fmt.Sprintf("%d 3 %d %s", flags, *w.Algorithm, w.PublicKey)
	}
	return k, nil
}

// id is the key's id as its delete path names it.
func (w wireKey) id() (string, error) {
	var s string
	if json.Unmarshal(w.ID, &s) == nil && s != "" {
		return s, nil
	}
	var n json.Number
	if json.Unmarshal(w.ID, &n) == nil && n != "" {
		return n.String(), nil
	}
	return "", errors.New("gandi: signing key without an id")
}

// heldKey is a key Gandi holds at the registry, read and checked.
type heldKey struct {
	id  string
	key dnsprovider.SigningKey
	// compared is the key in the form a held and a wanted key compare in.
	compared comparedKey
}

// heldKeys reads the keys Gandi holds at the registry for the Zone's
// domain, ordered by key tag.
func (p *Provider) heldKeys(ctx context.Context, z dnsprovider.Zone) ([]heldKey, error) {
	all, err := list[wireKey](ctx, p, p.domainURL, dnskeysPath(z))
	if err != nil {
		return nil, err
	}
	held := make([]heldKey, 0, len(all))
	for _, w := range all {
		k, err := w.signingKey()
		if err != nil {
			return nil, err
		}
		id, err := w.id()
		if err != nil {
			return nil, err
		}
		held = append(held, heldKey{id: id, key: k, compared: w.compared()})
	}
	slices.SortStableFunc(held, func(a, b heldKey) int { return cmp.Compare(a.key.KeyTag, b.key.KeyTag) })
	return held, nil
}

// ListDelegationSigners implements dnsprovider.Provider (CapDSRegistrar): the keys Gandi
// holds at the registry for the Zone's domain, ordered by key tag, each
// with the DS Gandi computed for it. The list holds every key Gandi has,
// so a key of type "zsk" or none reads too, its DNSKEY with flags 256.
//
// Gandi documents no 404 on the dnskeys routes: a 404 taken as
// ErrNotFound, a domain the Account does not hold, is an assumption, and
// a domain another organization holds may come back as 403,
// ErrUnauthorized, instead. Either error keeps Gandi's description.
func (p *Provider) ListDelegationSigners(ctx context.Context, z dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	held, err := p.heldKeys(ctx, z)
	if err != nil {
		return nil, err
	}
	keys := make([]dnsprovider.SigningKey, 0, len(held))
	for _, h := range held {
		keys = append(keys, h.key)
	}
	return keys, nil
}

// comparedKey is the form a held and a wanted key compare in: a key as
// Gandi takes it, to compute its DS itself, its public key canonical. It
// is also the body of a replace.
type comparedKey struct {
	Algorithm int    `json:"algorithm"`
	Type      string `json:"type"`
	PublicKey string `json:"public_key"`
}

// compared is the key in the form it compares in. Its algorithm is
// checked present.
func (w wireKey) compared() comparedKey {
	return comparedKey{Algorithm: *w.Algorithm, Type: w.Type, PublicKey: canonicalKey(w.PublicKey)}
}

// keyToSend is the key Gandi is sent for a Signing Key: its DNSKEY's
// algorithm and public key, of type gandiKSK, the key the DS of a
// Delegation names. Gandi takes no DS, and no DNSKEY of an algorithm
// DNSSEC does not sign with.
func keyToSend(k dnsprovider.SigningKey) (comparedKey, error) {
	if k.DNSKEY == "" {
		return comparedKey{}, fmt.Errorf("gandi: key tag %d has no DNSKEY, the only form Gandi takes: %w", k.KeyTag, dnsprovider.ErrUnsupported)
	}
	s, err := dnssec.Parse(dnssec.DNSKEY, k.DNSKEY)
	if err != nil {
		return comparedKey{}, fmt.Errorf("gandi: %w", err)
	}
	if err := s.Sendable(); err != nil {
		return comparedKey{}, fmt.Errorf("gandi: %w", err)
	}
	return comparedKey{Algorithm: int(s.Algorithm), Type: gandiKSK, PublicKey: strings.Fields(s.Value)[3]}, nil
}

// canonicalKey is a base64 public key in standard padded form, so two
// encodings of one key compare equal; the text itself when it is not
// base64.
func canonicalKey(pub string) string {
	b, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return pub
	}
	return base64.StdEncoding.EncodeToString(b)
}

func byComparedKey(a, b comparedKey) int {
	return cmp.Or(cmp.Compare(a.Algorithm, b.Algorithm), cmp.Compare(a.PublicKey, b.PublicKey), cmp.Compare(a.Type, b.Type))
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
// keys Gandi holds, a read even when nothing is to be written, and when
// they differ from the keys' DNSKEYs it sends those, in their order, as
// gandiKSK keys in one replace, Gandi computing their DS for the registry.
// No keys deletes each held key one by one instead, as the docs do not
// say a replace may hold none, so a delete failing partway leaves the
// keys not yet deleted held. Gandi answers each write with 202 and applies
// it at the registry asynchronously, so a read right after may still show
// the old set. A key with no DNSKEY is ErrUnsupported, and so is a replace
// Gandi answers with 400.
func (p *Provider) replaceDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	want := make([]comparedKey, 0, len(keys))
	for _, k := range keys {
		s, err := keyToSend(k)
		if err != nil {
			return err
		}
		if !slices.Contains(want, s) {
			want = append(want, s)
		}
	}
	held, err := p.heldKeys(ctx, z)
	if err != nil {
		return err
	}
	have := make([]comparedKey, 0, len(held))
	for _, h := range held {
		have = append(have, h.compared)
	}
	slices.SortFunc(have, byComparedKey)
	if slices.Equal(slices.SortedFunc(slices.Values(want), byComparedKey), have) {
		return nil
	}
	if len(want) > 0 {
		return refusedAsUnsupported(p.request(ctx, p.domainURL, http.MethodPut, dnskeysPath(z), nil, map[string]any{"keys": want}, nil))
	}
	for _, h := range held {
		if err := p.request(ctx, p.domainURL, http.MethodDelete, dnskeysPath(z)+"/"+url.PathEscape(h.id), nil, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// refusedAsUnsupported is err with Gandi's 400 to a key write typed
// ErrUnsupported: the keys were well formed when sent, so it is taken as
// the registry or Gandi refusing their algorithm or form. Gandi documents
// no 400 on the dnskeys routes, so this is an assumption; the error keeps
// Gandi's description of the refusal.
func refusedAsUnsupported(err error) error {
	var api *dnsprovider.APIError
	if errors.As(err, &api) && api.StatusCode == http.StatusBadRequest && api.Kind == nil {
		api.Kind = dnsprovider.ErrUnsupported
	}
	return err
}
