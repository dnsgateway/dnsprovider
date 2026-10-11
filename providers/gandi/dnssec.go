package gandi

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
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
	digest, err := hex.DecodeString(w.Digest)
	if w.KeyTag == nil || w.Algorithm == nil || w.DigestType == nil || err != nil || len(digest) == 0 ||
		*w.KeyTag < 0 || *w.KeyTag > 0xFFFF || *w.Algorithm < 0 || *w.Algorithm > 0xFF || *w.DigestType < 0 || *w.DigestType > 0xFF {
		return dnsprovider.SigningKey{}, errors.New("gandi: malformed signing key")
	}
	k := dnsprovider.SigningKey{
		KeyTag: uint16(*w.KeyTag),
		DS:     []string{fmt.Sprintf("%d %d %d %s", *w.KeyTag, *w.Algorithm, *w.DigestType, strings.ToUpper(hex.EncodeToString(digest)))},
	}
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
	// sent is the key as it was sent to Gandi.
	sent sentKey
}

// heldKeys reads the keys Gandi holds at the registry for the Zone's
// domain, ordered by key tag.
func (p *Provider) heldKeys(ctx context.Context, z dnsprovider.Zone) ([]heldKey, error) {
	all, err := listAt[wireKey](ctx, p, p.domainURL, dnskeysPath(z))
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
		held = append(held, heldKey{id: id, key: k, sent: sentKey{Algorithm: *w.Algorithm, Type: w.Type, PublicKey: canonicalKey(w.PublicKey)}})
	}
	slices.SortStableFunc(held, func(a, b heldKey) int { return cmp.Compare(a.key.KeyTag, b.key.KeyTag) })
	return held, nil
}

// DelegationSigners implements dnsprovider.DSRegistrar: the keys Gandi
// holds at the registry for the Zone's domain, ordered by key tag, each
// with the DS Gandi computed for it.
func (p *Provider) DelegationSigners(ctx context.Context, z dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
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

// sentKey is a key as Gandi takes it, to compute its DS itself.
type sentKey struct {
	Algorithm int    `json:"algorithm"`
	Type      string `json:"type"`
	PublicKey string `json:"public_key"`
}

// keyToSend is the key Gandi is sent for a Signing Key: its DNSKEY's
// algorithm and public key, of type gandiKSK, the key the DS of a
// Delegation names. Gandi takes no DS.
func keyToSend(k dnsprovider.SigningKey) (sentKey, error) {
	f := strings.Fields(k.DNSKEY)
	if len(f) < 4 {
		return sentKey{}, fmt.Errorf("gandi: key tag %d has no DNSKEY, the only form Gandi takes: %w", k.KeyTag, dnsprovider.ErrUnsupported)
	}
	alg, err := strconv.ParseUint(f[2], 10, 8)
	pub := strings.Join(f[3:], "")
	if _, errB := base64.StdEncoding.DecodeString(pub); err != nil || errB != nil || f[1] != "3" {
		return sentKey{}, fmt.Errorf("gandi: malformed DNSKEY %q", k.DNSKEY)
	}
	return sentKey{Algorithm: int(alg), Type: gandiKSK, PublicKey: canonicalKey(pub)}, nil
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

func bySentKey(a, b sentKey) int {
	return cmp.Or(cmp.Compare(a.Algorithm, b.Algorithm), cmp.Compare(a.PublicKey, b.PublicKey), cmp.Compare(a.Type, b.Type))
}

// SetDelegationSigners implements dnsprovider.DSRegistrar: it reads the
// keys Gandi holds, and when they differ from the keys' DNSKEYs it sends
// those, in their order, as gandiKSK keys in one replace, Gandi computing
// their DS for the registry. No keys deletes each held key instead, as the docs do
// not say a replace may hold none. A key with no DNSKEY is ErrUnsupported,
// and so is a replace Gandi answers with 400.
func (p *Provider) SetDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	want := make([]sentKey, 0, len(keys))
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
	have := make([]sentKey, 0, len(held))
	for _, h := range held {
		have = append(have, h.sent)
	}
	slices.SortFunc(have, bySentKey)
	if slices.Equal(slices.SortedFunc(slices.Values(want), bySentKey), have) {
		return nil
	}
	if len(want) > 0 {
		return refusedAsUnsupported(p.requestAt(ctx, p.domainURL, http.MethodPut, dnskeysPath(z), nil, map[string]any{"keys": want}, nil))
	}
	for _, h := range held {
		if err := p.requestAt(ctx, p.domainURL, http.MethodDelete, dnskeysPath(z)+"/"+url.PathEscape(h.id), nil, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// refusedAsUnsupported is err with Gandi's 400 to a key write typed
// ErrUnsupported: the keys were well formed when sent, so it is the
// registry or Gandi refusing their algorithm or form.
func refusedAsUnsupported(err error) error {
	var api *dnsprovider.APIError
	if errors.As(err, &api) && api.StatusCode == http.StatusBadRequest && api.Kind == nil {
		api.Kind = dnsprovider.ErrUnsupported
	}
	return err
}

var _ dnsprovider.DSRegistrar = (*Provider)(nil)
