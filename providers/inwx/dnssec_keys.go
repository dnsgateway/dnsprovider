package inwx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/dnssec"
	"github.com/dnsgateway/dnsprovider/rest"
)

// keyText is the value of a dnssec.listkeys field as text: INWX's
// documentation types the fields as integers and its Terraform provider
// reads them as strings, so either is taken, and an empty string or
// null is no value. A JSON boolean, which
// active may be, is "true" or "false".
type keyText string

func (f *keyText) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = keyText(strings.TrimSpace(s))

		return nil
	}

	switch v := string(bytes.TrimSpace(b)); v {
	case "null":
		*f = ""

		return nil
	case "true", "false":
		*f = keyText(v)

		return nil
	}

	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("not a string or number: %s", b)
	}

	*f = keyText(n)

	return nil
}

// wireKey is an entry of dnssec.listkeys: a key INWX holds for a
// domain, with its DNSKEY (flagId, algorithmId, publicKey), its DS
// (keyTag, algorithmId, digestTypeId, digest), or both.
type wireKey struct {
	ID           json.RawMessage `json:"id"`
	KeyTag       keyText         `json:"keyTag"`
	FlagID       keyText         `json:"flagId"`
	AlgorithmID  keyText         `json:"algorithmId"`
	PublicKey    keyText         `json:"publicKey"`
	DigestTypeID keyText         `json:"digestTypeId"`
	Digest       keyText         `json:"digest"`
	Status       keyText         `json:"status"`
	Active       keyText         `json:"active"`
}

// heldKey is a key the registry holds: the forms INWX gives it in, and
// the id dnssec.deletednskey removes it by, as INWX gave it.
type heldKey struct {
	id      json.RawMessage
	signers []dnssec.Signer
}

// signers reads an entry: its DNSKEY when it has a public key, its DS
// when it has a digest. dnssec.Parse checks the ranges and computes a
// DNSKEY's key tag.
func (w wireKey) signers() ([]dnssec.Signer, error) {
	var out []dnssec.Signer

	if w.PublicKey != "" {
		s, err := dnssec.Parse(dnssec.DNSKEY, fmt.Sprintf("%s 3 %s %s", w.FlagID, w.AlgorithmID, w.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("inwx: dnssec.listkeys: %w", err)
		}

		out = append(out, s)
	}

	if w.Digest != "" {
		s, err := dnssec.Parse(dnssec.DS, fmt.Sprintf("%s %s %s %s", w.KeyTag, w.AlgorithmID, w.DigestTypeID, w.Digest))
		if err != nil {
			return nil, fmt.Errorf("inwx: dnssec.listkeys: %w", err)
		}

		out = append(out, s)
	}

	if len(out) == 0 {
		return nil, errors.New("inwx: dnssec.listkeys holds an entry with neither a public key nor a digest")
	}

	return out, nil
}

// inactive reports whether an entry is not in force: one INWX marks
// inactive or deleted, which the active filter should have left out.
func (w wireKey) inactive() bool {
	return w.Active == "0" || strings.EqualFold(string(w.Active), "false") || strings.EqualFold(string(w.Status), "DELETED")
}

// ksk reports whether the entry is a key-signing key (flags 257: zone
// key and SEP).
func (w wireKey) ksk() bool {
	return w.FlagID == "257"
}

// decodeKeys reads dnssec.listkeys' resData, which INWX's Terraform
// provider reads as a bare array of entries and its documentation and
// goinwx as an object with the entries under dnskey; both are taken, and
// a missing resData is no entry.
func decodeKeys(data json.RawMessage) ([]wireKey, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, nil
	}

	var keys []wireKey
	if data[0] == '[' {
		err := json.Unmarshal(data, &keys)

		return keys, err
	}

	var wrapped struct {
		DNSKEY []wireKey `json:"dnskey"`
	}
	err := json.Unmarshal(data, &wrapped)

	return wrapped.DNSKEY, err
}

// registration is the Zone's domain, once the Account is known to
// register it and INWX not to host its zone: ErrNotFound when
// domain.info does not know it, and ErrUnsupported when nameserver.list
// holds a zone of it. INWX signs a zone it hosts itself, through the
// DNSSEC switch of UpdateZone; the registry's keys are set here only for
// a domain served elsewhere.
func (p *Provider) registration(ctx context.Context, zone dnsprovider.Zone) (string, error) {
	domain, err := namedZone(zone.Name)
	if err != nil {
		return "", err
	}

	if err := p.read(ctx, "domain.info", map[string]any{"domain": domain}, nil); err != nil {
		if errors.Is(err, dnsprovider.ErrNotFound) {
			return "", fmt.Errorf("inwx: the Account does not register %s: %w", domain, err)
		}

		return "", err
	}

	zones, err := p.zones(ctx)
	if err != nil {
		return "", err
	}

	for _, z := range zones {
		if z.Name == domain {
			return "", fmt.Errorf("inwx: INWX hosts the zone of %s and signs it through the DNSSEC switch; its Signing Keys are not the registry's to set: %w", domain, dnsprovider.ErrUnsupported)
		}
	}

	return domain, nil
}

// activeKeys reads dnssec.listkeys for the domain's active entries: the
// one reading of it, for ZoneDetails and the DS registrar alike. An
// entry INWX marks inactive or deleted all the same is left out.
func (p *Provider) activeKeys(ctx context.Context, domain string) ([]wireKey, error) {
	params := map[string]any{"domainName": domain, "active": 1}

	env, err := p.send(ctx, func(c *rest.Client) (envelope, error) {
		return p.rpc(ctx, c, "dnssec.listkeys", params)
	})
	if err != nil {
		return nil, err
	}

	entries, err := decodeKeys(env.ResData)
	if err != nil {
		return nil, fmt.Errorf("inwx: dnssec.listkeys: malformed resData: %w", err)
	}

	return slices.DeleteFunc(entries, wireKey.inactive), nil
}

// heldKeys reads the active keys INWX holds for the domain with
// dnssec.listkeys.
func (p *Provider) heldKeys(ctx context.Context, domain string) ([]heldKey, error) {
	entries, err := p.activeKeys(ctx, domain)
	if err != nil {
		return nil, err
	}

	out := make([]heldKey, 0, len(entries))

	for _, w := range entries {
		ss, err := w.signers()
		if err != nil {
			return nil, err
		}

		out = append(out, heldKey{id: w.ID, signers: ss})
	}

	return out, nil
}

// ListDelegationSigners implements dnsprovider.Provider
// (CapDSRegistrar): the Signing Keys the registry holds, through INWX,
// for a domain the Account registers and INWX does not host. Each entry
// gives a key's DNSKEY, its DS or both; DS records are grouped with
// their key by key tag and algorithm, SHA-256 first, in upper case, and
// a DNSKEY's tag is computed from its content.
func (p *Provider) ListDelegationSigners(ctx context.Context, zone dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	domain, err := p.registration(ctx, zone)
	if err != nil {
		return nil, err
	}

	held, err := p.heldKeys(ctx, domain)
	if err != nil {
		return nil, err
	}

	var signers []dnssec.Signer
	for _, h := range held {
		signers = append(signers, h.signers...)
	}

	keys, err := dnssec.Group(signers)
	if err != nil {
		return nil, fmt.Errorf("inwx: %w", err)
	}

	return keys, nil
}

// idString is an entry id as text, to compare ids however INWX typed
// them.
func idString(id json.RawMessage) string {
	if s, err := strconv.Unquote(string(id)); err == nil {
		return s
	}

	return string(bytes.TrimSpace(id))
}

// checkAccepted refuses, without a request, with
// dnsprovider.ErrUnsupported, a form INWX's documentation does not list: its dnssecAlgorithm values are 5, 7, 8,
// 10, 13, 14, 15 and 16, and its dnssecDigestType values 2 and 4.
func checkAccepted(s dnssec.Signer) error {
	switch s.Algorithm {
	case 5, 7, 8, 10, 13, 14, 15, 16:
	default:
		return fmt.Errorf("inwx: the %s %q has algorithm %d, which INWX does not take: %w", s.Form, s.Value, s.Algorithm, dnsprovider.ErrUnsupported)
	}

	if s.Form == dnssec.DS && s.DigestType != 2 && s.DigestType != 4 {
		return fmt.Errorf("inwx: the DS %q has digest type %d; INWX takes 2 and 4: %w", s.Value, s.DigestType, dnsprovider.ErrUnsupported)
	}

	return nil
}

// additions are the dnssec.adddnskey params that add a key: its DNSKEY,
// with calculateDigest so that INWX computes the DS, when it has one,
// and else each of its DS records. Each form sent must be one INWX
// takes.
func additions(domain string, k dnssec.Key) ([]map[string]any, error) {
	if k.DNSKEY != nil {
		if err := checkAccepted(*k.DNSKEY); err != nil {
			return nil, err
		}

		return []map[string]any{{"domainName": domain, "dnskey": domain + ". IN DNSKEY " + k.DNSKEY.Value, "calculateDigest": true}}, nil
	}

	out := make([]map[string]any, 0, len(k.DS))

	for _, s := range k.DS {
		if err := checkAccepted(s); err != nil {
			return nil, err
		}

		out = append(out, map[string]any{"domainName": domain, "ds": domain + ". IN DS " + s.Value})
	}

	return out, nil
}

// SetDelegationSigners implements dnsprovider.Provider (CapDSRegistrar):
// it replaces the Signing Keys the registry holds, through INWX, for a
// domain the Account registers and INWX does not host. It checks every
// key before any request, then reads the held set. A held entry and a
// key are the same key when they share a DNSKEY or a DS, held or
// computed from a DNSKEY, so an unchanged set in either form sends no
// write. Otherwise it first adds each missing key with dnssec.adddnskey,
// and only then removes each held entry no key wants with
// dnssec.deletednskey by its id: a failure part-way never leaves the
// Delegation without a key, and is reported with what was done, never
// undone. An algorithm, digest type or form INWX does not take is
// ErrUnsupported before any request; INWX's own refusals are APIErrors.
func (p *Provider) SetDelegationSigners(ctx context.Context, zone dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	if len(keys) == 0 {
		return dnsprovider.ErrNoSigningKeys
	}

	want, err := dnssec.CheckKeys(keys)
	if err != nil {
		return fmt.Errorf("inwx: %w", err)
	}

	domain := zoneName(zone.Name)

	var adds [][]map[string]any // per key, in key order

	for _, w := range want {
		a, err := additions(domain, w)
		if err != nil {
			return err
		}

		adds = append(adds, a)
	}

	if domain, err = p.registration(ctx, zone); err != nil {
		return err
	}

	held, err := p.heldKeys(ctx, domain)
	if err != nil {
		return err
	}

	plan := dnssec.Diff(domain, held, func(h heldKey) []dnssec.Signer { return h.signers }, want)

	var toAdd []map[string]any

	for _, i := range plan.Add {
		toAdd = append(toAdd, adds[i]...)
	}

	var toRemove []json.RawMessage

	seen := map[string]bool{}

	for _, i := range plan.Remove {
		id := idString(held[i].id)
		if seen[id] {
			continue
		}

		if id == "" || id == "null" {
			return errors.New("inwx: dnssec.listkeys holds a key to remove without an id; nothing was changed")
		}

		seen[id] = true
		toRemove = append(toRemove, held[i].id)
	}

	added, removed := 0, 0
	partial := func(err error) error {
		return fmt.Errorf("inwx: set Signing Keys: added %d of %d forms, removed %d of %d: %w", added, len(toAdd), removed, len(toRemove), err)
	}

	for _, params := range toAdd {
		if _, err := p.write(ctx, "dnssec.adddnskey", params, pendingTaken); err != nil {
			return partial(err)
		}

		added++
	}

	for _, id := range toRemove {
		if _, err := p.write(ctx, "dnssec.deletednskey", map[string]any{"key": id}, pendingTaken); err != nil {
			return partial(err)
		}

		removed++
	}

	return nil
}

// DeleteDelegationSigners implements dnsprovider.Provider
// (CapDSRegistrar): it removes every Signing Key the registry holds,
// through INWX, for a domain the Account registers and INWX does not
// host, with one dnssec.deleteall.
func (p *Provider) DeleteDelegationSigners(ctx context.Context, zone dnsprovider.Zone) error {
	domain, err := p.registration(ctx, zone)
	if err != nil {
		return err
	}

	if _, err := p.write(ctx, "dnssec.deleteall", map[string]any{"domainName": domain}, pendingTaken); err != nil {
		return fmt.Errorf("inwx: delete Signing Keys: %w", err)
	}

	return nil
}
