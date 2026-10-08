package namecheap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// setHostsResult is a setHosts CommandResponse.
type setHostsResult struct {
	Result struct {
		IsSuccess bool `xml:"IsSuccess,attr"`
	} `xml:"DomainDNSSetHostsResult"`
}

// sendHost is one host of a setHosts request.
type sendHost struct {
	Name, Type, Address string
	// MXPref is sent when not empty.
	MXPref string
	TTL    uint32
}

// ApplyChangeset implements dnsprovider.Batcher. setHosts replaces a
// domain's whole host list, so it reads the list and the EmailType with
// getHosts, makes the Changeset's changes to it, and sends the result in
// one call.
//
// The Changeset succeeds or fails as a whole. When it fails, nothing was
// applied (or, when the write's answer was lost, Namecheap may have taken
// it), so it returns an error of its own rather than per-change errors. On
// success, each added or modified Record is returned as Records reads it
// back, with its content ID, so a consumer need not read the Zone again.
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}
	for i, c := range cs.Changes {
		res.Results[i] = dnsprovider.ChangeResult{Change: c}
	}

	if len(cs.Changes) == 0 {
		return res, nil
	}

	if err := writable(cs); err != nil {
		return dnsprovider.ApplyResult{}, err
	}

	current, err := p.getHosts(ctx, cs.Zone)
	if err != nil {
		return dnsprovider.ApplyResult{}, fmt.Errorf("%w; nothing was applied", err)
	}

	if err := mailWritable(cs, current.Result.EmailType); err != nil {
		return dnsprovider.ApplyResult{}, err
	}

	hosts, sent, err := applyTo(cs, current.Result.Hosts)
	if err != nil {
		return dnsprovider.ApplyResult{}, err
	}

	if err := p.setHosts(ctx, cs.Zone, current.Result.EmailType, hosts); err != nil {
		return dnsprovider.ApplyResult{}, err
	}

	for i, h := range sent {
		if h != nil {
			res.Results[i].Record = h.read(cs.Zone.Name)
		}
	}

	return res, nil
}

// applyTo makes a Changeset's changes to the hosts as read: each host a
// change was built from is replaced, in its place, or left out; the hosts
// added go at the end; every other host is sent back exactly as read. sent
// are the hosts each addition or modification sends, by change. A
// Changeset that would leave a resource record more than once, and more
// often than Namecheap held it, fails with ErrConflict.
func applyTo(cs dnsprovider.Changeset, read []wireHost) (hosts []sendHost, sent []*sendHost, err error) {
	type slot struct {
		read    *wireHost
		send    *sendHost
		matched bool
	}

	slots := make([]slot, 0, len(read)+len(cs.Changes))
	for _, h := range read {
		send := asRead(h)
		slots = append(slots, slot{read: &h, send: &send})
	}

	sent = make([]*sendHost, len(cs.Changes))

	for ci, c := range cs.Changes {
		if c.Kind != dnsprovider.ChangeDelete {
			h, err := toHost(cs.Zone.Name, c.After)
			if err != nil {
				return nil, nil, err
			}

			sent[ci] = &h
		}

		if c.Kind == dnsprovider.ChangeAdd {
			slots = append(slots, slot{send: sent[ci]})

			continue
		}

		i := slices.IndexFunc(slots, func(s slot) bool {
			return s.read != nil && !s.matched && matches(cs.Zone.Name, *s.read, c.Before)
		})
		if i < 0 {
			return nil, nil, fmt.Errorf("namecheap: conflict, nothing was applied: %s %s %s is no longer at Namecheap as read (%w)",
				c.Before.Type, c.Before.Name, c.Before.Value, dnsprovider.ErrNotFound)
		}

		slots[i].matched, slots[i].send = true, sent[ci]
	}

	// A host a change sends that another host has, by type, name and
	// value, is the same resource record, whatever its TTL. Hosts
	// Namecheap holds more than once already are not the Changeset's
	// doing: only a record it leaves more often than it was read is.
	count := func(hs []*sendHost) map[string]int {
		n := map[string]int{}
		for _, h := range hs {
			if h != nil {
				n[h.key(cs.Zone.Name)]++
			}
		}

		return n
	}

	before := make([]*sendHost, 0, len(read))
	after := make([]*sendHost, 0, len(slots))

	for _, s := range slots {
		if s.read != nil {
			h := asRead(*s.read)
			before = append(before, &h)
		}

		after = append(after, s.send)
	}

	held, left, sends := count(before), count(after), count(sent)

	for _, h := range sent {
		if h == nil {
			continue
		}

		k := h.key(cs.Zone.Name)
		if left[k] <= 1 || left[k] <= held[k] {
			continue
		}

		r := h.read(cs.Zone.Name)
		if sends[k] > 1 {
			return nil, nil, fmt.Errorf("namecheap: nothing was applied: the Changeset sends %s %s %s more than once (%w)", r.Type, r.Name, r.Value, dnsprovider.ErrConflict)
		}

		return nil, nil, fmt.Errorf("namecheap: nothing was applied: %s %s %s is at Namecheap already (%w)", r.Type, r.Name, r.Value, dnsprovider.ErrConflict)
	}

	hosts = make([]sendHost, 0, len(slots))

	for _, s := range slots {
		if s.send != nil {
			hosts = append(hosts, *s.send)
		}
	}

	return hosts, sent, nil
}

// matches reports whether a host as read is the Record a change was built
// from: the host whose content is the Record's Provider ID (withID), or,
// for a Record without one, any host with its type, name and value. A
// host edited at Namecheap since is not it.
func matches(zone string, h wireHost, before dnsprovider.Record) bool {
	r := toRecord(zone, h)
	if before.ID != "" {
		return r.ID == before.ID
	}

	return strings.EqualFold(r.Type, before.Type) && strings.EqualFold(r.Name, before.Name) && r.Value == before.Value
}

// writeTypes are the Record types Apply adds and modifies. Namecheap-only
// types (URL, URL301, FRAME, ALIAS, MXE) are kept, not written; SRV and CAA
// wait for the manual pass (ticket 03) to confirm Namecheap's form shape
// for them. Any type can be deleted.
var writeTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}

// writable is an error for a change of no known kind, or naming each
// Record a Changeset adds or modifies to a type Apply does not write, or
// to NS at the apex; nil if there is none.
func writable(cs dnsprovider.Changeset) error {
	var bad []string

	for _, c := range cs.Changes {
		if c.Kind != dnsprovider.ChangeAdd && c.Kind != dnsprovider.ChangeModify && c.Kind != dnsprovider.ChangeDelete {
			return fmt.Errorf("namecheap: unknown change kind %d; nothing was applied", c.Kind)
		}

		r := c.After
		if c.Kind == dnsprovider.ChangeDelete {
			continue
		}

		if !slices.Contains(writeTypes, r.Type) || (r.Type == "NS" && names.RelativeName(cs.Zone.Name, r.Name) == "@") {
			bad = append(bad, r.Type+" "+r.Name)
		}
	}

	if bad == nil {
		return nil
	}

	return fmt.Errorf("namecheap: the adapter writes only A, AAAA, CNAME, MX, TXT and NS below the apex (SRV and CAA writes wait for a check against Namecheap), not %s; nothing was applied",
		strings.Join(bad, ", "))
}

// mailWritable is an error when a Changeset adds or modifies an MX Record
// of a domain whose EmailType is not MX ("Custom MX" in Namecheap's
// console): Namecheap ignores MX hosts then. Apply keeps the EmailType
// (mail forwarding or Private Email stays as set up); it is changed in
// Namecheap's console. Nil otherwise.
func mailWritable(cs dnsprovider.Changeset, emailType string) error {
	if strings.EqualFold(emailType, "MX") {
		return nil
	}

	for _, c := range cs.Changes {
		if c.Kind != dnsprovider.ChangeDelete && c.After.Type == "MX" {
			return fmt.Errorf("namecheap: %s's mail setting is %q, so Namecheap ignores MX records such as %s %s until it is \"Custom MX\"; nothing was applied",
				cs.Zone.Name, emailType, c.After.Type, c.After.Name)
		}
	}

	return nil
}

// read is a host as sent, as Records reads it back.
func (h sendHost) read(zone string) dnsprovider.Record {
	pref, _ := strconv.ParseUint(h.MXPref, 10, 16)

	return toRecord(zone, wireHost{Name: h.Name, Type: h.Type, Address: h.Address, MXPref: uint32(pref), TTL: h.TTL})
}

// key tells a host apart from another resource record: its type, name
// and value as Records reads it back, the type and name ignoring case.
func (h sendHost) key(zone string) string {
	r := h.read(zone)

	return strings.ToUpper(r.Type) + "|" + strings.ToLower(r.Name) + "|" + r.Value
}

// asRead is a host getHosts answered, to send back exactly as read.
func asRead(h wireHost) sendHost {
	return sendHost{
		Name: h.Name, Type: h.Type, Address: h.Address,
		MXPref: strconv.FormatUint(uint64(h.MXPref), 10), TTL: h.TTL,
	}
}

// toHost undoes what toRecord does to a Record of a Zone: its name becomes
// relative ("@" for the apex), the MX priority leaves the Value for MXPref,
// and host name targets end in a dot.
func toHost(zone string, r dnsprovider.Record) (sendHost, error) {
	h := sendHost{Name: names.RelativeName(zone, r.Name), Type: r.Type, Address: r.Value, TTL: r.TTL}

	switch r.Type {
	case "CNAME", "NS":
		h.Address = fqdn(r.Value)
	case "MX":
		f := strings.Fields(r.Value)
		if len(f) != 2 {
			return sendHost{}, fmt.Errorf("namecheap: MX value %q is not \"priority host\"; nothing was applied", r.Value)
		}

		if _, err := strconv.ParseUint(f[0], 10, 16); err != nil {
			return sendHost{}, fmt.Errorf("namecheap: MX value %q is not \"priority host\"; nothing was applied", r.Value)
		}

		h.MXPref, h.Address = f[0], fqdn(f[1])
	}

	return h, nil
}

// fqdn is a host name target with its trailing dot; the root stays ".".
func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}

	return name + "."
}

// setHosts replaces a Zone's hosts and its EmailType.
func (p *Provider) setHosts(ctx context.Context, zone dnsprovider.Zone, emailType string, hosts []sendHost) error {
	sld, tld := splitDomain(zone.ID)

	form := url.Values{"SLD": {sld}, "TLD": {tld}}
	if emailType != "" {
		form.Set("EmailType", emailType)
	}

	for i, h := range hosts {
		n := strconv.Itoa(i + 1)
		form.Set("HostName"+n, h.Name)
		form.Set("RecordType"+n, h.Type)
		form.Set("Address"+n, h.Address)
		form.Set("TTL"+n, strconv.FormatUint(uint64(h.TTL), 10))

		if h.MXPref != "" {
			form.Set("MXPref"+n, h.MXPref)
		}
	}

	res, err := call[setHostsResult](ctx, p, "namecheap.domains.dns.setHosts", form)

	// An ERROR answer (StatusCode 0) is Namecheap refusing the write. Any
	// other failure may come after Namecheap took it.
	var apiErr *dnsprovider.APIError

	switch {
	case errors.As(err, &apiErr) && apiErr.StatusCode == 0:
		return fmt.Errorf("%w; nothing was applied", err)
	case err != nil:
		return fmt.Errorf("%w; Namecheap may or may not have applied the changes", err)
	case !res.Result.IsSuccess:
		return errors.New("namecheap: setHosts answered without success; Namecheap may or may not have applied the changes")
	}

	return nil
}

// CreateRecord implements dnsprovider.Provider: a one-change Changeset
// through ApplyChangeset, so one getHosts and one setHosts.
func (p *Provider) CreateRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Create(ctx, p, zone, r)
}

// UpdateRecord implements dnsprovider.Provider: a one-change Changeset
// through ApplyChangeset. Namecheap has no record IDs, so before is found
// by its content: ErrNotFound when the Zone no longer holds it.
func (p *Provider) UpdateRecord(ctx context.Context, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Update(ctx, p, zone, before, after)
}

// DeleteRecord implements dnsprovider.Provider: a one-change Changeset
// through ApplyChangeset, found as UpdateRecord finds before.
func (p *Provider) DeleteRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) error {
	return batch.Delete(ctx, p, zone, r)
}
