package netim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// writable are the Record types the adapter writes. Netim takes no CAA or
// URI Records; TLSA, SVCB and HTTPS are read only.
var writable = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV"}

// checkWritable refuses a Record type the adapter does not write.
func checkWritable(typ string) error {
	if !slices.Contains(writable, strings.ToUpper(strings.TrimSpace(typ))) {
		return fmt.Errorf("netim: cannot write %s records", typ)
	}

	return nil
}

// maxValue is the longest value Netim takes, in characters.
const maxValue = 150

// apex is the subdomain the adapter sends for the Zone apex. Netim reads
// it as "" or "@"; which it expects on writes is undocumented.
const apex = ""

// protocols are the SRV protocols Netim takes.
var protocols = []string{"TCP", "UDP", "TLS"}

// wireWrite is a record as a create sends it: subdomain, type and value,
// and the options that carry its TTL and the numbers of an MX or SRV.
type wireWrite struct {
	Subdomain string         `json:"subdomain"`
	Type      string         `json:"type"`
	Value     string         `json:"value"`
	Options   map[string]any `json:"options"`
}

// prepare checks a Record to write to the Zone, before any request, and
// returns it in the form the Zone reads it back, with its wire form.
func prepare(zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, wireWrite, error) {
	domain, err := zoneName(zone)
	if err != nil {
		return dnsprovider.Record{}, wireWrite{}, err
	}

	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	if err := checkWritable(r.Type); err != nil {
		return dnsprovider.Record{}, wireWrite{}, err
	}

	if hasExtras(r.Extras) {
		return dnsprovider.Record{}, wireWrite{}, errors.New("netim: cannot write record options (Extras)")
	}

	name, err := dnsprovider.QualifyName(domain, r.Name)
	if err != nil {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("netim: %w", err)
	}

	r.Name = names.ZoneName(name)

	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("netim: %w", err)
	}

	if err := traits.TTL.Check(r.TTL); err != nil {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("netim: %w", err)
	}

	w := wireWrite{Type: r.Type, Value: r.Value, Options: map[string]any{"ttl": r.TTL, "ttlUnit": "S"}}
	owner := r.Name

	switch r.Type {
	case "CNAME", "NS":
		r.Value = target(r.Value)
		w.Value = fqdn(r.Value)
	case "MX":
		f := strings.Fields(r.Value)
		priority, _ := strconv.ParseUint(f[0], 10, 16)
		r.Value = numbered(target(f[1]), priority)
		w.Value = fqdn(target(f[1]))
		w.Options["priority"] = priority
	case "SRV":
		if owner, err = srvOwner(r.Name, w.Options); err != nil {
			return dnsprovider.Record{}, wireWrite{}, err
		}

		f := strings.Fields(r.Value)
		n := make([]uint64, 3)

		for i := range n {
			n[i], _ = strconv.ParseUint(f[i], 10, 16)
		}

		r.Value = numbered(target(f[3]), n...)
		w.Value = fqdn(target(f[3]))
		w.Options["priority"], w.Options["weight"], w.Options["port"] = n[0], n[1], n[2]
	}

	if !strings.EqualFold(owner, domain) && !strings.HasSuffix(strings.ToLower(owner), "."+strings.ToLower(domain)) {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("netim: %s is not inside the Zone %s", r.Name, domain)
	}

	w.Subdomain = apex
	if sub := names.RelativeName(domain, owner); sub != "@" {
		w.Subdomain = sub
	}

	// The trailing dot the adapter adds to a target is not counted.
	counted := w.Value
	if slices.Contains([]string{"CNAME", "NS", "MX", "SRV"}, r.Type) {
		counted = target(counted)
	}

	if len([]rune(counted)) > maxValue {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("netim: the value is longer than Netim's %d characters", maxValue)
	}

	return r, w, nil
}

// srvOwner splits an SRV Record's name into its service and protocol,
// which go in options, and the owner they are under.
func srvOwner(name string, options map[string]any) (string, error) {
	labels := strings.SplitN(name, ".", 3)
	if len(labels) < 3 || len(labels[0]) < 2 || len(labels[1]) < 2 || labels[0][0] != '_' || labels[1][0] != '_' {
		return "", fmt.Errorf("netim: an SRV name starts with _service._protocol, not %q", name)
	}

	protocol := strings.ToUpper(labels[1][1:])
	if !slices.Contains(protocols, protocol) {
		return "", fmt.Errorf("netim: the SRV protocol must be one of %s, not %q", strings.Join(protocols, ", "), labels[1][1:])
	}

	options["service"], options["protocol"] = strings.ToLower(labels[0][1:]), protocol

	return labels[2], nil
}

// fqdn is a domain name with a trailing dot.
func fqdn(s string) string {
	return strings.TrimSuffix(s, ".") + "."
}

// hasExtras reports whether a Record carries any Extra.
func hasExtras(extras map[string]string) bool {
	for _, v := range extras {
		if v != "" {
			return true
		}
	}

	return false
}

// operation is a write's StructOperationResponse.
type operation struct {
	Status  string `json:"STATUS"`
	Message string `json:"MESSAGE"`
}

// write sends a call that changes what Netim holds, once, and checks the
// operation Netim answers with. Done confirms it. Failed and Cancelled
// are refusals, an APIError with Netim's message. Pending, or a status
// the adapter does not know, is an Unconfirmed Write, as is a lost
// answer, a 5xx or an answer that is not an operation; a 4xx is a
// refusal. The call is never tried again, other than once with a new
// session after a 401, which Netim refuses before running the call.
func (p *Provider) write(ctx context.Context, method, path string, body any) error {
	return p.send(ctx, func(c *rest.Client, ctx context.Context, method, path string, body, _ any) error {
		c.Attempts = 1

		var op operation
		if err := c.Write(ctx, method, path, nil, body, &op); err != nil {
			return err
		}

		return c.RedactError(op.outcome())
	}, method, path, body, nil)
}

// outcome is the error an operation's status stands for; nil for Done.
func (op operation) outcome() error {
	status := strings.TrimSpace(op.Status)

	switch strings.ToLower(status) {
	case "done":
		return nil
	case "failed", "cancelled", "canceled":
		msg := strings.TrimSpace(op.Message)
		if msg == "" {
			msg = "operation " + status
		}

		return &dnsprovider.APIError{Provider: "netim", Messages: []string{msg}}
	}

	return fmt.Errorf("netim: operation status %q: %w", status, dnsprovider.ErrUnconfirmed)
}

// rejectConflict is ErrConflict when the Zone holds a Record like r, by
// SameRecord, other than the one at index excluded.
func rejectConflict(records []entry, r dnsprovider.Record, excluded int) error {
	for i, e := range records {
		if i != excluded && dnsprovider.SameRecord(e.Record, r) {
			return fmt.Errorf("netim: the Zone holds %s %s %q already: %w", r.Type, r.Name, r.Value, dnsprovider.ErrConflict)
		}
	}

	return nil
}

// readBack finds the one Record the Zone holds like want, with its TTL,
// after a write Netim confirmed. A failed read, or none or several such
// Records, is an Unconfirmed Write; the write is never sent again.
func (p *Provider) readBack(ctx context.Context, zone dnsprovider.Zone, want dnsprovider.Record) (dnsprovider.Record, error) {
	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("netim: the write was confirmed but its read-back failed: %w; %w", err, dnsprovider.ErrUnconfirmed)
	}

	var matches []dnsprovider.Record

	for _, e := range records {
		if dnsprovider.SameRecord(e.Record, want) && e.TTL == want.TTL {
			matches = append(matches, e.Record)
		}
	}

	if len(matches) != 1 {
		return dnsprovider.Record{}, fmt.Errorf("netim: the write was confirmed but its read-back found %d matching records: %w", len(matches), dnsprovider.ErrUnconfirmed)
	}

	return matches[0], nil
}

// CreateRecord implements dnsprovider.Provider: it adds an A, AAAA,
// CNAME, MX, TXT, NS or SRV Record with its TTL in seconds and returns it
// as read back. A Record the Zone holds already is ErrConflict, without
// a write.
func (p *Provider) CreateRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	r, w, err := prepare(zone, r)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := rejectConflict(records, r, -1); err != nil {
		return dnsprovider.Record{}, err
	}

	if err := p.write(ctx, http.MethodPost, domainPath(names.ZoneName(zone.Name), "zone"), w); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("netim: create: %w", err)
	}

	return p.readBack(ctx, zone, r)
}

// DeleteRecord implements dnsprovider.Provider: it finds the Record as
// last read in a fresh read and deletes it by its subdomain, type and
// value as Netim holds them. A Record the Zone no longer holds as read is
// ErrNotFound; one Netim's selector would not single out is ErrConflict.
// Neither sends a write.
func (p *Provider) DeleteRecord(ctx context.Context, zone dnsprovider.Zone, before dnsprovider.Record) error {
	if err := checkWritable(before.Type); err != nil {
		return err
	}

	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return err
	}

	i, err := selectRecord(records, before)
	if err != nil {
		return err
	}

	if err := p.write(ctx, http.MethodDelete, domainPath(names.ZoneName(zone.Name), "zone"), selector(records[i].wire)); err != nil {
		return fmt.Errorf("netim: delete: %w", err)
	}

	return nil
}

// selectRecord finds the Record as last read: by its ID, which derives
// from its content, or else by SameRecord and TTL. None is ErrNotFound.
// Several, or one whose subdomain, type and value Netim would also match
// with another Record, is ErrConflict: Netim selects a Record by those
// alone, so a write could reach both.
func selectRecord(records []entry, before dnsprovider.Record) (int, error) {
	index := -1

	for i, e := range records {
		matched := e.ID == before.ID
		if before.ID == "" {
			matched = dnsprovider.SameRecord(e.Record, before) && e.TTL == before.TTL
		}

		if !matched {
			continue
		}

		if index >= 0 {
			return -1, fmt.Errorf("netim: the Zone holds several records like %s %s: %w", before.Type, before.Name, dnsprovider.ErrConflict)
		}

		index = i
	}

	if index < 0 {
		return -1, fmt.Errorf("netim: the Zone holds no %s %s %q as read: %w", before.Type, before.Name, before.Value, dnsprovider.ErrNotFound)
	}

	key := wireKey(records[index].wire)

	for i, e := range records {
		if i != index && wireKey(e.wire) == key {
			return -1, fmt.Errorf("netim: Netim cannot tell %s %s %q from another record by subdomain, type and value: %w",
				before.Type, before.Name, before.Value, dnsprovider.ErrConflict)
		}
	}

	return index, nil
}

// wireKey is what Netim may select a record by, compared loosely: the
// subdomain with either apex, and the type and value ignoring case and a
// trailing dot.
func wireKey(w wireRecord) [3]string {
	sub := strings.ToLower(strings.TrimSuffix(w.Subdomain, "."))
	if sub == "@" {
		sub = ""
	}

	var value string
	if w.Value != nil {
		value = strings.ToLower(target(*w.Value))
	}

	return [3]string{sub, strings.ToUpper(w.Type), value}
}

// selector is the body that selects a record in a delete or update: its
// subdomain, type and value as Netim holds them.
func selector(w wireRecord) map[string]string {
	var value string
	if w.Value != nil {
		value = *w.Value
	}

	return map[string]string{"subdomain": w.Subdomain, "type": w.Type, "value": value}
}
