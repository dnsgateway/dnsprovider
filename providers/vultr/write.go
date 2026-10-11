package vultr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// writeTypes are the editable types Vultr takes. URI is not one of its
// types; SSHFP is, but the module does not edit it.
var writeTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"}

// wire is a Record as Vultr's write fields: priority is set for MX and SRV
// alone, where it is required and zero is a valid, explicit value.
type wire struct {
	Name, Type, Data string
	TTL              uint32
	Priority         *uint64
}

// toWire checks a Record locally and turns it into Vultr's fields. Host
// names are sent without their trailing dot, which Vultr reads as
// absolute; the root stays ".".
func (p *Provider) toWire(z dnsprovider.Zone, r dnsprovider.Record) (wire, error) {
	r.Type = strings.ToUpper(r.Type)
	if !slices.Contains(writeTypes, r.Type) {
		return wire{}, fmt.Errorf("vultr: cannot write %s Records", r.Type)
	}

	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return wire{}, fmt.Errorf("vultr: %w", err)
	}

	if err := dnsprovider.TTLRangeOf(p).Check(r.TTL); err != nil {
		return wire{}, fmt.Errorf("vultr: %w", err)
	}

	zone := zoneName(z)

	abs, err := dnsprovider.QualifyName(zone, r.Name)
	if err != nil {
		return wire{}, fmt.Errorf("vultr: %w", err)
	}

	// Vultr names the apex "", not "@".
	name := ""
	if !strings.EqualFold(abs, zone) {
		name = names.RelativeName(zone, abs)
	}

	w := wire{Name: name, Type: r.Type, Data: r.Value, TTL: r.TTL}
	f := strings.Fields(r.Value)
	number := func(s string) *uint64 { n, _ := strconv.ParseUint(s, 10, 16); return &n }

	switch r.Type {
	case "CNAME", "NS":
		w.Data = bare(f[0])
	case "MX":
		w.Priority, w.Data = number(f[0]), bare(f[1])
	case "SRV":
		w.Priority, w.Data = number(f[0]), f[1]+" "+f[2]+" "+bare(f[3])
	case "TXT":
		// Vultr takes TXT data in quotes, refuses quotes inside, and
		// reads a backslash literally.
		if strings.Contains(r.Value, `"`) {
			return wire{}, errors.New(`vultr: TXT values cannot hold a double quote (")`)
		}

		w.Data = `"` + r.Value + `"`
	case "CAA":
		flags, tag, value, err := caaFields(r.Value)
		if err != nil {
			return wire{}, err
		}

		w.Data = fmt.Sprintf("%s %s %s", flags, strings.ToLower(tag), charstr.Quote(value))
	}

	return w, nil
}

// bare is a host name without its trailing dot; the root stays ".".
func bare(name string) string {
	if name == "." {
		return name
	}

	return strings.TrimSuffix(name, ".")
}

// createBody is a POST body: every field.
func (w wire) createBody() map[string]any {
	body := map[string]any{"name": w.Name, "type": w.Type, "data": w.Data, "ttl": w.TTL}
	if w.Priority != nil {
		body["priority"] = *w.Priority
	}

	return body
}

// patchBody is a PATCH body: the fields PATCH documents, not the type.
func (w wire) patchBody() map[string]any {
	body := w.createBody()
	delete(body, "type")

	return body
}

// stored is the Record Vultr would answer for w.
func (w wire) stored(z dnsprovider.Zone) (dnsprovider.Record, error) {
	name, data, ttl := w.Name, w.Data, int64(w.TTL)
	wr := wireRecord{ID: "-", Type: w.Type, Name: &name, Data: &data, TTL: &ttl}

	if w.Priority != nil {
		n := int64(*w.Priority)
		wr.Priority = &n
	}

	return toRecord(zoneName(z), wr)
}

// collision fails with ErrConflict when all holds a Record identical to
// want, whatever its TTL, other than the one with ID exclude.
func collision(all []dnsprovider.Record, want dnsprovider.Record, exclude string) error {
	for _, r := range all {
		if r.ID != exclude && dnsprovider.SameRecord(r, want) {
			return fmt.Errorf("vultr: the Zone already holds %s %s %s: %w", want.Type, want.Name, want.Value, dnsprovider.ErrConflict)
		}
	}

	return nil
}

// recordPath is the path of a Record by its native ID, a UUID; any other
// ID names no Record and is never sent.
func recordPath(z dnsprovider.Zone, id string) (string, error) {
	if !isUUID(id) {
		return "", fmt.Errorf("vultr: missing or invalid Record ID %q: %w", id, dnsprovider.ErrNotFound)
	}

	return recordsPath(z) + "/" + id, nil
}

// isUUID reports whether id is a UUID in its hyphenated hexadecimal form,
// 8-4-4-4-12 digits.
func isUUID(id string) bool {
	if len(id) != 36 {
		return false
	}

	for i := range len(id) {
		c := id[i]

		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isDigit(c) && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}

	return true
}

// get reads one DNS Record by its ID.
func (p *Provider) get(ctx context.Context, z dnsprovider.Zone, id string) (dnsprovider.Record, error) {
	path, err := recordPath(z, id)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	var raw []byte
	if err := p.api().Do(ctx, http.MethodGet, path, nil, nil, &raw); err != nil {
		return dnsprovider.Record{}, err
	}

	r, ok := decodeRecord(z, raw)
	if !ok {
		return dnsprovider.Record{}, errors.New("vultr: malformed DNS Record answer")
	}

	if r.ID != id {
		return dnsprovider.Record{}, errors.New("vultr: the answer names a different DNS Record")
	}

	return r, nil
}

// decodeRecord decodes a {"record": …} answer.
func decodeRecord(z dnsprovider.Zone, raw []byte) (dnsprovider.Record, bool) {
	var answer struct {
		Record *wireRecord `json:"record"`
	}

	if json.Unmarshal(raw, &answer) != nil || answer.Record == nil {
		return dnsprovider.Record{}, false
	}

	r, err := toRecord(zoneName(z), *answer.Record)

	return r, err == nil
}

// create POSTs w once and decodes the stored Record it answers. An
// acknowledgement without a well-formed Record is read back as the one
// Record of its content, which the duplicate check proved new, never
// written again.
func (p *Provider) create(ctx context.Context, z dnsprovider.Zone, w wire) (dnsprovider.Record, error) {
	var raw []byte
	if err := p.write(ctx, "creation", http.MethodPost, recordsPath(z), w.createBody(), &raw); err != nil {
		return dnsprovider.Record{}, err
	}

	if r, ok := decodeRecord(z, raw); ok {
		return r, nil
	}

	r, err := p.findCreated(ctx, z, w)
	if err != nil {
		return dnsprovider.Record{}, acknowledged("creation", err)
	}

	return r, nil
}

func (p *Provider) findCreated(ctx context.Context, z dnsprovider.Zone, w wire) (dnsprovider.Record, error) {
	all, err := p.records(ctx, z)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	want, err := w.stored(z)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	var found []dnsprovider.Record

	for _, r := range all {
		if dnsprovider.SameRecord(r, want) {
			found = append(found, r)
		}
	}

	if len(found) != 1 {
		return dnsprovider.Record{}, fmt.Errorf("vultr: found %d Records of the created content", len(found))
	}

	return found[0], nil
}

// acknowledged is the error of a write Vultr acknowledged whose stored
// Record could not be read back.
func acknowledged(operation string, err error) error {
	return &uncertainError{"vultr: the Record " + operation + " was acknowledged, but reading the stored Record back failed; " +
		"it may have completed, so re-read Records before retrying", err}
}

// CreateRecord checks that the Zone holds no identical Record, whatever
// its TTL, then POSTs the Record once: a create is never retried, and a
// lost answer is reported unconfirmed.
func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	w, err := p.toWire(z, r)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	all, err := p.records(ctx, z)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	want, err := w.stored(z)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := collision(all, want, ""); err != nil {
		return dnsprovider.Record{}, err
	}

	return p.create(ctx, z, w)
}

// UpdateRecord finds before by its ID in one list of the Zone, which also
// shows a collision. A change of name, Value or TTL is one PATCH, keeping
// the ID; Vultr acknowledges it without a body, so the stored Record is
// read back by ID, never written again. A change of type, which PATCH
// does not document, creates the new Record and then deletes the old one,
// returning the new ID; a CNAME move at one owner deletes first, as a
// CNAME cannot share its owner, and re-creates the original when its
// replacement definitely failed. A failure between the writes says which Records may
// remain.
func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	w, err := p.toWire(z, after)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	want, err := w.stored(z)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	path, err := recordPath(z, before.ID)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	all, err := p.records(ctx, z)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	i := slices.IndexFunc(all, func(r dnsprovider.Record) bool { return r.ID == before.ID })
	if i < 0 {
		return dnsprovider.Record{}, fmt.Errorf("vultr: no Record %s in Zone %s: %w", before.ID, zoneName(z), dnsprovider.ErrNotFound)
	}

	current := all[i]

	if err := collision(all, want, before.ID); err != nil {
		return dnsprovider.Record{}, err
	}

	if current.Type == w.Type {
		if err := p.write(ctx, "update", http.MethodPatch, path, w.patchBody(), nil); err != nil {
			return dnsprovider.Record{}, err
		}

		r, err := p.get(ctx, z, before.ID)
		if err != nil {
			return dnsprovider.Record{}, acknowledged("update", err)
		}

		return r, nil
	}

	if strings.EqualFold(want.Name, current.Name) && (current.Type == "CNAME" || w.Type == "CNAME") {
		return p.replaceAtOwner(ctx, z, current, w, path)
	}

	r, err := p.create(ctx, z, w)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := p.api().Do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
		return r, fmt.Errorf("vultr: the replacement Record %s was created; deleting the original Record %s failed, and both may remain: %w", r.ID, before.ID, err)
	}

	return r, nil
}

// replaceAtOwner deletes current, then creates its replacement. current
// must be writable back, or nothing is written. When the replacement
// definitely failed, it re-creates current, as best it can, even when ctx
// ends, and reports whether it did and under which new ID; when the
// replacement may have completed, it does not.
func (p *Provider) replaceAtOwner(ctx context.Context, z dnsprovider.Zone, current dnsprovider.Record, w wire, path string) (dnsprovider.Record, error) {
	restore, err := p.toWire(z, current)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("vultr: the original Record %s could not be restored if its replacement failed, so it was left as it is: %w", current.ID, err)
	}

	if err := p.api().Do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("vultr: deleting the original Record %s failed or is unconfirmed; its replacement was not created: %w", current.ID, err)
	}

	r, err := p.create(ctx, z, w)
	if err == nil {
		return r, nil
	}

	if uncertain(err) {
		return dnsprovider.Record{}, fmt.Errorf("vultr: the original Record %s was deleted; its replacement may have completed, "+
			"so the original was not restored; re-read Records before retrying: %w", current.ID, err)
	}

	failed := fmt.Errorf("vultr: the original Record %s was deleted; creating its replacement failed: %w", current.ID, err)

	restored, err := p.create(context.WithoutCancel(ctx), z, restore)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("%w; restoring it failed, and the original may be lost: %w", failed, err)
	}

	return dnsprovider.Record{}, fmt.Errorf("%w; the original was restored as Record %s", failed, restored.ID)
}

// DeleteRecord deletes the Record of r's ID alone: ErrNotFound when the
// Zone has none of that ID.
func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	path, err := recordPath(z, r.ID)
	if err != nil {
		return err
	}

	return p.api().Do(ctx, http.MethodDelete, path, nil, nil, nil)
}
