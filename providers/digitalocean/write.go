package digitalocean

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
)

// writeTypes are the editable types the Domain Records API takes. URI is
// not one of its types.
var writeTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"}

// caaTags are the CAA tags the API takes.
var caaTags = []string{"issue", "issuewild", "iodef"}

// payload is a Record as a Domain Record write: the whole Record, every
// type-specific field the type does not take sent null, so a PUT clears
// what an earlier type left. Host names are sent absolute, with their
// trailing dot.
func (p *Provider) payload(z dnsprovider.Zone, r dnsprovider.Record) (map[string]any, error) {
	r.Type = strings.ToUpper(r.Type)
	if !slices.Contains(writeTypes, r.Type) {
		return nil, fmt.Errorf("digitalocean: cannot write %s Records", r.Type)
	}

	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return nil, fmt.Errorf("digitalocean: %w", err)
	}

	if err := dnsprovider.TTLRangeOf(p).Check(r.TTL); err != nil {
		return nil, fmt.Errorf("digitalocean: %w", err)
	}

	zone := zoneName(z)

	abs, err := dnsprovider.QualifyName(zone, r.Name)
	if err != nil {
		return nil, fmt.Errorf("digitalocean: %w", err)
	}

	body := map[string]any{
		"type": r.Type, "name": dnsprovider.RelativeName(zone, abs), "data": r.Value, "ttl": r.TTL,
		"priority": nil, "port": nil, "weight": nil, "flags": nil, "tag": nil,
	}

	f := strings.Fields(r.Value)
	number := func(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 16); return n }

	switch r.Type {
	case "CNAME", "NS":
		body["data"] = fqdn(f[0])
	case "MX":
		body["priority"], body["data"] = number(f[0]), fqdn(f[1])
	case "SRV":
		body["priority"], body["weight"], body["port"], body["data"] = number(f[0]), number(f[1]), number(f[2]), fqdn(f[3])
	case "CAA":
		tag := strings.ToLower(f[1])
		if !slices.Contains(caaTags, tag) {
			return nil, fmt.Errorf("digitalocean: the CAA tag must be one of %s, not %q", strings.Join(caaTags, ", "), f[1])
		}

		data, err := caaValue(r.Value)
		if err != nil {
			return nil, err
		}

		if issuer(tag, data) {
			data = fqdn(data)
		}

		body["flags"], body["tag"], body["data"] = number(f[0]), tag, data
	}

	return body, nil
}

// fqdn is a host name with its trailing dot: the module's Values hold
// absolute names, which DigitalOcean reads as such only with the dot.
func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}

	return name + "."
}

// caaValue is the value of a CAA presentation Value, after its flags and
// tag, unquoted. The fields may be split by any white space
// dnsprovider.CheckValue takes.
func caaValue(value string) (string, error) {
	rest := strings.TrimSpace(value)
	for range 2 {
		i := strings.IndexFunc(rest, unicode.IsSpace)
		if i < 0 {
			return "", fmt.Errorf("digitalocean: the CAA value %q has no value after its flags and tag", value)
		}

		rest = strings.TrimSpace(rest[i:])
	}

	if !strings.HasPrefix(rest, `"`) {
		return rest, nil
	}

	v, err := charstr.Unquote(rest)
	if err != nil {
		return "", fmt.Errorf("digitalocean: the CAA value %s: %w", rest, err)
	}

	return v, nil
}

// collision fails with ErrConflict when the Zone holds a Record identical
// to the payload's, whatever its TTL, other than the one with ID exclude.
func (p *Provider) collision(ctx context.Context, z dnsprovider.Zone, body map[string]any, exclude string) error {
	want := wireFields(z, body)

	all, err := p.records(ctx, z, want.Type)
	if err != nil {
		return err
	}

	for _, stored := range all {
		if stored.ID != exclude && dnsprovider.SameRecord(stored, want) {
			return fmt.Errorf("digitalocean: the Zone already holds %s %s %s: %w", want.Type, want.Name, want.Value, dnsprovider.ErrConflict)
		}
	}

	return nil
}

func (p *Provider) recordPath(z dnsprovider.Zone, id string) (string, error) {
	n, err := strconv.ParseUint(id, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != id {
		return "", fmt.Errorf("digitalocean: missing or invalid Record ID %q: %w", id, dnsprovider.ErrNotFound)
	}

	return recordsPath(z) + "/" + url.PathEscape(id), nil
}

// stored reads one Domain Record by its ID.
func (p *Provider) stored(ctx context.Context, z dnsprovider.Zone, id string) (dnsprovider.Record, error) {
	path, err := p.recordPath(z, id)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	var answer struct {
		Record *wireRecord `json:"domain_record"`
	}

	if err := p.api().Do(ctx, http.MethodGet, path, nil, nil, &answer); err != nil {
		return dnsprovider.Record{}, err
	}

	if answer.Record == nil {
		return dnsprovider.Record{}, errors.New("digitalocean: malformed Domain Record answer")
	}

	r, err := toRecord(zoneName(z), *answer.Record)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if r.ID != id {
		return dnsprovider.Record{}, errors.New("digitalocean: the answer names a different Domain Record")
	}

	return r, nil
}

// restricted refuses a write to a Record DigitalOcean manages: the SOA,
// which cannot be deleted and has only its TTL changed by DigitalOcean.
func restricted(r dnsprovider.Record) error {
	if r.Type != "SOA" {
		return nil
	}

	return &dnsprovider.APIError{Provider: "digitalocean", Kind: dnsprovider.ErrUnauthorized, Messages: []string{"the SOA Record is managed by DigitalOcean and cannot be edited or deleted"}}
}

// write sends a POST or PUT and decodes the stored Record it answers. An
// acknowledgement without one, empty or malformed, is read back, never
// written again.
func (p *Provider) write(ctx context.Context, z dnsprovider.Zone, method, path string, body map[string]any, id string) (dnsprovider.Record, error) {
	operation := map[string]string{http.MethodPost: "creation", http.MethodPut: "update"}[method]

	var raw []byte
	if err := p.api().Do(ctx, method, path, nil, body, &raw); err != nil {
		return dnsprovider.Record{}, unconfirmed(operation, err)
	}

	var answer struct {
		Record *wireRecord `json:"domain_record"`
	}

	if json.Unmarshal(raw, &answer) == nil && answer.Record != nil {
		r, err := toRecord(zoneName(z), *answer.Record)
		if err == nil && (id == "" || r.ID == id) {
			return r, nil
		}
	}

	r, err := p.readBack(ctx, z, body, id)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("digitalocean: the Record %s was acknowledged without a well-formed Record, "+
			"and reading it back failed; it may have completed, so re-read Records before retrying: %w", operation, err)
	}

	return r, nil
}

// readBack finds the Record an acknowledged write stored: by its ID, or
// for a create, as the one Record of its content, which the duplicate
// check proved new.
func (p *Provider) readBack(ctx context.Context, z dnsprovider.Zone, body map[string]any, id string) (dnsprovider.Record, error) {
	if id != "" {
		return p.stored(ctx, z, id)
	}

	all, err := p.records(ctx, z, body["type"].(string))
	if err != nil {
		return dnsprovider.Record{}, err
	}

	want := wireFields(z, body)

	var found []dnsprovider.Record

	for _, r := range all {
		if dnsprovider.SameRecord(r, want) {
			found = append(found, r)
		}
	}

	if len(found) != 1 {
		return dnsprovider.Record{}, fmt.Errorf("digitalocean: found %d Records of the created content", len(found))
	}

	return found[0], nil
}

// wireFields is a payload as the Record DigitalOcean answers for it.
func wireFields(z dnsprovider.Zone, body map[string]any) dnsprovider.Record {
	w := wireRecord{ID: 1, Type: body["type"].(string), TTL: new(uint32)}
	name, data := body["name"].(string), body["data"].(string)
	w.Name, w.Data = &name, &data

	u16 := func(k string) *uint16 {
		if v, ok := body[k].(uint64); ok {
			n := uint16(v)
			return &n
		}

		return nil
	}

	w.Priority, w.Weight, w.Port = u16("priority"), u16("weight"), u16("port")
	if v, ok := body["flags"].(uint64); ok {
		n := uint8(v)
		w.Flags = &n
	}

	if v, ok := body["tag"].(string); ok {
		w.Tag = &v
	}

	r, _ := toRecord(zoneName(z), w)

	return r
}

// CreateRecord checks that the Zone holds no identical Record, whatever
// its TTL, then POSTs the Record once: a create is never retried, and a
// lost answer is reported unconfirmed.
func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	body, err := p.payload(z, r)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := p.collision(ctx, z, body, ""); err != nil {
		return dnsprovider.Record{}, err
	}

	return p.write(ctx, z, http.MethodPost, recordsPath(z), body, "")
}

// UpdateRecord finds before by its ID. A change of name, Value or TTL is
// one PUT of the whole Record, keeping its ID. A change of type, which the
// API's update does not document, creates the new Record and then deletes
// the old one, returning the new ID; a CNAME move at one owner deletes
// first, as a CNAME cannot share its owner, and re-creates the original
// when its replacement fails. A failure between the writes says which
// Records may remain.
func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	body, err := p.payload(z, after)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	current, err := p.stored(ctx, z, before.ID)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := restricted(current); err != nil {
		return dnsprovider.Record{}, err
	}

	if err := p.collision(ctx, z, body, before.ID); err != nil {
		return dnsprovider.Record{}, err
	}

	path, _ := p.recordPath(z, before.ID)

	if current.Type == body["type"] {
		return p.write(ctx, z, http.MethodPut, path, body, before.ID)
	}

	abs, _ := dnsprovider.QualifyName(zoneName(z), after.Name)
	if strings.EqualFold(abs, current.Name) && (current.Type == "CNAME" || body["type"] == "CNAME") {
		return p.replaceAtOwner(ctx, z, current, body, path)
	}

	r, err := p.write(ctx, z, http.MethodPost, recordsPath(z), body, "")
	if err != nil {
		return dnsprovider.Record{}, err
	}

	if err := p.api().Do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
		return r, fmt.Errorf("digitalocean: the replacement Record %s was created; deleting the original Record %s failed, and both may remain: %w", r.ID, before.ID, err)
	}

	return r, nil
}

// replaceAtOwner deletes current, then creates its replacement. When the
// replacement fails, it re-creates current, as best it can, and reports
// whether it did and under which new ID.
func (p *Provider) replaceAtOwner(ctx context.Context, z dnsprovider.Zone, current dnsprovider.Record, body map[string]any, path string) (dnsprovider.Record, error) {
	if err := p.api().Do(ctx, http.MethodDelete, path, nil, nil, nil); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("digitalocean: deleting the original Record %s failed or is unconfirmed; its replacement was not created: %w", current.ID, err)
	}

	r, err := p.write(ctx, z, http.MethodPost, recordsPath(z), body, "")
	if err == nil {
		return r, nil
	}

	failed := fmt.Errorf("digitalocean: the original Record %s was deleted; creating its replacement failed or is unconfirmed: %w", current.ID, err)

	restore, rerr := p.payload(z, current)
	if rerr == nil {
		var restored dnsprovider.Record
		if restored, rerr = p.write(ctx, z, http.MethodPost, recordsPath(z), restore, ""); rerr == nil {
			return dnsprovider.Record{}, fmt.Errorf("%w; the original was restored as Record %s", failed, restored.ID)
		}
	}

	return dnsprovider.Record{}, fmt.Errorf("%w; restoring it failed, and the original may be lost: %w", failed, rerr)
}

// DeleteRecord deletes the Record of r's ID alone.
func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	current, err := p.stored(ctx, z, r.ID)
	if err != nil {
		return err
	}

	if err := restricted(current); err != nil {
		return err
	}

	path, _ := p.recordPath(z, r.ID)

	return p.api().Do(ctx, http.MethodDelete, path, nil, nil, nil)
}
