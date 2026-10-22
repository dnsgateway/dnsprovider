package infomaniak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// writable are the Record types the adapter writes. Infomaniak takes no
// URI Records; DS, TLSA, SSHFP, DNAME and SMIMEA are read only.
var writable = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA"}

// checkWritable refuses, without a request, a Record type the adapter
// does not write.
func checkWritable(typ string) error {
	if !slices.Contains(writable, strings.ToUpper(strings.TrimSpace(typ))) {
		return fmt.Errorf("infomaniak: cannot write %s records", typ)
	}

	return nil
}

// wireWrite is a record as a create sends it. The TTL is always sent.
type wireWrite struct {
	Source string `json:"source"`
	Type   string `json:"type"`
	Target string `json:"target"`
	TTL    uint32 `json:"ttl"`
}

// prepare checks a Record to write to the Zone, before any request, and
// returns it with its wire form.
func prepare(zone string, r dnsprovider.Record) (dnsprovider.Record, wireWrite, error) {
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	if err := checkWritable(r.Type); err != nil {
		return dnsprovider.Record{}, wireWrite{}, err
	}

	name, err := dnsprovider.QualifyName(zone, r.Name)
	if err != nil {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("infomaniak: %w", err)
	}

	r.Name = names.ZoneName(name)

	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("infomaniak: %w", err)
	}

	if err := traits.TTL.Check(r.TTL); err != nil {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("infomaniak: %w", err)
	}

	w := wireWrite{Source: apex, Type: r.Type, Target: r.Value, TTL: r.TTL}
	if sub := names.RelativeName(zone, r.Name); sub != "@" {
		w.Source = sub
	}

	if i, ok := hostField[r.Type]; ok {
		if f := strings.Fields(r.Value); len(f) == i+1 {
			f[i] = bare(f[i])
			w.Target = strings.Join(f, " ")
		}
	}

	// The Record as a list reads it back, to compare with what the Zone
	// holds.
	if r.Value, err = presentation(r.Type, w.Target); err != nil {
		return dnsprovider.Record{}, wireWrite{}, fmt.Errorf("infomaniak: %w", err)
	}

	return r, w, nil
}

// apex is the source Infomaniak takes for the Zone apex, as its API
// schema and its own certbot plugin write it.
const apex = "."

// bare is a host name without its trailing dot, as Infomaniak takes it;
// the root, ".", stays as it is.
func bare(name string) string {
	if name == "." {
		return name
	}

	return strings.TrimSuffix(name, ".")
}

// CreateRecord implements dnsprovider.Provider: it adds an A, AAAA,
// CNAME, MX, TXT, NS, SRV or CAA Record with its TTL in seconds, sending
// the POST once, and returns the Record as Infomaniak stored it, with
// its native ID. A Record the Zone holds already, by SameRecord, is
// ErrConflict without a write, as are Infomaniak's own duplicate and
// mutual-exclusion refusals.
func (p *Provider) CreateRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	name, err := zoneOf(zone)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	r, w, err := prepare(name, r)
	if err != nil {
		return dnsprovider.Record{}, err
	}

	held, err := p.ListRecords(ctx, zone, dnsprovider.RecordFilter{Type: r.Type})
	if err != nil {
		return dnsprovider.Record{}, err
	}

	for _, h := range held.Records {
		if dnsprovider.SameRecord(h, r) {
			return dnsprovider.Record{}, fmt.Errorf("infomaniak: the Zone holds %s %s %q already: %w", r.Type, r.Name, r.Value, dnsprovider.ErrConflict)
		}
	}

	return p.create(ctx, name, w)
}

// create POSTs a Record to the Zone, once, and returns it as Infomaniak
// stored it.
func (p *Provider) create(ctx context.Context, zone string, w wireWrite) (dnsprovider.Record, error) {
	data, err := p.write(ctx, http.MethodPost, zonePath(zone, "records"), w)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("infomaniak: create: %w", err)
	}

	return stored(zone, "create", data)
}

// stored is the Record an answer of success holds. An answer without
// one is an Unconfirmed Write.
func stored(zone, op string, data json.RawMessage) (dnsprovider.Record, error) {
	var w wireRecord
	if err := json.Unmarshal(data, &w); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("infomaniak: %s: the answer holds no record: %w", op, dnsprovider.ErrUnconfirmed)
	}

	r, err := toRecord(zone, w)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("infomaniak: %s: %w; %w", op, err, dnsprovider.ErrUnconfirmed)
	}

	return r, nil
}

// checkID refuses, without a request, a Record without a native ID.
func checkID(op string, r dnsprovider.Record) error {
	if !positiveID(r.ID) {
		return fmt.Errorf("infomaniak: %s: the Record has no Infomaniak ID; read it from ListRecords", op)
	}

	return nil
}

// write sends a call that changes what Infomaniak holds, a record or a
// Registration's DNSSEC, and returns the data of its answer. A POST is
// sent once; a PUT or DELETE is retried within
// the shared policy. A 4xx, or an error result in an answer of success,
// is a refusal: an APIError with Infomaniak's code. A lost answer, a
// 5xx, an answer that cannot be decoded, and an asynchronous result or
// one the adapter does not know, are Unconfirmed Writes.
func (p *Provider) write(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	c := p.api()
	if method == http.MethodPost {
		c.Attempts = 1
	}

	var raw []byte
	if err := c.Write(ctx, method, path, nil, body, &raw); err != nil {
		return nil, err
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("malformed answer for %s: %w", c.Redact(path), dnsprovider.ErrUnconfirmed)
	}

	switch env.Result {
	case "success":
		return env.Data, nil
	case "error":
		return nil, c.RedactError(env.Error.apiError(0))
	}

	return nil, fmt.Errorf("result %q for %s: %w", env.Result, c.Redact(path), dnsprovider.ErrUnconfirmed)
}

// DeleteRecord implements dnsprovider.Provider: it deletes the Record by
// its native ID. A Record without one fails without a request. A Record
// Infomaniak no longer holds is ErrNotFound; a DELETE retried after a
// 5xx and then answered not-found counts as done.
func (p *Provider) DeleteRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) error {
	if err := checkWritable(r.Type); err != nil {
		return err
	}

	if err := checkID("delete", r); err != nil {
		return err
	}

	name, err := zoneOf(zone)
	if err != nil {
		return err
	}

	if _, err := p.write(ctx, http.MethodDelete, zonePath(name, "records", r.ID), nil); err != nil {
		return fmt.Errorf("infomaniak: delete: %w", err)
	}

	return nil
}
