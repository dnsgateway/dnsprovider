package hetzner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/internal/rrset"
)

var _ dnsprovider.Provider = (*Provider)(nil)

// ttlRange is the TTL policy used by Record writes and reported by
// its Traits: Hetzner's documented numeric TTL range. Inheritance is
// reported as its effective numeric TTL and is not automatic TTL.
var ttlRange = dnsprovider.TTLRange{Min: 60, Max: 2147483647}

func normalizeValue(typ, value string) string {
	switch typ {
	case "A", "AAAA":
		if a, err := netip.ParseAddr(value); err == nil {
			return a.String()
		}
	case "TXT":
		if !strings.HasPrefix(value, `"`) {
			return charstr.Quote(value)
		}
	case "CNAME", "NS":
		if value != "." {
			return strings.ToLower(strings.TrimSuffix(value, ".")) + "."
		}
	case "MX", "SRV":
		f := strings.Fields(value)
		if len(f) > 0 {
			count := 1
			if typ == "SRV" {
				count = 3
			}
			for i := 0; i < count && i < len(f); i++ {
				if n, err := strconv.ParseUint(f[i], 10, 16); err == nil {
					f[i] = strconv.FormatUint(n, 10)
				}
			}
			last := len(f) - 1
			if f[last] != "." {
				f[last] = strings.ToLower(strings.TrimSuffix(f[last], ".")) + "."
			}
			return strings.Join(f, " ")
		}
	}
	return value
}

func normalized(z wireZone, r dnsprovider.Record, validate bool) (dnsprovider.Record, error) {
	r.Type = strings.ToUpper(r.Type)
	name, err := dnsprovider.QualifyName(names.ZoneName(z.Name), r.Name)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	r.Name = strings.ToLower(name)
	if validate {
		if !slices.Contains([]string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT"}, r.Type) {
			return dnsprovider.Record{}, fmt.Errorf("hetzner: unsupported editable type %s", r.Type)
		}
		if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
			return dnsprovider.Record{}, err
		}
		if err := ttlRange.Check(r.TTL); err != nil {
			return dnsprovider.Record{}, err
		}
	}
	r.Value = normalizeValue(r.Type, r.Value)
	return r, nil
}

func restriction(w wireRRset) error {
	if w.Protection.Change {
		return fmt.Errorf("hetzner: RRset %s is protected; protection must be changed explicitly", rrkey(w))
	}
	if w.Type == "SOA" {
		return fmt.Errorf("hetzner: RRset %s is managed by the service", rrkey(w))
	}
	return nil
}

// CreateRecord adds one value while preserving all RRset siblings.
func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Create(ctx, p, z, r)
}

// UpdateRecord finds before by content, retaining provider metadata.
func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Update(ctx, p, z, before, after)
}

// DeleteRecord removes only the selected value, deleting an empty RRset.
func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	return batch.Delete(ctx, p, z, r)
}

// writer is the rrset.Adapter of one primary Zone.
type writer struct {
	p    *Provider
	zone wireZone
}

// planned is the Wire of a value: as Hetzner holds or will hold it,
// whether it inherits the Zone's default TTL, and, for a moved value, the
// labels of the RRset it leaves.
type planned struct {
	wire      wireValue
	inherited bool
	labels    map[string]string
}

// setWire is the Wire of an RRset: as Hetzner holds it.
type setWire struct {
	rrset wireRRset
}

// sets are a Zone's RRsets as rrset.Apply plans from them.
func sets(z wireZone, read []wireRRset) []rrset.Set {
	out := make([]rrset.Set, 0, len(read))
	for _, w := range read {
		rs, _ := expand(z, w)
		s := rrset.Set{Key: rrset.Key{Name: strings.ToLower(names.AbsoluteName(names.ZoneName(z.Name), w.Name)), Type: strings.ToUpper(w.Type)}, TTL: effectiveTTL(z, w), Wire: setWire{w}}
		for i, v := range w.Records {
			s.Values = append(s.Values, rrset.Value{Record: rs[i], Wire: planned{wire: v, inherited: w.TTL == nil}})
		}
		out = append(out, s)
	}
	return out
}

func (w writer) Name() string { return "hetzner" }

func (w writer) Normalize(r dnsprovider.Record, after bool) (dnsprovider.Record, error) {
	return normalized(w.zone, r, after)
}

func (w writer) Same(typ, a, b string) bool { return charstr.Equivalent(typ, a, b) }

func (w writer) Writable(s *rrset.Set) error {
	if s == nil {
		return nil
	}
	return restriction(s.Wire.(setWire).rrset)
}

// Wire keeps the comment of the value a modification replaces. A moved
// value keeps inheriting the Zone's default TTL while its TTL stays it,
// and carries its RRset's labels to a destination it creates.
func (w writer) Wire(after dnsprovider.Record, from *rrset.Value, fromSet *rrset.Set) any {
	v := planned{wire: wireValue{Value: after.Value}}
	if from != nil {
		source := from.Wire.(planned)
		v.wire.Comment = source.wire.Comment
		v.inherited = source.inherited && after.TTL == w.zone.TTL
	}
	if fromSet != nil {
		v.labels = fromSet.Wire.(setWire).rrset.Labels
	}
	return v
}

// Write changes the RRset's TTL, then adds values with add_records, which
// creates a missing RRset, then removes values with remove_records, which
// deletes an emptied one. Each call names only the Delta's own values.
func (w writer) Write(ctx context.Context, d rrset.Delta) error {
	rr := wireRRset{Name: names.RelativeName(names.ZoneName(w.zone.Name), d.Key.Name), Type: d.Key.Type}
	if d.Set != nil {
		rr = d.Set.Wire.(setWire).rrset
	}
	path := rrPath(w.zone, rr)
	if d.TTLChanged {
		if err := w.p.action(ctx, http.MethodPost, path+"/actions/change_ttl", map[string]any{"ttl": d.TTL}); err != nil {
			return err
		}
	}
	if len(d.Add) > 0 {
		if err := w.add(ctx, d, rr, path); err != nil {
			return err
		}
	}
	for chunk := range slices.Chunk(d.Remove, maxValues) {
		if err := w.p.action(ctx, http.MethodPost, path+"/actions/remove_records", map[string]any{"records": wireValues(chunk)}); err != nil {
			return err
		}
	}
	return nil
}

// maxValues is the most values one add_records or remove_records takes.
const maxValues = 50

// add adds the Delta's values. The TTL is left out, keeping inheritance,
// when the RRset inherits the Zone's default and keeps doing so, or when a
// new RRset holds only moved values that inherited it.
//
// add_records cannot set labels: a move that creates its destination
// creates it with POST, carrying the source's labels, and adds to it as
// usual when another writer created it first.
func (w writer) add(ctx context.Context, d rrset.Delta, rr wireRRset, path string) error {
	var ttl any = d.TTL
	switch {
	case d.Set != nil && rr.TTL == nil && !d.TTLChanged:
		ttl = nil
	case d.Set == nil && !slices.ContainsFunc(d.Add, func(v rrset.Value) bool { return !v.Wire.(planned).inherited }):
		ttl = nil
	}
	if d.Set == nil && len(d.Add) <= maxValues {
		if at := slices.IndexFunc(d.Add, func(v rrset.Value) bool { return v.Wire.(planned).labels != nil }); at >= 0 {
			body := map[string]any{"name": rr.Name, "type": rr.Type, "ttl": ttl, "records": wireValues(d.Add), "labels": d.Add[at].Wire.(planned).labels}
			err := w.p.action(ctx, http.MethodPost, zonePath(w.zone)+"/rrsets", body)
			var created *dnsprovider.APIError
			if !errors.As(err, &created) || !errors.Is(err, dnsprovider.ErrConflict) {
				return err
			}
		}
	}
	for chunk := range slices.Chunk(d.Add, maxValues) {
		body := map[string]any{"records": wireValues(chunk)}
		if ttl != nil {
			body["ttl"] = ttl
		}
		if err := w.p.action(ctx, http.MethodPost, path+"/actions/add_records", body); err != nil {
			return err
		}
	}
	return nil
}

func wireValues(vs []rrset.Value) []wireValue {
	out := make([]wireValue, len(vs))
	for i, v := range vs {
		out[i] = v.Wire.(planned).wire
	}
	return out
}

// ReadBack reads the whole Zone: Hetzner lists RRsets only per Zone.
func (w writer) ReadBack(ctx context.Context, _ []rrset.Key) (dnsprovider.RecordSet, error) {
	return w.p.ListRecords(ctx, dnsprovider.Zone{ID: strconv.FormatInt(w.zone.ID, 10), Name: names.ZoneName(w.zone.Name)}, dnsprovider.RecordFilter{})
}

// ApplyChangeset writes only the values each change names: add_records
// and remove_records, never a replacement of the whole RRset, so a
// concurrent Changeset on the same RRset keeps its values. The RRset's
// TTL and protection stay last-writer-wins. Apply supplies the common
// stale-before check. Groups of RRsets a move joins are not atomic.
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	if len(cs.Changes) == 0 {
		return dnsprovider.ApplyResult{Results: []dnsprovider.ChangeResult{}}, nil
	}
	z, read, err := p.snapshot(ctx, cs.Zone)
	if err != nil {
		res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}
		for i, c := range cs.Changes {
			res.Results[i].Change = c
		}
		return res, err
	}
	return rrset.Apply(ctx, writer{p: p, zone: z}, cs, sets(z, read))
}

type wireAction struct {
	ID     int64                           `json:"id"`
	Status string                          `json:"status"`
	Error  *struct{ Code, Message string } `json:"error"`
}

func (p *Provider) action(ctx context.Context, method, path string, body any) error {
	var answer struct {
		Action *wireAction `json:"action"`
	}
	api := p.api()
	// Deletes also start asynchronous actions: the acknowledgement must
	// never be resubmitted after an unconfirmed HTTP response.
	api.Attempts = 1
	if err := api.Write(ctx, method, path, nil, body, &answer); err != nil {
		return err
	}
	if answer.Action == nil || answer.Action.ID <= 0 {
		return dnsprovider.Unconfirmed(errors.New("hetzner: malformed action acknowledgement"))
	}
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	a := answer.Action
	for {
		switch a.Status {
		case "success":
			return nil
		case "error":
			msg := "action failed"
			var kind error
			if a.Error != nil {
				msg = a.Error.Code + ": " + a.Error.Message
				kind = errorKind(a.Error.Code)
			}
			return &dnsprovider.APIError{Provider: "hetzner", Messages: []string{api.Redact(msg)}, Kind: kind}
		case "running":
		default:
			return dnsprovider.Unconfirmed(errors.New("hetzner: invalid action status"))
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return dnsprovider.Unconfirmed(fmt.Errorf("hetzner: action: %w", waitCtx.Err()))
		case <-timer.C:
		}
		var poll struct {
			Action *wireAction `json:"action"`
		}
		if err := p.api().Do(waitCtx, http.MethodGet, "/zones/actions/"+strconv.FormatInt(a.ID, 10), nil, nil, &poll); err != nil {
			// The action was acknowledged: even a refused poll leaves it
			// unconfirmed.
			return fmt.Errorf("hetzner: action poll: %w; %w", err, dnsprovider.ErrUnconfirmed)
		}
		if poll.Action == nil || poll.Action.ID != a.ID {
			return dnsprovider.Unconfirmed(errors.New("hetzner: malformed action response"))
		}
		a = poll.Action
	}
}
