package scaleway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

var (
	_ dnsprovider.Provider  = (*Provider)(nil)
	_ dnsprovider.Batcher   = (*Provider)(nil)
	_ dnsprovider.TTLLimits = (*Provider)(nil)
)

// TTLRange matches the current official Terraform provider validation.
func (p *Provider) TTLRange() (uint32, uint32) { return 60, 2592000 }

func (p *Provider) CreateRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Create(ctx, p, z, r)
}

func (p *Provider) UpdateRecord(ctx context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return batch.Update(ctx, p, z, before, after)
}

func (p *Provider) DeleteRecord(ctx context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	return batch.Delete(ctx, p, z, r)
}

func put(w wireRecord, key string, value any) { w[key], _ = json.Marshal(value) }

func (p *Provider) toWire(zone string, r dnsprovider.Record) (wireRecord, dnsprovider.Record, error) {
	r.Type = strings.ToUpper(r.Type)
	if !slices.Contains([]string{"A", "AAAA", "CNAME", "NS", "MX", "SRV", "TXT", "CAA"}, r.Type) {
		return nil, r, fmt.Errorf("scaleway: cannot edit %s Records", r.Type)
	}
	if len(r.Extras) > 0 {
		return nil, r, errors.New("scaleway: editing Record extras is unsupported")
	}
	var err error
	r.Name, err = dnsprovider.QualifyName(zone, r.Name)
	if err != nil {
		return nil, r, err
	}
	if err = dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return nil, r, err
	}
	if err = dnsprovider.TTLRangeOf(p).Check(r.TTL); err != nil {
		return nil, r, err
	}
	w := wireRecord{}
	put(w, "id", "planned")
	name := names.RelativeName(zone, r.Name)
	if name == "@" {
		name = ""
	}
	put(w, "name", name)
	put(w, "type", r.Type)
	put(w, "ttl", r.TTL)
	data := r.Value
	priority := uint32(0)
	switch r.Type {
	case "TXT":
		data = quoteDNS(data)
	case "CNAME", "NS":
		data = strings.TrimSuffix(data, ".") + "."
	case "MX", "SRV":
		f := strings.Fields(data)
		n, _ := strconv.ParseUint(f[0], 10, 16)
		priority = uint32(n)
		f = f[1:]
		f[len(f)-1] = strings.TrimSuffix(f[len(f)-1], ".") + "."
		data = strings.Join(f, " ")
	}
	put(w, "priority", priority)
	put(w, "data", data)
	canonical, err := w.record(zone)
	delete(w, "id")
	return w, canonical, err
}

var metadataKeys = []string{"comment", "geo_ip_config", "http_service_config", "weighted_config", "view_config"}

func preserve(w, old wireRecord, before, after dnsprovider.Record) error {
	for key := range old {
		if !slices.Contains([]string{"id", "name", "type", "data", "priority", "ttl", "updated_at"}, key) && !slices.Contains(metadataKeys, key) {
			return errors.New("scaleway: unknown Record metadata cannot be retained safely")
		}
	}
	dynamic := false
	for _, key := range metadataKeys {
		if raw, ok := old[key]; ok {
			w[key] = slices.Clone(raw)
			if key != "comment" && string(raw) != "null" {
				dynamic = true
			}
		}
	}
	if dynamic && !strings.EqualFold(before.Type, after.Type) {
		return errors.New("scaleway: a type edit cannot safely retain dynamic Record configuration")
	}
	return nil
}

type operation struct {
	Add    *addition    `json:"add,omitempty"`
	Set    *replacement `json:"set,omitempty"`
	Delete *deletion    `json:"delete,omitempty"`
}
type addition struct {
	Records []wireRecord `json:"records"`
}
type replacement struct {
	ID      string       `json:"id"`
	Records []wireRecord `json:"records"`
}
type deletion struct {
	ID string `json:"id"`
}

type plan struct {
	operations []operation
	expected   []dnsprovider.Record
	sources    []dnsprovider.Record
	initial    map[string]bool
	untouched  map[string]bool
}

func (p *Provider) plan(cs dnsprovider.Changeset, current []wireRecord) (plan, error) {
	live := make([]dnsprovider.Record, 0, len(current)+len(cs.Changes))
	raw := map[string]wireRecord{}
	for _, w := range current {
		r, err := w.record(zoneName(cs.Zone))
		if err != nil {
			return plan{}, err
		}
		if _, ok := raw[r.ID]; ok {
			return plan{}, errors.New("scaleway: repeated Record ID")
		}
		live = append(live, r)
		raw[r.ID] = w
	}
	initial := make(map[string]bool, len(raw))
	for id := range raw {
		initial[id] = true
	}
	untouched := make(map[string]bool, len(initial))
	for id := range initial {
		untouched[id] = true
	}
	out := plan{
		sources: make([]dnsprovider.Record, len(cs.Changes)), untouched: untouched, initial: initial,
		operations: make([]operation, 0, len(cs.Changes)), expected: make([]dnsprovider.Record, len(cs.Changes)),
	}
	touched := map[string]bool{}
	for _, i := range dnsprovider.ApplyOrder(cs.Changes) {
		c := cs.Changes[i]
		var before dnsprovider.Record
		if c.Kind == dnsprovider.ChangeDelete || c.Kind == dnsprovider.ChangeModify {
			at := slices.IndexFunc(live, func(r dnsprovider.Record) bool { return c.Before.ID != "" && r.ID == c.Before.ID })
			if at < 0 {
				return plan{}, fmt.Errorf("scaleway: Record missing: %w", dnsprovider.ErrNotFound)
			}
			if touched[c.Before.ID] {
				return plan{}, fmt.Errorf("scaleway: a Record is changed twice: %w", dnsprovider.ErrConflict)
			}
			touched[c.Before.ID] = true
			delete(out.untouched, c.Before.ID)
			before = live[at]
			out.sources[i] = before
			live = slices.Delete(live, at, at+1)
		}
		if c.Kind == dnsprovider.ChangeDelete {
			out.operations = append(out.operations, operation{Delete: &deletion{ID: before.ID}})
			continue
		}
		if c.Kind != dnsprovider.ChangeAdd && c.Kind != dnsprovider.ChangeModify {
			return plan{}, errors.New("scaleway: unknown change kind")
		}
		w, want, err := p.toWire(zoneName(cs.Zone), c.After)
		if err != nil {
			return plan{}, err
		}
		for _, r := range live {
			if dnsprovider.SameRecord(r, want) {
				return plan{}, fmt.Errorf("scaleway: duplicate Record: %w", dnsprovider.ErrConflict)
			}
		}
		if c.Kind == dnsprovider.ChangeModify {
			if want.Type == before.Type && want.Value == before.Value {
				w["data"] = slices.Clone(raw[before.ID]["data"])
				if priority, ok := raw[before.ID]["priority"]; ok {
					w["priority"] = slices.Clone(priority)
				}
			}
			if err = preserve(w, raw[before.ID], before, want); err != nil {
				return plan{}, err
			}
			out.operations = append(out.operations, operation{Set: &replacement{ID: before.ID, Records: []wireRecord{w}}})
		} else {
			out.operations = append(out.operations, operation{Add: &addition{Records: []wireRecord{w}}})
		}
		out.expected[i] = want
		live = append(live, want)
	}
	return out, nil
}

// ApplyChangeset sends targeted ID operations in Apply order. The API's batch
// response is not an atomicity guarantee. Missing outcomes and lost responses
// require reconciliation; additions are never retried automatically.
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}
	for i, c := range cs.Changes {
		res.Results[i].Change = c
	}
	if len(cs.Changes) == 0 {
		return res, nil
	}
	current, err := p.read(ctx, cs.Zone)
	if err != nil {
		return dnsprovider.ApplyResult{}, err
	}
	planned, err := p.plan(cs, current)
	if err != nil {
		return dnsprovider.ApplyResult{}, err
	}
	body := struct {
		Changes          []operation `json:"changes"`
		ReturnAll        bool        `json:"return_all_records"`
		DisallowCreation bool        `json:"disallow_new_zone_creation"`
	}{Changes: planned.operations, ReturnAll: true, DisallowCreation: true}
	var raw []byte
	if err = p.api().Do(ctx, http.MethodPatch, recordsPath(cs.Zone), nil, body, &raw); err != nil {
		var apiErr *dnsprovider.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return dnsprovider.ApplyResult{}, err
		}
		return dnsprovider.ApplyResult{}, unconfirmed(err)
	}
	for i := range res.Results {
		res.Results[i].Err = unconfirmed(errors.New("scaleway: change outcome requires readback"))
	}
	var answer struct {
		Records []wireRecord `json:"records"`
	}
	if json.Unmarshal(raw, &answer) != nil {
		answer.Records = nil
	}
	if answer.Records == nil || !mapResults(cs, planned, answer.Records, &res) {
		read, readErr := p.read(ctx, cs.Zone)
		if readErr != nil {
			return res, unconfirmed(readErr)
		}
		if !mapResults(cs, planned, read, &res) {
			return res, unconfirmed(errors.New("scaleway: not every batch change was confirmed"))
		}
	}
	return res, nil
}

func mapResults(cs dnsprovider.Changeset, p plan, stored []wireRecord, res *dnsprovider.ApplyResult) bool {
	byID := map[string]dnsprovider.Record{}
	all := make([]dnsprovider.Record, 0, len(stored))
	for _, w := range stored {
		r, err := w.record(zoneName(cs.Zone))
		if err != nil {
			return false
		}
		if _, ok := byID[r.ID]; ok {
			return false
		}
		byID[r.ID] = r
		all = append(all, r)
	}
	complete := true
	for id := range p.untouched {
		if _, ok := byID[id]; !ok {
			complete = false
		}
	}
	claimed := map[string]bool{}
	for i, c := range cs.Changes {
		result := &res.Results[i]
		result.Record = dnsprovider.Record{}
		result.Err = nil
		if c.Kind == dnsprovider.ChangeDelete {
			if _, ok := byID[c.Before.ID]; !ok {
				continue
			}
		} else {
			matches := make([]dnsprovider.Record, 0, 1)
			for _, r := range all {
				if claimed[r.ID] || !sameOutcomeRecord(r, p.expected[i]) {
					continue
				}
				if c.Kind == dnsprovider.ChangeAdd && p.initial[r.ID] {
					continue
				}
				if c.Kind == dnsprovider.ChangeModify {
					before := p.sources[i]
					if r.ID != before.ID {
						if _, oldRemains := byID[before.ID]; oldRemains {
							continue
						}
					}
					if r.ID == before.ID && sameOutcomeRecord(r, before) && p.expected[i].TTL != before.TTL && r.TTL == before.TTL {
						continue
					}
				}
				matches = append(matches, r)
			}
			if len(matches) == 1 {
				result.Record = matches[0]
				claimed[matches[0].ID] = true
				continue
			}
		}
		result.Err = unconfirmed(errors.New("scaleway: change was not confirmed in returned Records"))
		complete = false
	}
	return complete
}

func unconfirmed(err error) error {
	return fmt.Errorf("scaleway: mutation may have completed; re-read Records before retrying: %w", err)
}

// sameOutcomeRecord reconciles equivalent stored Values without changing the
// shared duplicate contract or the authoritative representation returned.
func sameOutcomeRecord(a, b dnsprovider.Record) bool {
	av, bv := a.Value, b.Value
	a.Value, b.Value = "", ""
	if !dnsprovider.SameRecord(a, b) {
		return false
	}
	if av == bv {
		return true
	}
	switch strings.ToUpper(a.Type) {
	case "CAA":
		af, at, ap, ae := caaOutcomeValue(av)
		bf, bt, bp, be := caaOutcomeValue(bv)
		return ae == nil && be == nil && af == bf && strings.EqualFold(at, bt) && ap == bp
	case "CNAME", "NS":
		return sameTarget(av, bv)
	case "MX", "SRV":
		af, bf := strings.Fields(av), strings.Fields(bv)
		count := 2
		if strings.EqualFold(a.Type, "SRV") {
			count = 4
		}
		if len(af) != count || len(bf) != count {
			return false
		}
		for i := range count - 1 {
			an, ae := strconv.ParseUint(af[i], 10, 16)
			bn, be := strconv.ParseUint(bf[i], 10, 16)
			if ae != nil || be != nil || an != bn {
				return false
			}
		}
		return sameTarget(af[count-1], bf[count-1])
	case "A", "AAAA":
		aa, ae := netip.ParseAddr(av)
		ba, be := netip.ParseAddr(bv)
		return ae == nil && be == nil && aa == ba
	}
	return false
}

func sameTarget(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// caaOutcomeValue compares presentation syntax while retaining payload bytes,
// including case. Quoted strings use the same DNS escape parser as TXT reads.
func caaOutcomeValue(value string) (uint64, string, string, error) {
	rest := strings.TrimSpace(value)
	var tokens [2]string
	for i := range tokens {
		cut := strings.IndexFunc(rest, unicode.IsSpace)
		if cut < 1 {
			return 0, "", "", errors.New("scaleway: malformed CAA outcome")
		}
		tokens[i] = rest[:cut]
		rest = strings.TrimSpace(rest[cut:])
	}
	flags, err := strconv.ParseUint(tokens[0], 10, 8)
	if err != nil || rest == "" {
		return 0, "", "", errors.New("scaleway: malformed CAA outcome")
	}
	if strings.HasPrefix(rest, `"`) {
		rest, err = unquoteDNS(rest)
	}
	return flags, tokens[1], rest, err
}
