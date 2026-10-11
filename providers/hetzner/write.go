package hetzner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/batch"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

var (
	_ dnsprovider.Provider = (*Provider)(nil)
	_ dnsprovider.Batcher  = (*Provider)(nil)
)

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

func rrFor(z wireZone, r dnsprovider.Record) wireRRset {
	return wireRRset{Name: names.RelativeName(names.ZoneName(z.Name), r.Name), Type: r.Type, Records: []wireValue{}}
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

type plannedValue struct {
	wire      wireValue
	ttl       uint32
	inherited bool
}
type plannedSet struct {
	before  wireRRset
	exists  bool
	values  []plannedValue
	indices []int
}

func addIndex(s *plannedSet, i int) {
	if !slices.Contains(s.indices, i) {
		s.indices = append(s.indices, i)
	}
}

func findValue(s *plannedSet, value, zone string) int {
	for i, v := range s.values {
		if charstr.Equivalent(s.before.Type, readValue(zone, s.before.Type, v.wire.Value), value) {
			return i
		}
	}
	return -1
}

type batchPlan struct {
	zone    wireZone
	sets    map[string]*plannedSet
	order   []string
	targets []dnsprovider.Record
}

func newPlan(z wireZone, sets []wireRRset, n int) *batchPlan {
	plan := &batchPlan{zone: z, sets: map[string]*plannedSet{}, targets: make([]dnsprovider.Record, n)}
	for _, w := range sets {
		s := &plannedSet{before: w, exists: true}
		for _, v := range w.Records {
			s.values = append(s.values, plannedValue{wire: v, ttl: effectiveTTL(z, w), inherited: w.TTL == nil})
		}
		plan.sets[rrkey(w)] = s
	}
	return plan
}

func (b *batchPlan) get(r dnsprovider.Record) *plannedSet {
	w := rrFor(b.zone, r)
	key := rrkey(w)
	s := b.sets[key]
	if s == nil {
		s = &plannedSet{before: w}
		b.sets[key] = s
	}
	if !slices.Contains(b.order, key) {
		b.order = append(b.order, key)
	}
	return s
}

func (b *batchPlan) change(i int, c dnsprovider.Change) error {
	if c.Kind != dnsprovider.ChangeAdd && c.Kind != dnsprovider.ChangeModify && c.Kind != dnsprovider.ChangeDelete {
		return fmt.Errorf("hetzner: unknown change kind %d", c.Kind)
	}
	var source *plannedSet
	sourceIndex := -1
	var original wireValue
	inherited := false
	if c.Kind != dnsprovider.ChangeAdd {
		before, err := normalized(b.zone, c.Before, false)
		if err != nil {
			return err
		}
		source = b.get(before)
		sourceIndex = findValue(source, before.Value, b.zone.Name)
		if sourceIndex < 0 {
			return dnsprovider.ErrNotFound
		}
		if err := restriction(source.before); err != nil {
			return err
		}
		original = source.values[sourceIndex].wire
		inherited = source.values[sourceIndex].inherited
	}
	var target *plannedSet
	var after dnsprovider.Record
	if c.Kind != dnsprovider.ChangeDelete {
		var err error
		after, err = normalized(b.zone, c.After, true)
		if err != nil {
			return err
		}
		target = b.get(after)
		if err := restriction(target.before); err != nil {
			return err
		}
		duplicate := findValue(target, after.Value, b.zone.Name)
		if duplicate >= 0 && !(source == target && duplicate == sourceIndex) {
			return dnsprovider.ErrConflict
		}
		b.targets[i] = after
	}
	if source != nil {
		source.values = slices.Delete(source.values, sourceIndex, sourceIndex+1)
		addIndex(source, i)
	}
	if target != nil {
		// Preserve the selected value's comment and carry source labels to a
		// newly created destination; existing destination metadata stays put.
		original.Value = after.Value
		if !target.exists && len(target.values) == 0 && source != nil {
			target.before.Labels = source.before.Labels
		}
		target.values = append(target.values, plannedValue{wire: original, ttl: after.TTL, inherited: inherited && after.TTL == b.zone.TTL})
		addIndex(target, i)
	}
	return nil
}

func (b *batchPlan) validate() error {
	for _, key := range b.order {
		s := b.sets[key]
		if len(s.indices) == 0 {
			continue
		}
		if len(s.values) > 50 {
			return fmt.Errorf("hetzner: RRset %s exceeds the 50-value write limit", key)
		}
		for _, v := range s.values {
			if v.ttl != s.values[0].ttl {
				return fmt.Errorf("hetzner: conflicting final TTLs in RRset %s; include every remaining sibling with the same TTL", key)
			}
		}
	}
	return nil
}

func (b *batchPlan) component(key string) ([]string, []int) {
	component := []string{key}
	indices := []int{}
	for pos := 0; pos < len(component); pos++ {
		for _, i := range b.sets[component[pos]].indices {
			if !slices.Contains(indices, i) {
				indices = append(indices, i)
			}
		}
		for _, other := range b.order {
			if slices.Contains(component, other) {
				continue
			}
			for _, i := range b.sets[other].indices {
				if slices.Contains(indices, i) {
					component = append(component, other)
					break
				}
			}
		}
	}
	slices.SortFunc(component, func(a, c string) int { return slices.Index(b.order, a) - slices.Index(b.order, c) })
	return component, indices
}

// ApplyChangeset plans final shared TTLs and groups source/destination
// RRsets before any write. Apply supplies the common stale-before check.
// Grouping reduces requests; it does not promise atomicity or rollback.
func (p *Provider) ApplyChangeset(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}
	for i, c := range cs.Changes {
		res.Results[i].Change = c
	}
	if len(cs.Changes) == 0 {
		return res, nil
	}
	z, sets, err := p.snapshot(ctx, cs.Zone)
	if err != nil {
		return res, err
	}
	if z.Mode != "primary" {
		return res, errors.New("hetzner: Records can only be changed in primary Zones")
	}
	plan := newPlan(z, sets, len(cs.Changes))
	for _, i := range dnsprovider.ApplyOrder(cs.Changes) {
		res.Results[i].Err = plan.change(i, cs.Changes[i])
	}
	// Untouched siblings participate in shared TTL validation. Reject the
	// entire conflicting plan before submitting any native mutation.
	if err := plan.validate(); err != nil {
		return res, err
	}
	visited := map[string]bool{}
	for _, key := range plan.order {
		if visited[key] || len(plan.sets[key].indices) == 0 {
			continue
		}
		component, indices := plan.component(key)
		for _, k := range component {
			visited[k] = true
		}
		p.completeGroup(ctx, cs.Zone, plan, component, indices, &res)
	}
	return res, nil
}

func (p *Provider) completeGroup(ctx context.Context, z dnsprovider.Zone, plan *batchPlan, component []string, indices []int, res *dnsprovider.ApplyResult) {
	var failure error
	wrote := false
	for _, k := range component {
		s := plan.sets[k]
		if changed(s, plan.zone) {
			wrote = true
			failure = p.writeSet(ctx, plan.zone, s)
			if failure != nil {
				break
			}
		}
	}
	var records []dnsprovider.Record
	if failure == nil && wrote {
		stored, err := p.ListRecords(ctx, z, dnsprovider.RecordFilter{})
		if err != nil {
			failure = uncertain("read-back", err)
		} else {
			res.Serial = stored.Serial
			records = stored.Records
			failure = plan.verify(component, records)
		}
	} else if failure == nil {
		for _, k := range component {
			rs, _ := expand(plan.zone, plan.sets[k].before)
			records = append(records, rs...)
		}
	}
	if failure == nil {
		failure = plan.results(indices, records, res)
	}
	if failure != nil {
		if wrote {
			failure = fmt.Errorf("hetzner: RRset group may have partial side effects: %w", failure)
		}
		for _, i := range indices {
			res.Results[i].Err = failure
			res.Results[i].Record = dnsprovider.Record{}
		}
	}
}

func (b *batchPlan) verify(component []string, records []dnsprovider.Record) error {
	for _, key := range component {
		s := b.sets[key]
		stored := []dnsprovider.Record{}
		for _, r := range records {
			if rrkey(rrFor(b.zone, r)) == key {
				stored = append(stored, r)
			}
		}
		if len(stored) != len(s.values) {
			return uncertain("read-back", fmt.Errorf("RRset %s does not contain its planned values", key))
		}
		for _, v := range s.values {
			found := false
			for _, r := range stored {
				if charstr.Equivalent(s.before.Type, readValue(b.zone.Name, s.before.Type, v.wire.Value), r.Value) && v.ttl == r.TTL {
					found = true
					break
				}
			}
			if !found {
				return uncertain("read-back", fmt.Errorf("RRset %s differs from its planned values or TTL", key))
			}
		}
	}
	return nil
}

func (b *batchPlan) results(indices []int, records []dnsprovider.Record, res *dnsprovider.ApplyResult) error {
	for _, i := range indices {
		if res.Results[i].Change.Kind == dnsprovider.ChangeDelete {
			continue
		}
		found := false
		for _, r := range records {
			target := b.targets[i]
			if r.Type == target.Type && r.Name == target.Name && r.TTL == target.TTL && charstr.Equivalent(r.Type, r.Value, target.Value) {
				res.Results[i].Record = r
				found = true
				break
			}
		}
		if !found {
			return uncertain("read-back", errors.New("stored Record is missing"))
		}
	}
	return nil
}

func changed(s *plannedSet, z wireZone) bool {
	if !s.exists {
		return len(s.values) > 0
	}
	if len(s.values) != len(s.before.Records) {
		return true
	}
	after := make([]wireValue, len(s.values))
	for i, v := range s.values {
		after[i] = v.wire
		if v.ttl != effectiveTTL(z, s.before) {
			return true
		}
	}
	return !sameNativeValues(s.before.Records, after)
}

type wireAction struct {
	ID     int64                           `json:"id"`
	Status string                          `json:"status"`
	Error  *struct{ Code, Message string } `json:"error"`
}

func uncertain(operation string, err error) error {
	return fmt.Errorf("hetzner: %s completion is unconfirmed; re-read Records before retrying: %w", operation, err)
}

func (p *Provider) action(ctx context.Context, method, path string, body any) error {
	var answer struct {
		Action *wireAction `json:"action"`
	}
	api := p.api()
	// Deletes also start asynchronous actions: the acknowledgement must
	// never be resubmitted after an uncertain HTTP response.
	api.Attempts = 1
	if err := api.Do(ctx, method, path, nil, body, &answer); err != nil {
		var e *dnsprovider.APIError
		if errors.As(err, &e) && e.StatusCode >= 400 && e.StatusCode < 500 {
			return err
		}
		return uncertain("action request", err)
	}
	if answer.Action == nil || answer.Action.ID <= 0 {
		return uncertain("action request", errors.New("malformed action acknowledgement"))
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
			return &dnsprovider.APIError{Provider: "hetzner", Messages: []string{p.redact(msg)}, Kind: kind}
		case "running":
		default:
			return uncertain("action", errors.New("invalid action status"))
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return uncertain("action", waitCtx.Err())
		case <-timer.C:
		}
		var poll struct {
			Action *wireAction `json:"action"`
		}
		if err := p.api().Do(waitCtx, http.MethodGet, "/zones/actions/"+strconv.FormatInt(a.ID, 10), nil, nil, &poll); err != nil {
			return uncertain("action poll", err)
		}
		if poll.Action == nil || poll.Action.ID != a.ID {
			return uncertain("action poll", errors.New("malformed action response"))
		}
		a = poll.Action
	}
}

func (p *Provider) writeSet(ctx context.Context, z wireZone, s *plannedSet) error {
	w := s.before
	values := make([]wireValue, len(s.values))
	for i, v := range s.values {
		values[i] = v.wire
	}
	if len(values) == 0 {
		return p.action(ctx, http.MethodDelete, rrPath(z, w), nil)
	}
	ttl := s.values[0].ttl
	if !s.exists {
		body := map[string]any{"name": w.Name, "type": w.Type, "ttl": ttl, "records": values}
		// New sets inherit only when every final value came from an unchanged
		// inherited source. Additions and mixed explicit sources stay explicit.
		if !slices.ContainsFunc(s.values, func(v plannedValue) bool { return !v.inherited }) {
			body["ttl"] = nil
		}
		if w.Labels != nil {
			body["labels"] = w.Labels
		}
		return p.action(ctx, http.MethodPost, zonePath(z)+"/rrsets", body)
	}
	if ttl != effectiveTTL(z, w) {
		if err := p.action(ctx, http.MethodPost, rrPath(z, w)+"/actions/change_ttl", map[string]any{"ttl": ttl}); err != nil {
			return err
		}
	}
	if !sameNativeValues(w.Records, values) {
		return p.action(ctx, http.MethodPost, rrPath(z, w)+"/actions/set_records", map[string]any{"records": values})
	}
	return nil
}

// sameNativeValues compares unordered native values including comments without
// reordering the original slices used to preserve RRset metadata.
func sameNativeValues(a, b []wireValue) bool {
	before := slices.Clone(a)
	after := slices.Clone(b)
	cmp := func(a, b wireValue) int { return strings.Compare(a.Value, b.Value) }
	slices.SortFunc(before, cmp)
	slices.SortFunc(after, cmp)
	return reflect.DeepEqual(before, after)
}
