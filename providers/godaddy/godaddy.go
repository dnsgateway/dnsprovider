// Package godaddy is the GoDaddy Provider, on the v1 Domains API over
// plain net/http: GoDaddy has no maintained Go SDK.
package godaddy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// DefaultBaseURL is the GoDaddy production API.
const DefaultBaseURL = "https://api.godaddy.com"

// DefaultRequestTimeout bounds each request to the GoDaddy API.
const DefaultRequestTimeout = 30 * time.Second

// domainsPerPage is the largest page GoDaddy serves for domains.
var domainsPerPage = 1000

// Config is a GoDaddy Account's credentials.
type Config struct {
	// Key is the API key. Required.
	Key string
	// Secret is the API secret. Required.
	Secret string
}

// Field names in Factory's field map.
const (
	FieldKey    = "key"
	FieldSecret = "secret"
)

// Factory builds the GoDaddy Provider from a field map, for a
// dnsprovider.Registry.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{
		{Name: FieldKey, Label: "API key", Secret: true},
		{Name: FieldSecret, Label: "API secret", Secret: true},
	}

	return fields.Factory("godaddy", fs, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Key: m[FieldKey], Secret: m[FieldSecret]}, opts...)
	})
}

// New builds the GoDaddy Provider for an Account, without a network call.
// Without WithBaseURL it talks to DefaultBaseURL; without WithHTTPClient
// each request times out after DefaultRequestTimeout.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if cfg.Key == "" || cfg.Secret == "" {
		return nil, errors.New("godaddy: the API key and secret are both required")
	}

	if strings.Contains(cfg.Key, ":") {
		return nil, errors.New("godaddy: the API key holds a colon")
	}

	o := dnsprovider.NewOptions(opts...)

	baseURL := o.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultRequestTimeout}
	}

	return &Provider{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		auth:    "sso-key " + cfg.Key + ":" + cfg.Secret,
		client:  client,
		limit:   rest.PerMinute(RequestsPerMinute),
		log:     o.Logger,
	}, nil
}

// RequestsPerMinute is GoDaddy's published rate limit for an Account.
const RequestsPerMinute = 60

// Provider is one GoDaddy Account.
type Provider struct {
	baseURL string
	auth    string
	client  *http.Client
	limit   *rate.Limiter
	log     *slog.Logger
}

// api is the Account's rest.Client. It is built per call so a Provider
// holds plain values alone, and two built alike are equal.
func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "godaddy",
		BaseURL:  p.baseURL,
		HTTP:     p.client,
		Auth:     func(r *http.Request) { r.Header.Set("Authorization", p.auth) },
		Limit:    p.limit,
		Decode:   apiError,
		Log:      p.log,
	}
}

var (
	_ dnsprovider.Provider  = (*Provider)(nil)
	_ dnsprovider.TTLLimits = (*Provider)(nil)
)

// TTLRange implements dnsprovider.TTLLimits: a GoDaddy TTL is at least 600
// seconds.
func (p *Provider) TTLRange() (minTTL, maxTTL uint32) {
	return 600, 86400
}

// wireDomain is the part of a v1 domain that the adapter reads.
type wireDomain struct {
	Domain      string   `json:"domain"`
	NameServers []string `json:"nameServers"`
}

// Zones implements dnsprovider.Provider: every ACTIVE domain of the Account.
func (p *Provider) Zones(ctx context.Context) ([]dnsprovider.Zone, error) {
	all, err := p.listDomains(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]dnsprovider.Zone, 0, len(all))
	for _, d := range all {
		out = append(out, dnsprovider.Zone{Name: d.Domain, ID: d.Domain, Nameservers: goDaddyNameservers(d.NameServers)})
	}

	return out, nil
}

// nameserverSuffix ends the name of every GoDaddy DNS nameserver.
const nameserverSuffix = ".domaincontrol.com"

// goDaddyNameservers are a domain's nameservers, in lower case, when they
// are all GoDaddy's. A domain delegated elsewhere, even in part, has none:
// its registration names nameservers GoDaddy does not run, and the Account
// expects the ones Nameservers lists.
func goDaddyNameservers(ns []string) []string {
	if len(ns) == 0 {
		return nil
	}

	out := make([]string, 0, len(ns))
	for _, n := range ns {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !strings.HasSuffix(n, nameserverSuffix) {
			return nil
		}

		out = append(out, n)
	}

	return out
}

// listDomains reads every page of the Account's ACTIVE domains. A page
// starts after the marker, the last domain of the page before.
func (p *Provider) listDomains(ctx context.Context) ([]wireDomain, error) {
	domains, err := rest.Pages(domainsPerPage, func(d wireDomain) string { return d.Domain }, func(pg rest.Page) ([]wireDomain, error) {
		q := url.Values{
			"statuses": {"ACTIVE"},
			"includes": {"nameServers"},
			"limit":    {strconv.Itoa(pg.Size)},
		}

		if pg.Marker != "" {
			q.Set("marker", pg.Marker)
		}

		var page []wireDomain

		return page, p.api().Do(ctx, http.MethodGet, "/v1/domains", q, nil, &page)
	})
	if errors.Is(err, rest.ErrSamePage) {
		return nil, fmt.Errorf("godaddy: the domain list: %w", err)
	}

	return domains, err
}

// recordsPerPage is the largest page GoDaddy serves for records.
var recordsPerPage = 500

// wireRecord is a v1 DNS record. Its name is relative to the domain, "@"
// for the apex. An SRV record's owner name is its service, protocol and
// name; its target is the data.
type wireRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	TTL      uint32 `json:"ttl"`
	Priority uint32 `json:"priority,omitempty"`
	Weight   uint32 `json:"weight,omitempty"`
	Port     uint32 `json:"port,omitempty"`
	Service  string `json:"service,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// Records implements dnsprovider.Provider. GoDaddy reports no SOA serial:
// A consumer asks the Zone's nameservers for it.
func (p *Provider) Records(ctx context.Context, zone dnsprovider.Zone) (dnsprovider.RecordSet, error) {
	all, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	records := make([]dnsprovider.Record, 0, len(all))
	for _, w := range all {
		records = append(records, toRecord(zone.Name, w))
	}

	return dnsprovider.RecordSet{Records: records}, nil
}

// listRecords reads every page of a domain's records. The offset is the
// page, from 1; GoDaddy answers a page past the last one with 422.
func (p *Provider) listRecords(ctx context.Context, zone dnsprovider.Zone) ([]wireRecord, error) {
	path := "/v1/domains/" + url.PathEscape(zone.ID) + "/records"

	records, err := rest.Pages(recordsPerPage, nil, func(pg rest.Page) ([]wireRecord, error) {
		q := url.Values{"offset": {strconv.Itoa(pg.Number)}, "limit": {strconv.Itoa(pg.Size)}}

		var page []wireRecord

		err := p.api().Do(ctx, http.MethodGet, path, q, nil, &page)

		var apiErr *dnsprovider.APIError
		if pg.Number > 1 && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnprocessableEntity {
			return nil, nil
		}

		return page, err
	})
	if errors.Is(err, rest.ErrSamePage) {
		return nil, fmt.Errorf("godaddy: the records of %s: %w", zone.Name, err)
	}

	return records, err
}

// toRecord turns a v1 record into a Record of a Zone, with an absolute
// name and its Value in presentation form: the MX and SRV priority first.
func toRecord(zone string, w wireRecord) dnsprovider.Record {
	name := w.Name
	if w.Type == "SRV" && w.Service != "" && w.Protocol != "" {
		name = underscore(w.Service) + "." + underscore(w.Protocol) + "." + name
	}

	rec := dnsprovider.Record{Type: w.Type, Name: names.AbsoluteName(zone, name), Value: w.Data, TTL: w.TTL}

	// GoDaddy writes a target at the Zone apex as "@".
	target := w.Data
	if target == "@" {
		target = zone
	}

	switch w.Type {
	case "CNAME", "NS":
		rec.Value = target
	case "MX":
		rec.Value = fmt.Sprintf("%d %s", w.Priority, target)
	case "SRV":
		rec.Value = fmt.Sprintf("%d %d %d %s", w.Priority, w.Weight, w.Port, target)
	}

	return withID(rec)
}

// withID gives a Record its Provider ID. GoDaddy has no record IDs, so
// the ID is what tells a Record apart in its RRset: its type, name, TTL
// and Value, as Apply matches it.
func withID(r dnsprovider.Record) dnsprovider.Record {
	r.ID = fmt.Sprintf("%s %s %d %s", r.Type, strings.ToLower(r.Name), r.TTL, r.Value)

	return r
}

// underscore puts the leading underscore on an SRV service or protocol.
func underscore(s string) string {
	if strings.HasPrefix(s, "_") {
		return s
	}

	return "_" + s
}

// rrset names a GoDaddy RRset: a type and a name relative to the domain.
// An SRV RRset is named by its host part: GoDaddy keeps the service and
// protocol in each record.
type rrset struct {
	typ, name string
}

// rrOp adds or removes one Record of an RRset, for the change at index.
type rrOp struct {
	index  int
	remove bool
	rec    dnsprovider.Record
}

// rrGroup is what a Changeset does to one RRset.
type rrGroup struct {
	set rrset
	ops []rrOp
}

// Apply implements dnsprovider.Provider. GoDaddy has no record IDs, so each
// RRset a Changeset touches is one call: it is read, has the changes made
// to it, and is replaced, or deleted when they leave it empty. RRsets left
// with only deletions go first, so a Record that takes the place of
// another does not collide with it. Every change of an RRset shares the
// result of its call; a failed RRset does not stop the others. A
// modification that moves a Record between RRsets and is made in only
// one of them is undone. The results are in Changeset order, with no serial.
func (p *Provider) Apply(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}

	var groups []*rrGroup

	group := func(r dnsprovider.Record) *rrGroup {
		set := rrsetOf(cs.Zone.Name, r)
		for _, g := range groups {
			if g.set == set {
				return g
			}
		}

		g := &rrGroup{set: set}
		groups = append(groups, g)

		return g
	}

	for i, c := range cs.Changes {
		res.Results[i] = dnsprovider.ChangeResult{Change: c}

		if c.Kind == dnsprovider.ChangeModify || c.Kind == dnsprovider.ChangeDelete {
			g := group(c.Before)
			g.ops = append(g.ops, rrOp{index: i, remove: true, rec: c.Before})
		}

		if c.Kind == dnsprovider.ChangeModify || c.Kind == dnsprovider.ChangeAdd {
			g := group(c.After)
			g.ops = append(g.ops, rrOp{index: i, rec: c.After})
			res.Results[i].Record = withID(c.After)
		}
	}

	slices.SortStableFunc(groups, func(a, b *rrGroup) int {
		return removesOnly(b) - removesOnly(a)
	})

	// done holds the ops written, by change and half.
	type half struct {
		index  int
		remove bool
	}

	done := map[half]bool{}

	for _, g := range groups {
		ops := slices.DeleteFunc(slices.Clone(g.ops), func(op rrOp) bool { return res.Results[op.index].Err != nil })
		if len(ops) == 0 {
			continue
		}

		failed, err := p.applyRRset(ctx, cs.Zone, g.set, ops)

		for _, op := range ops {
			switch {
			case failed[op.index] != nil:
				res.Results[op.index].Err = failed[op.index]
			case err != nil:
				res.Results[op.index].Err = err
			default:
				done[half{op.index, op.remove}] = true
			}
		}
	}

	// A modification that moves a Record to another RRset is two writes.
	// When only one of them was made, it is undone, so the failed change
	// leaves the Zone as it was.
	for i, c := range cs.Changes {
		if c.Kind != dnsprovider.ChangeModify || res.Results[i].Err == nil {
			continue
		}

		var undo rrOp

		switch {
		case done[half{i, true}] && !done[half{i, false}]:
			undo = rrOp{index: i, rec: c.Before}
		case done[half{i, false}] && !done[half{i, true}]:
			undo = rrOp{index: i, remove: true, rec: c.After}
		default:
			continue
		}

		failed, err := p.applyRRset(ctx, cs.Zone, rrsetOf(cs.Zone.Name, undo.rec), []rrOp{undo})
		if err == nil {
			err = failed[i]
		}

		if err != nil {
			state := "is gone"
			if undo.remove {
				state = "was added"
			}

			res.Results[i].Err = fmt.Errorf("%w; undoing its other half failed too, so %s %s %s %s: %v",
				res.Results[i].Err, undo.rec.Type, undo.rec.Name, undo.rec.Value, state, err)
		}
	}

	for i := range res.Results {
		if res.Results[i].Err != nil {
			res.Results[i].Record = dnsprovider.Record{}
		}
	}

	return res, nil
}

// removesOnly is 1 for a group that only removes Records, else 0.
func removesOnly(g *rrGroup) int {
	for _, op := range g.ops {
		if !op.remove {
			return 0
		}
	}

	return 1
}

// rrsetOf names the RRset a Record of a Zone belongs to.
func rrsetOf(zone string, r dnsprovider.Record) rrset {
	name := names.RelativeName(zone, r.Name)
	if r.Type == "SRV" {
		_, _, name = splitSRVName(name)
	}

	return rrset{typ: r.Type, name: name}
}

// applyRRset reads an RRset, makes the ops to it and writes it back. A
// Record an op removes that the RRset no longer holds fails that op's
// change alone, and the op that change adds is left out; err fails them all.
func (p *Provider) applyRRset(ctx context.Context, zone dnsprovider.Zone, set rrset, ops []rrOp) (failed map[int]error, err error) {
	path := "/v1/domains/" + url.PathEscape(zone.ID) + "/records/" + url.PathEscape(set.typ) + "/" + url.PathEscape(set.name)

	var current []wireRecord
	if err := p.api().Do(ctx, http.MethodGet, path, nil, nil, &current); err != nil && !errors.Is(err, dnsprovider.ErrNotFound) {
		return nil, err
	}

	records := make([]dnsprovider.Record, 0, len(current))
	for _, w := range current {
		// An SRV record's name may hold its service and protocol.
		if w.Type == "" {
			w.Type = set.typ
		}

		if w.Name == "" {
			w.Name = set.name
		}

		records = append(records, toRecord(zone.Name, w))
	}

	failed = map[int]error{}

	for _, op := range ops {
		if !op.remove || failed[op.index] != nil {
			continue
		}

		i := slices.IndexFunc(records, func(r dnsprovider.Record) bool {
			return strings.EqualFold(r.Name, op.rec.Name) && r.Value == op.rec.Value && r.TTL == op.rec.TTL
		})
		if i < 0 {
			failed[op.index] = fmt.Errorf("godaddy: %s %s %s is not there any more: %w", op.rec.Type, op.rec.Name, op.rec.Value, dnsprovider.ErrNotFound)

			continue
		}

		records = slices.Delete(records, i, i+1)
	}

	for _, op := range ops {
		if op.remove || failed[op.index] != nil {
			continue
		}

		records = append(records, op.rec)
	}

	if !slices.ContainsFunc(ops, func(op rrOp) bool { return failed[op.index] == nil }) {
		return failed, nil
	}

	if len(records) == 0 {
		return failed, p.api().Do(ctx, http.MethodDelete, path, nil, nil, nil)
	}

	body := make([]putRecord, 0, len(records))
	for _, r := range records {
		w, err := toWire(zone.Name, r)
		if err != nil {
			return failed, err
		}

		body = append(body, w)
	}

	return failed, p.api().Do(ctx, http.MethodPut, path, nil, body, nil)
}

// putRecord is one record of an RRset replace.
type putRecord struct {
	Data     string  `json:"data"`
	TTL      uint32  `json:"ttl"`
	Priority *uint64 `json:"priority,omitempty"`
	Weight   *uint64 `json:"weight,omitempty"`
	Port     *uint64 `json:"port,omitempty"`
	Service  string  `json:"service,omitempty"`
	Protocol string  `json:"protocol,omitempty"`
}

// toWire undoes what toRecord does: the MX and SRV priority, and the SRV
// weight and port, leave the Value for their own fields, and an SRV
// Record's service and protocol leave its name.
func toWire(zone string, r dnsprovider.Record) (putRecord, error) {
	w := putRecord{Data: r.Value, TTL: r.TTL}

	f := strings.Fields(r.Value)
	bad := fmt.Errorf("godaddy: %s value %q is not in presentation form", r.Type, r.Value)

	var nums []uint64

	// num parses the first n fields as numbers.
	num := func(n int) bool {
		if len(f) < n {
			return false
		}

		for _, s := range f[:n] {
			v, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return false
			}

			nums = append(nums, v)
		}

		return true
	}

	switch r.Type {
	case "MX":
		if len(f) != 2 || !num(1) {
			return w, bad
		}

		w.Priority, w.Data = &nums[0], f[1]
	case "SRV":
		if len(f) != 4 || !num(3) {
			return w, bad
		}

		service, protocol, _ := splitSRVName(names.RelativeName(zone, r.Name))
		if service == "" {
			return w, fmt.Errorf("godaddy: SRV name %s does not start with _service._protocol", r.Name)
		}

		w.Priority, w.Weight, w.Port, w.Data = &nums[0], &nums[1], &nums[2], f[3]
		w.Service, w.Protocol = service, protocol
	case "URI":
		return w, errors.New("godaddy: GoDaddy has no URI records")
	}

	return w, nil
}

// splitSRVName splits a relative SRV name into its service, protocol and
// host part, "@" for the apex. A name that does not start with two
// underscore labels has no service or protocol.
func splitSRVName(name string) (service, protocol, host string) {
	labels := strings.SplitN(name, ".", 3)
	if len(labels) < 2 || !strings.HasPrefix(labels[0], "_") || !strings.HasPrefix(labels[1], "_") {
		return "", "", name
	}

	host = "@"
	if len(labels) == 3 {
		host = labels[2]
	}

	return labels[0], labels[1], host
}

// ZoneStatus implements dnsprovider.Provider. The v1 API reports neither
// DNSSEC nor HSTS, so both are unknown.
func (p *Provider) ZoneStatus(context.Context, dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	return dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Unknown, HSTS: dnsprovider.Unknown}, nil
}

// Nameservers implements dnsprovider.Provider. GoDaddy assigns each Account
// its own pair of domaincontrol.com nameservers, so the Account expects
// every GoDaddy nameserver its domains name, sorted.
func (p *Provider) Nameservers(ctx context.Context) ([]string, error) {
	all, err := p.listDomains(ctx)
	if err != nil {
		return nil, err
	}

	var ns []string
	for _, d := range all {
		ns = append(ns, goDaddyNameservers(d.NameServers)...)
	}

	slices.Sort(ns)

	return slices.Compact(ns), nil
}
