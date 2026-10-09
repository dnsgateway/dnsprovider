// Package providertest is a scriptable, in-memory Provider for consumers'
// tests.
//
// It is scripted with Zones, Records and failures, and records every call
// made to it, including the fields it was built from.
package providertest

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// Op names a Provider operation, for scripted failures and recorded calls.
type Op string

// Operations.
const (
	OpNew     Op = "New"
	OpZones   Op = "Zones"
	OpZone    Op = "Zone"
	OpRecords Op = "Records"
	// OpApply is the Batcher's ApplyChangeset; see SetBatcher.
	OpApply Op = "Apply"
	// OpCreateRecord, OpUpdateRecord and OpDeleteRecord are the Record CRUD
	// operations, which dnsprovider.Apply calls once per change on a fake
	// that is no Batcher.
	OpCreateRecord Op = "CreateRecord"
	OpUpdateRecord Op = "UpdateRecord"
	OpDeleteRecord Op = "DeleteRecord"
	OpZoneStatus   Op = "ZoneStatus"
	OpAccount      Op = "Account"
	OpTenants      Op = "Tenants"
	// OpUpdateZone is the ZoneUpdater's UpdateZone; see SetZoneUpdater.
	OpUpdateZone Op = "UpdateZone"
	// OpCreateZone is the ZoneCreator's CreateZone; see SetZoneCreator.
	OpCreateZone Op = "CreateZone"
	// OpDeleteZone is the ZoneDeleter's DeleteZone; see SetZoneDeleter.
	OpDeleteZone Op = "DeleteZone"
)

// Call is one recorded call.
type Call struct {
	Op Op
	// Fields are the field map, set for OpNew.
	Fields map[string]string
	// Zone is set for the Zone operations; for OpZone and OpCreateZone,
	// its Name alone, as asked for.
	Zone dnsprovider.Zone
	// ZoneFilter is set for OpZones.
	ZoneFilter dnsprovider.ZoneFilter
	// RecordFilter is set for OpRecords.
	RecordFilter dnsprovider.RecordFilter
	// Changeset is set for OpApply.
	Changeset dnsprovider.Changeset
	// Change is the change a CRUD operation makes.
	Change dnsprovider.Change
	// ZoneUpdate is set for OpUpdateZone.
	ZoneUpdate dnsprovider.ZoneUpdate
}

// Provider is the fake. Its zero value is not usable; call New.
type Provider struct {
	mu         sync.Mutex
	zones      []dnsprovider.Zone
	records    map[string][]dnsprovider.Record // by Zone ID
	serials    map[string]uint32
	hosting    map[string]dnsprovider.HostingState // by Zone ID, over the State added
	status     map[string]dnsprovider.ZoneStatus
	readStatus bool // whether Zone Status is scripted
	account    dnsprovider.AccountInfo
	tenants    []dnsprovider.Tenant // nil when not scripted
	fail       map[Op]error
	failChange func(dnsprovider.Change) error
	withhold   bool
	noSerial   bool
	ttlRange   []uint32 // min, max; nil when not scripted
	proxiable  []string // nil when not scripted
	autoTTL    bool
	batcher    bool
	updater    bool
	creator    bool
	deleter    bool
	calls      []Call
	nextID     int
}

// New returns an empty fake Provider.
func New() *Provider {
	return &Provider{
		records: map[string][]dnsprovider.Record{},
		serials: map[string]uint32{},
		hosting: map[string]dnsprovider.HostingState{},
		status:  map[string]dnsprovider.ZoneStatus{},
		fail:    map[Op]error{},
	}
}

// AddZone scripts a Zone, identified by its ID, with its Records. The
// Zone keeps its State as given: set it to the Hosting State the
// Provider under test would report.
func (p *Provider) AddZone(z dnsprovider.Zone, records ...dnsprovider.Record) *Provider {
	p.mu.Lock()
	defer p.mu.Unlock()

	z.Nameservers = slices.Clone(z.Nameservers)
	p.zones = append(p.zones, z)
	p.records[z.ID] = slices.Clone(records)

	return p
}

// SetHostingState scripts a Zone's Hosting State, as when Delegation
// comes to name the Provider's nameservers or leaves them. Like SetSerial,
// it holds for a Zone added later with that ID, over the State AddZone
// was given, until RemoveZone.
func (p *Provider) SetHostingState(zoneID string, s dnsprovider.HostingState) *Provider {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.hosting[zoneID] = s

	return p
}

// SetSerial scripts a Zone's SOA serial, which Records reports and each
// write that changes a Record bumps: once per CRUD call, once per
// Changeset through the Batcher.
func (p *Provider) SetSerial(zoneID string, serial uint32) *Provider {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.serials[zoneID] = serial

	return p
}

// RemoveZone drops a scripted Zone, as if it was deleted outside the
// consumer, with its Records, serial, Hosting State and Zone Status: a
// Zone added again with the same ID starts clean.
func (p *Provider) RemoveZone(zoneID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.zones = slices.DeleteFunc(p.zones, func(z dnsprovider.Zone) bool { return z.ID == zoneID })
	delete(p.records, zoneID)
	delete(p.serials, zoneID)
	delete(p.hosting, zoneID)
	delete(p.status, zoneID)
}

// SetRecords replaces a scripted Zone's Records, as if they were changed
// outside the consumer.
func (p *Provider) SetRecords(zoneID string, records ...dnsprovider.Record) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.records[zoneID] = slices.Clone(records)
}

// SetTTLRange makes the Providers New builds report a TTL range through
// dnsprovider.TTLLimits. Unscripted, they report DefaultTTLRange.
func (p *Provider) SetTTLRange(minTTL, maxTTL uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ttlRange = []uint32{minTTL, maxTTL}
}

// SetProxiableTypes makes the Providers New builds proxy Records of these
// types, through dnsprovider.ProxyFlag. Unscripted, they proxy none.
// The fake stores Records as given, so scripted Records carry the flag
// under dnsprovider.ExtraProxied as a real Provider's would.
func (p *Provider) SetProxiableTypes(types ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.proxiable = slices.Clone(types)
}

// SetAutoTTL makes the Providers New builds read TTL 1 as automatic,
// through dnsprovider.AutoTTL. Unscripted, they do not.
func (p *Provider) SetAutoTTL(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.autoTTL = on
}

//go:generate go run gen_wrappers.go

// The fake implements the optional interfaces whose absence the
// dnsprovider helpers read as their unscripted answer, such as
// TTLRangeOf's DefaultTTLRange. TenantLister and ZoneStatusReader, which a
// consumer may branch on, and Batcher, which changes how
// dnsprovider.Apply writes, are implemented by wrapper types, built only
// once scripted: one type per combination, generated (see
// gen_wrappers.go) and picked by build. So are ZoneUpdater, ZoneCreator
// and ZoneDeleter, which a consumer offers its Zone writes by.
var (
	_ dnsprovider.TTLLimits = (*Provider)(nil)
	_ dnsprovider.AutoTTL   = (*Provider)(nil)
	_ dnsprovider.ProxyFlag = (*Provider)(nil)
)

// TTLRange implements dnsprovider.TTLLimits; the default range when not
// scripted.
func (p *Provider) TTLRange() (minTTL, maxTTL uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ttlRange == nil {
		return dnsprovider.DefaultTTLRange.Min, dnsprovider.DefaultTTLRange.Max
	}

	return p.ttlRange[0], p.ttlRange[1]
}

// AutoTTL implements dnsprovider.AutoTTL.
func (p *Provider) AutoTTL() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.autoTTL
}

// ProxiableTypes implements dnsprovider.ProxyFlag.
func (p *Provider) ProxiableTypes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.proxiable)
}

// SetZoneStatus scripts a Zone's Zone Status, and makes the Providers New
// builds read it through dnsprovider.ZoneStatusReader; another Zone's
// settings are then Unknown. Unscripted, they do not implement it, and
// dnsprovider.ZoneStatusOf reports Unknown settings without a call.
func (p *Provider) SetZoneStatus(zoneID string, s dnsprovider.ZoneStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.status[zoneID] = s
	p.readStatus = true
}

// SetAccount scripts what Account reports.
func (p *Provider) SetAccount(info dnsprovider.AccountInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()

	info.Nameservers = slices.Clone(info.Nameservers)
	p.account = info
}

// SetTenants makes the Providers New builds list these Tenants, through
// dnsprovider.TenantLister. Unscripted, they do not implement it.
func (p *Provider) SetTenants(tenants ...dnsprovider.Tenant) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.tenants = append([]dnsprovider.Tenant{}, tenants...)
}

// tenantList is the scripted Tenants, for dnsprovider.TenantLister.
func (p *Provider) tenantList(context.Context) ([]dnsprovider.Tenant, error) {
	if err := p.record(Call{Op: OpTenants}); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.tenants), nil
}

// Fail makes every later call of op fail with err; a nil err clears it.
func (p *Provider) Fail(op Op, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err == nil {
		delete(p.fail, op)

		return
	}

	p.fail[op] = err
}

// SetBatcher makes the Providers New builds implement dnsprovider.Batcher,
// so dnsprovider.Apply hands them each Changeset whole, recorded as
// OpApply. Unscripted, they do not, and Apply makes one CRUD call per
// change.
func (p *Provider) SetBatcher(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.batcher = on
}

// SetZoneUpdater makes the Providers New builds implement
// dnsprovider.ZoneUpdater, recorded as OpUpdateZone: UpdateZone turns
// HSTS On or Off as it is given, and DNSSEC, either way, Pending, as
// Cloudflare signs and unsigns a Zone over time, in the scripted Zone
// Status, which a fake that reads Zone Status (see SetZoneStatus) then
// reports, and returns that Zone Status; SetZoneStatus settles DNSSEC.
// Unscripted, they do not implement it.
func (p *Provider) SetZoneUpdater(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.updater = on
}

// SetZoneCreator makes the Providers New builds implement
// dnsprovider.ZoneCreator, recorded as OpCreateZone: CreateZone adds a
// Zone of the name, without Records, Pending, with a new ID and the
// scripted Account's nameservers, as Cloudflare Onboards a zone name, and
// returns it. The fake's Zones are one Tenant's, the one a Provider is
// built within: a name the fake holds in a Hosting State other than Moved
// is dnsprovider.ErrConflict; a Moved Zone's name is Onboarded again
// beside it. A Provider of a fake scripted with Tenants built without
// one (see Factory) has nowhere to Onboard it: dnsprovider.ErrNoTenant,
// recorded. Unscripted, they do not implement it.
func (p *Provider) SetZoneCreator(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.creator = on
}

// SetZoneDeleter makes the Providers New builds implement
// dnsprovider.ZoneDeleter, recorded as OpDeleteZone with the Zone: DeleteZone
// removes the Zone of that ID with its Records, as RemoveZone does, as
// Cloudflare Offboards a Zone; dnsprovider.ErrNotFound for an ID the fake
// does not hold. Unscripted, they do not implement it.
func (p *Provider) SetZoneDeleter(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.deleter = on
}

// FailChanges makes each write fail a change for which fn returns an
// error, while the Batcher applies the rest: a partial failure. The CRUD
// methods are handed their call as a Change.
func (p *Provider) FailChanges(fn func(dnsprovider.Change) error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.failChange = fn
}

// WithholdRecords makes the writes report no stored Record for the
// changes they confirm, like a Provider whose API does not return them.
func (p *Provider) WithholdRecords(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.withhold = on
}

// WithholdSerial makes Records and the Batcher report no SOA serial,
// like a Provider whose API has no easy way to read it. The scripted
// serial still goes up with each write.
func (p *Provider) WithholdSerial(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.noSerial = on
}

// serial is the serial Records and the Batcher report for a Zone.
func (p *Provider) serial(zoneID string) uint32 {
	if p.noSerial {
		return 0
	}

	return p.serials[zoneID]
}

// Calls returns the calls made so far, in order.
func (p *Provider) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.calls)
}

// FieldTenant is the Tenant field of a fake scripted with Tenants.
const FieldTenant = "tenant"

// Factory builds Providers from a field map with one required, secret
// "token" field, for a consumer's dnsprovider.Registry, and, once Tenants
// are scripted (SetTenants), an optional FieldTenant marked Tenant, as
// Cloudflare takes one. As the Factory contract wants, a missing token or
// a field it does not take is an error. It declares the Zone writes
// scripted by then (SetZoneUpdater, SetZoneCreator, SetZoneDeleter) as
// its Capabilities.
// Every Provider it builds shares this fake's script; it records each
// build of valid fields as OpNew with its fields.
func (p *Provider) Factory() dnsprovider.Factory {
	p.mu.Lock()
	defer p.mu.Unlock()

	fs := []dnsprovider.Field{{Name: "token", Label: "API token", Secret: true}}
	if p.tenants != nil {
		fs = append(fs, dnsprovider.Field{Name: FieldTenant, Label: "Tenant", Tenant: true})
	}

	f := fields.Factory("providertest", fs, p.build)

	if p.updater {
		f.Capabilities = append(f.Capabilities, dnsprovider.CapZoneUpdater)
	}

	if p.creator {
		f.Capabilities = append(f.Capabilities, dnsprovider.CapZoneCreator)
	}

	if p.deleter {
		f.Capabilities = append(f.Capabilities, dnsprovider.CapZoneDeleter)
	}

	return f
}

// scope is the Tenant a Provider the fake built acts within.
type scope struct {
	// unscoped is set for a Provider of a fake scripted with Tenants,
	// built without one: like Cloudflare's, it acts within no Tenant.
	unscoped bool
}

func (p *Provider) build(m map[string]string, _ ...dnsprovider.Option) (dnsprovider.Provider, error) {
	if m["token"] == "" {
		return nil, errors.New("providertest: no API token")
	}

	if err := p.record(Call{Op: OpNew, Fields: maps.Clone(m)}); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var set opts

	if p.tenants != nil {
		set |= optTenants
	}

	if p.readStatus {
		set |= optZoneStatus
	}

	if p.batcher {
		set |= optBatcher
	}

	if p.updater {
		set |= optZoneUpdater
	}

	if p.creator {
		set |= optZoneCreator
	}

	if p.deleter {
		set |= optZoneDeleter
	}

	return wrap(p, set, scope{unscoped: p.tenants != nil && m[FieldTenant] == ""}), nil
}

// record logs a call and returns its scripted failure, if any.
func (p *Provider) record(c Call) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls = append(p.calls, c)

	return p.fail[c.Op]
}

// Zones implements dnsprovider.Provider: the scripted Zones the filter
// matches, in the order added, with their scripted Hosting State.
func (p *Provider) Zones(_ context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	if err := p.record(Call{Op: OpZones, ZoneFilter: f}); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var out []dnsprovider.Zone

	for _, z := range p.zones {
		if dnsprovider.MatchZone(f, z) {
			out = append(out, p.scripted(z))
		}
	}

	return out, nil
}

// Zone implements dnsprovider.Provider: the scripted Zone of that name,
// matched as the adapters match it, ignoring case and a trailing dot;
// ErrNotFound when none is. Of several, such as one Moved and one
// Onboarded again, it is the Active one, else the Pending one, else the
// first added, as Cloudflare's.
func (p *Provider) Zone(_ context.Context, name string) (dnsprovider.Zone, error) {
	if err := p.record(Call{Op: OpZone, Zone: dnsprovider.Zone{Name: name}}); err != nil {
		return dnsprovider.Zone{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var found []dnsprovider.Zone

	for _, z := range p.zones {
		if names.ZoneName(z.Name) == names.ZoneName(name) {
			found = append(found, p.scripted(z))
		}
	}

	for _, s := range []dnsprovider.HostingState{dnsprovider.HostingActive, dnsprovider.HostingPending} {
		if i := slices.IndexFunc(found, func(z dnsprovider.Zone) bool { return z.State == s }); i >= 0 {
			return found[i], nil
		}
	}

	if len(found) > 0 {
		return found[0], nil
	}

	return dnsprovider.Zone{}, fmt.Errorf("providertest: zone %q: %w", name, dnsprovider.ErrNotFound)
}

// scripted is a scripted Zone as the fake reports it, with its scripted
// Hosting State, sharing nothing with the script.
func (p *Provider) scripted(z dnsprovider.Zone) dnsprovider.Zone {
	if s, ok := p.hosting[z.ID]; ok {
		z.State = s
	}

	z.Nameservers = slices.Clone(z.Nameservers)

	return z
}

// Records implements dnsprovider.Provider: the scripted Records that
// match the filter, by dnsprovider.MatchRecord.
func (p *Provider) Records(_ context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	if err := p.record(Call{Op: OpRecords, Zone: z, RecordFilter: f}); err != nil {
		return dnsprovider.RecordSet{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	records, ok := p.records[z.ID]
	if !ok {
		return dnsprovider.RecordSet{}, fmt.Errorf("zone %s (%s) not found", z.Name, z.ID)
	}

	matched := make([]dnsprovider.Record, 0, len(records))

	for _, r := range records {
		if dnsprovider.MatchRecord(f, r) {
			matched = append(matched, r)
		}
	}

	return dnsprovider.RecordSet{Records: matched, Serial: p.serial(z.ID)}, nil
}

// CreateRecord implements dnsprovider.Provider: it adds the Record with
// a new ID, unless FailChanges fails it, and bumps the serial. A Record
// identical to one the Zone holds (type, name and Value) fails with
// dnsprovider.ErrConflict.
func (p *Provider) CreateRecord(_ context.Context, z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	return p.write(OpCreateRecord, z, dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: r})
}

// UpdateRecord implements dnsprovider.Provider: it replaces the Record
// with before's ID by after, keeping the ID, unless FailChanges fails it,
// and bumps the serial. Before's ID not in the Zone fails with
// dnsprovider.ErrNotFound.
func (p *Provider) UpdateRecord(_ context.Context, z dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	return p.write(OpUpdateRecord, z, dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: before, After: after})
}

// DeleteRecord implements dnsprovider.Provider: it drops the Record with
// r's ID, unless FailChanges fails it, and bumps the serial. An ID not in
// the Zone fails with dnsprovider.ErrNotFound.
func (p *Provider) DeleteRecord(_ context.Context, z dnsprovider.Zone, r dnsprovider.Record) error {
	_, err := p.write(OpDeleteRecord, z, dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: r})

	return err
}

// write records a CRUD call and makes its change.
func (p *Provider) write(op Op, z dnsprovider.Zone, c dnsprovider.Change) (dnsprovider.Record, error) {
	if err := p.record(Call{Op: op, Zone: z, Change: c}); err != nil {
		return dnsprovider.Record{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.records[z.ID]; !ok {
		return dnsprovider.Record{}, fmt.Errorf("providertest: zone %s (%s): %w", z.Name, z.ID, dnsprovider.ErrNotFound)
	}

	r := p.change(z.ID, c)
	if r.Err == nil {
		p.serials[z.ID]++
	}

	return r.Record, r.Err
}

// change makes one change to a Zone's Records, unless FailChanges fails
// it, and returns its result, with no Record when WithholdRecords is on.
func (p *Provider) change(zid string, c dnsprovider.Change) dnsprovider.ChangeResult {
	r := dnsprovider.ChangeResult{Change: c}
	if p.failChange != nil {
		r.Err = p.failChange(c)
	}

	if r.Err == nil {
		p.records[zid], r.Record, r.Err = p.applyChange(p.records[zid], c)
	}

	if p.withhold || r.Err != nil {
		r.Record = dnsprovider.Record{}
	}

	return r
}

func (p *Provider) applyChange(records []dnsprovider.Record, c dnsprovider.Change) ([]dnsprovider.Record, dnsprovider.Record, error) {
	if c.Kind != dnsprovider.ChangeAdd && c.Kind != dnsprovider.ChangeModify && c.Kind != dnsprovider.ChangeDelete {
		return records, dnsprovider.Record{}, fmt.Errorf("providertest: unknown change kind %d", c.Kind)
	}

	i := -1

	if c.Kind != dnsprovider.ChangeAdd {
		i = slices.IndexFunc(records, func(r dnsprovider.Record) bool { return r.ID == c.Before.ID })
		if i < 0 {
			return records, dnsprovider.Record{}, fmt.Errorf("providertest: record %s: %w", c.Before.ID, dnsprovider.ErrNotFound)
		}
	}

	if c.Kind == dnsprovider.ChangeDelete {
		return slices.Delete(records, i, i+1), dnsprovider.Record{}, nil
	}

	for j, r := range records {
		if j != i && dnsprovider.SameRecord(r, c.After) {
			return records, dnsprovider.Record{}, fmt.Errorf("providertest: %s %s %s: %w", r.Type, r.Name, r.Value, dnsprovider.ErrConflict)
		}
	}

	r := c.After

	if c.Kind == dnsprovider.ChangeAdd {
		p.nextID++
		r.ID = fmt.Sprintf("fake-%d", p.nextID)

		return append(records, r), r, nil
	}

	r.ID = c.Before.ID
	records[i] = r

	return records, r, nil
}

// applyChangeset is the fake's Batcher: it makes each change as the CRUD
// methods do, in dnsprovider.ApplyOrder, and
// reports the serial, bumped once when any change succeeded.
func (p *Provider) applyChangeset(_ context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	if err := p.record(Call{Op: OpApply, Zone: cs.Zone, Changeset: cs}); err != nil {
		return dnsprovider.ApplyResult{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	zid := cs.Zone.ID
	if _, ok := p.records[zid]; !ok {
		return dnsprovider.ApplyResult{}, fmt.Errorf("providertest: zone %s (%s): %w", cs.Zone.Name, zid, dnsprovider.ErrNotFound)
	}

	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}

	for _, i := range dnsprovider.ApplyOrder(cs.Changes) {
		res.Results[i] = p.change(zid, cs.Changes[i])
	}

	for _, r := range res.Results {
		if r.Err == nil {
			p.serials[zid]++
			res.Serial = p.serial(zid)

			break
		}
	}

	return res, nil
}

// zoneStatus is the scripted Zone Status, for
// dnsprovider.ZoneStatusReader, every setting Unknown for a
// Zone without one.
func (p *Provider) zoneStatus(_ context.Context, z dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	if err := p.record(Call{Op: OpZoneStatus, Zone: z}); err != nil {
		return dnsprovider.ZoneStatus{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.status[z.ID], nil
}

// updateZone is the fake's dnsprovider.ZoneUpdater: it turns HSTS On or
// Off and DNSSEC Pending in the scripted Zone Status and returns it;
// ErrNotFound for a Zone not scripted.
func (p *Provider) updateZone(_ context.Context, z dnsprovider.Zone, u dnsprovider.ZoneUpdate) (dnsprovider.ZoneStatus, error) {
	if err := p.record(Call{Op: OpUpdateZone, Zone: z, ZoneUpdate: u}); err != nil {
		return dnsprovider.ZoneStatus{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !slices.ContainsFunc(p.zones, func(s dnsprovider.Zone) bool { return s.ID == z.ID }) {
		return dnsprovider.ZoneStatus{}, fmt.Errorf("providertest: zone %s (%s): %w", z.Name, z.ID, dnsprovider.ErrNotFound)
	}

	st := p.status[z.ID]

	// Like Cloudflare, which signs and unsigns a Zone over time.
	if u.DNSSEC != nil {
		st.DNSSEC = dnsprovider.Pending
	}

	if u.HSTS != nil {
		st.HSTS = setting(*u.HSTS)
	}

	p.status[z.ID] = st

	return st, nil
}

// createZone is the fake's dnsprovider.ZoneCreator; see SetZoneCreator.
func (p *Provider) createZone(_ context.Context, unscoped bool, name string) (dnsprovider.Zone, error) {
	if err := p.record(Call{Op: OpCreateZone, Zone: dnsprovider.Zone{Name: name}}); err != nil {
		return dnsprovider.Zone{}, err
	}

	if unscoped {
		return dnsprovider.Zone{}, fmt.Errorf("providertest: Onboard %q: %w", name, dnsprovider.ErrNoTenant)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	key := names.ZoneName(strings.TrimSpace(name))
	if key == "" {
		return dnsprovider.Zone{}, errors.New("providertest: Onboard: no zone name")
	}

	for _, z := range p.zones {
		if names.ZoneName(z.Name) == key && p.scripted(z).State != dnsprovider.HostingMoved {
			return dnsprovider.Zone{}, fmt.Errorf("providertest: zone %q: %w", key, dnsprovider.ErrConflict)
		}
	}

	p.nextID++

	z := dnsprovider.Zone{
		ID:          fmt.Sprintf("fake-zone-%d", p.nextID),
		Name:        key,
		State:       dnsprovider.HostingPending,
		Nameservers: slices.Clone(p.account.Nameservers),
	}

	p.zones = append(p.zones, z)
	p.records[z.ID] = []dnsprovider.Record{}

	return p.scripted(z), nil
}

// deleteZone is the fake's dnsprovider.ZoneDeleter; see SetZoneDeleter.
func (p *Provider) deleteZone(_ context.Context, z dnsprovider.Zone) error {
	if err := p.record(Call{Op: OpDeleteZone, Zone: z}); err != nil {
		return err
	}

	p.mu.Lock()
	held := slices.ContainsFunc(p.zones, func(s dnsprovider.Zone) bool { return s.ID == z.ID })
	p.mu.Unlock()

	if !held {
		return fmt.Errorf("providertest: zone %s (%s): %w", z.Name, z.ID, dnsprovider.ErrNotFound)
	}

	p.RemoveZone(z.ID)

	return nil
}

// setting is On or Off.
func setting(on bool) dnsprovider.Setting {
	if on {
		return dnsprovider.On
	}

	return dnsprovider.Off
}

// Account implements dnsprovider.Provider: the scripted AccountInfo.
func (p *Provider) Account(context.Context) (dnsprovider.AccountInfo, error) {
	if err := p.record(Call{Op: OpAccount}); err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	info := p.account
	info.Nameservers = slices.Clone(info.Nameservers)

	return info, nil
}
