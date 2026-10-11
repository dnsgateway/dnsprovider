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
	OpNew       Op = "New"
	OpListZones Op = "ListZones"
	OpGetZone   Op = "GetZone"
	OpRecords   Op = "Records"
	// OpApply is the Batcher's ApplyChangeset; see SetBatcher.
	OpApply Op = "Apply"
	// OpCreateRecord, OpUpdateRecord and OpDeleteRecord are the Record CRUD
	// operations, which dnsprovider.Apply calls once per change on a fake
	// that is no Batcher.
	OpCreateRecord Op = "CreateRecord"
	OpUpdateRecord Op = "UpdateRecord"
	OpDeleteRecord Op = "DeleteRecord"
	OpZoneDetails  Op = "ZoneDetails"
	// OpListDelegationSigners is the DSRegistrar's ListDelegationSigners;
	// see SetRegistration.
	OpListDelegationSigners Op = "ListDelegationSigners"
	// OpSetDelegationSigners is the DSRegistrar's SetDelegationSigners;
	// see SetRegistration.
	OpSetDelegationSigners Op = "SetDelegationSigners"
	// OpDeleteDelegationSigners is the DSRegistrar's
	// DeleteDelegationSigners; see SetRegistration.
	OpDeleteDelegationSigners Op = "DeleteDelegationSigners"
	OpAccount                 Op = "Account"
	OpTenants                 Op = "Tenants"
	// OpUpdateZone is the Provider's UpdateZone; see SetZoneUpdater.
	OpUpdateZone Op = "UpdateZone"
	// OpCreateZone is the Provider's CreateZone; see SetZoneCreator.
	OpCreateZone Op = "CreateZone"
	// OpDeleteZone is the Provider's DeleteZone; see SetZoneDeleter.
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
	// ZoneDetailRequest is set for OpZoneDetails.
	ZoneDetailRequest dnsprovider.ZoneDetailRequest
	// Keys are the Signing Keys written, set for OpSetDelegationSigners.
	Keys []dnsprovider.SigningKey
}

// Provider is the fake. Its zero value is not usable; call New.
type Provider struct {
	mu             sync.Mutex
	zones          []dnsprovider.Zone
	records        map[string][]dnsprovider.Record // by Zone ID
	serials        map[string]uint32
	hosting        map[string]dnsprovider.HostingState // by Zone ID, over the State added
	status         map[string]dnsprovider.ZoneStatus
	details        map[string]dnsprovider.ZoneDetails
	readStatus     bool                                // whether Zone Status is scripted
	keys           map[string][]dnsprovider.SigningKey // by Zone ID
	readKeys       bool                                // whether signing keys are scripted
	registryKeys   map[string][]dnsprovider.SigningKey // by Zone ID of each Registration: the keys its registry holds
	dsRegistrar    bool                                // whether built Providers are DSRegistrars
	account        dnsprovider.AccountInfo
	tenants        []dnsprovider.Tenant // nil when not scripted
	fail           map[Op]error
	failChange     func(dnsprovider.Change) error
	withhold       bool
	noSerial       bool
	partialZones   bool            // whether Zones is a Partial View
	partialRecords map[string]bool // by Zone ID: whether its Records are a Partial View
	ttlRange       []uint32        // min, max; nil when not scripted
	proxiable      []string        // nil when not scripted
	autoTTL        bool
	batcher        bool
	updater        bool
	creator        bool
	deleter        bool
	calls          []Call
	nextID         int
}

// New returns an empty fake Provider.
func New() *Provider {
	return &Provider{
		records:        map[string][]dnsprovider.Record{},
		serials:        map[string]uint32{},
		hosting:        map[string]dnsprovider.HostingState{},
		status:         map[string]dnsprovider.ZoneStatus{},
		details:        map[string]dnsprovider.ZoneDetails{},
		keys:           map[string][]dnsprovider.SigningKey{},
		registryKeys:   map[string][]dnsprovider.SigningKey{},
		fail:           map[Op]error{},
		partialRecords: map[string]bool{},
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
// consumer, with its Records, serial, Hosting State, Zone Status, signing
// keys, Registration and Partial View: a Zone added again with the same ID
// starts clean.
func (p *Provider) RemoveZone(zoneID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.removeHosting(zoneID)
	delete(p.registryKeys, zoneID)
}

// removeHosting drops scripted DNS hosting while preserving Registration.
// The caller holds p.mu.
func (p *Provider) removeHosting(zoneID string) {
	p.zones = slices.DeleteFunc(p.zones, func(z dnsprovider.Zone) bool { return z.ID == zoneID })
	delete(p.records, zoneID)
	delete(p.serials, zoneID)
	delete(p.hosting, zoneID)
	delete(p.status, zoneID)
	delete(p.details, zoneID)
	delete(p.keys, zoneID)
	delete(p.partialRecords, zoneID)
}

// SetRecords replaces a scripted Zone's Records, as if they were changed
// outside the consumer.
func (p *Provider) SetRecords(zoneID string, records ...dnsprovider.Record) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.records[zoneID] = slices.Clone(records)
}

// SetTTLRange makes the Providers New builds report a TTL range in their
// Traits. Unscripted, they report DefaultTTLRange.
func (p *Provider) SetTTLRange(minTTL, maxTTL uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ttlRange = []uint32{minTTL, maxTTL}
}

// SetProxiableTypes makes the Providers New builds proxy Records of these
// types, declared in their Traits. Unscripted, they proxy none.
// The fake stores Records as given, so scripted Records carry the flag
// under dnsprovider.ExtraProxied as a real Provider's would.
func (p *Provider) SetProxiableTypes(types ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.proxiable = slices.Clone(types)
}

// SetAutoTTL makes the Providers New builds read TTL 1 as automatic, as
// their Traits declare. Unscripted, they do not.
func (p *Provider) SetAutoTTL(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.autoTTL = on
}

//go:generate go run gen_wrappers.go

// TenantLister and DSRegistrar, which a
// consumer may branch on, and Batcher, which changes how
// dnsprovider.Apply writes, are implemented by wrapper types, built only
// once scripted: one type per combination, generated (see
// gen_wrappers.go) and picked by build. Core Zone writes always exist;
// Traits declare each as scripted, and an unscripted write returns
// dnsprovider.ErrNotImplemented, recording nothing.

// traits are the Traits scripted so far: the Zone writes, the TTL range
// (SetTTLRange, SetAutoTTL), with the default range when none is, and the
// ExtraProxied types. The caller holds p.mu.
func (p *Provider) traits() dnsprovider.Traits {
	t := dnsprovider.Traits{Capabilities: p.zoneWrites(), TTL: dnsprovider.DefaultTTLRange}
	if p.ttlRange != nil {
		t.TTL.Min, t.TTL.Max = p.ttlRange[0], p.ttlRange[1]
	}

	t.TTL.Auto = p.autoTTL

	if p.proxiable != nil {
		t.Extras = []dnsprovider.ExtraSpec{dnsprovider.ProxiedExtra(p.proxiable...)}
	}

	return t
}

// SetZoneStatus scripts a Zone's Zone Status, which ZoneDetails then
// reads for every Zone not scripted with SetZoneDetails: its DNSSEC, HSTS
// and MinTLS read, another Zone's Unknown. Unscripted, they are
// unsupported.
func (p *Provider) SetZoneStatus(zoneID string, s dnsprovider.ZoneStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.status[zoneID] = s
	p.readStatus = true
}

// SetSigningKeys scripts a Zone's signing keys, which ZoneDetails then
// reads when requested for every Zone not scripted with SetZoneDetails;
// another Zone has none, as an unsigned Zone. Unscripted, they are
// unsupported, as for a Provider whose API returns no keys.
func (p *Provider) SetSigningKeys(zoneID string, keys ...dnsprovider.SigningKey) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.keys[zoneID] = cloneKeys(keys)
	p.readKeys = true
}

// SetRegistration scripts a Zone as a Registration and enables the
// dnsprovider.DSRegistrar methods, recorded as OpListDelegationSigners,
// OpSetDelegationSigners and OpDeleteDelegationSigners; a
// SetDelegationSigners with no keys is ErrNoSigningKeys, recording
// nothing. Other Zones return ErrNotFound; without this
// script, the Provider does not implement DSRegistrar.
func (p *Provider) SetRegistration(zoneID string, keys ...dnsprovider.SigningKey) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.registryKeys[zoneID] = cloneKeys(keys)
	p.dsRegistrar = true
}

// cloneKeys is a deep copy of keys.
func cloneKeys(keys []dnsprovider.SigningKey) []dnsprovider.SigningKey {
	out := make([]dnsprovider.SigningKey, len(keys))
	for i, k := range keys {
		k.DS = slices.Clone(k.DS)
		out[i] = k
	}

	return out
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

// SetZoneUpdater declares support for UpdateZone and records calls as
// OpUpdateZone. Updates apply HSTS and MinTLS as given and set DNSSEC to
// Pending; SetZoneStatus controls the reported DNSSEC state. Without this
// script, the method returns dnsprovider.ErrNotImplemented.
func (p *Provider) SetZoneUpdater(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.updater = on
}

// SetZoneCreator declares support for CreateZone and records calls as
// OpCreateZone. It creates an empty Pending Zone with a new ID and the
// scripted Account's nameservers. Existing non-Moved names conflict;
// without a Tenant it returns ErrNoTenant. Without this script, creation
// returns dnsprovider.ErrNotImplemented.
func (p *Provider) SetZoneCreator(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.creator = on
}

// SetZoneDeleter declares support for DeleteZone and records calls as
// OpDeleteZone. DeleteZone removes hosting and Records, retains Registration,
// and returns
// dnsprovider.ErrNotFound for an unknown ID. Without this script, deletion
// returns dnsprovider.ErrNotImplemented.
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

	out := slices.Clone(p.calls)
	for i := range out {
		out[i].Zone = cloneZone(out[i].Zone)
	}
	return out
}

// FieldTenant is the Tenant field of a fake scripted with Tenants.
const FieldTenant = "tenant"

// Factory builds Providers from fields, requiring a secret "token" and
// optionally accepting FieldTenant when Tenants are scripted. Its
// Traits reflect the scripts set so far. Built Providers share the fake's script; valid builds are
// recorded as OpNew.
func (p *Provider) Factory() dnsprovider.Factory {
	p.mu.Lock()
	defer p.mu.Unlock()

	fs := []dnsprovider.Field{{Name: "token", Label: "API token", Secret: true}}
	if p.tenants != nil {
		fs = append(fs, dnsprovider.Field{Name: FieldTenant, Label: "Tenant", Tenant: true})
	}

	return fields.Factory("providertest", fs, p.traits(), p.build)
}

// zoneWrites are the Zone writes scripted; nil when none is. The caller
// holds p.mu.
func (p *Provider) zoneWrites() []dnsprovider.Capability {
	var out []dnsprovider.Capability

	if p.updater {
		out = append(out, dnsprovider.CapZoneUpdater)
	}

	if p.creator {
		out = append(out, dnsprovider.CapZoneCreator)
	}

	if p.deleter {
		out = append(out, dnsprovider.CapZoneDeleter)
	}

	return out
}

// scope is what a Provider the fake built acts within: its Tenant, and
// the Zone writes scripted when it was built.
type scope struct {
	// unscoped is set for a Provider of a fake scripted with Tenants,
	// built without one: like Cloudflare's, it acts within no Tenant.
	unscoped bool
	// writes are the Zone writes scripted, as the Factory declares them.
	writes []dnsprovider.Capability
}

// unscripted refuses a Zone write that was not scripted when the Provider
// was built. It records nothing.
func (sc scope) unscripted(c dnsprovider.Capability) error {
	if slices.Contains(sc.writes, c) {
		return nil
	}

	return fmt.Errorf("providertest: %s not scripted: %w", c, dnsprovider.ErrNotImplemented)
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

	if p.dsRegistrar {
		set |= optDSRegistrar
	}

	if p.batcher {
		set |= optBatcher
	}

	writes := p.zoneWrites()

	return wrap(p, set, scope{unscoped: p.tenants != nil && m[FieldTenant] == "", writes: writes}), nil
}

// record logs a call and returns its scripted failure, if any.
func (p *Provider) record(c Call) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls = append(p.calls, c)

	return p.fail[c.Op]
}

// SetPartialZones makes Zones report a Partial View, as an adapter in
// front of a Gateway does when the caller's access does not cover every
// Zone. The Zones listed stay as scripted. Unscripted, Zones is a Full
// View.
func (p *Provider) SetPartialZones(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.partialZones = on
}

// ListZones implements dnsprovider.Provider: the scripted Zones the filter
// matches, in the order added, with their scripted Hosting State, as a
// Partial View once SetPartialZones scripts one.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	if err := ctx.Err(); err != nil {
		return dnsprovider.ZoneSet{}, err
	}
	if err := p.record(Call{Op: OpListZones, ZoneFilter: f}); err != nil {
		return dnsprovider.ZoneSet{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	var out []dnsprovider.Zone

	for _, z := range p.zones {
		if dnsprovider.MatchZone(f, z) {
			out = append(out, p.scripted(z))
		}
	}

	return dnsprovider.ZoneSet{Zones: out, Partial: p.partialZones}, nil
}

// GetZone implements dnsprovider.Provider: the scripted Zone of that name,
// matched as the adapters match it, ignoring case and a trailing dot;
// ErrNotFound when none is. Of several, such as one Moved and one
// Onboarded again, it is the Active one, else the Pending one, else the
// first added, as Cloudflare's.
func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	if err := ctx.Err(); err != nil {
		return dnsprovider.Zone{}, err
	}
	if err := p.record(Call{Op: OpGetZone, Zone: dnsprovider.Zone{Name: name}}); err != nil {
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

// SetPartialRecords makes a Zone's Records report a Partial View while
// returning the scripted Records. The setting is keyed by Zone ID and
// remains effective for a later Zone with that ID until RemoveZone.
// Without this setting, Records reports a Full View.
func (p *Provider) SetPartialRecords(zoneID string, on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.partialRecords[zoneID] = on
}

// ListRecords implements dnsprovider.Provider: the scripted Records that
// match the filter, by dnsprovider.MatchRecord, as a Partial View once
// SetPartialRecords scripts one for the Zone.
func (p *Provider) ListRecords(_ context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
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

	return dnsprovider.RecordSet{Records: matched, Serial: p.serial(z.ID), Partial: p.partialRecords[z.ID]}, nil
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

// listDelegationSigners is the DS the registry holds for a Registration, for
// dnsprovider.DSRegistrar; ErrNotFound for a Zone not scripted as one.
func (p *Provider) listDelegationSigners(_ context.Context, z dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	if err := p.record(Call{Op: OpListDelegationSigners, Zone: z}); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	keys, ok := p.registryKeys[z.ID]
	if !ok {
		return nil, notRegistered(z)
	}

	return cloneKeys(keys), nil
}

// setDelegationSigners replaces the DS the registry holds for a
// Registration with keys, at least one, for dnsprovider.DSRegistrar;
// ErrNotFound for a Zone not scripted as one.
func (p *Provider) setDelegationSigners(ctx context.Context, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	if len(keys) == 0 {
		return dnsprovider.ErrNoSigningKeys
	}

	return p.replaceDelegationSigners(ctx, OpSetDelegationSigners, z, keys)
}

// deleteDelegationSigners removes the DS the registry holds for a
// Registration, for dnsprovider.DSRegistrar; ErrNotFound for a Zone not
// scripted as one.
func (p *Provider) deleteDelegationSigners(ctx context.Context, z dnsprovider.Zone) error {
	return p.replaceDelegationSigners(ctx, OpDeleteDelegationSigners, z, nil)
}

// replaceDelegationSigners records op and replaces a Registration's DS
// with keys.
func (p *Provider) replaceDelegationSigners(_ context.Context, op Op, z dnsprovider.Zone, keys []dnsprovider.SigningKey) error {
	if err := p.record(Call{Op: op, Zone: z, Keys: cloneKeys(keys)}); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.registryKeys[z.ID]; !ok {
		return notRegistered(z)
	}

	p.registryKeys[z.ID] = cloneKeys(keys)

	return nil
}

// notRegistered is the DSRegistrar's error for a Zone not scripted as a
// Registration: the Account does not register its domain.
func notRegistered(z dnsprovider.Zone) error {
	return fmt.Errorf("providertest: %s is not registered by the Account: %w", z.Name, dnsprovider.ErrNotFound)
}

// updateZone implements the fake's UpdateZone: it turns HSTS On or
// Off, sets the minimum TLS version and turns DNSSEC Pending in the
// scripted Zone Status and returns it;
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

	if u.MinTLS != nil {
		st.MinTLS = *u.MinTLS
	}

	p.status[z.ID] = st

	return st, nil
}

// createZone implements the fake's CreateZone; see SetZoneCreator.
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

// deleteZone removes scripted hosting only; see SetZoneDeleter.
func (p *Provider) deleteZone(_ context.Context, z dnsprovider.Zone) error {
	if err := p.record(Call{Op: OpDeleteZone, Zone: z}); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	held := slices.ContainsFunc(p.zones, func(s dnsprovider.Zone) bool { return s.ID == z.ID })

	if !held {
		return fmt.Errorf("providertest: zone %s (%s): %w", z.Name, z.ID, dnsprovider.ErrNotFound)
	}

	p.removeHosting(z.ID)

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
