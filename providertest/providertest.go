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
	"sync"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
)

// Op names a Provider operation, for scripted failures and recorded calls.
type Op string

// Operations.
const (
	OpNew        Op = "New"
	OpZones      Op = "Zones"
	OpRecords    Op = "Records"
	OpApply      Op = "Apply"
	OpZoneStatus Op = "ZoneStatus"
	OpAccount    Op = "Account"
	OpTenants    Op = "Tenants"
)

// Call is one recorded call.
type Call struct {
	Op Op
	// Fields are the field map, set for OpNew.
	Fields map[string]string
	// Zone is set for the Zone operations.
	Zone dnsprovider.Zone
	// Changeset is set for OpApply.
	Changeset dnsprovider.Changeset
}

// Provider is the fake. Its zero value is not usable; call New.
type Provider struct {
	mu         sync.Mutex
	zones      []dnsprovider.Zone
	records    map[string][]dnsprovider.Record // by Zone ID
	serials    map[string]uint32
	status     map[string]dnsprovider.ZoneStatus
	account    dnsprovider.AccountInfo
	tenants    []dnsprovider.Tenant // nil when not scripted
	fail       map[Op]error
	failChange func(dnsprovider.Change) error
	withhold   bool
	noSerial   bool
	ttlRange   []uint32 // min, max; nil when not scripted
	proxiable  []string // nil when not scripted
	autoTTL    bool
	calls      []Call
	nextID     int
}

// New returns an empty fake Provider.
func New() *Provider {
	return &Provider{
		records: map[string][]dnsprovider.Record{},
		serials: map[string]uint32{},
		status:  map[string]dnsprovider.ZoneStatus{},
		fail:    map[Op]error{},
	}
}

// AddZone scripts a Zone, identified by its ID, with its Records.
func (p *Provider) AddZone(z dnsprovider.Zone, records ...dnsprovider.Record) *Provider {
	p.mu.Lock()
	defer p.mu.Unlock()

	z.Nameservers = slices.Clone(z.Nameservers)
	p.zones = append(p.zones, z)
	p.records[z.ID] = slices.Clone(records)

	return p
}

// SetSerial scripts a Zone's SOA serial, which Records reports and each
// Apply that changes a Record bumps.
func (p *Provider) SetSerial(zoneID string, serial uint32) *Provider {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.serials[zoneID] = serial

	return p
}

// RemoveZone drops a scripted Zone, as if it was deleted outside the
// consumer, with its Records, serial and Zone Status: a Zone added again
// with the same ID starts clean.
func (p *Provider) RemoveZone(zoneID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.zones = slices.DeleteFunc(p.zones, func(z dnsprovider.Zone) bool { return z.ID == zoneID })
	delete(p.records, zoneID)
	delete(p.serials, zoneID)
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

// The fake implements the optional interfaces whose absence the
// dnsprovider helpers read as their unscripted answer, such as
// TTLRangeOf's DefaultTTLRange or ZoneStatusOf's Unknown settings. Only one whose absence a CanX helper
// reports, such as TenantLister, needs a wrapper type, built when
// scripted; see build.
var (
	_ dnsprovider.TTLLimits = (*Provider)(nil)
	_ dnsprovider.AutoTTL   = (*Provider)(nil)
	_ dnsprovider.ProxyFlag = (*Provider)(nil)

	_ dnsprovider.ZoneStatusReader = (*Provider)(nil)
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

// SetZoneStatus scripts a Zone's Zone Status.
func (p *Provider) SetZoneStatus(zoneID string, s dnsprovider.ZoneStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.status[zoneID] = s
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

// withTenants is the fake with scripted Tenants.
type withTenants struct {
	*Provider
}

// Tenants implements dnsprovider.TenantLister.
func (p withTenants) Tenants(context.Context) ([]dnsprovider.Tenant, error) {
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

// FailChanges makes Apply fail each change for which fn returns an error,
// while applying the rest: a partial failure.
func (p *Provider) FailChanges(fn func(dnsprovider.Change) error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.failChange = fn
}

// WithholdRecords makes Apply report no stored Record for the changes it
// confirms, like a Provider whose API does not return them.
func (p *Provider) WithholdRecords(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.withhold = on
}

// WithholdSerial makes Records and Apply report no SOA serial, like a
// Provider whose API has no easy way to read it. The scripted serial
// still goes up with each Apply.
func (p *Provider) WithholdSerial(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.noSerial = on
}

// serial is the serial Records and Apply report for a Zone.
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

// Factory builds Providers from a field map with one required, secret
// "token" field, for a consumer's dnsprovider.Registry. As the Factory
// contract wants, a missing token or a field other than "token" is an
// error. Every Provider it builds shares this fake's script; it records
// each build of valid fields as OpNew with its fields.
func (p *Provider) Factory() dnsprovider.Factory {
	return fields.Factory("providertest", []dnsprovider.Field{{Name: "token", Label: "API token", Secret: true}}, p.build)
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

	if p.tenants != nil {
		return withTenants{p}, nil
	}

	return p, nil
}

// record logs a call and returns its scripted failure, if any.
func (p *Provider) record(c Call) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls = append(p.calls, c)

	return p.fail[c.Op]
}

// Zones implements dnsprovider.Provider.
func (p *Provider) Zones(context.Context, dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	if err := p.record(Call{Op: OpZones}); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.zones), nil
}

// Records implements dnsprovider.Provider.
func (p *Provider) Records(_ context.Context, z dnsprovider.Zone) (dnsprovider.RecordSet, error) {
	if err := p.record(Call{Op: OpRecords, Zone: z}); err != nil {
		return dnsprovider.RecordSet{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	records, ok := p.records[z.ID]
	if !ok {
		return dnsprovider.RecordSet{}, fmt.Errorf("zone %s (%s) not found", z.Name, z.ID)
	}

	return dnsprovider.RecordSet{Records: slices.Clone(records), Serial: p.serial(z.ID)}, nil
}

// Apply implements dnsprovider.Provider. It applies each change to the
// scripted Records, unless FailChanges fails it, and bumps the serial when
// any change succeeded.
func (p *Provider) Apply(_ context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	if err := p.record(Call{Op: OpApply, Zone: cs.Zone, Changeset: cs}); err != nil {
		return dnsprovider.ApplyResult{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	zid := cs.Zone.ID

	records, ok := p.records[zid]
	if !ok {
		return dnsprovider.ApplyResult{}, fmt.Errorf("zone %s (%s) not found", cs.Zone.Name, zid)
	}

	var res dnsprovider.ApplyResult

	for _, c := range cs.Changes {
		r := dnsprovider.ChangeResult{Change: c}
		if p.failChange != nil {
			r.Err = p.failChange(c)
		}

		if r.Err == nil {
			records, r.Record, r.Err = p.applyChange(records, c)
		}

		if p.withhold {
			r.Record = dnsprovider.Record{}
		}

		res.Results = append(res.Results, r)
	}

	p.records[zid] = records

	for _, r := range res.Results {
		if r.Err == nil {
			p.serials[zid]++
			res.Serial = p.serial(zid)

			break
		}
	}

	return res, nil
}

func (p *Provider) applyChange(records []dnsprovider.Record, c dnsprovider.Change) ([]dnsprovider.Record, dnsprovider.Record, error) {
	if c.Kind == dnsprovider.ChangeAdd {
		p.nextID++
		r := c.After
		r.ID = fmt.Sprintf("fake-%d", p.nextID)

		return append(records, r), r, nil
	}

	i := slices.IndexFunc(records, func(r dnsprovider.Record) bool { return r.ID == c.Before.ID })
	if i < 0 {
		return records, dnsprovider.Record{}, fmt.Errorf("record %s not found", c.Before.ID)
	}

	if c.Kind == dnsprovider.ChangeDelete {
		return slices.Delete(records, i, i+1), dnsprovider.Record{}, nil
	}

	r := c.After
	r.ID = c.Before.ID
	records[i] = r

	return records, r, nil
}

// ZoneStatus implements dnsprovider.ZoneStatusReader: the scripted Zone
// Status, every setting Unknown when not scripted, as ZoneStatusOf
// reports for a Provider without a reader.
func (p *Provider) ZoneStatus(_ context.Context, z dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	if err := p.record(Call{Op: OpZoneStatus, Zone: z}); err != nil {
		return dnsprovider.ZoneStatus{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.status[z.ID], nil
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
