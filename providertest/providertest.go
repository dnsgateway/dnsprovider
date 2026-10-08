// Package providertest is a scriptable, in-memory Provider for consumers'
// tests.
//
// It is scripted with Zones, Records and failures, and records every call
// made to it, including the API token it was built with.
package providertest

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/dnsgateway/dnsprovider"
)

// Op names a Provider operation, for scripted failures and recorded calls.
type Op string

// Operations.
const (
	OpNew         Op = "New"
	OpZones       Op = "Zones"
	OpRecords     Op = "Records"
	OpApply       Op = "Apply"
	OpZoneStatus  Op = "ZoneStatus"
	OpNameservers Op = "Nameservers"
)

// Call is one recorded call.
type Call struct {
	Op Op
	// Token is set for OpNew.
	Token string
	// Zone is set for the Zone operations.
	Zone dnsprovider.Zone
	// Changeset is set for OpApply.
	Changeset dnsprovider.Changeset
}

// Provider is the fake. Its zero value is not usable; call New.
type Provider struct {
	mu          sync.Mutex
	zones       []dnsprovider.Zone
	records     map[string][]dnsprovider.Record // by Zone ID
	serials     map[string]uint32
	status      map[string]dnsprovider.ZoneStatus
	nameservers []string
	fail        map[Op]error
	failChange  func(dnsprovider.Change) error
	withhold    bool
	noSerial    bool
	ttlRange    []uint32 // min, max; nil when not scripted
	proxiable   []string // nil when not scripted
	autoTTL     bool
	calls       []Call
	nextID      int
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

// RemoveZone drops a scripted Zone, as if it was deleted outside the consumer.
func (p *Provider) RemoveZone(zoneID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.zones = slices.DeleteFunc(p.zones, func(z dnsprovider.Zone) bool { return z.ID == zoneID })
	delete(p.records, zoneID)
}

// SetRecords replaces a scripted Zone's Records, as if they were changed
// outside the consumer.
func (p *Provider) SetRecords(zoneID string, records ...dnsprovider.Record) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.records[zoneID] = slices.Clone(records)
}

// SetTTLRange makes the Providers New builds report a TTL range through
// dnsprovider.TTLLimits. Unscripted, they do not implement it.
func (p *Provider) SetTTLRange(minTTL, maxTTL uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ttlRange = []uint32{minTTL, maxTTL}
}

// SetProxiableTypes makes the Providers New builds proxy Records of these
// types, through dnsprovider.ProxyFlag. Unscripted, they do not implement it.
func (p *Provider) SetProxiableTypes(types ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.proxiable = slices.Clone(types)
}

// SetAutoTTL makes the Providers New builds read TTL 1 as automatic,
// through dnsprovider.AutoTTL. Unscripted, they do not implement it.
func (p *Provider) SetAutoTTL(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.autoTTL = on
}

// withOptions is the fake with its scripted optional interfaces.
type withOptions struct {
	*Provider
}

// TTLRange implements dnsprovider.TTLLimits; the default range when not
// scripted.
func (p withOptions) TTLRange() (minTTL, maxTTL uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ttlRange == nil {
		return dnsprovider.DefaultTTLRange.Min, dnsprovider.DefaultTTLRange.Max
	}

	return p.ttlRange[0], p.ttlRange[1]
}

// AutoTTL implements dnsprovider.AutoTTL.
func (p withOptions) AutoTTL() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.autoTTL
}

// ProxiableTypes implements dnsprovider.ProxyFlag.
func (p withOptions) ProxiableTypes() []string {
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

// SetNameservers scripts the Account's expected nameservers.
func (p *Provider) SetNameservers(ns ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nameservers = ns
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

// New is the dnsprovider.Constructor for the fake: every Provider it
// builds shares this fake's script.
func (p *Provider) New(token string) (dnsprovider.Provider, error) {
	if err := p.record(Call{Op: OpNew, Token: token}); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ttlRange != nil || p.proxiable != nil || p.autoTTL {
		return withOptions{p}, nil
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
func (p *Provider) Zones(context.Context) ([]dnsprovider.Zone, error) {
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

// ZoneStatus implements dnsprovider.Provider.
func (p *Provider) ZoneStatus(_ context.Context, z dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	if err := p.record(Call{Op: OpZoneStatus, Zone: z}); err != nil {
		return dnsprovider.ZoneStatus{}, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.status[z.ID], nil
}

// Nameservers implements dnsprovider.Provider.
func (p *Provider) Nameservers(context.Context) ([]string, error) {
	if err := p.record(Call{Op: OpNameservers}); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.Clone(p.nameservers), nil
}
