package ovhcloud

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// fieldTypes are the record types the record listing filters by
// (domain.zone.RecordTypeEnum). Only these are pushed down.
var fieldTypes = []string{"A", "AAAA", "CAA", "CNAME", "DKIM", "DMARC", "DNAME", "HTTPS", "LOC", "MX", "NAPTR", "NS", "PTR", "RP", "SPF", "SRV", "SSHFP", "SVCB", "TLSA", "TXT"}

// readWorkers bounds concurrent per-record reads.
const readWorkers = 4

// wireRecord is domain.zone.Record. A zero TTL is the Zone default.
type wireRecord struct {
	ID        int64   `json:"id"`
	FieldType string  `json:"fieldType"`
	SubDomain *string `json:"subDomain"`
	Target    *string `json:"target"`
	TTL       *int64  `json:"ttl"`
	Zone      string  `json:"zone"`
}

func (w wireRecord) sub() string {
	if w.SubDomain == nil {
		return ""
	}

	return *w.SubDomain
}

func (w wireRecord) inherited() bool { return w.TTL == nil || *w.TTL == 0 }

type wireZone struct {
	Name        string   `json:"name"`
	NameServers []string `json:"nameServers"`
}

type wireSOA struct {
	Serial int64 `json:"serial"`
	TTL    int64 `json:"ttl"`
}

// serial is the SOA serial, zero when it is out of range.
func (w wireSOA) serial() uint32 {
	if w.Serial > 0 && w.Serial <= math.MaxUint32 {
		return uint32(w.Serial)
	}

	return 0
}

func zonePath(name string) string { return "/domain/zone/" + url.PathEscape(name) }

func publicZone(w wireZone) (dnsprovider.Zone, error) {
	name := names.ZoneName(w.Name)
	if name == "" {
		return dnsprovider.Zone{}, errors.New("ovhcloud: malformed Zone")
	}

	var ns []string
	for _, n := range w.NameServers {
		if n = names.ZoneName(n); n != "" {
			ns = append(ns, n)
		}
	}

	// The Zone service has no hosting signal: deployment on OVHcloud's
	// servers does not establish Delegation.
	return dnsprovider.Zone{ID: name, Name: name, State: dnsprovider.HostingUnknown, Nameservers: ns}, nil
}

func (p *Provider) zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)
	if name == "" {
		return dnsprovider.Zone{}, dnsprovider.ErrNotFound
	}

	var w wireZone
	if err := p.do(ctx, http.MethodGet, zonePath(name), nil, nil, &w); err != nil {
		return dnsprovider.Zone{}, err
	}

	z, err := publicZone(w)
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	if z.Name != name {
		return dnsprovider.Zone{}, errors.New("ovhcloud: response names another Zone")
	}

	return z, nil
}

// ListZones implements dnsprovider.Provider: the DNS Zone services (not
// registrar domains) that match the filter, reading the details of each.
// The listing is unpaged.
// The ZoneSet is a Full View.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	var list *[]string
	if err := p.do(ctx, http.MethodGet, "/domain/zone", nil, nil, &list); err != nil {
		return dnsprovider.ZoneSet{}, err
	}

	if list == nil {
		return dnsprovider.ZoneSet{}, errors.New("ovhcloud: malformed Zone listing")
	}

	seen := map[string]bool{}
	out := []dnsprovider.Zone{}

	for _, raw := range *list {
		name := names.ZoneName(raw)
		if name == "" {
			return dnsprovider.ZoneSet{}, errors.New("ovhcloud: malformed Zone listing")
		}

		if seen[name] {
			return dnsprovider.ZoneSet{}, fmt.Errorf("ovhcloud: Zone listing repeats %s: %w", name, rest.ErrSamePage)
		}

		seen[name] = true

		if !dnsprovider.MatchZone(f, dnsprovider.Zone{Name: name}) {
			continue
		}

		z, err := p.zone(ctx, name)
		if err != nil {
			return dnsprovider.ZoneSet{}, err
		}

		out = append(out, z)
	}

	return dnsprovider.ZoneSet{Zones: out}, nil
}

// GetZone reads the exact Zone service, ErrNotFound when there is none.
func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	return p.zone(ctx, name)
}

func zoneName(z dnsprovider.Zone) string {
	if z.Name != "" {
		return names.ZoneName(z.Name)
	}

	return names.ZoneName(z.ID)
}

// storedRecord is a native Record with its public form.
type storedRecord struct {
	wire   wireRecord
	record dnsprovider.Record
}

type snapshot struct {
	zone       string
	defaultTTL uint32
	serial     uint32
	entries    []storedRecord
}

func (p *Provider) soa(ctx context.Context, zone string) (wireSOA, error) {
	var soa wireSOA
	if err := p.do(ctx, http.MethodGet, zonePath(zone)+"/soa", nil, nil, &soa); err != nil {
		return wireSOA{}, err
	}

	if soa.TTL <= 0 || soa.TTL > math.MaxUint32 {
		return wireSOA{}, errors.New("ovhcloud: malformed SOA: no default TTL")
	}

	return soa, nil
}

func (p *Provider) read(ctx context.Context, z dnsprovider.Zone, typ string) (snapshot, error) {
	zone := zoneName(z)
	if zone == "" {
		return snapshot{}, dnsprovider.ErrNotFound
	}

	soa, err := p.soa(ctx, zone)
	if err != nil {
		return snapshot{}, err
	}

	s := snapshot{zone: zone, defaultTTL: uint32(soa.TTL), serial: soa.serial()}

	var q url.Values
	if typ != "" {
		q = url.Values{"fieldType": {typ}}
	}

	var ids *[]int64
	if err := p.do(ctx, http.MethodGet, zonePath(zone)+"/record", q, nil, &ids); err != nil {
		return snapshot{}, err
	}

	if ids == nil {
		return snapshot{}, errors.New("ovhcloud: malformed record listing")
	}

	seen := map[int64]bool{}
	for _, id := range *ids {
		if id <= 0 {
			return snapshot{}, errors.New("ovhcloud: malformed record listing")
		}

		if seen[id] {
			return snapshot{}, fmt.Errorf("ovhcloud: record listing repeats %d: %w", id, rest.ErrSamePage)
		}

		seen[id] = true
	}

	s.entries = make([]storedRecord, len(*ids))

	errs := make([]error, len(*ids))
	next := make(chan int)

	var wg sync.WaitGroup

	for range min(readWorkers, len(*ids)) {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range next {
				s.entries[i], errs[i] = p.record(ctx, zone, s.defaultTTL, (*ids)[i])
			}
		}()
	}

	for i := range *ids {
		next <- i
	}

	close(next)
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		return snapshot{}, err
	}

	return s, nil
}

func recordPath(zone string, id int64) string {
	return zonePath(zone) + "/record/" + strconv.FormatInt(id, 10)
}

func (p *Provider) record(ctx context.Context, zone string, defaultTTL uint32, id int64) (storedRecord, error) {
	var w wireRecord
	if err := p.do(ctx, http.MethodGet, recordPath(zone, id), nil, nil, &w); err != nil {
		return storedRecord{}, err
	}

	if w.ID != id {
		return storedRecord{}, fmt.Errorf("ovhcloud: record %d answered as %d", id, w.ID)
	}

	return publicRecord(zone, defaultTTL, w)
}

func publicRecord(zone string, defaultTTL uint32, w wireRecord) (storedRecord, error) {
	if w.ID <= 0 || w.FieldType == "" || w.Target == nil || (w.Zone != "" && names.ZoneName(w.Zone) != zone) {
		return storedRecord{}, fmt.Errorf("ovhcloud: malformed record %d", w.ID)
	}

	ttl := defaultTTL
	if !w.inherited() {
		if *w.TTL < 0 || *w.TTL > math.MaxUint32 {
			return storedRecord{}, fmt.Errorf("ovhcloud: malformed record %d TTL", w.ID)
		}

		ttl = uint32(*w.TTL)
	}

	typ := strings.ToUpper(w.FieldType)

	return storedRecord{wire: w, record: dnsprovider.Record{
		ID:    strconv.FormatInt(w.ID, 10),
		Type:  typ,
		Name:  strings.ToLower(names.AbsoluteName(zone, w.sub())),
		Value: readValue(zone, typ, *w.Target),
		TTL:   ttl,
	}}, nil
}

// Records lists the Zone's record IDs and reads each Record. A type
// filter of a native record type is pushed down; every other filter is
// applied locally.
func (p *Provider) Records(ctx context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	typ := strings.ToUpper(f.Type)
	if !slices.Contains(fieldTypes, typ) {
		typ = ""
	}

	s, err := p.read(ctx, z, typ)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	out := dnsprovider.RecordSet{Records: []dnsprovider.Record{}, Serial: s.serial}

	for _, e := range s.entries {
		if dnsprovider.MatchRecord(f, e.record) {
			out.Records = append(out.Records, e.record)
		}
	}

	return out, nil
}

// readValue turns a native target into zone-file presentation: host
// names relative to the Zone become absolute, and unquoted text is
// quoted.
func readValue(zone, typ, value string) string {
	return presentValue(typ, value, func(v string) string {
		switch {
		case v == "." || strings.HasSuffix(v, "."):
			return strings.ToLower(v)
		case v == "@" || v == "":
			return zone + "."
		}

		return strings.ToLower(v) + "." + zone + "."
	})
}
