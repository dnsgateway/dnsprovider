package godaddy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/charstr"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// recordsPerPage is the largest page GoDaddy serves for records.
var recordsPerPage = 100

// wireRecord is a v3 DNS record. Its name is relative to the domain, "@"
// for the apex. An SRV record's owner name is its service, protocol and
// name; its target is the data. A CAA record's flag and tag are fields of
// their own; its data is the value.
type wireRecord struct {
	RecordID string  `json:"recordId,omitempty"`
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Data     string  `json:"data"`
	TTL      uint32  `json:"ttl"`
	Priority *uint64 `json:"priority,omitempty"`
	Weight   *uint64 `json:"weight,omitempty"`
	Port     *uint64 `json:"port,omitempty"`
	Service  string  `json:"service,omitempty"`
	Protocol string  `json:"protocol,omitempty"`
	Flag     *uint64 `json:"flag,omitempty"`
	Tag      string  `json:"tag,omitempty"`
}

// recordTypes are the types GoDaddy holds, and filters a list by; any
// other type is filtered here.
var recordTypes = []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "SRV", "TXT"}

// ListRecords implements dnsprovider.Provider. GoDaddy filters the list by
// a type it holds; a type it does not hold is filtered here, from the
// whole list, so it finds none rather than failing. The name filter, and
// the type again, are applied with dnsprovider.MatchRecord. GoDaddy
// reports no SOA serial: query the Zone's nameservers for it.
func (p *Provider) ListRecords(ctx context.Context, zone dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	typ := strings.ToUpper(f.Type)
	if !slices.Contains(recordTypes, typ) {
		typ = ""
	}

	all, err := p.listRecords(ctx, zone, typ)
	if err != nil {
		return dnsprovider.RecordSet{}, p.notServed(ctx, zone, err)
	}

	records := make([]dnsprovider.Record, 0, len(all))
	for _, w := range all {
		if rec := toRecord(zone.Name, w); dnsprovider.MatchRecord(f, rec) {
			records = append(records, rec)
		}
	}

	return dnsprovider.RecordSet{Records: records}, nil
}

// notServed turns the not-found of a Zone's records into ErrNotServed when
// the Account still holds the domain: GoDaddy keeps no zone file for a
// domain it registers while its Delegation names other nameservers. A
// domain gone from the Account, and any other error, is left as it is.
func (p *Provider) notServed(ctx context.Context, zone dnsprovider.Zone, err error) error {
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		return err
	}

	if _, zerr := p.GetZone(ctx, zone.Name); zerr != nil {
		return err
	}

	return fmt.Errorf("godaddy: zone %q: %w: %w", zone.Name, dnsprovider.ErrNotServed, err)
}

// recordsPath is the path of a Zone's records.
func recordsPath(zone dnsprovider.Zone) string {
	return "/zones/" + url.PathEscape(zone.ID) + "/dns-records"
}

// listRecords reads every page of a domain's records, only those of a
// type when typ is set. Pages are numbered from 1; the page without a
// rel=next link is the last.
func (p *Provider) listRecords(ctx context.Context, zone dnsprovider.Zone, typ string) ([]wireRecord, error) {
	last := false

	records, err := rest.Pages(recordsPerPage, nil, func(pg rest.Page) ([]wireRecord, error) {
		if last {
			return nil, nil
		}

		q := url.Values{"page": {strconv.Itoa(pg.Number)}, "pageSize": {strconv.Itoa(pg.Size)}}
		if typ != "" {
			q.Set("type", typ)
		}

		var page struct {
			Items []wireRecord `json:"items"`
			Links []wireLink   `json:"links"`
		}
		if err := p.api().Do(ctx, http.MethodGet, recordsPath(zone), q, nil, &page); err != nil {
			return nil, err
		}

		last = next(page.Links) == ""

		return page.Items, nil
	})
	if errors.Is(err, rest.ErrSamePage) {
		return nil, fmt.Errorf("godaddy: the records of %s: %w", zone.Name, err)
	}

	return records, err
}

// toRecord turns a v3 record into a Record of a Zone, with an absolute
// name, its recordId as its ID, and its Value in presentation form: the
// MX and SRV priority first, and a CAA flag and tag first.
func toRecord(zone string, w wireRecord) dnsprovider.Record {
	name := w.Name
	if w.Type == "SRV" && w.Service != "" && w.Protocol != "" {
		name = underscore(w.Service) + "." + underscore(w.Protocol) + "." + name
	}

	rec := dnsprovider.Record{ID: w.RecordID, Type: w.Type, Name: names.AbsoluteName(zone, name), Value: w.Data, TTL: w.TTL}

	// GoDaddy writes a target at the Zone apex as "@".
	target := w.Data
	if target == "@" {
		target = zone
	}

	num := func(n *uint64) uint64 {
		if n == nil {
			return 0
		}

		return *n
	}

	switch w.Type {
	case "CNAME", "NS":
		rec.Value = target
	case "MX":
		rec.Value = fmt.Sprintf("%d %s", num(w.Priority), target)
	case "SRV":
		rec.Value = fmt.Sprintf("%d %d %d %s", num(w.Priority), num(w.Weight), num(w.Port), target)
	case "CAA":
		if w.Tag != "" {
			rec.Value = fmt.Sprintf("%d %s %s", num(w.Flag), w.Tag, charstr.Quote(w.Data))
		}
	}

	return rec
}

// underscore puts the leading underscore on an SRV service or protocol.
func underscore(s string) string {
	if strings.HasPrefix(s, "_") {
		return s
	}

	return "_" + s
}

// toWire undoes what toRecord does: the MX and SRV priority, and the SRV
// weight and port, leave the Value for their own fields, so do a CAA flag
// and tag, and an SRV Record's service and protocol leave its name.
func toWire(zone string, r dnsprovider.Record) (wireRecord, error) {
	w := wireRecord{Type: r.Type, Name: names.RelativeName(zone, r.Name), Data: r.Value, TTL: r.TTL}

	f := strings.Fields(r.Value)
	bad := fmt.Errorf("godaddy: %s value %q is not in presentation form", r.Type, r.Value)

	var nums []uint64

	// num parses the first n fields as numbers of up to bits bits.
	num := func(n, bits int) bool {
		if len(f) < n {
			return false
		}

		for _, s := range f[:n] {
			v, err := strconv.ParseUint(s, 10, bits)
			if err != nil {
				return false
			}

			nums = append(nums, v)
		}

		return true
	}

	switch r.Type {
	case "MX":
		if len(f) != 2 || !num(1, 16) {
			return w, bad
		}

		w.Priority, w.Data = &nums[0], f[1]
	case "SRV":
		if len(f) != 4 || !num(3, 16) {
			return w, bad
		}

		service, protocol, host := splitSRVName(w.Name)
		if service == "" {
			return w, fmt.Errorf("godaddy: SRV name %s does not start with _service._protocol", r.Name)
		}

		w.Priority, w.Weight, w.Port, w.Data = &nums[0], &nums[1], &nums[2], f[3]
		w.Service, w.Protocol, w.Name = service, protocol, host
	case "CAA":
		flag, rest, ok := strings.Cut(strings.TrimSpace(r.Value), " ")
		tag, value, ok2 := strings.Cut(strings.TrimSpace(rest), " ")
		if !ok || !ok2 {
			return w, bad
		}

		f = []string{flag}
		if !num(1, 8) {
			return w, bad
		}

		data, err := charstr.Unquote(strings.TrimSpace(value))
		if err != nil {
			data = strings.TrimSpace(value)
		}

		w.Flag, w.Tag, w.Data = &nums[0], strings.ToLower(tag), data
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
