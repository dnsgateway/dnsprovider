package internetbs

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

func prepare(zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	if err := checkZone(zone); err != nil {
		return dnsprovider.Record{}, err
	}
	r.Type = strings.ToUpper(r.Type)
	if !slices.Contains([]string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}, r.Type) {
		return dnsprovider.Record{}, fmt.Errorf("internetbs: cannot write %s records", r.Type)
	}
	name, err := dnsprovider.QualifyName(names.ZoneName(zone.Name), r.Name)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	r.Name = names.ZoneName(name)
	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return dnsprovider.Record{}, err
	}
	if err := dnsprovider.DefaultTTLRange.Check(r.TTL); err != nil {
		return dnsprovider.Record{}, err
	}
	switch r.Type {
	case "CNAME", "NS":
		r.Value = target(r.Value)
	case "MX":
		parts := strings.Fields(r.Value)
		priority, _ := strconv.ParseUint(parts[0], 10, 16)
		r.Value = fmt.Sprintf("%d %s", priority, target(parts[1]))
	}
	return r, nil
}

func metadata(r dnsprovider.Record) map[string]string {
	extra := maps.Clone(r.Extras)
	delete(extra, ExtraWireValue)
	return extra
}

func params(r dnsprovider.Record, prefix string, selector bool) url.Values {
	form := url.Values{"FullRecordName": {r.Name}, "Type": {r.Type}, prefix + "Ttl": {strconv.FormatUint(uint64(r.TTL), 10)}}
	value := r.Value
	if r.Type == "MX" {
		priority, host, _ := strings.Cut(value, " ")
		form.Set(prefix+"Priority", priority)
		value = host
	}
	if selector && r.Extras[ExtraWireValue] != "" {
		value = r.Extras[ExtraWireValue]
	}
	form.Set(prefix+"Value", value)
	return form
}

func rejectConflict(records []dnsprovider.Record, r dnsprovider.Record, excluded int) error {
	for i, existing := range records {
		if i != excluded && dnsprovider.SameRecord(existing, r) {
			return fmt.Errorf("internetbs: duplicate record: %w", dnsprovider.ErrConflict)
		}
	}
	return nil
}

func selectRecord(records []dnsprovider.Record, before dnsprovider.Record) (int, error) {
	index := -1
	for i, r := range records {
		matched := r.ID == before.ID
		if before.ID == "" {
			matched = dnsprovider.SameRecord(r, before) && r.TTL == before.TTL && r.Extras[ExtraWireValue] == before.Extras[ExtraWireValue]
		}
		if matched {
			if index >= 0 {
				return -1, fmt.Errorf("internetbs: ambiguous record selection: %w", dnsprovider.ErrConflict)
			}
			index = i
		}
	}
	if index < 0 {
		return -1, fmt.Errorf("internetbs: record selection: %w", dnsprovider.ErrNotFound)
	}
	return index, nil
}

func definitive(err error) bool {
	var api *dnsprovider.APIError
	return errors.As(err, &api) && api.StatusCode == 0
}

func mutationError(command string, err error) error {
	if definitive(err) {
		return fmt.Errorf("internetbs: %s rejected; %w", command, err)
	}
	return fmt.Errorf("internetbs: %s completion uncertain; refresh records: %w", command, err)
}

func (p *Provider) stored(ctx context.Context, zone dnsprovider.Zone, want dnsprovider.Record) (dnsprovider.Record, error) {
	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.Record{}, fmt.Errorf("internetbs: mutation acknowledged but readback failed; refresh records: %w", err)
	}
	var matches []dnsprovider.Record
	for _, r := range records {
		if dnsprovider.SameRecord(r, want) {
			matches = append(matches, r)
		}
	}
	if len(matches) != 1 {
		return dnsprovider.Record{}, fmt.Errorf("internetbs: mutation acknowledged but readback missing or ambiguous (%d matches); refresh records", len(matches))
	}
	return matches[0], nil
}

// CreateRecord adds a supported record and returns the stored record after readback.
func (p *Provider) CreateRecord(ctx context.Context, zone dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	r, err := prepare(zone, r)
	if err != nil {
		return dnsprovider.Record{}, p.cleanError(err)
	}
	if len(metadata(r)) > 0 {
		return dnsprovider.Record{}, errors.New("internetbs: cannot create record metadata")
	}
	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	if err := rejectConflict(records, r, -1); err != nil {
		return dnsprovider.Record{}, err
	}
	if _, err := p.call(ctx, "Domain/DnsRecord/Add", params(r, "", false)); err != nil {
		return dnsprovider.Record{}, mutationError("add", err)
	}
	return p.stored(ctx, zone, r)
}

// DeleteRecord removes exactly the selected record with its complete selectors.
func (p *Provider) DeleteRecord(ctx context.Context, zone dnsprovider.Zone, before dnsprovider.Record) error {
	if !slices.Contains([]string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}, strings.ToUpper(before.Type)) {
		return errors.New("internetbs: unsupported record deletion")
	}
	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return err
	}
	index, err := selectRecord(records, before)
	if err != nil {
		return err
	}
	if !slices.Contains([]string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}, records[index].Type) {
		return errors.New("internetbs: unsupported source record deletion")
	}
	_, err = p.call(ctx, "Domain/DnsRecord/Remove", params(records[index], "", true))
	if err != nil {
		return mutationError("remove", err)
	}
	return nil
}

// UpdateRecord uses precise native updates for value/TTL edits and checked
// replacement for owner/type moves. Replacement is not atomic.
func (p *Provider) UpdateRecord(ctx context.Context, zone dnsprovider.Zone, before, after dnsprovider.Record) (dnsprovider.Record, error) {
	after, err := prepare(zone, after)
	if err != nil {
		return dnsprovider.Record{}, p.cleanError(err)
	}
	records, err := p.listRecords(ctx, zone)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	index, err := selectRecord(records, before)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	source := records[index]
	if !slices.Contains([]string{"A", "AAAA", "CNAME", "MX", "TXT", "NS"}, source.Type) {
		return dnsprovider.Record{}, errors.New("internetbs: unsupported source record")
	}
	if !maps.Equal(metadata(source), metadata(after)) {
		return dnsprovider.Record{}, errors.New("internetbs: cannot change record metadata")
	}
	if err := rejectConflict(records, after, index); err != nil {
		return dnsprovider.Record{}, err
	}
	if source.Name == after.Name && source.Type == after.Type {
		form := params(source, "Current", true)
		for k, v := range params(after, "New", false) {
			if strings.HasPrefix(k, "New") {
				form[k] = v
			}
		}
		if _, err := p.call(ctx, "Domain/DnsRecord/Update", form); err != nil {
			return dnsprovider.Record{}, mutationError("update", err)
		}
		return p.stored(ctx, zone, after)
	}
	if len(metadata(source)) > 0 {
		return dnsprovider.Record{}, errors.New("internetbs: cannot reproduce metadata during replacement")
	}
	return p.replace(ctx, zone, source, after)
}

func (p *Provider) replace(ctx context.Context, zone dnsprovider.Zone, source, after dnsprovider.Record) (dnsprovider.Record, error) {
	if _, err := p.call(ctx, "Domain/DnsRecord/Remove", params(source, "", true)); err != nil {
		return dnsprovider.Record{}, mutationError("replacement remove", err)
	}
	_, addErr := p.call(ctx, "Domain/DnsRecord/Add", params(after, "", false))
	if addErr == nil {
		return p.stored(ctx, zone, after)
	}
	if !definitive(addErr) {
		records, err := p.listRecords(ctx, zone)
		if err != nil {
			return dnsprovider.Record{}, fmt.Errorf("internetbs: replacement add completion uncertain; original removed; readback failed: %w", errors.Join(addErr, err))
		}
		for _, r := range records {
			if dnsprovider.SameRecord(r, after) || dnsprovider.SameRecord(r, source) {
				return dnsprovider.Record{}, fmt.Errorf("internetbs: replacement add completion uncertain; no restoration attempted; refresh records: %w", addErr)
			}
		}
	}
	// A verified rejection or complete read proving both source and destination
	// absent makes restoring the retained original safe to attempt once.
	_, restoreErr := p.call(ctx, "Domain/DnsRecord/Add", params(source, "", true))
	if restoreErr != nil {
		return dnsprovider.Record{}, fmt.Errorf("internetbs: replacement failed; original removed; restoration failed (%s): %w", mutationError("restore", restoreErr), errors.Join(addErr, restoreErr))
	}
	if _, err := p.stored(ctx, zone, source); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("internetbs: replacement failed; restoration acknowledged: %w", errors.Join(addErr, err))
	}
	return dnsprovider.Record{}, fmt.Errorf("internetbs: replacement failed; original restored: %w", addErr)
}

// Factory builds an account from its two secret API credential fields.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{{Name: FieldKey, Label: "API key", Secret: true}, {Name: FieldPassword, Label: "API password", Secret: true}}
	return fields.Factory("internetbs", fs, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Key: m[FieldKey], Password: m[FieldPassword]}, opts...)
	})
}
