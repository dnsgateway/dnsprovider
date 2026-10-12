package dnsimple

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

var _ dnsprovider.Provider = (*Provider)(nil)

func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "dnsimple", BaseURL: p.baseURL, HTTP: p.client, Limit: p.limit, Log: p.log,
		Auth:    func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+p.token) },
		Secrets: []string{p.token}, Decode: p.apiError,
	}
}

func (p *Provider) apiError(res *http.Response, body []byte) error {
	var payload struct {
		Message string              `json:"message"`
		Errors  map[string][]string `json:"errors"`
	}
	_ = json.Unmarshal(body, &payload)
	e := &dnsprovider.APIError{Provider: "dnsimple", StatusCode: res.StatusCode}
	if payload.Message != "" {
		e.Messages = append(e.Messages, payload.Message)
	}
	for _, key := range slices.Sorted(maps.Keys(payload.Errors)) {
		for _, msg := range payload.Errors[key] {
			e.Messages = append(e.Messages, key+": "+msg)
		}
	}
	switch res.StatusCode {
	case http.StatusConflict:
		e.Kind = dnsprovider.ErrConflict
	case http.StatusPaymentRequired, http.StatusPreconditionFailed:
		e.Kind = dnsprovider.ErrUnauthorized
	}
	if res.StatusCode == http.StatusTooManyRequests {
		e.RetryAfter = rest.RetryAfter(res.Header.Get("Retry-After"), time.Now())
		if e.RetryAfter == 0 {
			if reset, err := strconv.ParseInt(res.Header.Get("X-Ratelimit-Reset"), 10, 64); err == nil {
				e.RetryAfter = max(time.Until(time.Unix(reset, 0)), 0)
			}
		}
	}
	return e
}

type pagination struct {
	CurrentPage int `json:"current_page"`
	PerPage     int `json:"per_page"`
	TotalPages  int `json:"total_pages"`
}

// data requires the documented success envelope, never treating a missing
// data field or an error-shaped success as an empty result.
func (p *Provider) data(ctx context.Context, method, path string, q url.Values, body, out any) (*pagination, error) {
	var raw []byte
	if err := p.api().Do(ctx, method, path, q, body, &raw); err != nil {
		return nil, err
	}
	var envelope struct {
		Data       json.RawMessage `json:"data"`
		Pagination *pagination     `json:"pagination"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("dnsimple: malformed response for %s", path)
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, fmt.Errorf("dnsimple: missing data for %s", path)
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		return nil, fmt.Errorf("dnsimple: malformed data for %s", path)
	}
	return envelope.Pagination, nil
}

// list uses DNSimple's total_pages rather than guessing from page length.
// The shared pager detects repeated contents even when page numbers advance.
func list[T any](ctx context.Context, p *Provider, path string, optionalPagination bool) ([]T, error) {
	done := false
	pages, err := rest.Pages(1, nil, func(pg rest.Page) ([][]T, error) {
		if done {
			return nil, nil
		}
		var items []T
		meta, err := p.data(ctx, http.MethodGet, path, url.Values{"page": {strconv.Itoa(pg.Number)}, "per_page": {"100"}}, nil, &items)
		if err != nil {
			return nil, err
		}
		if meta == nil {
			if !optionalPagination {
				return nil, errors.New("dnsimple: missing pagination")
			}
			done = true
		} else {
			if meta.CurrentPage != pg.Number || meta.PerPage < 1 || meta.TotalPages < 0 || (meta.TotalPages < pg.Number && len(items) > 0) {
				return nil, errors.New("dnsimple: inconsistent pagination")
			}
			done = pg.Number >= meta.TotalPages
		}
		if len(items) == 0 && !done {
			return nil, errors.New("dnsimple: empty intermediate page")
		}
		return [][]T{items}, nil
	})
	if err != nil {
		return nil, err
	}
	var out []T
	for _, page := range pages {
		out = append(out, page...)
	}
	return out, nil
}

type wireAccount struct {
	ID    uint64 `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Account verifies the identity, membership and Zone-read access even when
// the configured Account has no Zones. User identities do not select a Tenant.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var identity struct {
		Account *wireAccount `json:"account"`
		User    *wireAccount `json:"user"`
	}
	if _, err := p.data(ctx, http.MethodGet, "/whoami", nil, nil, &identity); err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	if identity.Account == nil && identity.User == nil {
		return dnsprovider.AccountInfo{}, errors.New("dnsimple: missing authenticated identity")
	}
	unauthorized := &dnsprovider.APIError{Provider: "dnsimple", Kind: dnsprovider.ErrUnauthorized, Messages: []string{"token cannot access the configured Account"}}
	if identity.Account != nil && strconv.FormatUint(identity.Account.ID, 10) != p.accountID {
		return dnsprovider.AccountInfo{}, unauthorized
	}
	accounts, err := list[wireAccount](ctx, p, "/accounts", true)
	if err != nil {
		return dnsprovider.AccountInfo{}, err
	}
	for _, a := range accounts {
		if strconv.FormatUint(a.ID, 10) != p.accountID {
			continue
		}
		if _, err := p.zoneList(ctx, dnsprovider.ZoneFilter{}); err != nil {
			return dnsprovider.AccountInfo{}, err
		}
		name := a.Name
		if name == "" {
			name = a.Email
		}
		return dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: p.accountID, Name: name}}, nil
	}
	return dnsprovider.AccountInfo{}, unauthorized
}

type wireZone struct {
	ID        uint64 `json:"id"`
	AccountID uint64 `json:"account_id"`
	Name      string `json:"name"`
	Active    *bool  `json:"active"`
}

func (p *Provider) zone(w wireZone) (dnsprovider.Zone, error) {
	if w.ID == 0 || w.Name == "" || strconv.FormatUint(w.AccountID, 10) != p.accountID {
		return dnsprovider.Zone{}, errors.New("dnsimple: malformed or out-of-account Zone")
	}
	z := dnsprovider.Zone{ID: strconv.FormatUint(w.ID, 10), Name: names.ZoneName(w.Name), State: dnsprovider.HostingUnknown}
	if w.Active != nil && *w.Active {
		z.State = dnsprovider.HostingActive
	}
	return z, nil
}

// ListZones implements dnsprovider.Provider: the Account's Zones that match
// the filter.
// The ZoneSet is a Full View.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	zs, err := p.zoneList(ctx, f)

	return dnsprovider.ZoneSet{Zones: zs}, err
}

// zoneList lists the Zones that Zones returns, as a bare slice: Zones
// wraps it in a ZoneSet, while Account calls it to prove read access.
func (p *Provider) zoneList(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	all, err := list[wireZone](ctx, p, "/"+p.accountID+"/zones", false)
	if err != nil {
		return nil, err
	}
	out := make([]dnsprovider.Zone, 0, len(all))
	for _, w := range all {
		z, err := p.zone(w)
		if err != nil {
			return nil, err
		}
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}
	return out, nil
}

func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)
	if name == "" {
		return dnsprovider.Zone{}, fmt.Errorf("dnsimple: empty Zone: %w", dnsprovider.ErrNotFound)
	}
	var w wireZone
	if _, err := p.data(ctx, http.MethodGet, "/"+p.accountID+"/zones/"+url.PathEscape(name), nil, nil, &w); err != nil {
		return dnsprovider.Zone{}, err
	}
	z, err := p.zone(w)
	if err != nil {
		return dnsprovider.Zone{}, err
	}
	if z.Name != name {
		return dnsprovider.Zone{}, errors.New("dnsimple: response names a different Zone")
	}
	return z, nil
}

const (
	// ExtraRegions is the JSON array of existing regional placements (read-only).
	ExtraRegions = "regions"
	// ExtraSystemRecord identifies service-managed Records (read-only).
	ExtraSystemRecord = "system_record"
	// ExtraParentID identifies service-managed child Records (read-only).
	ExtraParentID = "parent_id"
)

// Pointers distinguish required fields absent or null in malformed answers
// from the legitimate empty apex, empty text and zero-second TTL.
type wireRecord struct {
	ID       uint64   `json:"id"`
	ZoneID   string   `json:"zone_id"`
	Name     *string  `json:"name"`
	Type     string   `json:"type"`
	Content  *string  `json:"content"`
	TTL      *uint32  `json:"ttl"`
	Priority *uint16  `json:"priority"`
	Regions  []string `json:"regions"`
	System   bool     `json:"system_record"`
	ParentID *uint64  `json:"parent_id"`
}

func toRecord(zone string, w wireRecord) (dnsprovider.Record, error) {
	if w.ID == 0 || w.Type == "" || w.Name == nil || w.Content == nil || w.TTL == nil || names.ZoneName(w.ZoneID) != names.ZoneName(zone) {
		return dnsprovider.Record{}, errors.New("dnsimple: malformed or out-of-zone Record")
	}
	r := dnsprovider.Record{
		ID: strconv.FormatUint(w.ID, 10), Type: w.Type, Name: names.AbsoluteName(names.ZoneName(zone), *w.Name), Value: *w.Content, TTL: *w.TTL,
		Extras: map[string]string{ExtraSystemRecord: strconv.FormatBool(w.System)},
	}
	if len(w.Regions) > 0 {
		regions, _ := json.Marshal(w.Regions)
		r.Extras[ExtraRegions] = string(regions)
	}
	if w.ParentID != nil {
		r.Extras[ExtraParentID] = strconv.FormatUint(*w.ParentID, 10)
	}
	if w.Type == "MX" || w.Type == "SRV" {
		if w.Priority == nil {
			return dnsprovider.Record{}, errors.New("dnsimple: missing Record priority")
		}
		r.Value = fmt.Sprintf("%d %s", *w.Priority, *w.Content)
	}
	return r, nil
}

func (p *Provider) recordPath(z dnsprovider.Zone) string {
	return "/" + p.accountID + "/zones/" + url.PathEscape(names.ZoneName(z.Name)) + "/records"
}

func (p *Provider) ListRecords(ctx context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	all, err := list[wireRecord](ctx, p, p.recordPath(z), false)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}
	out := make([]dnsprovider.Record, 0, len(all))
	var serial uint32
	for _, w := range all {
		r, err := toRecord(z.Name, w)
		if err != nil {
			return dnsprovider.RecordSet{}, err
		}
		if r.Type == "SOA" && strings.EqualFold(r.Name, names.ZoneName(z.Name)) {
			fs := strings.Fields(r.Value)
			if len(fs) == 7 {
				if n, err := strconv.ParseUint(fs[2], 10, 32); err == nil {
					serial = uint32(n)
				}
			}
		}
		if dnsprovider.MatchRecord(f, r) {
			out = append(out, r)
		}
	}
	return dnsprovider.RecordSet{Records: out, Serial: serial}, nil
}
