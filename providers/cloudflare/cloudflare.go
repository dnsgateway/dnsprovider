// Package cloudflare is the Cloudflare Provider, built on cloudflare-go
// (ADR-0003).
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/accounts"
	cfdns "github.com/cloudflare/cloudflare-go/v7/dns"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/packages/pagination"
	"github.com/cloudflare/cloudflare-go/v7/user"
	"github.com/cloudflare/cloudflare-go/v7/zones"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/internal/names"
)

// DefaultBaseURL is the Cloudflare v4 API.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4/"

// zonesPerPage is the largest page Cloudflare serves for Zones.
const zonesPerPage = 50

// accountsPerPage is the largest page Cloudflare serves for accounts.
const accountsPerPage = 50

// recordsPerPage keeps reading a large Zone's Records to a few requests.
const recordsPerPage = 1000

// Config is a Cloudflare Account's credentials.
type Config struct {
	// Token is a Cloudflare API token. Required.
	Token string
	// TenantID is the Cloudflare account the Provider acts within, 32
	// lower-case hex digits, which scopes every call. Empty until a
	// Tenant is picked, when only Account and Tenants work; see
	// ErrNoTenant.
	TenantID string
}

// Field names in Factory's field map.
const (
	FieldToken    = "token"
	FieldTenantID = "tenant_id"
)

// Factory builds the Cloudflare Provider from a field map, for a
// dnsprovider.Registry.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{
		{Name: FieldToken, Label: "API token", Secret: true},
		{Name: FieldTenantID, Label: "Account ID"},
	}

	return fields.Factory("cloudflare", fs, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Token: m[FieldToken], TenantID: m[FieldTenantID]}, opts...)
	})
}

// DefaultRequestTimeout bounds each request to the Cloudflare API. A
// failed request may be retried, each try with its own timeout.
const DefaultRequestTimeout = 30 * time.Second

// requestTimeout is DefaultRequestTimeout, which tests shorten.
var requestTimeout = DefaultRequestTimeout

// defaultHTTPClient is http.DefaultTransport with the timeouts
// cloudflare-go's own default client sets, which building the services
// from bare options leaves out.
func defaultHTTPClient() *http.Client {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{}
	}

	t = t.Clone()
	t.ResponseHeaderTimeout = requestTimeout

	return &http.Client{Transport: t}
}

// New builds the Cloudflare Provider for an Account, without a network
// call. Without WithBaseURL it talks to DefaultBaseURL; without
// WithHTTPClient each request times out after DefaultRequestTimeout.
//
// It ignores the CLOUDFLARE_* environment variables cloudflare-go reads by
// default: the Config is the only credential.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if cfg.Token == "" {
		return nil, errors.New("cloudflare: no API token")
	}

	if cfg.TenantID != "" && !isAccountID(cfg.TenantID) {
		return nil, fmt.Errorf("cloudflare: Tenant ID %q is not a Cloudflare account ID (32 lower-case hex digits)", cfg.TenantID)
	}

	o := dnsprovider.NewOptions(opts...)

	baseURL := o.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	// A consumer's client brings its own timeouts; the adapter's apply
	// only to the client it builds.
	client := o.HTTPClient

	usesOwnClient := client == nil
	if usesOwnClient {
		client = defaultHTTPClient()
	}

	ropts := []option.RequestOption{
		option.WithBaseURL(baseURL),
		option.WithAPIToken(cfg.Token),
		option.WithMiddleware(reportRateLimits),
		option.WithHTTPClient(client),
	}

	if usesOwnClient {
		ropts = append(ropts, option.WithRequestTimeout(requestTimeout))
	}

	return &Provider{
		tenantID:      cfg.TenantID,
		log:           o.Logger,
		tokens:        user.NewTokenService(ropts...),
		accountTokens: accounts.NewTokenService(ropts...),
		accounts:      accounts.NewAccountService(ropts...),
		zones:         zones.NewZoneService(ropts...),
		settings:      zones.NewSettingService(ropts...),
		records:       cfdns.NewRecordService(ropts...),
		dnssec:        cfdns.NewDNSSECService(ropts...),
	}, nil
}

// isAccountID reports whether s has the form of a Cloudflare account ID.
func isAccountID(s string) bool {
	if len(s) != 32 {
		return false
	}

	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}

// Provider is one Cloudflare Account.
//
// Every call but Account and Tenants is scoped to the Tenant: before
// Config.TenantID is set it fails with ErrNoTenant, without a request.
// The calls on a Zone trust that it came from Zones or Zone, which read
// the Tenant's Zones alone, and do not read it again to check its Tenant.
type Provider struct {
	// tenantID is the Cloudflare account calls are scoped to; empty
	// until a Tenant is picked.
	tenantID string
	log      *slog.Logger
	tokens   *user.TokenService
	// accountTokens verifies an account-owned token.
	accountTokens *accounts.TokenService
	accounts      *accounts.AccountService
	zones         *zones.ZoneService
	settings      *zones.SettingService
	records       *cfdns.RecordService
	dnssec        *cfdns.DNSSECService
}

var (
	_ dnsprovider.Provider  = (*Provider)(nil)
	_ dnsprovider.TTLLimits = (*Provider)(nil)
	_ dnsprovider.ProxyFlag = (*Provider)(nil)
	_ dnsprovider.AutoTTL   = (*Provider)(nil)

	_ dnsprovider.TenantLister     = (*Provider)(nil)
	_ dnsprovider.ZoneStatusReader = (*Provider)(nil)
)

// AutoTTL implements dnsprovider.AutoTTL: Cloudflare reads TTL 1 as automatic.
func (p *Provider) AutoTTL() bool {
	return true
}

// TTLRange implements dnsprovider.TTLLimits: below Enterprise plans, a
// Cloudflare TTL is at least 60 seconds, besides 1 for automatic.
func (p *Provider) TTLRange() (minTTL, maxTTL uint32) {
	return 60, 86400
}

// Zones implements dnsprovider.Provider: the Zones of the configured
// Tenant whose names match the filter, ErrNoTenant before one is set.
// Cloudflare filters by name itself, "contains:" ignoring case; the
// answer is filtered again with dnsprovider.MatchZone. Each Zone carries
// its Hosting State and the nameservers Cloudflare assigned to it, which
// can differ between Zones of one Account.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	name := ""
	if f.Contains != "" {
		name = "contains:" + strings.ToLower(f.Contains)
	}

	all, err := p.listZones(ctx, name)
	if err != nil {
		return nil, err
	}

	out := make([]dnsprovider.Zone, 0, len(all))
	for _, z := range all {
		zone := toZone(z)
		if dnsprovider.MatchZone(f, zone) {
			out = append(out, zone)
		}
	}

	return out, nil
}

// Zone implements dnsprovider.Provider: the Tenant's Zone of that exact
// name, read with Cloudflare's name filter; ErrNotFound when the Tenant
// has none, and ErrNoTenant before a Tenant is set.
func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)

	if err := p.needTenant(); err != nil {
		return dnsprovider.Zone{}, err
	}

	if name != "" {
		all, err := p.listZones(ctx, name)
		if err != nil {
			return dnsprovider.Zone{}, err
		}

		for _, z := range all {
			if strings.EqualFold(z.Name, name) {
				return toZone(z), nil
			}
		}
	}

	return dnsprovider.Zone{}, fmt.Errorf("cloudflare: zone %q: %w", name, dnsprovider.ErrNotFound)
}

// toZone turns a v4 zone into a Zone.
func toZone(z zones.Zone) dnsprovider.Zone {
	return dnsprovider.Zone{Name: z.Name, ID: z.ID, State: hostingState(z.Status), Nameservers: slices.Clone(z.NameServers)}
}

// zoneStatusDeactivated is a status Cloudflare documents for a Zone it
// stopped serving, which cloudflare-go's enum leaves out.
const zoneStatusDeactivated zones.ZoneStatus = "deactivated"

// hostingState is the Hosting State of a Zone in a Cloudflare status. An
// initializing Zone, just Onboarded, waits for Delegation as a pending one
// does. A deactivated Zone is Moved: Cloudflare no longer serves it, which
// is what Moved tells a consumer, whatever made Cloudflare stop.
func hostingState(s zones.ZoneStatus) dnsprovider.HostingState {
	switch s {
	case zones.ZoneStatusActive:
		return dnsprovider.HostingActive
	case zones.ZoneStatusPending, zones.ZoneStatusInitializing:
		return dnsprovider.HostingPending
	case zones.ZoneStatusMoved, zoneStatusDeactivated:
		return dnsprovider.HostingMoved
	}

	return dnsprovider.HostingUnknown
}

// listZones reads every Zone of the Tenant whose name matches a Cloudflare
// name filter; every Zone when it is empty.
func (p *Provider) listZones(ctx context.Context, name string) ([]zones.Zone, error) {
	if err := p.needTenant(); err != nil {
		return nil, err
	}

	var params zones.ZoneListParams
	params.Account.Value.ID.Value, params.Account.Value.ID.Present = p.tenantID, true
	params.Account.Present = true

	if name != "" {
		params.Name.Value, params.Name.Present = name, true
	}

	return listAll(ctx, zonesPerPage, func(opts ...option.RequestOption) (*pagination.V4PagePaginationArray[zones.Zone], error) {
		return p.zones.List(ctx, params, opts...)
	})
}

// needTenant is ErrNoTenant, wrapped, until a Tenant is set.
func (p *Provider) needTenant() error {
	if p.tenantID == "" {
		return fmt.Errorf("cloudflare: %w", ErrNoTenant)
	}

	return nil
}

// listAll reads every page of a v4 list. It pages by hand, rather than with
// cloudflare-go's auto-pager, so that later pages keep the caller's context
// and paging stops at result_info.total_pages.
func listAll[T any](ctx context.Context, perPage int, list func(...option.RequestOption) (*pagination.V4PagePaginationArray[T], error)) ([]T, error) {
	var out []T

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		var raw *http.Response

		res, err := list(
			option.WithQuery("page", strconv.Itoa(page)),
			option.WithQuery("per_page", strconv.Itoa(perPage)),
			option.WithResponseInto(&raw),
		)
		if err != nil {
			return nil, apiError(err, raw)
		}

		out = append(out, res.Result...)

		// cloudflare-go does not decode total_pages.
		total, err := strconv.Atoi(res.ResultInfo.JSON.ExtraFields["total_pages"].Raw())
		if err != nil {
			total = page
			if len(res.Result) > 0 && int64(len(res.Result)) >= res.ResultInfo.PerPage {
				total = page + 1
			}
		}

		if page >= total || len(res.Result) == 0 {
			return out, nil
		}
	}
}

// Records implements dnsprovider.Provider. The v4 API reports no SOA serial
// short of a BIND export of the whole Zone, so the RecordSet has none:
// A consumer asks the Zone's nameservers for it.
func (p *Provider) Records(ctx context.Context, zone dnsprovider.Zone) (dnsprovider.RecordSet, error) {
	if err := p.needTenant(); err != nil {
		return dnsprovider.RecordSet{}, err
	}

	// ZoneID is a param.Field, which only cloudflare-go's root package can
	// build with F(); importing that package compiles the whole SDK.
	var params cfdns.RecordListParams
	params.ZoneID.Value, params.ZoneID.Present = zone.ID, true

	all, err := listAll(ctx, recordsPerPage, func(opts ...option.RequestOption) (*pagination.V4PagePaginationArray[cfdns.RecordResponse], error) {
		return p.records.List(ctx, params, opts...)
	})
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	records := make([]dnsprovider.Record, 0, len(all))
	for _, r := range all {
		rec, err := toRecord(r)
		if err != nil {
			return dnsprovider.RecordSet{}, err
		}

		records = append(records, rec)
	}

	return dnsprovider.RecordSet{Records: records}, nil
}

// ExtraProxied is the Record extra holding Cloudflare's proxy flag, set
// only on Records of a type Cloudflare can proxy: "true" or "false". It is
// dnsprovider.ExtraProxied.
const ExtraProxied = dnsprovider.ExtraProxied

// ProxiableTypes implements dnsprovider.ProxyFlag.
func (p *Provider) ProxiableTypes() []string {
	return []string{"A", "AAAA", "CNAME"}
}

// wireRecord is the part of a v4 DNS record that the adapter reads.
//
// It is decoded from the record's raw JSON: cloudflare-go decodes records
// into an untagged union that settles on the A-record shape for every type,
// dropping type-specific fields such as the MX priority.
type wireRecord struct {
	ID        string  `json:"id"`
	Type      string  `json:"type"`
	Name      string  `json:"name"`
	Content   string  `json:"content"`
	TTL       uint32  `json:"ttl"`
	Priority  float64 `json:"priority"`
	Proxiable bool    `json:"proxiable"`
	Proxied   bool    `json:"proxied"`
}

func toRecord(r cfdns.RecordResponse) (dnsprovider.Record, error) {
	return decodeRecord([]byte(r.JSON.RawJSON()))
}

// decodeRecord decodes a v4 DNS record's JSON.
func decodeRecord(data []byte) (dnsprovider.Record, error) {
	var w wireRecord
	if err := json.Unmarshal(data, &w); err != nil {
		return dnsprovider.Record{}, fmt.Errorf("cloudflare: decode record: %w", err)
	}

	rec := dnsprovider.Record{
		ID:    w.ID,
		Type:  w.Type,
		Name:  w.Name,
		Value: w.Content,
		TTL:   w.TTL,
	}

	// Cloudflare keeps the MX, SRV and URI priority out of the content;
	// the Value is in zone-file presentation form, priority first.
	if w.Type == "MX" || w.Type == "SRV" || w.Type == "URI" {
		rec.Value = strconv.FormatFloat(w.Priority, 'f', -1, 64) + " " + w.Content
	}

	if w.Proxiable {
		rec.Extras = map[string]string{ExtraProxied: strconv.FormatBool(w.Proxied)}
	}

	return rec, nil
}

// Apply implements dnsprovider.Provider. Each change is its own API call,
// made one at a time: deletions first, then modifications, then additions,
// so a Record that takes the place of another does not collide with it. A
// failed change does not stop the others. The results are in Changeset
// order, and carry no serial: Cloudflare's API does not report it.
func (p *Provider) Apply(ctx context.Context, cs dnsprovider.Changeset) (dnsprovider.ApplyResult, error) {
	if err := p.needTenant(); err != nil {
		return dnsprovider.ApplyResult{}, err
	}

	res := dnsprovider.ApplyResult{Results: make([]dnsprovider.ChangeResult, len(cs.Changes))}

	order := make([]int, len(cs.Changes))
	for i := range order {
		order[i] = i
	}

	slices.SortStableFunc(order, func(a, b int) int {
		return applyRank(cs.Changes[a].Kind) - applyRank(cs.Changes[b].Kind)
	})

	for _, i := range order {
		c := cs.Changes[i]
		rec, err := p.applyChange(ctx, cs.Zone, c)
		res.Results[i] = dnsprovider.ChangeResult{Change: c, Record: rec, Err: err}
	}

	return res, nil
}

// applyRank is when Apply makes a change of a kind: lowest first.
func applyRank(k dnsprovider.ChangeKind) int {
	switch k {
	case dnsprovider.ChangeDelete:
		return 0
	case dnsprovider.ChangeModify:
		return 1
	default:
		return 2
	}
}

// applyChange makes one change and returns the Record as Cloudflare
// stored it; an empty Record for a deletion.
//
// A modification is a PATCH of the Record it was built from, so the
// fields the module does not model, such as a comment or tags, are kept.
func (p *Provider) applyChange(ctx context.Context, zone dnsprovider.Zone, c dnsprovider.Change) (dnsprovider.Record, error) {
	var (
		env  envelope
		raw  *http.Response
		opts = []option.RequestOption{option.WithResponseBodyInto(&env), option.WithResponseInto(&raw)}
		err  error
	)

	if c.Kind != dnsprovider.ChangeAdd && c.Before.ID == "" {
		return dnsprovider.Record{}, fmt.Errorf("cloudflare: %s %s has no record ID", c.Before.Type, c.Before.Name)
	}

	if c.Kind != dnsprovider.ChangeDelete {
		wb, err := writeBody(c.After)
		if err != nil {
			return dnsprovider.Record{}, err
		}

		// A PATCH keeps what it does not send: a Record that loses its
		// proxy flag, as it changes to a type that cannot have one, has
		// it turned off.
		if _, had := c.Before.Extras[ExtraProxied]; had && wb.Proxied == nil && c.Kind == dnsprovider.ChangeModify {
			wb.Proxied = new(bool)
		}

		body, err := json.Marshal(wb)
		if err != nil {
			return dnsprovider.Record{}, fmt.Errorf("cloudflare: encode record: %w", err)
		}

		opts = append(opts, option.WithRequestBody("application/json", body))
	}

	// tries counts the requests a change takes, retries included.
	var tries int

	opts = append(opts, option.WithMiddleware(func(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		tries++

		return next(req)
	}))

	switch c.Kind {
	case dnsprovider.ChangeAdd:
		// A create is not idempotent: a retry of one Cloudflare stored,
		// but whose answer was lost, would make a second Record.
		var params cfdns.RecordNewParams
		params.ZoneID.Value, params.ZoneID.Present = zone.ID, true
		_, err = p.records.New(ctx, params, append(opts, option.WithMaxRetries(0))...)
	case dnsprovider.ChangeModify:
		var params cfdns.RecordEditParams
		params.ZoneID.Value, params.ZoneID.Present = zone.ID, true
		_, err = p.records.Edit(ctx, c.Before.ID, params, opts...)
	case dnsprovider.ChangeDelete:
		var params cfdns.RecordDeleteParams
		params.ZoneID.Value, params.ZoneID.Present = zone.ID, true
		_, err = p.records.Delete(ctx, c.Before.ID, params, opts...)
	default:
		return dnsprovider.Record{}, fmt.Errorf("cloudflare: unknown change kind %d", c.Kind)
	}

	if err != nil {
		err = apiError(err, raw)

		// A retried delete that finds the Record gone was made by an
		// earlier try whose answer was lost.
		if c.Kind == dnsprovider.ChangeDelete && tries > 1 && errors.Is(err, dnsprovider.ErrNotFound) {
			return dnsprovider.Record{}, nil
		}

		return dnsprovider.Record{}, err
	}

	// Any 2xx is an answer; Cloudflare says in the body when it did not
	// take the change. A body without "success" took it.
	if env.Success != nil && !*env.Success {
		e := &dnsprovider.APIError{Provider: "cloudflare", StatusCode: raw.StatusCode}
		addErrors(e, env.Errors)

		return dnsprovider.Record{}, e
	}

	if c.Kind == dnsprovider.ChangeDelete {
		return dnsprovider.Record{}, nil
	}

	return decodeRecord(env.Result)
}

// envelope is the v4 response envelope of a record write.
type envelope struct {
	Success *bool           `json:"success"`
	Errors  []wireError     `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// recordBody is the body of a record create or update.
type recordBody struct {
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Content  string  `json:"content,omitempty"`
	Priority *uint64 `json:"priority,omitempty"`
	Data     any     `json:"data,omitempty"`
	TTL      uint32  `json:"ttl"`
	Proxied  *bool   `json:"proxied,omitempty"`
}

type srvData struct {
	Priority uint64 `json:"priority"`
	Weight   uint64 `json:"weight"`
	Port     uint64 `json:"port"`
	Target   string `json:"target"`
}

type uriData struct {
	Weight uint64 `json:"weight"`
	Target string `json:"target"`
}

type caaData struct {
	Flags uint64 `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// writeBody is the body that creates r, or updates a record to r. It
// undoes what decodeRecord does: the MX, SRV and URI priority leaves the
// Value for its own field, and SRV, URI and CAA Records are written as
// structured data, from which Cloudflare formats their content.
func writeBody(r dnsprovider.Record) (recordBody, error) {
	b := recordBody{Type: r.Type, Name: r.Name, TTL: r.TTL}

	if v, ok := r.Extras[ExtraProxied]; ok {
		proxied := v == "true"
		b.Proxied = &proxied
	}

	f := strings.Fields(r.Value)
	bad := fmt.Errorf("cloudflare: %s value %q is not in presentation form", r.Type, r.Value)

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
			return b, bad
		}

		b.Priority, b.Content = &nums[0], f[1]
	case "SRV":
		if len(f) != 4 || !num(3) {
			return b, bad
		}

		b.Priority = &nums[0]
		b.Data = srvData{Priority: nums[0], Weight: nums[1], Port: nums[2], Target: f[3]}
	case "URI":
		if len(f) != 3 || !num(2) {
			return b, bad
		}

		b.Priority = &nums[0]
		b.Data = uriData{Weight: nums[1], Target: unquote(f[2])}
	case "CAA":
		// CAA flags are one octet (RFC 8659).
		if len(f) < 3 || !num(1) || nums[0] > 255 {
			return b, bad
		}

		// The value is the rest of the Value, which may hold spaces.
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Value), f[0]))
		rest = strings.TrimSpace(strings.TrimPrefix(rest, f[1]))
		b.Data = caaData{Flags: nums[0], Tag: f[1], Value: unquote(rest)}
	default:
		b.Content = r.Value
	}

	return b, nil
}

// unquote strips the double quotes around a presentation-form string.
func unquote(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s[1 : len(s)-1]
	}

	return s
}

// ZoneStatus implements dnsprovider.ZoneStatusReader. DNSSEC comes from the Zone's
// DNSSEC status and HSTS from its security_header setting, read
// concurrently. A setting the API token lacks the permission to read
// (HTTP 403), or that fails to read while the other one is read, is
// unknown. It fails only when both reads fail.
func (p *Provider) ZoneStatus(ctx context.Context, zone dnsprovider.Zone) (dnsprovider.ZoneStatus, error) {
	if err := p.needTenant(); err != nil {
		return dnsprovider.ZoneStatus{}, err
	}

	var (
		status  dnsprovider.ZoneStatus
		hstsErr error
		wg      sync.WaitGroup
	)

	wg.Add(1)

	go func() {
		defer wg.Done()

		status.HSTS, hstsErr = p.hstsStatus(ctx, zone)
	}()

	dnssec, dnssecErr := p.dnssecStatus(ctx, zone)

	wg.Wait()

	if dnssecErr != nil && hstsErr != nil {
		return dnsprovider.ZoneStatus{}, errors.Join(dnssecErr, hstsErr)
	}

	status.DNSSEC = dnssec
	if dnssecErr != nil {
		status.DNSSEC = dnsprovider.Unknown
	}

	if hstsErr != nil {
		status.HSTS = dnsprovider.Unknown
	}

	return status, nil
}

func (p *Provider) dnssecStatus(ctx context.Context, zone dnsprovider.Zone) (dnsprovider.Setting, error) {
	var params cfdns.DNSSECGetParams
	params.ZoneID.Value, params.ZoneID.Present = zone.ID, true

	var raw *http.Response

	res, err := p.dnssec.Get(ctx, params, option.WithResponseInto(&raw))
	if err != nil {
		return settingError(err, raw)
	}

	// Pending and pending-disabled are being signed or unsigned; error is
	// neither signed nor unsigned.
	switch res.Status {
	case cfdns.DNSSECStatusActive:
		return dnsprovider.On, nil
	case cfdns.DNSSECStatusDisabled:
		return dnsprovider.Off, nil
	case cfdns.DNSSECStatusPending, cfdns.DNSSECStatusPendingDisabled:
		return dnsprovider.Pending, nil
	}

	return dnsprovider.Unknown, nil
}

// securityHeader is the part of the security_header setting the adapter reads.
// It is decoded from the raw JSON: cloudflare-go decodes a setting's value
// into a union of every setting's value.
type securityHeader struct {
	Value struct {
		StrictTransportSecurity struct {
			Enabled bool `json:"enabled"`
		} `json:"strict_transport_security"`
	} `json:"value"`
}

func (p *Provider) hstsStatus(ctx context.Context, zone dnsprovider.Zone) (dnsprovider.Setting, error) {
	var params zones.SettingGetParams
	params.ZoneID.Value, params.ZoneID.Present = zone.ID, true

	var raw *http.Response

	res, err := p.settings.Get(ctx, "security_header", params, option.WithResponseInto(&raw))
	if err != nil {
		return settingError(err, raw)
	}

	var h securityHeader
	if err := json.Unmarshal([]byte(res.JSON.RawJSON()), &h); err != nil {
		return dnsprovider.Unknown, fmt.Errorf("cloudflare: decode security_header setting: %w", err)
	}

	if h.Value.StrictTransportSecurity.Enabled {
		return dnsprovider.On, nil
	}

	return dnsprovider.Off, nil
}

// settingError makes a setting the API token may not read unknown, and
// any other failure an error.
func settingError(err error, res *http.Response) (dnsprovider.Setting, error) {
	if res != nil && res.StatusCode == http.StatusForbidden {
		return dnsprovider.Unknown, nil
	}

	return dnsprovider.Unknown, apiError(err, res)
}

// Account implements dnsprovider.Provider. It verifies the API token
// and, once a Tenant is set, names it. Cloudflare assigns nameservers per
// Zone, so the Account expects none of its own.
//
// With a Tenant set, the token is verified within it first, as an
// account-owned token can only be, then as a user's token. The Tenant's
// name comes from the accounts the token reaches; a token that may not
// list them, such as a DNS-only one, gets the Tenant ID alone. A Tenant a
// user's token lists no account for, or an account-owned token does not
// belong to, is ErrUnauthorized.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	owned, err := p.verifyToken(ctx)
	if err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	if p.tenantID == "" {
		return dnsprovider.AccountInfo{}, nil
	}

	tenant := dnsprovider.Tenant{ID: p.tenantID}

	tenants, err := p.Tenants(ctx)
	if errors.Is(err, dnsprovider.ErrUnauthorized) {
		return dnsprovider.AccountInfo{Tenant: tenant}, nil
	}

	if err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	if i := slices.IndexFunc(tenants, func(t dnsprovider.Tenant) bool { return t.ID == p.tenantID }); i >= 0 {
		tenant.Name = tenants[i].Name
	} else if !owned {
		return dnsprovider.AccountInfo{}, &dnsprovider.APIError{
			Provider: "cloudflare",
			Messages: []string{fmt.Sprintf("the API token does not reach account %s", p.tenantID)},
			Kind:     dnsprovider.ErrUnauthorized,
		}
	}

	return dnsprovider.AccountInfo{Tenant: tenant}, nil
}

// verifyToken checks the API token is active, and reports whether it is
// owned by the Tenant: verified within it. Before a Tenant is set, only a
// user's token can be verified.
func (p *Provider) verifyToken(ctx context.Context) (owned bool, err error) {
	var raw *http.Response

	if p.tenantID != "" {
		var params accounts.TokenVerifyParams
		params.AccountID.Value, params.AccountID.Present = p.tenantID, true

		tok, err := p.accountTokens.Verify(ctx, params, option.WithResponseInto(&raw))
		if err == nil {
			return true, tokenActive(string(tok.Status))
		}

		// A user's token is not the Tenant's: it is verified below.
		if err = apiError(err, raw); !errors.Is(err, dnsprovider.ErrUnauthorized) && !errors.Is(err, dnsprovider.ErrNotFound) {
			return false, err
		}
	}

	tok, err := p.tokens.Verify(ctx, option.WithResponseInto(&raw))
	if err != nil {
		return false, apiError(err, raw)
	}

	return false, tokenActive(string(tok.Status))
}

// tokenActive is ErrUnauthorized for a token whose status is not active.
func tokenActive(status string) error {
	if status == "active" {
		return nil
	}

	return &dnsprovider.APIError{
		Provider: "cloudflare",
		Messages: []string{fmt.Sprintf("the API token is %s", status)},
		Kind:     dnsprovider.ErrUnauthorized,
	}
}

// Tenants implements dnsprovider.TenantLister: every Cloudflare account
// the API token reaches. It works before a Tenant is set.
func (p *Provider) Tenants(ctx context.Context) ([]dnsprovider.Tenant, error) {
	all, err := listAll(ctx, accountsPerPage, func(opts ...option.RequestOption) (*pagination.V4PagePaginationArray[accounts.Account], error) {
		return p.accounts.List(ctx, accounts.AccountListParams{}, opts...)
	})
	if err != nil {
		return nil, err
	}

	out := make([]dnsprovider.Tenant, 0, len(all))
	for _, a := range all {
		out = append(out, dnsprovider.Tenant{ID: a.ID, Name: a.Name})
	}

	return out, nil
}
