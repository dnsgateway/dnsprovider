// Package godaddy is the GoDaddy Provider, on the v3 Domains API over
// the shared rest client: GoDaddy has no maintained Go SDK.
package godaddy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// DefaultBaseURL is the GoDaddy production API.
const DefaultBaseURL = "https://api.godaddy.com"

// DefaultRequestTimeout bounds each request to the GoDaddy API.
const DefaultRequestTimeout = 30 * time.Second

// apiPath is where the v3 Domains API is, below the base URL.
const apiPath = "/v3/domains"

// domainsPerPage is the largest page GoDaddy serves for domains.
var domainsPerPage = 200

// Config is a GoDaddy Account's credentials.
type Config struct {
	// Token is a personal access token with the domains.domain:read
	// scope, and domains.dns:update for writes. Required. The v3 API
	// takes no API key and secret.
	Token string
}

// FieldToken is the field name of Config.Token in Factory's field map.
const FieldToken = "token"

// Factory builds the GoDaddy Provider from a field map, for a
// dnsprovider.Registry.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{{Name: FieldToken, Label: "Personal access token", Secret: true}}

	return fields.Factory("godaddy", fs, traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Token: m[FieldToken]}, opts...)
	})
}

// traits are the Traits of every Provider, which Traits and Factory
// report.
var traits = dnsprovider.Traits{Capabilities: []dnsprovider.Capability{dnsprovider.CapBatcher}, TTL: ttlRange}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}

// New builds the GoDaddy Provider for an Account, without a network call.
// Without WithBaseURL it talks to DefaultBaseURL; without WithHTTPClient
// each request times out after DefaultRequestTimeout.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if cfg.Token == "" {
		return nil, errors.New("godaddy: the personal access token is required")
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

	baseURL = strings.TrimSuffix(baseURL, "/")

	// The token is marked secret: the Account is named by its hash.
	tokenHash := sha256.Sum256([]byte(cfg.Token))

	return &Provider{
		baseURL: baseURL,
		auth:    "Bearer " + cfg.Token,
		secrets: []string{cfg.Token},
		client:  client,
		limit:   rest.AccountPerMinute("godaddy "+baseURL+" "+hex.EncodeToString(tokenHash[:]), RequestsPerMinute),
		log:     o.Logger,
	}, nil
}

// RequestsPerMinute is GoDaddy's published rate limit for a credential.
// Every Provider built for the same token and endpoint shares it.
const RequestsPerMinute = 60

// Provider is one GoDaddy Account.
type Provider struct {
	dnsprovider.UnimplementedZoneWrites
	dnsprovider.UnimplementedZoneDetails
	dnsprovider.UnimplementedTenants
	dnsprovider.UnimplementedDelegationSigners

	baseURL string
	auth    string
	secrets []string
	client  *http.Client
	limit   *rest.Window
	log     *slog.Logger
}

// api is the Account's rest.Client. It is built per call, not held: its
// Auth and Decode are funcs, which reflect.DeepEqual never finds equal, and
// two Providers built alike must be equal.
func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "godaddy",
		BaseURL:  p.baseURL + apiPath,
		HTTP:     p.client,
		Auth:     func(r *http.Request) { r.Header.Set("Authorization", p.auth) },
		Secrets:  p.secrets,
		Limit:    p.limit,
		Decode:   apiError,
		Log:      p.log,
	}
}

var _ dnsprovider.Provider = (*Provider)(nil)

// ttlRange is the TTLRange of every Provider, which its Traits
// report: a GoDaddy TTL is at least 600 seconds.
var ttlRange = dnsprovider.TTLRange{Min: 600, Max: 86400}

// wireDomain is the part of a v3 domain that the adapter reads.
type wireDomain struct {
	Domain      string   `json:"domain"`
	Status      string   `json:"status"`
	NameServers []string `json:"nameServers"`
}

// wireLink is a v3 HATEOAS link.
type wireLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

// next is the href of the rel=next link; empty on the last page.
func next(links []wireLink) string {
	for _, l := range links {
		if l.Rel == "next" {
			return l.Href
		}
	}

	return ""
}

// ListZones implements dnsprovider.Provider: the ACTIVE domains of the
// Account whose names match the filter. The API has no name filter, so
// every page is read and filtered with dnsprovider.MatchZone. A Zone's
// Hosting State follows its Delegation; see hostingState.
// The ZoneSet is a Full View.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	all, err := p.listDomains(ctx)
	if err != nil {
		return dnsprovider.ZoneSet{}, err
	}

	out := make([]dnsprovider.Zone, 0, len(all))
	for _, d := range all {
		if z := toZone(d); dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}

	return dnsprovider.ZoneSet{Zones: out}, nil
}

// GetZone implements dnsprovider.Provider: the ACTIVE domain of that name,
// read with GET /domain-names/{domain}; ErrNotFound when the Account has
// no such domain, or has it in another status, which Zones does not list.
// A token GoDaddy refuses stays ErrUnauthorized; see listedDomain.
func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)
	notFound := fmt.Errorf("godaddy: zone %q: %w", name, dnsprovider.ErrNotFound)

	if name == "" {
		return dnsprovider.Zone{}, notFound
	}

	var d wireDomain

	err := p.api().Do(ctx, http.MethodGet, "/domain-names/"+url.PathEscape(name), nil, nil, &d)

	var apiErr *dnsprovider.APIError
	if errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusUnprocessableEntity) {
		d, err = p.listedDomain(ctx, name)
	}

	switch {
	case err != nil:
		return dnsprovider.Zone{}, err
	case d.Status != "ACTIVE" || names.ZoneName(d.Domain) != name:
		return dnsprovider.Zone{}, notFound
	}

	return toZone(d), nil
}

// listedDomain is the ACTIVE domain of that name in the Account's list,
// read up to the page that holds it; ErrNotFound when the list has none.
// GetZone reads it when GoDaddy answers a domain the Account does not hold
// with 403 or 422, as it may for one held by another Account, which a
// token GoDaddy refuses altogether also gets: the list tells them apart,
// failing for the token with ErrUnauthorized.
func (p *Provider) listedDomain(ctx context.Context, name string) (wireDomain, error) {
	isName := func(d wireDomain) bool { return names.ZoneName(d.Domain) == name }

	read, err := p.pageDomains(ctx, func(page []wireDomain) bool { return slices.ContainsFunc(page, isName) })
	if err != nil {
		return wireDomain{}, err
	}

	if i := slices.IndexFunc(read, isName); i >= 0 {
		return read[i], nil
	}

	return wireDomain{}, fmt.Errorf("godaddy: zone %q: %w", name, dnsprovider.ErrNotFound)
}

// toZone turns a v3 domain into a Zone.
func toZone(d wireDomain) dnsprovider.Zone {
	return dnsprovider.Zone{Name: d.Domain, ID: d.Domain, State: hostingState(d.NameServers), Nameservers: goDaddyNameservers(d.NameServers)}
}

// hostingState is the Hosting State of a domain delegated to these
// nameservers. GoDaddy lists every ACTIVE domain it registers, wherever
// it is delegated: the domain is Active while GoDaddy's nameservers answer
// for it, even in part, and Moved once Delegation names none of them, as
// GoDaddy then no longer serves it. Without nameservers it is Unknown.
func hostingState(ns []string) dnsprovider.HostingState {
	if len(ns) == 0 {
		return dnsprovider.HostingUnknown
	}

	if slices.ContainsFunc(ns, isGoDaddyNameserver) {
		return dnsprovider.HostingActive
	}

	return dnsprovider.HostingMoved
}

// isGoDaddyNameserver reports whether GoDaddy's DNS runs a nameserver.
func isGoDaddyNameserver(n string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSuffix(n, ".")), nameserverSuffix)
}

// nameserverSuffix ends the name of every GoDaddy DNS nameserver.
const nameserverSuffix = ".domaincontrol.com"

// goDaddyNameservers are a domain's nameservers, in lower case, when they
// are all GoDaddy's. A domain delegated elsewhere, even in part, has none:
// its registration names nameservers GoDaddy does not run, and the Account
// expects the ones Account reports.
func goDaddyNameservers(ns []string) []string {
	if len(ns) == 0 {
		return nil
	}

	out := make([]string, 0, len(ns))
	for _, n := range ns {
		if !isGoDaddyNameserver(n) {
			return nil
		}

		out = append(out, strings.ToLower(strings.TrimSuffix(n, ".")))
	}

	return out
}

// listDomains reads every page of the Account's ACTIVE domains.
func (p *Provider) listDomains(ctx context.Context) ([]wireDomain, error) {
	return p.pageDomains(ctx, func([]wireDomain) bool { return false })
}

// errStopPaging ends pageDomains early.
var errStopPaging = errors.New("godaddy: stop paging")

// pageDomains reads the pages of the Account's ACTIVE domains until stop,
// given each page, returns true, and returns the domains read. A page
// starts at the pageToken of the page before's rel=next link; the page
// without one is the last.
func (p *Provider) pageDomains(ctx context.Context, stop func([]wireDomain) bool) ([]wireDomain, error) {
	var (
		read  []wireDomain
		token string
		last  bool
	)

	_, err := rest.Pages(domainsPerPage, nil, func(pg rest.Page) ([]wireDomain, error) {
		if last {
			return nil, nil
		}

		q := url.Values{"statuses": {"ACTIVE"}, "pageSize": {strconv.Itoa(pg.Size)}}
		if token != "" {
			q.Set("pageToken", token)
		}

		var page struct {
			Items []wireDomain `json:"items"`
			Links []wireLink   `json:"links"`
		}
		if err := p.api().Do(ctx, http.MethodGet, "/domain-names", q, nil, &page); err != nil {
			return nil, err
		}

		read = append(read, page.Items...)

		if stop(page.Items) {
			return nil, errStopPaging
		}

		href := next(page.Links)
		if href == "" {
			last = true

			return page.Items, nil
		}

		u, err := url.Parse(href)
		if err != nil || u.Query().Get("pageToken") == "" || u.Query().Get("pageToken") == token {
			return nil, rest.ErrSamePage
		}

		token = u.Query().Get("pageToken")

		return page.Items, nil
	})

	switch {
	case errors.Is(err, errStopPaging):
		return read, nil
	case errors.Is(err, rest.ErrSamePage):
		return nil, fmt.Errorf("godaddy: the domain list: %w", err)
	case err != nil:
		return nil, err
	}

	return read, nil
}

// Account implements dnsprovider.Provider. GoDaddy has no account
// endpoint, so it reads the ACTIVE domains, which checks the token even
// when the Account has none. GoDaddy assigns each Account its own pair of
// domaincontrol.com nameservers: the ones the first domain on GoDaddy's
// DNS names, so the pages stop there. The API does not say who the
// customer is, so the Tenant is empty.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	var info dnsprovider.AccountInfo

	_, err := p.pageDomains(ctx, func(page []wireDomain) bool {
		for _, d := range page {
			if ns := goDaddyNameservers(d.NameServers); ns != nil {
				slices.Sort(ns)
				info.Nameservers = slices.Compact(ns)

				return true
			}
		}

		return false
	})
	if err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	return info, nil
}
