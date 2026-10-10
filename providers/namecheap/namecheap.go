// Package namecheap is the Namecheap Provider, on the Namecheap XML API
// over the shared rest client's transport: Namecheap has no Go SDK of its
// own.
package namecheap

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
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

// DefaultBaseURL is the Namecheap production API endpoint. The sandbox is
// https://api.sandbox.namecheap.com/xml.response.
const DefaultBaseURL = "https://api.namecheap.com/xml.response"

// DefaultRequestTimeout bounds each request to the Namecheap API.
const DefaultRequestTimeout = 30 * time.Second

// maxResponseBytes bounds an answer the adapter reads; a larger one is an
// error. A page of 100 domains or a domain's whole host list is far less.
const maxResponseBytes = 4 << 20

// domainsPerPage is the largest page Namecheap serves for domains.
const domainsPerPage = 100

// Config is a Namecheap Account's credentials.
type Config struct {
	// User is the API user, which is also the account the calls act on.
	// Required.
	User string
	// Key is the API key. Required.
	Key string
	// ClientIP is the IPv4 address whitelisted for the API, which
	// Namecheap wants in every call. Required: the adapter does not look
	// up its own public IP.
	ClientIP string
}

// Field names in Factory's field map.
const (
	FieldUser     = "user"
	FieldKey      = "key"
	FieldClientIP = "client_ip"
)

// Factory builds the Namecheap Provider from a field map, for a
// dnsprovider.Registry.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{
		{Name: FieldUser, Label: "API user"},
		{Name: FieldKey, Label: "API key", Secret: true},
		{Name: FieldClientIP, Label: "Whitelisted client IPv4"},
	}

	f := fields.Factory("namecheap", fs, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{User: m[FieldUser], Key: m[FieldKey], ClientIP: m[FieldClientIP]}, opts...)
	})
	f.TTL = ttlRange

	return f
}

// New builds the Namecheap Provider for an Account, without a network
// call. Without WithBaseURL it talks to DefaultBaseURL, whose sandbox
// counterpart is in its doc; without WithHTTPClient each request times
// out after DefaultRequestTimeout.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if cfg.User == "" || cfg.Key == "" || cfg.ClientIP == "" {
		return nil, errors.New("namecheap: the API user, API key and client IP are all required")
	}

	ip, err := netip.ParseAddr(cfg.ClientIP)
	if err != nil || !ip.Is4() {
		return nil, errors.New("namecheap: the client IP is not an IPv4 address")
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

	// A non-2xx answer is an error page, not XML: rest's own APIError,
	// with the status alone, reports it.
	return &Provider{
		api: &rest.Client{
			Provider: "namecheap",
			BaseURL:  baseURL,
			HTTP:     client,
			Limit:    rest.AccountPerMinute("namecheap "+baseURL+" "+cfg.User, RequestsPerMinute),
			MaxBody:  maxResponseBytes,
			Log:      o.Logger,
		},
		auth: url.Values{
			"ApiUser":  {cfg.User},
			"UserName": {cfg.User},
			"ApiKey":   {cfg.Key},
			"ClientIp": {cfg.ClientIP},
		},
	}, nil
}

// RequestsPerMinute is Namecheap's published rate limit for an Account.
// Every Provider built for the same API user and endpoint shares it.
const RequestsPerMinute = 20

// Provider is one Namecheap Account.
type Provider struct {
	// api sends the Account's commands.
	api *rest.Client
	// auth are the parameters every request carries.
	auth url.Values
}

var (
	_ dnsprovider.Provider  = (*Provider)(nil)
	_ dnsprovider.TTLLimits = (*Provider)(nil)
	_ dnsprovider.Batcher   = (*Provider)(nil)
)

// TTLRange implements dnsprovider.TTLLimits. Namecheap's "Automatic" TTL is
// 1799 seconds, an ordinary TTL here.
func (p *Provider) TTLRange() (minTTL, maxTTL uint32) {
	return ttlRange.Min, ttlRange.Max
}

// ttlRange is the TTLRange of every Provider, which TTLRange and
// Factory report.
var ttlRange = dnsprovider.TTLRange{Min: 60, Max: 60000}

// wireDomain is the part of a getList domain that the adapter reads.
type wireDomain struct {
	Name     string `xml:"Name,attr"`
	IsOurDNS bool   `xml:"IsOurDNS,attr"`
}

// getListResult is a getList CommandResponse.
type getListResult struct {
	Domains []wireDomain `xml:"DomainGetListResult>Domain"`
	Paging  struct {
		TotalItems int `xml:"TotalItems"`
		PageSize   int `xml:"PageSize"`
	} `xml:"Paging"`
}

// Zones implements dnsprovider.Provider: the domains of the Account on
// Namecheap's own DNS whose names match the filter. A domain delegated
// elsewhere has no host list Namecheap will read. The filter goes to
// getList as its SearchTerm, and the answer is filtered again with
// dnsprovider.MatchZone. Every Zone is Active.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	all, err := p.listDomains(ctx, names.ZoneName(f.Contains))
	if err != nil {
		return nil, err
	}

	var out []dnsprovider.Zone

	for _, d := range all {
		if z := toZone(d); dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}

	return out, nil
}

// Zone implements dnsprovider.Provider: the domain of that exact name on
// Namecheap's DNS, found through getList's SearchTerm; ErrNotFound when
// the Account has none, or has it delegated elsewhere. Reading stops at
// the page that holds the name.
func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)

	var (
		found wireDomain
		ok    bool
	)

	if name != "" {
		err := p.pageDomains(ctx, name, func(d wireDomain) bool {
			found, ok = d, names.ZoneName(d.Name) == name

			return ok
		})
		if err != nil {
			return dnsprovider.Zone{}, err
		}
	}

	if !ok || !found.IsOurDNS {
		return dnsprovider.Zone{}, fmt.Errorf("namecheap: zone %q: %w", name, dnsprovider.ErrNotFound)
	}

	return toZone(found), nil
}

// toZone turns a domain on Namecheap's DNS into an Active Zone.
func toZone(d wireDomain) dnsprovider.Zone {
	return dnsprovider.Zone{Name: d.Name, ID: d.Name, State: dnsprovider.HostingActive}
}

// listDomains reads every page of the Account's domains on Namecheap's
// DNS that getList finds for a SearchTerm; all of them when it is empty.
func (p *Provider) listDomains(ctx context.Context, search string) ([]wireDomain, error) {
	var out []wireDomain

	err := p.pageDomains(ctx, search, func(d wireDomain) bool {
		if d.IsOurDNS {
			out = append(out, d)
		}

		return false
	})
	if err != nil {
		return nil, err
	}

	return out, nil
}

// pageDomains reads the pages of the Account's domains that getList finds
// for a SearchTerm, all of them when it is empty, and hands each domain,
// wherever its DNS is, to each, until each returns true or the list ends.
func (p *Provider) pageDomains(ctx context.Context, search string, each func(wireDomain) bool) error {
	var (
		read int
		last []wireDomain
	)

	for page := 1; ; page++ {
		params := url.Values{
			"Page":     {strconv.Itoa(page)},
			"PageSize": {strconv.Itoa(domainsPerPage)},
		}

		if search != "" {
			params.Set("SearchTerm", search)
		}

		res, err := call[getListResult](ctx, p, "namecheap.domains.getList", params)
		if err != nil {
			return err
		}

		if len(res.Domains) == 0 {
			return nil
		}

		if slices.Equal(res.Domains, last) {
			return errors.New("namecheap: the domain list answered the same page twice")
		}

		if slices.ContainsFunc(res.Domains, each) {
			return nil
		}

		// A page shorter than the size Namecheap says it served (or, if it
		// does not say, than asked for) is the last; so is the page that
		// reaches the total, when Namecheap reports one.
		read += len(res.Domains)

		size := res.Paging.PageSize
		if size <= 0 {
			size = domainsPerPage
		}

		if len(res.Domains) < size || (res.Paging.TotalItems > 0 && read >= res.Paging.TotalItems) {
			return nil
		}

		last = res.Domains
	}
}

// wireHost is one host of a getHosts answer. Its name is relative to the
// domain, "@" for the apex. Its HostId is not read (see withID).
type wireHost struct {
	Name    string `xml:"Name,attr"`
	Type    string `xml:"Type,attr"`
	Address string `xml:"Address,attr"`
	MXPref  uint32 `xml:"MXPref,attr"`
	TTL     uint32 `xml:"TTL,attr"`
}

// getHostsResult is a getHosts CommandResponse.
type getHostsResult struct {
	Result struct {
		// EmailType is the domain's mail setting, such as MX or FWD.
		EmailType string     `xml:"EmailType,attr"`
		Hosts     []wireHost `xml:"host"`
	} `xml:"DomainDNSGetHostsResult"`
}

// Records implements dnsprovider.Provider. getHosts answers the whole host
// list at once, so the filter is applied here with dnsprovider.MatchRecord.
// Namecheap reports no SOA serial.
func (p *Provider) Records(ctx context.Context, zone dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	res, err := p.getHosts(ctx, zone)
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}

	records := make([]dnsprovider.Record, 0, len(res.Result.Hosts))
	for _, h := range res.Result.Hosts {
		if rec := toRecord(zone.Name, h); dnsprovider.MatchRecord(f, rec) {
			records = append(records, rec)
		}
	}

	return dnsprovider.RecordSet{Records: records}, nil
}

// getHosts reads a Zone's whole host list and its EmailType.
func (p *Provider) getHosts(ctx context.Context, zone dnsprovider.Zone) (getHostsResult, error) {
	sld, tld := splitDomain(zone.ID)

	return call[getHostsResult](ctx, p, "namecheap.domains.dns.getHosts", url.Values{"SLD": {sld}, "TLD": {tld}})
}

// toRecord turns a host into a Record of a Zone, with an absolute name, its
// content as the Provider ID (withID), and its Value in presentation form:
// the MX and SRV priority first, and host names without the trailing dot.
// A Namecheap-only type, such as URL or MXE, keeps its type name and address.
func toRecord(zone string, h wireHost) dnsprovider.Record {
	rec := dnsprovider.Record{Type: h.Type, Name: names.AbsoluteName(zone, h.Name), Value: h.Address, TTL: h.TTL}
	pref := strconv.FormatUint(uint64(h.MXPref), 10)

	switch h.Type {
	case "CNAME", "NS", "ALIAS":
		rec.Value = target(h.Address)
	case "MX":
		rec.Value = pref + " " + target(h.Address)
	case "SRV":
		// Namecheap keeps the SRV priority in MXPref, as for MX, and the
		// rest in the address as "weight port target". Any other shape is
		// kept as given.
		if f := strings.Fields(h.Address); len(f) == 3 {
			rec.Value = pref + " " + f[0] + " " + f[1] + " " + target(f[2])
		}
	}

	return withID(rec)
}

// withID gives a Record its Provider ID: its type, lower-cased name, TTL
// and Value, as GoDaddy's are. Namecheap's HostIds are not used: every
// setHosts gives every host a new one, so the HostIds a consumer cached would
// go stale on each Apply, even for the hosts it did not change.
func withID(r dnsprovider.Record) dnsprovider.Record {
	r.ID = fmt.Sprintf("%s %s %d %s", r.Type, strings.ToLower(r.Name), r.TTL, r.Value)

	return r
}

// target is a host name target without its trailing dot. The root, ".",
// stays "." (a null MX reads "0 .").
func target(name string) string {
	if name == "." {
		return name
	}

	return strings.TrimSuffix(name, ".")
}

// splitDomain splits a domain into Namecheap's SLD, its first label, and
// TLD, the rest. Namecheap registers domains only at public suffixes, so
// "example.co.uk" is "example" and "co.uk".
func splitDomain(domain string) (sld, tld string) {
	sld, tld, _ = strings.Cut(strings.TrimSuffix(domain, "."), ".")

	return sld, tld
}

// basicDNS are Namecheap's BasicDNS nameservers, the same for every Account.
func basicDNS() []string {
	return []string{"dns1.registrar-servers.com", "dns2.registrar-servers.com"}
}

// Account implements dnsprovider.Provider. users.getBalances is the
// cheapest authenticated command, so it checks the API user, key and
// client IP. The Tenant is the API user, and the nameservers are BasicDNS.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	if _, err := call[struct{}](ctx, p, "namecheap.users.getBalances", nil); err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	user := p.auth.Get("ApiUser")

	return dnsprovider.AccountInfo{
		Tenant:      dnsprovider.Tenant{ID: user, Name: user},
		Nameservers: basicDNS(),
	}, nil
}

// apiResponse is the envelope of every answer, around a command's own
// response. Namecheap answers HTTP 200 whether or not the command worked;
// Status says which.
type apiResponse[T any] struct {
	Status          string      `xml:"Status,attr"`
	Errors          []wireError `xml:"Errors>Error"`
	CommandResponse T           `xml:"CommandResponse"`
}

// wireError is one error of an ERROR answer.
type wireError struct {
	Number string `xml:"Number,attr"`
	Text   string `xml:",chardata"`
}

// call sends a command with its parameters and the Account's through
// rest, and decodes its CommandResponse. The parameters go in a POST form,
// so the API key stays out of URLs and the errors that quote them.
func call[T any](ctx context.Context, p *Provider, command string, params url.Values) (T, error) {
	var zero T

	form := url.Values{"Command": {command}}
	maps.Copy(form, p.auth)
	maps.Copy(form, params)

	// Every command is a POST, so none is tried again: rest retries only
	// GET, PUT and DELETE.
	var data []byte
	if err := p.api.Do(ctx, http.MethodPost, "", nil, form, &data); err != nil {
		return zero, err
	}

	var body apiResponse[T]
	if err := xml.Unmarshal(data, &body); err != nil {
		return zero, fmt.Errorf("namecheap: decode %s: %w", command, err)
	}

	if !strings.EqualFold(body.Status, "OK") {
		return zero, statusError(body.Errors)
	}

	return body.CommandResponse, nil
}
