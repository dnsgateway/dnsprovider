package infomaniak

import (
	"bytes"
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

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

// envelope is Infomaniak's answer: its result, its data and, for a page
// of a list, the paging fields.
type envelope struct {
	Result       string          `json:"result"`
	Data         json.RawMessage `json:"data"`
	Error        *wireError      `json:"error"`
	Total        *int            `json:"total"`
	Page         *int            `json:"page"`
	Pages        *int            `json:"pages"`
	ItemsPerPage *int            `json:"items_per_page"`
}

// get reads path and decodes its envelope's data into out. An answer of
// success whose result is error is a refusal: an APIError of status 0.
func (p *Provider) get(ctx context.Context, path string, q url.Values, out any) (envelope, error) {
	c := p.api()

	var raw []byte
	if err := c.Do(ctx, http.MethodGet, path, q, nil, &raw); err != nil {
		return envelope{}, err
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return envelope{}, fmt.Errorf("infomaniak: malformed answer for %s", c.Redact(path))
	}

	switch env.Result {
	case "success":
	case "error":
		return envelope{}, c.RedactError(env.Error.apiError(0))
	default:
		return envelope{}, fmt.Errorf("infomaniak: unexpected result %q for %s", env.Result, c.Redact(path))
	}

	if out != nil {
		if len(env.Data) == 0 || string(env.Data) == "null" || json.Unmarshal(env.Data, out) != nil {
			return envelope{}, fmt.Errorf("infomaniak: malformed data for %s", c.Redact(path))
		}
	}

	return env, nil
}

// domainsQuery is the query of the domain list, scoped to the Account
// when the Provider has one.
func (p *Provider) domainsQuery() url.Values {
	q := url.Values{}
	if p.accountID != "" {
		q.Set("account_id", p.accountID)
	}

	return q
}

// Account implements dnsprovider.Provider: it reads one domain of the
// list, which an empty Account answers too, to prove the token. The
// Tenant is the account_id, when set; Infomaniak sets no account-wide
// nameservers.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	q := p.domainsQuery()
	q.Set("per_page", "1")

	var domains []json.RawMessage
	if _, err := p.get(ctx, "/2/domains/domains", q, &domains); err != nil {
		return dnsprovider.AccountInfo{}, err
	}

	return dnsprovider.AccountInfo{Tenant: dnsprovider.Tenant{ID: p.accountID}}, nil
}

// perPage is the page size the adapter asks for. Infomaniak documents
// neither its default nor its largest page; a page it answers smaller
// says so in items_per_page.
const perPage = 100

// list reads every page of a list, asking for each by its number. Each
// answer must be the page asked for, with its paging fields, and every
// page before the last full: a page repeated, short or missing its
// paging fields is an error, as reading on would lose or repeat items.
func list[T any](ctx context.Context, p *Provider, path string, q url.Values) ([]T, error) {
	var (
		out  []T
		last json.RawMessage
	)

	for page := 1; ; page++ {
		query := maps.Clone(q)
		if query == nil {
			query = url.Values{}
		}

		query.Set("page", strconv.Itoa(page))
		query.Set("per_page", strconv.Itoa(perPage))

		var items []T

		env, err := p.get(ctx, path, query, &items)
		if err != nil {
			return nil, err
		}

		if env.Page == nil || env.Pages == nil {
			return nil, fmt.Errorf("infomaniak: page %d of %s has no paging fields", page, path)
		}

		if *env.Page != page || (len(items) > 0 && bytes.Equal(env.Data, last)) {
			return nil, fmt.Errorf("infomaniak: page %d of %s: %w", page, path, rest.ErrSamePage)
		}

		out = append(out, items...)

		if page >= *env.Pages {
			if env.Total != nil && *env.Total != len(out) {
				return nil, fmt.Errorf("infomaniak: %s answered %d items of a total of %d", path, len(out), *env.Total)
			}

			return out, nil
		}

		size := perPage
		if env.ItemsPerPage != nil && *env.ItemsPerPage > 0 {
			size = *env.ItemsPerPage
		}

		if len(items) == 0 || len(items) < size {
			return nil, fmt.Errorf("infomaniak: page %d of %d of %s is short: %d items of %d", page, *env.Pages, path, len(items), size)
		}

		last = env.Data
	}
}

// wireDomain is a domain of the domain list.
type wireDomain struct {
	Name string `json:"name"`
}

// domains reads every domain of the Account as a Zone: its ID is its
// lower-case name. The list is of Registrations, which say nothing of
// whether Infomaniak serves a Zone: the Hosting State is Unknown. A
// search narrows the list to the names Infomaniak finds for it, which
// hold it; the caller filters them exactly.
func (p *Provider) domains(ctx context.Context, search string) ([]dnsprovider.Zone, error) {
	q := p.domainsQuery()
	if search != "" {
		q.Set("search", search)
	}

	all, err := list[wireDomain](ctx, p, "/2/domains/domains", q)
	if err != nil {
		return nil, err
	}

	out := make([]dnsprovider.Zone, 0, len(all))

	for _, d := range all {
		name := names.ZoneName(strings.TrimSpace(d.Name))
		if name == "" {
			return nil, errors.New("infomaniak: the domain list holds a domain without a name")
		}

		out = append(out, dnsprovider.Zone{ID: name, Name: name, State: dnsprovider.HostingUnknown})
	}

	return out, nil
}

// ListZones implements dnsprovider.Provider: every domain of the
// Account, read page by page. Contains is pushed down as the list's
// search, which Infomaniak matches as a substring of the name, and is
// applied again locally, exactly. The ZoneSet is a Full View.
func (p *Provider) ListZones(ctx context.Context, f dnsprovider.ZoneFilter) (dnsprovider.ZoneSet, error) {
	all, err := p.domains(ctx, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(f.Contains)), "."))
	if err != nil {
		return dnsprovider.ZoneSet{}, err
	}

	out := make([]dnsprovider.Zone, 0, len(all))

	for _, z := range all {
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}

	return dnsprovider.ZoneSet{Zones: out}, nil
}

// zonePath is the path of a Zone's resource, such as
// /2/zones/example.ch/records.
func zonePath(name string, resource ...string) string {
	return "/2/zones/" + url.PathEscape(name) + strings.Join(append([]string{""}, resource...), "/")
}

// GetZone implements dnsprovider.Provider: the Zone Infomaniak serves of
// that name, with its nameservers, as the zone answers them. ErrNotServed
// when the Account registers the domain but Infomaniak holds no Zone of
// it, and ErrNotFound when it does neither. With an account_id, a Zone
// that Account does not register is ErrNotFound, as ListZones leaves it
// out; that costs a read of the domain list, narrowed by a search for
// the name.
func (p *Provider) GetZone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name, err := zoneOf(dnsprovider.Zone{Name: name})
	if err != nil {
		return dnsprovider.Zone{}, err
	}

	var zone struct {
		FQDN        string   `json:"fqdn"`
		Nameservers []string `json:"nameservers"`
	}

	if _, err := p.get(ctx, zonePath(name), nil, &zone); err != nil {
		return dnsprovider.Zone{}, p.notServed(ctx, name, err)
	}

	if names.ZoneName(zone.FQDN) != name {
		return dnsprovider.Zone{}, fmt.Errorf("infomaniak: the answer for Zone %q names another Zone", name)
	}

	// The zone call takes no account_id: a Zone of another Account the
	// token reaches is out of scope, as ListZones leaves it out.
	if p.accountID != "" {
		held, err := p.registers(ctx, name)
		if err != nil {
			return dnsprovider.Zone{}, err
		}

		if !held {
			return dnsprovider.Zone{}, fmt.Errorf("infomaniak: Account %s does not register %s: %w", p.accountID, name, dnsprovider.ErrNotFound)
		}
	}

	z := dnsprovider.Zone{ID: name, Name: name, State: dnsprovider.HostingUnknown}

	for _, ns := range zone.Nameservers {
		if ns = names.ZoneName(strings.TrimSpace(ns)); ns != "" {
			z.Nameservers = append(z.Nameservers, ns)
		}
	}

	return z, nil
}

// notServed turns the not-found of a Zone into ErrNotServed when the
// Account still registers the domain: Infomaniak then holds no Zone of
// it, as for a domain whose Delegation names other nameservers. A domain
// the Account does not register, and any other error, is left as it is.
func (p *Provider) notServed(ctx context.Context, name string, err error) error {
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		return err
	}

	if held, lerr := p.registers(ctx, name); lerr != nil || !held {
		return err
	}

	return fmt.Errorf("infomaniak: zone %q: %w: %w", name, dnsprovider.ErrNotServed, err)
}

// registers reports whether the Account, scoped to its account_id when
// set, registers the domain: the domain list, narrowed by a search for
// the name, holds it exactly.
func (p *Provider) registers(ctx context.Context, domain string) (bool, error) {
	all, err := p.domains(ctx, domain)
	if err != nil {
		return false, err
	}

	return slices.ContainsFunc(all, func(z dnsprovider.Zone) bool { return z.Name == domain }), nil
}
