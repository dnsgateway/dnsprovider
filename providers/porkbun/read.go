package porkbun

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

type domain struct {
	Domain    string
	APIAccess *int `json:"apiAccess"`
}

func (p *Provider) domains(ctx context.Context) ([]domain, error) {
	return rest.Pages(1000, nil, func(page rest.Page) ([]domain, error) {
		var env struct{ Domains []domain }
		err := p.call(ctx, http.MethodGet, "/domain/listAll", url.Values{"start": {strconv.Itoa(page.Offset)}, "apiAccess": {"yes"}, "sortName": {"domain"}}, nil, &env)
		if err != nil {
			return nil, err
		}
		if env.Domains == nil {
			return nil, errors.New("porkbun: missing domains list")
		}
		for _, d := range env.Domains {
			if d.Domain == "" || d.APIAccess == nil {
				return nil, errors.New("porkbun: malformed domain")
			}
		}
		return env.Domains, nil
	})
}

func domainZone(d domain) dnsprovider.Zone {
	n := names.ZoneName(d.Domain)
	return dnsprovider.Zone{ID: n, Name: n, State: dnsprovider.HostingUnknown}
}

// Zones discovers matching API-enabled Zones and checks per-domain access.
func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	ds, err := p.domains(ctx)
	if err != nil {
		return nil, err
	}
	var zs []dnsprovider.Zone
	for _, d := range ds {
		z := domainZone(d)
		if *d.APIAccess != 1 || !dnsprovider.MatchZone(f, z) {
			continue
		}
		if err := p.access(ctx, z); err != nil {
			var ae *codedError
			if errors.As(err, &ae) && (ae.code == "DOMAIN_NOT_ALLOWED" || ae.code == "API_ACCESS_DISABLED") {
				continue
			}
			return nil, err
		}
		zs = append(zs, z)
	}
	return zs, nil
}

// Zone reads one accessible Zone by its exact name.
func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	ds, err := p.domains(ctx)
	if err != nil {
		return dnsprovider.Zone{}, err
	}
	for _, d := range ds {
		if strings.EqualFold(names.ZoneName(d.Domain), names.ZoneName(name)) {
			z := domainZone(d)
			if *d.APIAccess != 1 {
				return dnsprovider.Zone{}, &dnsprovider.APIError{Provider: "porkbun", Kind: dnsprovider.ErrUnauthorized, Messages: []string{"domain API access is disabled"}}
			}
			if err := p.access(ctx, z); err != nil {
				return dnsprovider.Zone{}, err
			}
			return z, nil
		}
	}
	return dnsprovider.Zone{}, dnsprovider.ErrNotFound
}
func zonePath(z dnsprovider.Zone) string { return url.PathEscape(names.ZoneName(z.Name)) }
func (p *Provider) access(ctx context.Context, z dnsprovider.Zone) error {
	var env struct{ Records []jsonRecord }
	if err := p.call(ctx, http.MethodGet, "/dns/retrieve/"+zonePath(z), nil, nil, &env); err != nil {
		return err
	}
	if env.Records == nil {
		return errors.New("porkbun: missing records list")
	}
	return nil
}

type jsonRecord struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Content  string  `json:"content"`
	TTL      string  `json:"ttl"`
	Priority *string `json:"prio"`
	Notes    *string `json:"notes"`
}

// ExtraNotes holds Porkbun's optional record annotation, not served in DNS.
const ExtraNotes = "notes"

func (p *Provider) readRecords(ctx context.Context, z dnsprovider.Zone, id string) ([]dnsprovider.Record, error) {
	path := "/dns/retrieve/" + zonePath(z)
	if id != "" {
		path += "/" + url.PathEscape(id)
	}
	var env struct{ Records []jsonRecord }
	if err := p.call(ctx, http.MethodGet, path, nil, nil, &env); err != nil {
		return nil, err
	}
	if env.Records == nil {
		return nil, errors.New("porkbun: missing records list")
	}
	out := make([]dnsprovider.Record, 0, len(env.Records))
	for _, w := range env.Records {
		ttl, err := strconv.ParseUint(w.TTL, 10, 32)
		if err != nil || w.ID == "" || w.Name == "" || w.Type == "" || w.Content == "" {
			return nil, errors.New("porkbun: malformed record")
		}
		value := w.Content
		if strings.EqualFold(w.Type, "MX") || strings.EqualFold(w.Type, "SRV") {
			if w.Priority == nil {
				return nil, errors.New("porkbun: missing record priority")
			}
			if _, err := strconv.ParseUint(*w.Priority, 10, 16); err != nil {
				return nil, errors.New("porkbun: malformed record priority")
			}
			value = *w.Priority + " " + value
		}
		if dnsprovider.Editable(strings.ToUpper(w.Type)) {
			if err := dnsprovider.CheckValue(strings.ToUpper(w.Type), value); err != nil {
				return nil, errors.New("porkbun: malformed record value")
			}
		}
		r := dnsprovider.Record{ID: w.ID, Name: strings.TrimSuffix(w.Name, "."), Type: strings.ToUpper(w.Type), Value: value, TTL: uint32(ttl)}
		if w.Notes != nil {
			r.Extras = map[string]string{ExtraNotes: *w.Notes}
		}
		out = append(out, r)
	}
	return out, nil
}

// Records reads all editable DNS records and applies the common filters.
func (p *Provider) Records(ctx context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	rs, err := p.readRecords(ctx, z, "")
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}
	out := make([]dnsprovider.Record, 0, len(rs))
	for _, r := range rs {
		if dnsprovider.MatchRecord(f, r) {
			out = append(out, r)
		}
	}
	return dnsprovider.RecordSet{Records: out}, nil
}

func (p *Provider) record(ctx context.Context, z dnsprovider.Zone, id string) (dnsprovider.Record, error) {
	if id == "" {
		return dnsprovider.Record{}, dnsprovider.ErrNotFound
	}
	rs, err := p.readRecords(ctx, z, id)
	if err != nil {
		return dnsprovider.Record{}, err
	}
	for _, r := range rs {
		if r.ID == id {
			return r, nil
		}
	}
	return dnsprovider.Record{}, dnsprovider.ErrNotFound
}
