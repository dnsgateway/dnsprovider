// Package gandi implements the Gandi v5 LiveDNS API with personal access tokens.
package gandi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/internal/names"
	"github.com/dnsgateway/dnsprovider/rest"
)

const (
	DefaultBaseURL        = "https://api.gandi.net/v5/livedns"
	DefaultRequestTimeout = 30 * time.Second
	FieldToken            = "token"
)

// Config is the personal access token; deprecated API keys are not supported.
type Config struct{ Token string }

// Provider manages the LiveDNS resources visible to its token.
type Provider struct {
	token, baseURL string
	client         *http.Client
	log            *slog.Logger
	limit          *rest.Window
}

// New validates local configuration without contacting Gandi.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.Token) == "" || strings.ContainsAny(cfg.Token, "\r\n") {
		return nil, errors.New("gandi: a valid personal access token is required")
	}
	o := dnsprovider.NewOptions(opts...)
	endpoint := strings.TrimRight(o.BaseURL, "/")
	if endpoint == "" {
		endpoint = DefaultBaseURL
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultRequestTimeout}
	}
	// Gandi's quota is per IP, so all credentials using an endpoint share it.
	return &Provider{token: cfg.Token, baseURL: endpoint, client: client, log: o.Logger, limit: rest.AccountPerMinute("gandi "+endpoint, 1000)}, nil
}

// Factory declares the token field and constructs the same Provider as New.
func Factory() dnsprovider.Factory {
	f := fields.Factory("gandi", []dnsprovider.Field{{Name: FieldToken, Label: "Personal access token", Secret: true}}, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Token: m[FieldToken]}, opts...)
	})
	f.TTL = ttlRange

	return f
}

func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "gandi", BaseURL: p.baseURL, HTTP: p.client, Log: p.log, Limit: p.limit,
		Auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+p.token) }, Decode: p.apiError, Attempts: 1,
	}
}

func (p *Provider) apiError(res *http.Response, body []byte) error {
	var payload struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	}
	_ = json.Unmarshal(body, &payload)
	e := &dnsprovider.APIError{Provider: "gandi", StatusCode: res.StatusCode}
	if payload.Message != "" {
		e.Messages = []string{strings.ReplaceAll(payload.Message, p.token, "[redacted]")}
	}
	code := res.StatusCode
	if code == 0 {
		code = payload.Code
	}
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		e.Kind = dnsprovider.ErrUnauthorized
	case http.StatusNotFound:
		e.Kind = dnsprovider.ErrNotFound
	case http.StatusConflict:
		e.Kind = dnsprovider.ErrConflict
	case http.StatusTooManyRequests:
		e.Kind = dnsprovider.ErrRateLimited
	}
	if res.StatusCode == http.StatusTooManyRequests {
		e.RetryAfter = rest.RetryAfter(res.Header.Get("Retry-After"), time.Now())
	}
	return e
}

func (p *Provider) request(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var raw []byte
	client := p.api()
	if method == http.MethodGet {
		client.Attempts = rest.DefaultAttempts
	}
	if err := client.Do(ctx, method, path, q, body, &raw); err != nil {
		return err
	}
	if len(raw) == 0 && out == nil {
		return nil
	}
	var failure struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &failure) == nil && failure.Code >= 400 {
		return p.apiError(&http.Response{Header: http.Header{}}, raw)
	}
	if !json.Valid(raw) || strings.TrimSpace(string(raw)) == "null" {
		return errors.New("gandi: malformed API response")
	}
	if out == nil && failure.Message == "" {
		return errors.New("gandi: malformed mutation acknowledgement")
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return errors.New("gandi: malformed API response")
	}
	return nil
}

// list deliberately requests until the documented empty page. The server may
// cap page length below per_page; the shared pager guards repeated pages.
func list[T any](ctx context.Context, p *Provider, path string) ([]T, error) {
	pages, err := rest.Pages(1, nil, func(pg rest.Page) ([][]T, error) {
		var items []T
		err := p.request(ctx, http.MethodGet, path, url.Values{"page": {strconv.Itoa(pg.Number)}, "per_page": {"100"}}, nil, &items)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return nil, nil
		}
		return [][]T{items}, nil
	})
	if err != nil {
		return nil, err
	}
	var all []T
	for _, page := range pages {
		all = append(all, page...)
	}
	return all, nil
}

// Account proves LiveDNS read access even when the Account has no Zones.
// LiveDNS does not expose the authenticated organization's identity here.
func (p *Provider) Account(ctx context.Context) (dnsprovider.AccountInfo, error) {
	_, err := p.Zones(ctx, dnsprovider.ZoneFilter{})
	return dnsprovider.AccountInfo{}, err
}

type wireZone struct {
	Name string `json:"fqdn"`
}

func zone(w wireZone) (dnsprovider.Zone, error) {
	if w.Name == "" {
		return dnsprovider.Zone{}, errors.New("gandi: malformed Zone")
	}
	n := names.ZoneName(w.Name)
	return dnsprovider.Zone{ID: n, Name: n, State: dnsprovider.HostingUnknown}, nil
}

func (p *Provider) Zones(ctx context.Context, f dnsprovider.ZoneFilter) ([]dnsprovider.Zone, error) {
	all, err := list[wireZone](ctx, p, "/domains")
	if err != nil {
		return nil, err
	}
	out := make([]dnsprovider.Zone, 0, len(all))
	for _, w := range all {
		z, err := zone(w)
		if err != nil {
			return nil, err
		}
		if dnsprovider.MatchZone(f, z) {
			out = append(out, z)
		}
	}
	return out, nil
}

func (p *Provider) Zone(ctx context.Context, name string) (dnsprovider.Zone, error) {
	name = names.ZoneName(name)
	if name == "" {
		return dnsprovider.Zone{}, dnsprovider.ErrNotFound
	}
	var w wireZone
	if err := p.request(ctx, http.MethodGet, "/domains/"+url.PathEscape(name), nil, nil, &w); err != nil {
		return dnsprovider.Zone{}, err
	}
	z, err := zone(w)
	if err == nil && z.Name != name {
		return dnsprovider.Zone{}, errors.New("gandi: response names a different Zone")
	}
	return z, err
}

// wireSet retains unknown properties while individual Records are edited.
type wireSet map[string]json.RawMessage

type rrset struct {
	Name   string   `json:"rrset_name"`
	Type   string   `json:"rrset_type"`
	TTL    *uint32  `json:"rrset_ttl"`
	Values []string `json:"rrset_values"`
}

func decode(w wireSet) (rrset, error) {
	raw, _ := json.Marshal(w)
	var s rrset
	if json.Unmarshal(raw, &s) != nil || s.Name == "" || s.Type == "" || s.TTL == nil || s.Values == nil {
		return s, errors.New("gandi: malformed RRset")
	}
	return s, nil
}

func contentKey(r dnsprovider.Record) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(r.Type) + "\x00" + names.ZoneName(r.Name) + "\x00" + r.Value))
	return hex.EncodeToString(sum[:])
}

func records(z dnsprovider.Zone, s rrset) []dnsprovider.Record {
	out := make([]dnsprovider.Record, 0, len(s.Values))
	for _, v := range s.Values {
		r := dnsprovider.Record{Name: names.AbsoluteName(names.ZoneName(z.Name), strings.ToLower(s.Name)), Type: s.Type, Value: v, TTL: *s.TTL}
		// A single ordinary quoted TXT string maps to the module's literal text;
		// multi-chunk strings retain their presentation verbatim. The original
		// wire strings remain intact when sibling values are rewritten.
		if s.Type == "TXT" {
			if text, err := unquoteDNS(v); err == nil {
				r.Value = text
			}
		}
		r.ID = contentKey(r)
		out = append(out, r)
	}
	return out
}

func (p *Provider) recordPath(z dnsprovider.Zone) string {
	return "/domains/" + url.PathEscape(names.ZoneName(z.Name)) + "/records"
}

func (p *Provider) Records(ctx context.Context, z dnsprovider.Zone, f dnsprovider.RecordFilter) (dnsprovider.RecordSet, error) {
	all, err := list[wireSet](ctx, p, p.recordPath(z))
	if err != nil {
		return dnsprovider.RecordSet{}, err
	}
	var out []dnsprovider.Record
	var serial uint32
	for _, w := range all {
		s, err := decode(w)
		if err != nil {
			return dnsprovider.RecordSet{}, err
		}
		for _, r := range records(z, s) {
			if r.Type == "SOA" && strings.EqualFold(r.Name, z.Name) {
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
	}
	return dnsprovider.RecordSet{Records: out, Serial: serial}, nil
}

// TTLRange is the documented LiveDNS cache interval; there is no auto sentinel.
func (p *Provider) TTLRange() (minTTL, maxTTL uint32) {
	return ttlRange.Min, ttlRange.Max
}

// ttlRange is the TTLRange of every Provider, which TTLRange and
// Factory report.
var ttlRange = dnsprovider.TTLRange{Min: 300, Max: 2592000}

var _ dnsprovider.TTLLimits = (*Provider)(nil)

func normalize(z dnsprovider.Zone, r dnsprovider.Record) (dnsprovider.Record, error) {
	r.Type = strings.ToUpper(r.Type)
	if !dnsprovider.Editable(r.Type) || r.Type == "URI" {
		return r, fmt.Errorf("gandi: unsupported Record type %s", r.Type)
	}
	if err := dnsprovider.CheckValue(r.Type, r.Value); err != nil {
		return r, err
	}
	if err := (dnsprovider.TTLRange{Min: 300, Max: 2592000}).Check(r.TTL); err != nil {
		return r, err
	}
	abs, err := dnsprovider.QualifyName(z.Name, r.Name)
	if err != nil {
		return r, err
	}
	r.Name = names.ZoneName(abs)
	// Target values are absolute on the wire, as in Gandi's examples.
	switch r.Type {
	case "CNAME", "NS":
		r.Value = strings.TrimSuffix(r.Value, ".") + "."
	case "MX", "SRV":
		fs := strings.Fields(r.Value)
		if fs[len(fs)-1] != "." {
			fs[len(fs)-1] = strings.TrimSuffix(fs[len(fs)-1], ".") + "."
		}
		r.Value = strings.Join(fs, " ")
	}
	r.ID = contentKey(r)
	return r, nil
}
