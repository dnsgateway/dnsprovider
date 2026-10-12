// Package scaleway manages DNS in one Scaleway Project using the Domain v2beta1 API.
package scaleway

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/rest"
	"golang.org/x/time/rate"
)

const (
	DefaultBaseURL        = "https://api.scaleway.com/domain/v2beta1"
	DefaultRequestTimeout = 30 * time.Second
	FieldSecretKey        = "secret_key"
	FieldProjectID        = "project_id"
)

// Config scopes a secret key to one required Project.
type Config struct{ SecretKey, ProjectID string }

// Factory describes the credentials and constructs locally.
func Factory() dnsprovider.Factory {
	return fields.Factory("scaleway", []dnsprovider.Field{
		{Name: FieldSecretKey, Label: "Secret key", Secret: true},
		{Name: FieldProjectID, Label: "Project ID"},
	}, traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{SecretKey: m[FieldSecretKey], ProjectID: m[FieldProjectID]}, opts...)
	})
}

// traits are the Traits of every Provider, which Traits and Factory
// report.
var traits = dnsprovider.Traits{Capabilities: []dnsprovider.Capability{dnsprovider.CapBatcher}, TTL: ttlRange}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}

// Provider manages the existing DNS Zones of one Project.
type Provider struct {
	dnsprovider.UnimplementedZoneWrites
	dnsprovider.UnimplementedZoneDetails
	dnsprovider.UnimplementedTenants
	dnsprovider.UnimplementedDelegationSigners

	key, project, baseURL string
	client                *http.Client
	log                   *slog.Logger
	limit                 *rate.Limiter
}

var projectPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// New validates credentials without a network request.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.SecretKey) == "" || strings.ContainsAny(cfg.SecretKey, " \t\r\n") {
		return nil, errors.New("scaleway: a valid secret key is required")
	}
	if !projectPattern.MatchString(cfg.ProjectID) {
		return nil, errors.New("scaleway: a UUID Project ID is required")
	}
	o := dnsprovider.NewOptions(opts...)
	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultRequestTimeout}
	}
	return &Provider{key: cfg.SecretKey, project: strings.ToLower(cfg.ProjectID), baseURL: base, client: client, log: o.Logger, limit: rate.NewLimiter(10, 1)}, nil
}

func (p *Provider) api() *rest.Client {
	return &rest.Client{
		Provider: "scaleway", BaseURL: p.baseURL, HTTP: p.client, Log: p.log, Limit: p.limit,
		Auth:    func(r *http.Request) { r.Header.Set("X-Auth-Token", p.key) },
		Secrets: []string{p.key}, Decode: p.apiError,
	}
}

func (p *Provider) apiError(res *http.Response, body []byte) error {
	var payload struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	}
	_ = json.Unmarshal(body, &payload)
	e := &dnsprovider.APIError{Provider: "scaleway", StatusCode: res.StatusCode}
	if res.StatusCode == http.StatusConflict {
		e.Kind = dnsprovider.ErrConflict
	}
	if payload.Message != "" {
		e.Messages = []string{payload.Message}
	}
	return e
}
