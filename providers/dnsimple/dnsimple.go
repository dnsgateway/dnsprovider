// Package dnsimple implements DNSimple API v2 for an explicitly configured Account.
package dnsimple

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/rest"
)

const (
	DefaultBaseURL        = "https://api.dnsimple.com/v2"
	DefaultRequestTimeout = 30 * time.Second
	FieldToken            = "token"
	FieldAccountID        = "account_id"
)

// Config supplies a token and a canonical positive decimal Account ID.
type Config struct{ Token, AccountID string }

// Factory builds the adapter without contacting DNSimple.
func Factory() dnsprovider.Factory {
	return fields.Factory("dnsimple", []dnsprovider.Field{{Name: FieldToken, Label: "API token", Secret: true}, {Name: FieldAccountID, Label: "Account ID"}},
		traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
			return New(Config{Token: m[FieldToken], AccountID: m[FieldAccountID]}, opts...)
		})
}

// traits are the Traits of every Provider, which Traits and Factory
// report.
var traits = dnsprovider.Traits{
	TTL: ttlRange,
	Extras: []dnsprovider.ExtraSpec{
		{Key: ExtraSystemRecord, Label: "System record", Kind: dnsprovider.ExtraBool},
		{Key: ExtraRegions, Label: "Regions", Kind: dnsprovider.ExtraJSON},
		{Key: ExtraParentID, Label: "Parent record ID", Kind: dnsprovider.ExtraString},
	},
}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}

// Provider holds one Account's credentials, endpoint and consumer options.
type Provider struct {
	dnsprovider.UnimplementedZoneWrites
	dnsprovider.UnimplementedZoneDetails
	dnsprovider.UnimplementedBatch
	dnsprovider.UnimplementedTenants
	dnsprovider.UnimplementedDelegationSigners

	token, accountID, baseURL string
	client                    *http.Client
	limit                     *rest.Window
	log                       *slog.Logger
}

// New validates configuration locally; Account proves remote access.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	id, err := strconv.ParseUint(cfg.AccountID, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != cfg.AccountID {
		return nil, errors.New("dnsimple: a positive decimal account_id is required")
	}
	if strings.TrimSpace(cfg.Token) == "" || strings.ContainsAny(cfg.Token, "\r\n") {
		return nil, errors.New("dnsimple: a valid API token is required")
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
	hash := sha256.Sum256([]byte(cfg.Token))
	return &Provider{
		token: cfg.Token, accountID: cfg.AccountID, baseURL: endpoint, client: client, log: o.Logger,
		limit: rest.AccountPerMinute("dnsimple "+endpoint+" "+hex.EncodeToString(hash[:]), 40),
	}, nil
}
