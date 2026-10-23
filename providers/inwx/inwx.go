// Package inwx provides INWX DNS hosting through the DomRobot JSON-RPC
// API.
//
// A Provider logs in with account.login on its first call, unlocks the
// session with a TOTP code when the account has two-factor
// authentication, and shares the session between goroutines. Call Close
// when done, to log out.
package inwx

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/fields"
	"github.com/dnsgateway/dnsprovider/rest"
)

// DefaultBaseURL is the production DomRobot JSON-RPC endpoint. INWX's
// OT&E (test) environment, https://api.ote.domrobot.com/jsonrpc/, is
// reached with dnsprovider.WithBaseURL.
const DefaultBaseURL = "https://api.domrobot.com/jsonrpc/"

// DefaultRequestTimeout bounds requests when no HTTP client is supplied.
const DefaultRequestTimeout = 30 * time.Second

// RequestsPerMinute is a conservative local allowance, per username and
// endpoint; INWX publishes no general request rate.
const RequestsPerMinute = 60

// Factory field names.
const (
	FieldUsername     = "username"
	FieldPassword     = "password"
	FieldSharedSecret = "shared_secret"
)

// Config is one INWX account's credentials.
type Config struct {
	// Username is the account's (or sub-user's) login name.
	Username string
	// Password is its password.
	Password string
	// SharedSecret is the base32 TOTP shared secret of an account with
	// two-factor authentication, from which the Provider computes a code
	// at each login; empty for an account without it. Case, spaces and
	// padding are ignored.
	SharedSecret string
}

// Provider is one INWX account.
type Provider struct {
	dnsprovider.UnimplementedBatch
	dnsprovider.UnimplementedTenants

	username string
	password string
	totpKey  []byte // the decoded shared secret; nil without 2FA
	secrets  []string
	base     string
	client   *http.Client
	log      *slog.Logger
	limit    rest.Limiter
	session  *session
}

var _ dnsprovider.Provider = (*Provider)(nil)

// New builds a Provider without sending a request.
func New(cfg Config, opts ...dnsprovider.Option) (*Provider, error) {
	if strings.TrimSpace(cfg.Username) == "" || strings.TrimSpace(cfg.Password) == "" {
		return nil, errors.New("inwx: username and password are required")
	}

	secrets := []string{cfg.Password}

	var key []byte

	if strings.TrimSpace(cfg.SharedSecret) != "" {
		normal := normalSecret(cfg.SharedSecret)

		var err error
		if key, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normal); err != nil || len(key) == 0 {
			return nil, errors.New("inwx: shared_secret is not a base32 TOTP secret")
		}

		secrets = append(secrets, cfg.SharedSecret, normal)
	}

	o := dnsprovider.NewOptions(opts...)

	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}

	// The adapter holds the session cookie itself: a supplied client's
	// jar is left out, so that it neither needs one nor sends its cookies.
	client := &http.Client{Timeout: DefaultRequestTimeout}
	if o.HTTPClient != nil {
		c := *o.HTTPClient
		c.Jar = nil
		client = &c
	}

	identity := sha256.Sum256([]byte(cfg.Username))

	return &Provider{
		username: cfg.Username, password: cfg.Password, totpKey: key, secrets: secrets,
		base: base, client: client, log: o.Logger,
		limit:   rest.AccountPerMinute(fmt.Sprintf("inwx %s %x", base, identity), RequestsPerMinute),
		session: &session{sem: make(chan struct{}, 1)},
	}, nil
}

// normalSecret is a shared secret as base32 decodes it: upper case,
// without spaces or padding.
func normalSecret(s string) string {
	s = strings.ToUpper(strings.Join(strings.Fields(s), ""))

	return strings.TrimRight(s, "=")
}

// Factory builds a Provider from the username, the password and an
// optional TOTP shared secret, all secret fields.
func Factory() dnsprovider.Factory {
	fs := []dnsprovider.Field{
		{Name: FieldUsername, Label: "Username", Secret: true},
		{Name: FieldPassword, Label: "Password", Secret: true},
		{Name: FieldSharedSecret, Label: "TOTP shared secret (2FA accounts only)", Secret: true},
	}

	return fields.Factory("inwx", fs, traits, func(m map[string]string, opts ...dnsprovider.Option) (*Provider, error) {
		return New(Config{Username: m[FieldUsername], Password: m[FieldPassword], SharedSecret: m[FieldSharedSecret]}, opts...)
	})
}

// traits are the Traits of every Provider, which Traits and Factory
// report. The TTL minimum is INWX's (its Terraform provider's); the
// maximum is a library bound.
var traits = dnsprovider.Traits{
	Capabilities: []dnsprovider.Capability{
		dnsprovider.CapZoneCreator,
		dnsprovider.CapZoneUpdater,
		dnsprovider.CapZoneDeleter,
		dnsprovider.CapDSRegistrar,
	},
	TTL: dnsprovider.TTLRange{Min: 300, Max: 86400},
}

// Traits implements dnsprovider.Provider.
func (p *Provider) Traits() dnsprovider.Traits {
	return traits.Clone()
}
