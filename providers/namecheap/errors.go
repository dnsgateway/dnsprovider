package namecheap

import (
	"strings"

	"github.com/dnsgateway/dnsprovider"
)

// errorKinds are the typed Provider errors of Namecheap's error numbers.
// Namecheap's own docs list few of them: these come from its global error
// list and third-party clients (lego, libdns, dnscontrol).
var errorKinds = map[string]error{
	// The API user or key is missing, invalid or disabled, the Account has
	// no API access, or the client IP is not whitelisted.
	"1010101": dnsprovider.ErrUnauthorized,
	"1010102": dnsprovider.ErrUnauthorized,
	"1011100": dnsprovider.ErrUnauthorized,
	"1011102": dnsprovider.ErrUnauthorized,
	"1011150": dnsprovider.ErrUnauthorized,
	"1017101": dnsprovider.ErrUnauthorized,
	"1017105": dnsprovider.ErrUnauthorized,
	"1017150": dnsprovider.ErrUnauthorized,
	"1017411": dnsprovider.ErrUnauthorized,
	"1050900": dnsprovider.ErrUnauthorized,
	// The domain is unknown, or not the Account's.
	"2019166": dnsprovider.ErrNotFound,
	"2016166": dnsprovider.ErrNotFound,
	// getHosts of a domain that is not on Namecheap's DNS ("domain is not
	// using proper DNS servers"): the Zone has moved away.
	"2030288": dnsprovider.ErrNotServed,
	// Too many requests.
	"500000": dnsprovider.ErrRateLimited,
}

// errorTexts classify an error whose number errorKinds does not know by
// its lower-cased text, until the manual pass confirms the numbers.
var errorTexts = []struct {
	text string
	kind error
}{
	{"too many requests", dnsprovider.ErrRateLimited},
	{"rate limit", dnsprovider.ErrRateLimited},
	{"request ip", dnsprovider.ErrUnauthorized},
	{"client ip", dnsprovider.ErrUnauthorized},
	{"ip is not", dnsprovider.ErrUnauthorized},
	{"whitelist", dnsprovider.ErrUnauthorized},
	{"white list", dnsprovider.ErrUnauthorized},
	{"api key", dnsprovider.ErrUnauthorized},
	{"apikey", dnsprovider.ErrUnauthorized},
	{"api user", dnsprovider.ErrUnauthorized},
	{"apiuser", dnsprovider.ErrUnauthorized},
	{"api access", dnsprovider.ErrUnauthorized},
	{"access denied", dnsprovider.ErrUnauthorized},
}

// statusError turns an ERROR answer into a *dnsprovider.APIError, whose
// messages are each error's "Number: text" and whose kind is the first
// error that has one, by its number or else by its text. Namecheap sends
// it with HTTP 200, so the APIError has no HTTP status (StatusCode 0).
// Namecheap says nothing of when to retry: a rate limit is reported, never
// waited out.
func statusError(errs []wireError) error {
	e := &dnsprovider.APIError{Provider: "namecheap"}

	for _, w := range errs {
		e.Messages = append(e.Messages, w.Number+": "+w.Text)

		if e.Kind == nil {
			e.Kind = errorKind(w)
		}
	}

	return e
}

// errorKind is the typed Provider error of one error, nil if none.
func errorKind(w wireError) error {
	if kind, ok := errorKinds[w.Number]; ok {
		return kind
	}

	text := strings.ToLower(w.Text)
	for _, t := range errorTexts {
		if strings.Contains(text, t.text) {
			return t.kind
		}
	}

	return nil
}
