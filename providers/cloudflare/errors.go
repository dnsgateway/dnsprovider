package cloudflare

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/option"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// ErrNoTenant is dnsprovider.ErrNoTenant: a call scoped to a Tenant was
// made before Config.TenantID was set. Tenants lists the ones to pick from.
var ErrNoTenant = dnsprovider.ErrNoTenant

// reportRateLimits stops cloudflare-go from waiting out a rate limit: its
// Retry-After can be minutes, so the caller gets dnsprovider.ErrRateLimited
// and decides when to try again. Server errors are still retried.
func reportRateLimits(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
	res, err := next(req)
	if res != nil && res.StatusCode == http.StatusTooManyRequests {
		res.Header.Set("X-Should-Retry", "false")
	}

	return res, err
}

// apiError turns a failed cloudflare-go call into a *dnsprovider.APIError
// when the API answered with an error status, given that call's last
// response. Other errors, such as a lost connection, are wrapped as is.
func apiError(err error, res *http.Response) error {
	if res == nil || res.StatusCode < http.StatusBadRequest {
		return fmt.Errorf("cloudflare: %w", err)
	}

	e := &dnsprovider.APIError{
		Provider:   "cloudflare",
		StatusCode: res.StatusCode,
		RetryAfter: rest.RetryAfter(res.Header.Get("Retry-After"), time.Now()),
	}

	// cloudflare-go leaves the error body readable.
	var body struct {
		Errors []wireError `json:"errors"`
	}

	if data, rerr := io.ReadAll(res.Body); rerr == nil && json.Unmarshal(data, &body) == nil {
		addErrors(e, body.Errors)
	}

	return e
}

// wireError is one error of a v4 response.
type wireError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// addErrors adds a response's errors to e, and classifies e by the first
// error code that says what went wrong.
func addErrors(e *dnsprovider.APIError, errs []wireError) {
	for _, m := range errs {
		e.Messages = append(e.Messages, fmt.Sprintf("%s (code %d)", m.Message, m.Code))

		if kind, ok := errorCodes[m.Code]; ok && e.Kind == nil {
			e.Kind = kind
		}
	}
}

// errorCodes are the Cloudflare v4 error codes that say what went wrong
// when the HTTP status does not, such as a bad token answered with 400.
// The list is short on purpose: any other code is classified by status.
var errorCodes = map[int]error{
	6003:  dnsprovider.ErrUnauthorized, // Invalid request headers (e.g. a malformed token)
	6111:  dnsprovider.ErrUnauthorized, // Invalid format for Authorization header
	9106:  dnsprovider.ErrUnauthorized, // Missing X-Auth-Key, X-Auth-Email or Authorization headers
	10000: dnsprovider.ErrUnauthorized, // Authentication error
	7003:  dnsprovider.ErrNotFound,     // Could not route to …, perhaps your object identifier is invalid?
	81044: errRecordMissing,            // Record does not exist.
	81053: dnsprovider.ErrConflict,     // An A, AAAA, or CNAME record with that host already exists.
	81054: dnsprovider.ErrConflict,     // A CNAME record with that host already exists.
	81057: dnsprovider.ErrConflict,     // Record already exists.
	81058: dnsprovider.ErrConflict,     // An identical record already exists.
}

// errRecordMissing is the kind of error Cloudflare's code 81044, "Record
// does not exist", gives: dnsprovider.ErrNotFound, told apart from a Zone
// Cloudflare cannot route to, which a retried delete does not take as done.
var errRecordMissing error = recordMissing{}

type recordMissing struct{}

func (recordMissing) Error() string { return dnsprovider.ErrNotFound.Error() }

func (recordMissing) Is(target error) bool { return target == dnsprovider.ErrNotFound }
