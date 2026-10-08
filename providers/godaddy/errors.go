package godaddy

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// wireError is a v1 error body.
type wireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Fields  []struct {
		Message string `json:"message"`
		Path    string `json:"path"`
	} `json:"fields"`
	// RetryAfterSec is how long a 429 asks to wait, in seconds. It is
	// read as rest.RetryAfter reads a Retry-After header, so a wait too
	// long for a Duration, or for an int64, neither overflows nor fails
	// the body.
	RetryAfterSec json.RawMessage `json:"retryAfterSec"`
}

// apiError turns an error response into a *dnsprovider.APIError, classified
// by its HTTP status, for rest.Client.Decode. A wait the body does not
// give is the Retry-After header's, which rest reads.
func apiError(res *http.Response, data []byte) error {
	e := &dnsprovider.APIError{Provider: "godaddy", StatusCode: res.StatusCode}

	var body wireError
	if json.Unmarshal(data, &body) != nil {
		return e
	}

	if body.Message != "" {
		e.Messages = append(e.Messages, body.Message+" ("+body.Code+")")
	}

	for _, f := range body.Fields {
		e.Messages = append(e.Messages, f.Path+": "+f.Message)
	}

	e.RetryAfter = rest.RetryAfter(strings.Trim(string(body.RetryAfterSec), `"`), time.Now())

	return e
}
