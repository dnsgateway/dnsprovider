package godaddy

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dnsgateway/dnsprovider"
)

// wireError is a v1 error body.
type wireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Fields  []struct {
		Message string `json:"message"`
		Path    string `json:"path"`
	} `json:"fields"`
	// RetryAfterSec is how long a 429 asks to wait.
	RetryAfterSec int `json:"retryAfterSec"`
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

	if body.RetryAfterSec > 0 {
		e.RetryAfter = time.Duration(body.RetryAfterSec) * time.Second
	}

	return e
}
