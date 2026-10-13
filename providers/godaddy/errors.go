package godaddy

import (
	"encoding/json"
	"net/http"

	"github.com/dnsgateway/dnsprovider"
)

// wireError is a v3 error body.
type wireError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Details []struct {
		Field       string `json:"field"`
		Issue       string `json:"issue"`
		Description string `json:"description"`
	} `json:"details"`
}

// apiError turns an error response into a *dnsprovider.APIError, classified
// by its HTTP status, for rest.Client.Decode: 409, which v3 answers for a
// record GoDaddy manages and is assumed to answer for a record the RRset
// holds already, is ErrConflict. rest reads the Retry-After header.
func apiError(res *http.Response, data []byte) error {
	e := &dnsprovider.APIError{Provider: "godaddy", StatusCode: res.StatusCode}
	if res.StatusCode == http.StatusConflict {
		e.Kind = dnsprovider.ErrConflict
	}

	var body wireError
	if json.Unmarshal(data, &body) != nil {
		return e
	}

	if body.Message != "" {
		e.Messages = append(e.Messages, body.Message+" ("+body.Name+")")
	}

	for _, d := range body.Details {
		msg := d.Issue
		if d.Description != "" {
			msg += ": " + d.Description
		}

		if d.Field != "" {
			msg = d.Field + ": " + msg
		}

		e.Messages = append(e.Messages, msg)
	}

	return e
}
