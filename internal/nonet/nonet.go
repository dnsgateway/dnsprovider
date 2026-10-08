// Package nonet is for adapters' tests that a Provider is built without a
// network call.
package nonet

import (
	"errors"
	"net/http"
	"testing"
)

// Client returns an HTTP client that fails t on any request.
func Client(t testing.TB) *http.Client {
	t.Helper()

	return &http.Client{Transport: transport{t}}
}

type transport struct{ t testing.TB }

func (n transport) RoundTrip(r *http.Request) (*http.Response, error) {
	n.t.Errorf("building the Provider sent %s %s", r.Method, r.URL)

	return nil, errors.New("no network")
}
