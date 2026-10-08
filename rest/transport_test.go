package rest_test

// Seam: rest.Client.Do as the transport of a Provider that does not speak
// JSON, such as Namecheap's XML over a POST form.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestDoSendsAFormAndHandsBackTheRawAnswer(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want a form", ct)
		}

		if accept := r.Header.Get("Accept"); accept == "application/json" {
			t.Errorf("Accept = %q, want no JSON asked for: the answer is not decoded", accept)
		}

		if err := r.ParseForm(); err != nil || r.PostForm.Get("Command") != "getHosts" {
			t.Errorf("form = %v (%v), want Command getHosts", r.PostForm, err)
		}

		if r.URL.RawQuery != "" {
			t.Errorf("query = %q, want the form kept out of the URL", r.URL.RawQuery)
		}

		_, _ = w.Write([]byte(`<ApiResponse Status="OK"/>`))
	}))

	var raw []byte

	err := c.Do(context.Background(), http.MethodPost, "", nil, url.Values{"Command": {"getHosts"}}, &raw)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if string(raw) != `<ApiResponse Status="OK"/>` {
		t.Errorf("raw = %q, want the answer as sent", raw)
	}
}

func TestDoRefusesAnAnswerOverMaxBody(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 1025)))
	}))
	c.MaxBody = 1024

	var raw []byte

	err := c.Do(context.Background(), http.MethodGet, "/big", nil, nil, &raw)
	if err == nil || !strings.Contains(err.Error(), "test") || !strings.Contains(err.Error(), "1024 bytes") {
		t.Errorf("err = %v, want the test Provider's answer refused over 1024 bytes", err)
	}

	c.MaxBody = 1025
	if err := c.Do(context.Background(), http.MethodGet, "/big", nil, nil, &raw); err != nil || len(raw) != 1025 {
		t.Errorf("Do = %d bytes, %v, want an answer of exactly MaxBody read", len(raw), err)
	}
}
