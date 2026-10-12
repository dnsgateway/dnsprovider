package rest_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

// secret has characters a URL escapes, so its escaped forms differ.
const secret = "s3cr/t+key=="

func TestATransportErrorShowsNoSecretFromTheQuery(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	c := &rest.Client{Provider: "test", BaseURL: srv.URL, HTTP: srv.Client(), Secrets: []string{secret}}

	err := c.Do(context.Background(), http.MethodPost, "/x", url.Values{"key": {secret}}, nil, nil)
	if err == nil {
		t.Fatal("Do succeeded against a closed server")
	}

	if leaks(err.Error()) {
		t.Errorf("error %q shows the secret", err)
	}

	var uerr *url.Error
	if !errors.As(err, &uerr) {
		t.Fatalf("error %v holds no *url.Error", err)
	}

	if leaks(uerr.URL) {
		t.Errorf("url.Error.URL %q shows the secret", uerr.URL)
	}
}

func TestAnAPIErrorShowsNoSecretAndKeepsItsKind(t *testing.T) {
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	c.Secrets = []string{secret}
	c.Decode = func(res *http.Response, _ []byte) error {
		// Providers echo the credential, sometimes escaped in lower case.
		echo := strings.ToLower(url.QueryEscape(secret))

		return &dnsprovider.APIError{Provider: "test", StatusCode: res.StatusCode, Messages: []string{"bad key " + secret, "query key=" + echo}}
	}

	err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil, nil)

	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Errorf("error %v does not match ErrUnauthorized", err)
	}

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %v holds no *APIError", err)
	}

	for _, m := range apiErr.Messages {
		if leaks(m) || strings.Contains(m, strings.ToLower(url.QueryEscape(secret))) {
			t.Errorf("message %q shows the secret", m)
		}
	}
}

func TestAWrappedSecretIsRedactedAndStillMatches(t *testing.T) {
	sentinel := errors.New("sentinel")
	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	c.Secrets = []string{secret}
	c.Decode = func(*http.Response, []byte) error {
		return errors.Join(sentinel, errors.New("token "+secret+" refused"))
	}

	err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil, nil)

	if leaks(err.Error()) {
		t.Errorf("error %q shows the secret", err)
	}

	if !errors.Is(err, sentinel) {
		t.Errorf("error %v no longer matches its cause", err)
	}

	for e := errors.Unwrap(err); e != nil; e = errors.Unwrap(e) {
		if leaks(e.Error()) {
			t.Errorf("cause %q shows the secret", e)
		}
	}
}

func TestARetryLogShowsNoSecret(t *testing.T) {
	var log bytes.Buffer

	c := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	c.Secrets = []string{secret}
	c.Attempts, c.Backoff = 2, 1
	c.Log = slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	c.Decode = func(res *http.Response, _ []byte) error {
		return &dnsprovider.APIError{Provider: "test", StatusCode: res.StatusCode, Messages: []string{secret}}
	}

	_ = c.Do(context.Background(), http.MethodGet, "/x/"+url.PathEscape(secret), nil, nil, nil)

	if !strings.Contains(log.String(), "retry") {
		t.Fatalf("no retry logged: %q", log.String())
	}

	if leaks(log.String()) {
		t.Errorf("log %q shows the secret", log.String())
	}
}

func TestRedactReplacesEveryForm(t *testing.T) {
	c := &rest.Client{Secrets: []string{secret, ""}}

	got := c.Redact(secret + " " + url.QueryEscape(secret) + " " + url.PathEscape(secret))
	if got != "[redacted] [redacted] [redacted]" {
		t.Errorf("Redact = %q", got)
	}

	if got := (&rest.Client{}).Redact(secret); got != secret {
		t.Errorf("Redact without Secrets = %q, want it unchanged", got)
	}
}

// leaks reports whether s shows the secret in any form.
func leaks(s string) bool {
	return strings.Contains(s, secret) || strings.Contains(s, url.QueryEscape(secret)) || strings.Contains(s, url.PathEscape(secret))
}
