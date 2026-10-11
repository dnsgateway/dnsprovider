package porkbun_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
)

func TestFailedEnvelopesHaveTypedRedactedErrors(t *testing.T) {
	cases := []struct {
		code string
		kind error
	}{
		{"INVALID_API_KEYS_001", dnsprovider.ErrUnauthorized},
		{"INSUFFICIENT_SCOPE", dnsprovider.ErrUnauthorized},
		{"API_ACCESS_DISABLED", dnsprovider.ErrUnauthorized},
		{"DOMAIN_NOT_ALLOWED", dnsprovider.ErrUnauthorized},
		{"INVALID_RECORD_ID", dnsprovider.ErrNotFound},
		{"DOMAIN_NOT_FOUND", dnsprovider.ErrNotFound},
		{"DOMAIN_NOT_REGISTERED", dnsprovider.ErrNotFound},
		{"DNSSEC_ALGORITHM_DEPRECATED", dnsprovider.ErrUnsupported},
		{"DUPLICATE_RECORD", dnsprovider.ErrConflict},
		{"RECORD_CONFLICT", dnsprovider.ErrConflict},
		{"RATE_LIMIT_EXCEEDED", dnsprovider.ErrRateLimited},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"status":"ERROR","code":"` + tc.code + `","message":"test-key test-secret","ttlRemaining":12}`))
			}))
			defer s.Close()
			p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
			_, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
			var ae *dnsprovider.APIError
			if !errors.Is(err, tc.kind) || !errors.As(err, &ae) || ae.StatusCode != 0 || ae.RetryAfter != 12*time.Second {
				t.Fatalf("error=%v", err)
			}
			if strings.Contains(err.Error(), "test-key") || strings.Contains(err.Error(), "test-secret") {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestMalformedResponsesFailExplicitly(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `{`, `{}`, `{"status":"SUCCESS"}`, `{"status":"SUCCESS","records":null}`, `{"status":"SUCCESS","records":[{"id":"1","type":"A","name":"example.com","content":"invalid address","ttl":"600"}]}`, `{"status":"SUCCESS","records":[{"id":"1","type":"A","name":"example.com","content":"192.0.2.1","ttl":"bad"}]}`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer s.Close()
			p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
			if _, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{}); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestCreateIsNeverRetried(t *testing.T) {
	api, p := fixtureAPI(t)
	api.fail = "create"
	_, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.9", TTL: 600})
	if err == nil {
		t.Fatal("failed create succeeded")
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.writes) != 1 {
		t.Fatalf("create retried: %v", api.writes)
	}
}

func TestCanceledContextAndSuppliedClientTimeout(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	client := s.Client()
	client.Timeout = 20 * time.Millisecond
	p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(client))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Account(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled=%v", err)
	}
	if _, err := p.Account(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout=%v", err)
	}
}

func TestInvalidDomainInputIsNotReportedAsAbsent(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ERROR","code":"INVALID_DOMAIN","message":"invalid domain syntax"}`))
	}))
	defer s.Close()
	p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
	_, err := p.Records(context.Background(), dnsprovider.Zone{Name: "invalid/name"}, dnsprovider.RecordFilter{})
	var api *dnsprovider.APIError
	if err == nil || !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("invalid domain=%v", err)
	}
}

func TestADomainNotInTheAccountIsNotFoundOnEveryEndpoint(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/domain/listAll" {
			w.Write([]byte(`{"status":"SUCCESS","domains":[{"domain":"example.com","apiAccess":1}]}`))
			return
		}
		w.Write([]byte(`{"status":"ERROR","code":"INVALID_DOMAIN","message":"Invalid domain.","account":"alice"}`))
	}))
	defer s.Close()
	p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
	if _, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Records=%v", err)
	}
	if _, err := p.GetZone(context.Background(), "example.com"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Zone=%v", err)
	}
}

func TestHTTPFailuresRetainStatusAndRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		status int
		code   string
		kind   error
	}{{http.StatusBadRequest, "INVALID_API_KEYS_002", dnsprovider.ErrUnauthorized}, {http.StatusForbidden, "DOMAIN_NOT_ALLOWED", dnsprovider.ErrUnauthorized}, {http.StatusNotFound, "DNS_RECORD_NOT_FOUND", dnsprovider.ErrNotFound}, {http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", dnsprovider.ErrRateLimited}} {
		t.Run(tc.code, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "12")
				w.WriteHeader(tc.status)
				w.Write([]byte(`{"status":"ERROR","code":"` + tc.code + `","message":"test-secret"}`))
			}))
			defer s.Close()
			p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
			_, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
			var api *dnsprovider.APIError
			if !errors.Is(err, tc.kind) || !errors.As(err, &api) || api.StatusCode != tc.status || api.RetryAfter != 12*time.Second || strings.Contains(err.Error(), "test-secret") {
				t.Fatalf("HTTP failure=%v", err)
			}
		})
	}
}
