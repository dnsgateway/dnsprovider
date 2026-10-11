package internetbs_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/internetbs"
)

func TestResponseFailuresAreTypedRedactedAndNeverRetried(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
		kind   error
		retry  time.Duration
	}{
		{"auth", 200, `{"status":"FAILURE","code":107002,"message":"Invalid API key and/or Password: api-secret pass&secret"}`, dnsprovider.ErrUnauthorized, 0},
		{"permission", 200, `{"status":"FAILURE","code":100005,"message":"Permission denied!"}`, dnsprovider.ErrUnauthorized, 0},
		{"quota", 200, `{"status":"FAILURE","message":"API rate limit exceeded api-secret"}`, dnsprovider.ErrRateLimited, 0},
		{"http quota", 429, `{"message":"pass%26secret"}`, dnsprovider.ErrRateLimited, 3 * time.Second},
		{"server", 503, `{"message":"api-secret"}`, nil, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if tt.retry > 0 {
					w.Header().Set("Retry-After", "3")
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer s.Close()
			p, _ := internetbs.New(internetbs.Config{Key: "api-secret", Password: "pass&secret"}, dnsprovider.WithBaseURL(s.URL))
			_, err := p.Account(context.Background())
			if err == nil {
				t.Fatal("expected failure")
			}
			var api *dnsprovider.APIError
			if !errors.As(err, &api) || (tt.kind != nil && !errors.Is(err, tt.kind)) || api.RetryAfter != tt.retry || calls != 1 {
				t.Fatalf("error=%v api=%+v calls=%d", err, api, calls)
			}
			if strings.Contains(fmt.Sprint(err, api), "api-secret") || strings.Contains(fmt.Sprint(err, api), "pass&secret") || strings.Contains(fmt.Sprint(err, api), "pass%26secret") {
				t.Fatalf("credentials exposed: %v", err)
			}
		})
	}
}

type echoTransport struct{}

func (echoTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("transport leaked pass&secret: %w", context.Canceled)
}

func TestTransportRedactionPreservesCancellationAndSafeURLCause(t *testing.T) {
	p, _ := internetbs.New(internetbs.Config{Key: "api-secret", Password: "pass&secret"}, dnsprovider.WithHTTPClient(&http.Client{Transport: echoTransport{}}))
	_, err := p.Account(context.Background())
	var uerr *url.Error
	if !errors.Is(err, context.Canceled) || !errors.As(err, &uerr) {
		t.Fatalf("lost transport cause: %v", err)
	}
	if strings.Contains(err.Error(), "pass&secret") || strings.Contains(uerr.Error(), "pass&secret") {
		t.Fatalf("secret in cause: %v / %v", err, uerr)
	}
}

func TestMalformedSuccessNeverLooksLikeEmptyInventory(t *testing.T) {
	for _, body := range []string{`{`, `{}`, `{"status":"SUCCESS"}`, `{"status":"SUCCESS","domaincount":null,"domain":[]}`, `{"status":"SUCCESS","domaincount":2,"domain":[{"name":"example.com"}]}`, `{"status":"SUCCESS","domaincount":1,"domain":[null]}`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer s.Close()
			p, _ := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithBaseURL(s.URL))
			if _, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
				t.Fatal("malformed success accepted")
			}
		})
	}
}

type failureTransport struct{ err error }

func (f failureTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

func TestCredentialRedactionMatchesEncodedAndOverlappingSecrets(t *testing.T) {
	for _, tt := range []struct{ key, password, echo string }{
		{"key", "pa/ss?", "pa%2fss%3f"},
		{"key", "pa/ss?", "pa%2Fss%3f"},
		{"secret", "secret&suffix", "secret&suffix"},
		{"secret", "secret&suffix", "secret%26suffix"},
	} {
		for _, transport := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/transport=%v", tt.echo, transport), func(t *testing.T) {
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = fmt.Fprintf(w, `{"status":"FAILURE","message":"echo %s"}`, tt.echo)
				}))
				defer s.Close()
				client := s.Client()
				if transport {
					client = &http.Client{Transport: failureTransport{fmt.Errorf("echo %s: %w", tt.echo, context.Canceled)}}
				}
				p, _ := internetbs.New(internetbs.Config{Key: tt.key, Password: tt.password}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(client))
				_, err := p.Account(context.Background())
				if err == nil || !strings.Contains(err.Error(), "echo [redacted]") || strings.Contains(err.Error(), "suffix") || strings.Contains(err.Error(), tt.echo) {
					t.Fatalf("incomplete redaction: %v", err)
				}
				if transport && !errors.Is(err, context.Canceled) {
					t.Fatalf("lost cancellation: %v", err)
				}
			})
		}
	}
}

type typedTransportError struct{ cause error }

func (*typedTransportError) Error() string   { return "transport metadata" }
func (e *typedTransportError) Unwrap() error { return e.cause }

func TestSafeTypedTransportCauseRetainsAsAndIs(t *testing.T) {
	original := &typedTransportError{cause: context.Canceled}
	p, _ := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithHTTPClient(&http.Client{Transport: failureTransport{original}}))
	_, err := p.Account(context.Background())
	var typed *typedTransportError
	if !errors.As(err, &typed) || typed != original || !errors.Is(err, context.Canceled) {
		t.Fatalf("lost safe transport metadata or cause: %v", err)
	}
}

func TestHiddenAndJoinedSecretCausesAreSanitized(t *testing.T) {
	for _, cause := range []error{
		&typedTransportError{cause: fmt.Errorf("password: %w", context.Canceled)},
		errors.Join(&typedTransportError{cause: fmt.Errorf("password: %w", context.Canceled)}, context.DeadlineExceeded),
	} {
		p, _ := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithHTTPClient(&http.Client{Transport: failureTransport{cause}}))
		_, err := p.Account(context.Background())
		var typed *typedTransportError
		if errors.As(err, &typed) || !errors.Is(err, context.Canceled) {
			t.Fatalf("unsafe typed cause exposed or cancellation lost: %v", err)
		}
		var walk func(error)
		walk = func(e error) {
			if e == nil {
				return
			}
			if strings.Contains(e.Error(), "password") {
				t.Errorf("secret in reachable error: %v", e)
			}
			if multi, ok := e.(interface{ Unwrap() []error }); ok {
				for _, child := range multi.Unwrap() {
					walk(child)
				}
			} else {
				walk(errors.Unwrap(e))
			}
		}
		walk(err)
	}
}

func TestLocalRecordValidationRedactsCredentials(t *testing.T) {
	p, _ := internetbs.New(internetbs.Config{Key: "api-secret", Password: "pass&secret"}, dnsprovider.WithHTTPClient(&http.Client{Transport: failureTransport{errors.New("unexpected request")}}))
	ctx := context.Background()
	invalidZone := dnsprovider.Zone{Name: "pass&secret.example.com"}
	validZone := dnsprovider.Zone{Name: "example.com"}
	valid := dnsprovider.Record{Name: "@", Type: "TXT", Value: "text", TTL: 300}
	invalidValue := dnsprovider.Record{Name: "@", Type: "A", Value: "pass&secret", TTL: 300}
	invalidOwner := dnsprovider.Record{Name: "pass&secret", Type: "TXT", Value: "text", TTL: 300}
	var errs []error
	_, err := p.Records(ctx, invalidZone, dnsprovider.RecordFilter{})
	errs = append(errs, err)
	errs = append(errs, p.DeleteRecord(ctx, invalidZone, valid))
	for _, input := range []struct {
		zone   dnsprovider.Zone
		record dnsprovider.Record
	}{{invalidZone, valid}, {validZone, invalidValue}, {validZone, invalidOwner}} {
		_, err = p.CreateRecord(ctx, input.zone, input.record)
		errs = append(errs, err)
		_, err = p.UpdateRecord(ctx, input.zone, valid, input.record)
		errs = append(errs, err)
	}
	for _, err := range errs {
		if err == nil || strings.Contains(err.Error(), "pass&secret") || strings.Contains(err.Error(), "unexpected request") {
			t.Errorf("unsafe local validation: %v", err)
		}
	}
}

func TestMalformedListedZoneNamesFailWithoutCredentialEcho(t *testing.T) {
	for _, name := range []string{"pass&secret.example.com", "bad..example.com", ".", "*.example.com"} {
		t.Run(name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprintf(w, `{"status":"SUCCESS","domaincount":1,"domain":[{"name":%q}]}`, name)
			}))
			defer s.Close()
			p, _ := internetbs.New(internetbs.Config{Key: "api-secret", Password: "pass&secret"}, dnsprovider.WithBaseURL(s.URL))
			_, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{})
			if err == nil || strings.Contains(err.Error(), "pass&secret") {
				t.Fatalf("invalid domain accepted or credential echoed: %v", err)
			}
		})
	}
}
