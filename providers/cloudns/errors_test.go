package cloudns_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudns"
)

func TestAPIEnvelopesAndHTTPFailuresAreTypedAndRedacted(t *testing.T) {
	for _, tc := range []struct {
		status  int
		message string
		kind    error
	}{{200, "Invalid authentication, incorrect auth-id or auth-password. secret-password 12345", dnsprovider.ErrUnauthorized}, {200, "Permission denied", dnsprovider.ErrUnauthorized}, {200, "Missing domain-name", dnsprovider.ErrNotFound}, {200, "Record already exists", dnsprovider.ErrConflict}, {200, "API request limit exceeded", dnsprovider.ErrRateLimited}, {401, "", dnsprovider.ErrUnauthorized}, {403, "", dnsprovider.ErrUnauthorized}, {404, "", dnsprovider.ErrNotFound}, {409, "", dnsprovider.ErrConflict}, {429, "", dnsprovider.ErrRateLimited}} {
		t.Run(fmt.Sprint(tc.status, tc.message), func(t *testing.T) {
			p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"status":"Failed","statusDescription":%q}`, tc.message)
			})
			_, err := p.Account(context.Background())
			var api *dnsprovider.APIError
			if !errors.Is(err, tc.kind) || !errors.As(err, &api) {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "secret-password") || strings.Contains(err.Error(), "12345") {
				t.Fatal("credential leak")
			}
		})
	}
}

func TestMalformedResponsesFailAndCancellationIsRespected(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"status":"mystery"}`, `not json`, `{"status":"Success","statusDescription":"ok"}`} {
		p := newProvider(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		if _, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
			t.Fatalf("accepted malformed zones %s", body)
		}
	}
	p := newProvider(t, func(w http.ResponseWriter, r *http.Request) { t.Error("canceled request sent") })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Account(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMutationsAreNeverRetried(t *testing.T) {
	for _, path := range []string{"/dns/add-record.json", "/dns/mod-record.json", "/dns/delete-record.json"} {
		attempts := 0
		p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/dns/records.json":
				fmt.Fprint(w, `{"1":{"id":"1","type":"A","host":"www","record":"192.0.2.1","ttl":"300"}}`)
			case "/dns/get-available-ttl.json":
				fmt.Fprint(w, `[300]`)
			default:
				attempts++
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, `{"status":"Failed","statusDescription":"unavailable"}`)
			}
		})
		r := dnsprovider.Record{ID: "1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}
		var err error
		switch path {
		case "/dns/add-record.json":
			r.Name = "new.example.com"
			_, err = p.CreateRecord(context.Background(), testZone, r)
		case "/dns/mod-record.json":
			after := r
			after.Value = "192.0.2.9"
			_, err = p.UpdateRecord(context.Background(), testZone, r, after)
		default:
			err = p.DeleteRecord(context.Background(), testZone, r)
		}
		if !errors.Is(err, dnsprovider.ErrUnconfirmed) || attempts != 1 {
			t.Fatalf("%s: attempts %d, error %v, want ErrUnconfirmed", path, attempts, err)
		}
	}
}

// writeAnswered creates a Record against a Provider whose add-record
// command is answered by add.
func writeAnswered(t *testing.T, add http.HandlerFunc) error {
	t.Helper()
	p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dns/records.json":
			fmt.Fprint(w, `{}`)
		case "/dns/get-available-ttl.json":
			fmt.Fprint(w, `[300]`)
		default:
			add(w, r)
		}
	})
	_, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "A", Name: "new.example.com", Value: "192.0.2.1", TTL: 300})
	return err
}

func TestAWriteWithALostOrMalformedAnswerIsUnconfirmed(t *testing.T) {
	for name, add := range map[string]http.HandlerFunc{
		"lost":      func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) },
		"malformed": func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"status":"mystery"}`) },
		"not json":  func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `not json`) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := writeAnswered(t, add); !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("create = %v, want ErrUnconfirmed", err)
			}
		})
	}
}

func TestAWriteTheAnswerRefusesIsNotUnconfirmed(t *testing.T) {
	for name, status := range map[string]int{"in the answer": http.StatusOK, "4xx": http.StatusBadRequest} {
		t.Run(name, func(t *testing.T) {
			err := writeAnswered(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				fmt.Fprint(w, `{"status":"Failed","statusDescription":"Invalid record"}`)
			})
			if err == nil || errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("refused create = %v, want an error without ErrUnconfirmed", err)
			}
		})
	}
}

func TestAFailedReadIsNotUnconfirmed(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"status":"Failed","statusDescription":"unavailable"}`)
	})
	_, err := p.ListRecords(context.Background(), testZone, dnsprovider.RecordFilter{})
	if err == nil || errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("read = %v, want an error without ErrUnconfirmed", err)
	}
}

func TestQuotaIsSharedAcrossCredentialsAndHonorsDeadline(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `[]`) }))
	defer s.Close()
	p, err := cloudns.New(cloudns.Config{Password: "first", AuthID: "1"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	other, err := cloudns.New(cloudns.Config{Password: "second", SubAuthID: "2"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err = other.ListZones(ctx, dnsprovider.ZoneFilter{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("quota ignored deadline: %v", err)
	}
}

func TestMalformedModeledRecordFieldsFailWithoutLeakingCredentials(t *testing.T) {
	for _, field := range []string{"id", "type", "host", "ttl", "record"} {
		p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
			rec := map[string]any{"id": "1", "type": "A", "host": "www", "record": "192.0.2.1", "ttl": "300"}
			rec[field] = map[string]string{"secret-password": "12345"}
			_ = json.NewEncoder(w).Encode(map[string]any{"1": rec})
		})
		if _, err := p.ListRecords(context.Background(), testZone, dnsprovider.RecordFilter{}); err == nil {
			t.Fatalf("accepted malformed %s", field)
		} else if strings.Contains(err.Error(), "secret-password") || strings.Contains(err.Error(), "12345") {
			t.Fatal("credential leak")
		}
	}
}

func TestSuppliedClientTimeoutBoundsRequest(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, `{"status":"Success"}`)
	}))
	defer s.Close()
	p, err := cloudns.New(cloudns.Config{Password: "secret", AuthID: "123"}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(&http.Client{Timeout: 20 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Account(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
