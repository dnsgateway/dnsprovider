package porkbun_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
)

type dnsAPI struct {
	mu           sync.Mutex
	records      []map[string]any
	writes       []string
	fail         string
	readbackFail bool
	next         int
}

func fixtureAPI(t *testing.T) (*dnsAPI, dnsprovider.Provider) {
	t.Helper()
	api := &dnsAPI{next: 200, records: []map[string]any{
		{"id": "101", "name": "www.example.com", "type": "A", "content": "192.0.2.1", "ttl": "600", "prio": nil, "notes": "retain annotation", "providerFutureField": "retained"},
		{"id": "102", "name": "www.example.com", "type": "A", "content": "192.0.2.2", "ttl": "600", "prio": nil},
		{"id": "103", "name": "example.com", "type": "HTTPS", "content": "1 . alpn=h2", "ttl": "600", "prio": nil},
	}}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()
		if r.Header.Get("X-Api-Key") != "test-key" || r.Header.Get("X-Secret-Api-Key") != "test-secret" {
			t.Error("missing credentials")
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		op := parts[1]
		id := ""
		if len(parts) > 3 {
			id = parts[3]
		}
		if op == "retrieve" {
			if api.readbackFail && len(api.writes) > 0 && id != "" {
				w.Header().Set("Retry-After", "12")
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"status":"ERROR","code":"DNS_READ_FAILED","message":"readback unavailable"}`))
				return
			}
			if r.Method != http.MethodGet {
				t.Error("reads must be safe GET")
			}
			rs := make([]map[string]any, 0)
			for _, v := range api.records {
				if id == "" || v["id"] == id {
					rs = append(rs, v)
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "records": rs})
			return
		}
		if r.Method != http.MethodPost {
			t.Error("writes must be POST")
		}
		api.writes = append(api.writes, op)
		if op == api.fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"ERROR","code":"DNS_READ_FAILED","message":"unavailable"}`))
			return
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid mutation JSON")
		}
		if op == "create" {
			api.next++
			id = strconv.Itoa(api.next)
			v := map[string]any{"id": id, "name": "example.com", "type": body["type"], "content": body["content"], "ttl": fmt.Sprint(body["ttl"]), "prio": nil}
			if n, ok := body["name"].(string); ok && n != "" {
				v["name"] = strings.ToLower(n) + ".example.com"
			}
			if pr, ok := body["prio"]; ok {
				v["prio"] = fmt.Sprint(pr)
			}
			if n, ok := body["notes"]; ok {
				v["notes"] = n
			}
			api.records = append(api.records, v)
			json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "id": id})
			return
		}
		for i, v := range api.records {
			if v["id"] != id {
				continue
			}
			if op == "delete" {
				api.records = append(api.records[:i], api.records[i+1:]...)
			} else {
				for k, val := range body {
					switch k {
					case "name":
						n := val.(string)
						v[k] = "example.com"
						if n != "" {
							v[k] = strings.ToLower(n) + ".example.com"
						}
					case "ttl", "prio":
						v[k] = fmt.Sprint(val)
					default:
						v[k] = val
					}
				}
			}
			w.Write([]byte(`{"status":"SUCCESS"}`))
			return
		}
		w.Write([]byte(`{"status":"ERROR","code":"INVALID_RECORD_ID","message":"record absent"}`))
	}))
	t.Cleanup(s.Close)
	p, err := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	return api, p
}

func TestCRUDPreservesSiblingsAndMetadataAcrossNameAndTypeMoves(t *testing.T) {
	api, p := fixtureAPI(t)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	set, err := p.Records(ctx, z, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	before := set.Records[0]
	_, err = p.CreateRecord(ctx, z, dnsprovider.Record{Type: "a", Name: "WWW.EXAMPLE.COM.", Value: "192.0.2.1", TTL: 1200})
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("duplicate error=%v", err)
	}
	after := dnsprovider.Record{Type: "MX", Name: "@", Value: "10 mail.example.net.", TTL: 1200}
	updated, err := p.UpdateRecord(ctx, z, before, after)
	if err != nil || updated.ID != before.ID || updated.Name != "example.com" || updated.Value != after.Value || updated.Extras[porkbun.ExtraNotes] != "retain annotation" {
		t.Fatalf("update=%+v,%v", updated, err)
	}
	api.mu.Lock()
	if api.records[0]["providerFutureField"] != "retained" {
		t.Error("edit discarded unmodeled metadata")
	}
	api.mu.Unlock()
	if err = p.DeleteRecord(ctx, z, updated); err != nil {
		t.Fatal(err)
	}
	remaining, err := p.Records(ctx, z, dnsprovider.RecordFilter{})
	if err != nil || len(remaining.Records) != 2 || remaining.Records[0].ID != "102" || remaining.Records[1].Type != "HTTPS" {
		t.Fatalf("remaining=%+v,%v", remaining, err)
	}
	for _, r := range []dnsprovider.Record{
		{Type: "A", Name: "new", Value: "192.0.2.9", TTL: 600},
		{Type: "AAAA", Name: "new", Value: "2001:db8::1", TTL: 600},
		{Type: "CNAME", Name: "alias", Value: "target.example.net.", TTL: 600},
		{Type: "NS", Name: "child", Value: "ns1.example.net.", TTL: 600},
		{Type: "SRV", Name: "_sip._tcp", Value: "10 5 443 sip.example.net.", TTL: 600},
		{Type: "TXT", Name: "*", Value: `hello "world"`, TTL: 600},
		{Type: "CAA", Name: "@", Value: `0 issue "letsencrypt.org"`, TTL: 600},
	} {
		got, err := p.CreateRecord(ctx, z, r)
		if err != nil || got.ID == "" || got.Value != r.Value || got.TTL != r.TTL {
			t.Fatalf("roundtrip %s=%+v,%v", r.Type, got, err)
		}
	}
}

func TestUnsupportedWritesAndMissingIDsCauseNoWrites(t *testing.T) {
	api, p := fixtureAPI(t)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	for _, r := range []dnsprovider.Record{
		{Type: "URI", Name: "@", Value: `10 1 "https://example.com/"`, TTL: 600},
		{Type: "A", Name: "@", Value: "192.0.2.9", TTL: 1},
		{Type: "A", Name: "@", Value: "192.0.2.9", TTL: 599},
	} {
		if _, err := p.CreateRecord(ctx, z, r); err == nil {
			t.Errorf("unsupported record accepted: %+v", r)
		}
	}
	_, err := p.UpdateRecord(ctx, z, dnsprovider.Record{ID: "999"}, dnsprovider.Record{Type: "A", Name: "@", Value: "192.0.2.9", TTL: 600})
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("missing update=%v", err)
	}
	if err := p.DeleteRecord(ctx, z, dnsprovider.Record{}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("missing ID delete=%v", err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.writes) != 0 {
		t.Fatalf("unsupported write sent: %v", api.writes)
	}
}

func TestPriorityInputsAcceptPresentationWhitespace(t *testing.T) {
	_, p := fixtureAPI(t)
	for _, r := range []dnsprovider.Record{{Type: "MX", Name: "@", Value: "10\tmail.example.net.", TTL: 600}, {Type: "SRV", Name: "_sip._tcp", Value: "20\t 5 443  sip.example.net.", TTL: 600}} {
		got, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, r)
		want := strings.Join(strings.Fields(r.Value), " ")
		if err != nil || got.Value != want {
			t.Fatalf("whitespace=%+v,%v want %s", got, err, want)
		}
	}
}

func TestUpdateCollisionLeavesEveryRecordUntouched(t *testing.T) {
	api, p := fixtureAPI(t)
	ctx := context.Background()
	z := dnsprovider.Zone{Name: "example.com"}
	rs, err := p.Records(ctx, z, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.UpdateRecord(ctx, z, rs.Records[0], rs.Records[1])
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("collision=%v", err)
	}
	api.mu.Lock()
	if len(api.writes) != 0 {
		t.Errorf("collision wrote %v", api.writes)
	}
	api.mu.Unlock()
	if err := p.DeleteRecord(ctx, z, rs.Records[0]); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteRecord(ctx, z, rs.Records[1]); err != nil {
		t.Fatal(err)
	}
	remaining, err := p.Records(ctx, z, dnsprovider.RecordFilter{})
	if err != nil || len(remaining.Records) != 1 || remaining.Records[0].ID != "103" {
		t.Fatalf("last sibling delete=%+v,%v", remaining, err)
	}
}

func TestCompletedWritesReportReadbackFailureWithoutResubmitting(t *testing.T) {
	for _, op := range []string{"create", "edit"} {
		t.Run(op, func(t *testing.T) {
			api, p := fixtureAPI(t)
			ctx := context.Background()
			z := dnsprovider.Zone{Name: "example.com"}
			rs, err := p.Records(ctx, z, dnsprovider.RecordFilter{})
			if err != nil {
				t.Fatal(err)
			}
			api.mu.Lock()
			api.readbackFail = true
			api.mu.Unlock()
			desired := dnsprovider.Record{Type: "AAAA", Name: "changed", Value: "2001:db8::1", TTL: 1200}
			if op == "create" {
				_, err = p.CreateRecord(ctx, z, desired)
			} else {
				_, err = p.UpdateRecord(ctx, z, rs.Records[0], desired)
			}
			if err == nil || !strings.Contains(err.Error(), "readback failed") {
				t.Fatalf("completed mutation=%v", err)
			}
			api.mu.Lock()
			if !slices.Equal(api.writes, []string{op}) {
				t.Errorf("mutation resubmitted %v", api.writes)
			}
			api.mu.Unlock()
			final, err := p.Records(ctx, z, dnsprovider.RecordFilter{Type: "AAAA"})
			if err != nil || len(final.Records) != 1 || final.Records[0].Value != desired.Value {
				t.Fatalf("completed DNS state=%+v,%v", final, err)
			}
		})
	}
}
