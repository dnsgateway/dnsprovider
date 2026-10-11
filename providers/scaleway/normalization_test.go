package scaleway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/scaleway"
)

// normalizedProvider returns protocol replies with known stored wire data,
// independently of the Value submitted by the caller.
func normalizedProvider(t *testing.T, typ, data string, priority uint32) (*scaleway.Provider, *int) {
	t.Helper()
	writes := 0
	stored := []map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dns-zones" {
			fmt.Fprintf(w, `{"total_count":1,"dns_zones":[{"domain":"example.com","subdomain":"dev","project_id":%q}]}`, project)
			return
		}
		if r.Method == http.MethodPatch {
			writes++
			stored = []map[string]any{{"id": "stored-id", "name": "www", "type": typ, "data": data, "priority": priority, "ttl": 600}}
			_ = json.NewEncoder(w).Encode(map[string]any{"records": stored})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(stored), "records": stored})
	}))
	t.Cleanup(srv.Close)
	p, err := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, dnsprovider.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return p, &writes
}

func TestCreateReturnsAuthoritativeNormalizedAddress(t *testing.T) {
	p, writes := normalizedProvider(t, "AAAA", "2001:db8::1", 0)
	got, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:0db8:0:0:0:0:0:1", TTL: 600})
	if err != nil || got.ID != "stored-id" || got.Value != "2001:db8::1" || *writes != 1 {
		t.Fatalf("normalized create %+v %v writes %d", got, err, *writes)
	}
}

func TestCreateReturnsAuthoritativeNormalizedTargets(t *testing.T) {
	for _, tc := range []struct {
		typ, input, data, want string
		priority               uint32
	}{
		{"CNAME", "TARGET.EXAMPLE.NET.", "target.example.net.", "target.example.net.", 0},
		{"NS", "NS.EXAMPLE.NET.", "ns.example.net.", "ns.example.net.", 0},
		{"MX", "10 MAIL.EXAMPLE.NET.", "mail.example.net.", "10 mail.example.net.", 10},
		{"SRV", "7 005 0443 TARGET.EXAMPLE.NET.", "5 443 target.example.net.", "7 5 443 target.example.net.", 7},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			p, writes := normalizedProvider(t, tc.typ, tc.data, tc.priority)
			got, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: tc.typ, Name: "www", Value: tc.input, TTL: 600})
			if err != nil || got.ID != "stored-id" || got.Value != tc.want || *writes != 1 {
				t.Fatalf("normalized target %+v %v writes %d", got, err, *writes)
			}
		})
	}
}

func TestNormalizationDoesNotConfirmDifferentPayloads(t *testing.T) {
	for _, tc := range []struct{ typ, input, data string }{
		{"AAAA", "2001:db8::1", "2001:db8::2"},
		{"CNAME", "target.example.net.", "other.example.net."},
		{"TXT", "CaseSensitive", `"casesensitive"`},
		{"CAA", `0 issue "LetsEncrypt.org"`, `0 issue "letsencrypt.org"`},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			p, writes := normalizedProvider(t, tc.typ, tc.data, 0)
			got, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: tc.typ, Name: "www", Value: tc.input, TTL: 600})
			if err == nil || got.ID != "" || *writes != 1 {
				t.Fatalf("different payload confirmed %+v %v writes %d", got, err, *writes)
			}
		})
	}
}

func TestCreateReturnsAuthoritativeNormalizedCAA(t *testing.T) {
	p, writes := normalizedProvider(t, "CAA", `0 issue "letsencrypt.org"`, 0)
	got, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "CAA", Name: "www", Value: `00 issue letsencrypt.org`, TTL: 600})
	if err != nil || got.ID != "stored-id" || got.Value != `0 issue "letsencrypt.org"` || *writes != 1 {
		t.Fatalf("normalized CAA %+v %v writes %d", got, err, *writes)
	}
}

func TestUpdateReturnsAuthoritativeNormalizedAddress(t *testing.T) {
	f, p := newFixture(t)
	f.records = []map[string]any{{"id": "old-id", "type": "AAAA", "name": "www", "data": "2001:db8::1", "priority": 0, "ttl": 600}}
	ctx := context.Background()
	before, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	after := before.Records[0]
	after.Value = "2001:0db8:0:0:0:0:0:2"
	f.normalizeData = "2001:db8::2"
	got, err := p.UpdateRecord(ctx, testZone, before.Records[0], after)
	if err != nil || got.ID == "" || got.ID == "old-id" || got.Value != "2001:db8::2" || f.writes != 1 {
		t.Fatalf("normalized update %+v %v writes %d", got, err, f.writes)
	}
}

func TestNormalizedUnchangedTTLModificationIsUnconfirmed(t *testing.T) {
	f, p := newFixture(t)
	f.records = []map[string]any{{"id": "old-id", "type": "AAAA", "name": "www", "data": "2001:0db8:0:0:0:0:0:1", "priority": 0, "ttl": 300}}
	ctx := context.Background()
	before, err := p.ListRecords(ctx, testZone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	after := before.Records[0]
	after.TTL = 600
	f.partial = true
	f.normalizeData = "2001:db8::1"
	res, err := dnsprovider.Apply(ctx, p, dnsprovider.Changeset{Zone: testZone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeModify, Before: before.Records[0], After: after}}})
	if err == nil || len(res.Results) != 1 || res.Results[0].Err == nil || f.writes != 1 {
		t.Fatalf("normalized partial %+v %v writes %d", res, err, f.writes)
	}
}

func TestNormalizedAdditionCannotReuseExistingIdentity(t *testing.T) {
	f, p := newFixture(t)
	f.records = []map[string]any{{"id": "existing-id", "type": "AAAA", "name": "www", "data": "2001:db8::1", "priority": 0, "ttl": 600}}
	f.partial = true
	got, err := p.CreateRecord(context.Background(), testZone, dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:0db8:0:0:0:0:0:1", TTL: 600})
	if err == nil || got.ID != "" || f.writes != 1 {
		t.Fatalf("existing identity accepted %+v %v writes %d", got, err, f.writes)
	}
}
