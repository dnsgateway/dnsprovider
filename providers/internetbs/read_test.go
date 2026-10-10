package internetbs_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/internetbs"
)

func TestAccountVerifiesEmptyBalanceWithoutExposingIdentity(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/Account/Balance/Get" || r.URL.RawQuery != "" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("ApiKey") != "key" || r.Form.Get("Password") != "password" || r.Form.Get("ResponseFormat") != "json" {
			t.Errorf("authentication form missing")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "balance": []any{}})
	}))
	defer s.Close()
	p, err := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	account, err := p.Account(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if account.Tenant.ID != "" || account.Tenant.Name != "" || len(account.Nameservers) != 0 {
		t.Fatalf("unexpected account metadata: %+v", account)
	}
}

func TestZonesNormalizesCompleteInventoryAndExactLookup(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Domain/List" {
			t.Errorf("unexpected command %s", r.URL.Path)
		}
		_ = r.ParseForm()
		if r.Form.Get("CompactList") != "no" || r.Form.Get("ReturnFields") != "NSList" {
			t.Errorf("unexpected listing options")
		}
		_, _ = w.Write([]byte(`{"status":"SUCCESS","domaincount":3,"domain":[{"name":"EXAMPLE.COM.","nslist":"NS-UK.TOPDNS.COM.,ns-canada.topdns.com"},{"name":"example.community","nslist":""},{"name":"shop.example.com","nslist":"external.invalid"}]}`))
	}))
	defer s.Close()
	p, err := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	set, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."})
	if err != nil {
		t.Fatal(err)
	}

	if set.Partial {
		t.Error("Zones is a Partial View, want a Full View")
	}

	zs := set.Zones

	if len(zs) != 2 || zs[0].ID != "example.com" || zs[0].Name != "example.com" || zs[0].State != dnsprovider.HostingUnknown || len(zs[0].Nameservers) != 2 || zs[0].Nameservers[0] != "ns-uk.topdns.com" {
		t.Fatalf("unexpected zones: %+v", zs)
	}
	z, err := p.Zone(context.Background(), "Example.Com.")
	if err != nil || z.ID != "example.com" {
		t.Fatalf("exact lookup: %+v %v", z, err)
	}
}

func TestRecordsPreserveValuesFiltersAndContentIdentity(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/Domain/DnsRecord/List" || r.Form.Get("Domain") != "example.com" || r.Form.Get("FilterType") != "" {
			t.Errorf("unexpected request: %s %v", r.URL.Path, r.Form)
		}
		_, _ = w.Write([]byte(`{"status":"SUCCESS","total_records":5,"records":[{"name":"EXAMPLE.COM.","type":"mx","value":"Mail.Example.Com.","ttl":300,"priority":10},{"name":"*.EXAMPLE.COM","type":"txt","value":"a \"quote\" and \\ escape","ttl":60},{"name":"www.example.com","type":"A","value":"192.0.2.1","ttl":3600},{"name":"example.com","type":"CAA","value":"0 issue letsencrypt.org","ttl":120,"priority":17,"comment":"retained"},{"name":"example.com","type":"MX","value":"Mail.Example.Com.","ttl":600,"priority":10}]}`))
	}))
	defer s.Close()
	p, err := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	zone := dnsprovider.Zone{ID: "example.com", Name: "Example.Com."}
	all, err := p.Records(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if all.Partial {
		t.Error("Records is a Partial View, want a Full View")
	}

	if len(all.Records) != 5 || all.Serial != 0 || all.Records[0].Name != "example.com" || all.Records[0].Type != "MX" || all.Records[0].Value != "10 Mail.Example.Com" || all.Records[0].TTL != 300 || all.Records[0].ID == "" || all.Records[0].ID == all.Records[4].ID {
		t.Fatalf("unexpected records: %+v", all)
	}
	if all.Records[3].Extras["priority"] != "17" || all.Records[3].Extras["comment"] != `"retained"` {
		t.Fatalf("metadata lost: %+v", all.Records[3])
	}
	for _, r := range all.Records {
		if err := internetbs.Factory().CheckExtras(r); err != nil {
			t.Errorf("Factory does not declare the extras of %+v: %v", r, err)
		}
	}
	if all.Records[1].Value != `a "quote" and \ escape` || all.Records[1].Name != "*.example.com" {
		t.Fatalf("TXT changed: %+v", all.Records[1])
	}
	filtered, err := p.Records(context.Background(), zone, dnsprovider.RecordFilter{Type: "mX", Contains: "EXAMPLE.COM."})
	if err != nil || len(filtered.Records) != 2 {
		t.Fatalf("filter: %+v %v", filtered, err)
	}
	unknown, err := p.Records(context.Background(), zone, dnsprovider.RecordFilter{Type: "unsupported"})
	if err != nil || len(unknown.Records) != 0 {
		t.Fatalf("unknown filter: %+v %v", unknown, err)
	}
}

func TestEmptyRecordsAcceptDocumentedMissingList(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"SUCCESS","total_records":0}`))
	}))
	defer s.Close()
	p, _ := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithBaseURL(s.URL))
	got, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil || len(got.Records) != 0 {
		t.Fatalf("empty records: %+v %v", got, err)
	}
}

func TestMalformedStoredRecordsRejectReadsAndMutations(t *testing.T) {
	for _, record := range []map[string]any{
		{"name": "example.com", "type": "MX", "value": "", "priority": 10, "ttl": 300},
		{"name": "example.com", "type": "MX", "value": " \t", "priority": 10, "ttl": 300},
		{"name": "example.com", "type": "MX", "value": "mail.example.com extra", "priority": 10, "ttl": 300},
		{"name": "example.com", "type": "MX", "value": "mail.example.com", "priority": 65536, "ttl": 300},
		{"name": ".", "type": "TXT", "value": "text", "ttl": 300},
		{"name": "bad..example.com", "type": "TXT", "value": "text", "ttl": 300},
		{"name": "example.com", "type": "A", "value": "invalid", "ttl": 300},
		{"name": "example.com", "type": "CNAME", "value": " ", "ttl": 300},
	} {
		t.Run(record["type"].(string)+"/"+record["value"].(string)+"/"+record["name"].(string), func(t *testing.T) {
			p, fixture := newDNSFixture(t, record)
			zone := dnsprovider.Zone{Name: "example.com"}
			if _, err := p.Records(context.Background(), zone, dnsprovider.RecordFilter{}); err == nil {
				t.Fatal("malformed record accepted")
			}
			if err := p.DeleteRecord(context.Background(), zone, dnsprovider.Record{Name: "example.com", Type: "MX", Value: "10 mail.example.com", TTL: 300}); err == nil {
				t.Fatal("deletion accepted malformed list")
			}
			if len(fixture.writes) != 0 {
				t.Fatalf("mutations sent: %v", fixture.writes)
			}
		})
	}
}

func TestNullMXAndStoredTTLRemainReadable(t *testing.T) {
	p, _ := newDNSFixture(t, map[string]any{"name": "@", "type": "MX", "value": ".", "priority": 0, "ttl": 2})
	got, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil || len(got.Records) != 1 || got.Records[0].Value != "0 ." || got.Records[0].TTL != 2 {
		t.Fatalf("null MX or stored TTL lost: %+v %v", got, err)
	}
}

func TestAPIFieldsCannotOverwriteRawRecordSelector(t *testing.T) {
	p, fixture := newDNSFixture(t, map[string]any{"name": "example.com", "type": "MX", "value": "mail.example.com.", "priority": 10, "ttl": 300, internetbs.ExtraWireValue: "other.example.com"})
	if _, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{}); err == nil {
		t.Fatal("reserved selector field accepted")
	}
	if len(fixture.writes) != 0 {
		t.Fatalf("mutations sent: %v", fixture.writes)
	}
}

func TestEmptyStoredTXTAndUnknownValuesRemainReadable(t *testing.T) {
	p, _ := newDNSFixture(t, map[string]any{"name": "example.com", "type": "TXT", "value": "", "ttl": 0}, map[string]any{"name": "example.com", "type": "FUTURE", "value": "", "ttl": 300})
	got, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil || len(got.Records) != 2 || got.Records[0].Value != "" || got.Records[0].TTL != 0 || got.Records[1].Type != "FUTURE" {
		t.Fatalf("stored data lost: %+v %v", got, err)
	}
}

func TestMalformedRecordErrorsRedactServerCredentialEcho(t *testing.T) {
	p, _ := newDNSFixture(t, map[string]any{"name": "example.com", "type": "A", "value": "test-password", "ttl": 300})
	_, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
	if err == nil || strings.Contains(err.Error(), "test-password") {
		t.Fatalf("unsafe malformed record error: %v", err)
	}
}
