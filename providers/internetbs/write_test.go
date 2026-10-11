package internetbs_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/internetbs"
)

type dnsFixture struct {
	records  []map[string]any
	writes   []url.Values
	fail     map[string]string
	readFail bool
}

func newDNSFixture(t *testing.T, records ...map[string]any) (*internetbs.Provider, *dnsFixture) {
	t.Helper()
	f := &dnsFixture{records: append([]map[string]any{}, records...), fail: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		command := strings.TrimPrefix(r.URL.Path, "/")
		if command == "Domain/DnsRecord/List" {
			if f.readFail {
				http.Error(w, "read failed", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "total_records": len(f.records), "records": f.records})
			return
		}
		f.writes = append(f.writes, r.Form)
		if mode := f.fail[command]; mode != "" {
			delete(f.fail, command)
			if mode == "reject-twice" {
				f.fail[command] = "reject"
				mode = "reject"
			}
			if mode == "reject" {
				_, _ = w.Write([]byte(`{"status":"FAILURE","code":100002,"message":"invalid value"}`))
				return
			}
			if mode == "uncertain-read-failure" {
				f.readFail = true
			}
			if mode == "uncertain" || mode == "uncertain-read-failure" {
				http.Error(w, "uncertain", http.StatusInternalServerError)
				return
			}
			if mode == "acknowledged-read-failure" {
				defer func() { f.readFail = true }()
			}
			if mode == "lost-after-write" {
				defer func() { f.readFail = false }()
				f.readFail = true
			}
		}
		switch command {
		case "Domain/DnsRecord/Add":
			f.records = append(f.records, recordFromForm(r.Form, ""))
		case "Domain/DnsRecord/Remove":
			for i, rec := range f.records {
				if selected(rec, r.Form, false) {
					f.records = append(f.records[:i], f.records[i+1:]...)
					break
				}
			}
		case "Domain/DnsRecord/Update":
			for i, rec := range f.records {
				if selected(rec, r.Form, true) {
					changed := recordFromForm(r.Form, "New")
					for key, value := range rec {
						if _, exists := changed[key]; !exists {
							changed[key] = value
						}
					}
					f.records[i] = changed
					break
				}
			}
		default:
			t.Errorf("unexpected command %s", command)
		}
		if f.readFail {
			http.Error(w, "response lost", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS"})
	}))
	t.Cleanup(srv.Close)
	p, err := internetbs.New(internetbs.Config{Key: "test-key", Password: "test-password"}, dnsprovider.WithBaseURL(srv.URL), dnsprovider.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return p, f
}

func rr(name, typ, value string, ttl uint32) map[string]any {
	return map[string]any{"name": name, "type": typ, "value": value, "ttl": ttl}
}

func recordFromForm(form url.Values, prefix string) map[string]any {
	ttl := form.Get(prefix + "Ttl")
	var n uint32
	_, _ = fmt.Sscan(ttl, &n)
	rec := rr(form.Get("FullRecordName"), form.Get("Type"), form.Get(prefix+"Value"), n)
	if form.Get("Type") == "MX" {
		var priority uint32
		_, _ = fmt.Sscan(form.Get(prefix+"Priority"), &priority)
		rec["priority"] = priority
	}
	return rec
}

func selected(rec map[string]any, form url.Values, update bool) bool {
	prefix := ""
	if update {
		prefix = "Current"
	}
	if rec["name"] != form.Get("FullRecordName") || rec["type"] != form.Get("Type") || rec["value"] != form.Get(prefix+"Value") || fmt.Sprint(rec["ttl"]) != form.Get(prefix+"Ttl") {
		return false
	}
	return rec["type"] != "MX" || fmt.Sprint(rec["priority"]) == form.Get(prefix+"Priority")
}

func TestCreateReadback(t *testing.T) {
	p, f := newDNSFixture(t)
	got, err := p.CreateRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.Record{Name: "@", Type: "TXT", Value: `a "quoted" \\ text`, TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "example.com" || got.ID == "" || got.Value != `a "quoted" \\ text` || len(f.records) != 1 {
		t.Fatalf("stored record: %+v, %+v", got, f.records)
	}
}

func TestNativeUpdateAndExactDeletePreserveSibling(t *testing.T) {
	p, f := newDNSFixture(t, rr("www.example.com", "A", "192.0.2.1", 300), rr("www.example.com", "A", "192.0.2.2", 300), rr("example.com", "DYNAMIC", "opaque", 300))
	zone := dnsprovider.Zone{Name: "example.com"}
	set, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	after := set.Records[0]
	after.Value = "192.0.2.3"
	after.TTL = 600
	changed, err := p.UpdateRecord(context.Background(), zone, set.Records[0], after)
	if err != nil {
		t.Fatal(err)
	}
	if changed.ID == set.Records[0].ID || changed.TTL != 600 {
		t.Fatalf("changed %+v", changed)
	}
	if err := p.DeleteRecord(context.Background(), zone, changed); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 2 || f.records[0]["value"] != "192.0.2.2" || f.records[1]["type"] != "DYNAMIC" {
		t.Fatalf("siblings %+v", f.records)
	}
}

func TestFactory(t *testing.T) {
	factory := internetbs.Factory()
	for _, field := range factory.Fields {
		if !field.Secret || field.Label == "" {
			t.Fatalf("field %+v", field)
		}
	}
	for _, values := range []map[string]string{{}, {"key": "x", "password": " "}, {"key": "x", "password": "y", "unknown": "secret-value"}} {
		p, err := factory.New(values)
		if err == nil || p != nil || strings.Contains(err.Error(), "secret-value") {
			t.Fatalf("config: %v %v", p, err)
		}
	}
	p, err := factory.New(map[string]string{"key": "x", "password": "y"})
	if err != nil {
		t.Fatal(err)
	}
	if len(factory.Capabilities) != 0 || dnsprovider.Can(p, dnsprovider.CapZoneCreator) || dnsprovider.Can(p, dnsprovider.CapZoneUpdater) || dnsprovider.Can(p, dnsprovider.CapZoneDeleter) || dnsprovider.AutoTTLOf(p) {
		t.Fatal("unexpected capabilities")
	}
}

func TestSupportedWritesAndRawSelectors(t *testing.T) {
	for _, record := range []dnsprovider.Record{{Name: "*", Type: "A", Value: "192.0.2.1", TTL: 300}, {Name: "@", Type: "AAAA", Value: "2001:db8::1", TTL: 300}, {Name: "www", Type: "CNAME", Value: "target.example.net.", TTL: 300}, {Name: "@", Type: "MX", Value: "20 mail.example.net.", TTL: 300}, {Name: "@", Type: "NS", Value: "Ns.Example.net.", TTL: 300}} {
		t.Run(record.Type, func(t *testing.T) {
			p, f := newDNSFixture(t)
			zone := dnsprovider.Zone{Name: "example.com"}
			got, err := p.CreateRecord(context.Background(), zone, record)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.DeleteRecord(context.Background(), zone, got); err != nil || len(f.records) != 0 {
				t.Fatalf("delete: %v %+v", err, f.records)
			}
		})
	}
	mx := rr("example.com", "MX", "Mail.example.net.", 300)
	mx["priority"] = uint32(10)
	p, f := newDNSFixture(t, rr("www.example.com", "CNAME", "Target.example.net.", 300), mx)
	set, err := p.ListRecords(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range set.Records {
		if err := p.DeleteRecord(context.Background(), dnsprovider.Zone{Name: "example.com"}, r); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.records) != 0 || f.writes[0].Get("Value") != "Target.example.net." || f.writes[1].Get("Priority") != "10" {
		t.Fatalf("selectors %+v", f.writes)
	}
}

func TestSelectionAndValidationHaveNoSideEffects(t *testing.T) {
	p, f := newDNSFixture(t, rr("example.com", "A", "192.0.2.1", 300), rr("example.com", "A", "192.0.2.2", 300))
	zone := dnsprovider.Zone{Name: "example.com"}
	set, _ := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	_, err := p.CreateRecord(context.Background(), zone, dnsprovider.Record{Name: "@", Type: "A", Value: "192.0.2.1", TTL: 600})
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatal(err)
	}
	after := set.Records[0]
	after.Value = "192.0.2.2"
	_, err = p.UpdateRecord(context.Background(), zone, set.Records[0], after)
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatal(err)
	}
	missing := set.Records[0]
	missing.ID = "missing"
	if err := p.DeleteRecord(context.Background(), zone, missing); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatal(err)
	}
	for _, r := range []dnsprovider.Record{{Name: "@", Type: "SRV", Value: "10 2 443 host.example.net", TTL: 300}, {Name: "elsewhere.net.", Type: "A", Value: "192.0.2.3", TTL: 300}, {Name: "@", Type: "AAAA", Value: "192.0.2.3", TTL: 300}, {Name: "@", Type: "TXT", Value: "x", TTL: 0}, {Name: "@", Type: "TXT", Value: "x", TTL: 300, Extras: map[string]string{"unknown": "x"}}} {
		if _, err := p.CreateRecord(context.Background(), zone, r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	if len(f.writes) != 0 {
		t.Fatalf("unsafe writes %+v", f.writes)
	}
	f.records = append(f.records, rr("example.com", "A", "192.0.2.1", 300))
	if err := p.DeleteRecord(context.Background(), zone, set.Records[0]); !errors.Is(err, dnsprovider.ErrConflict) || len(f.writes) != 0 {
		t.Fatalf("ambiguous %v %+v", err, f.writes)
	}
}

func TestReplacementRestorationAndUncertainty(t *testing.T) {
	for _, mode := range []string{"", "reject", "uncertain", "lost-after-write"} {
		t.Run(mode, func(t *testing.T) {
			p, f := newDNSFixture(t, rr("old.example.com", "A", "192.0.2.1", 300))
			zone := dnsprovider.Zone{Name: "example.com"}
			set, _ := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
			f.fail["Domain/DnsRecord/Add"] = mode
			after := set.Records[0]
			after.Name = "new.example.com"
			after.Type = "TXT"
			after.Value = "replacement"
			got, err := p.UpdateRecord(context.Background(), zone, set.Records[0], after)
			if mode == "" {
				if err != nil || got.Name != "new.example.com" || len(f.records) != 1 {
					t.Fatalf("move %+v %v", got, err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected failure")
			}
			if mode == "acknowledged-read-failure" {
				defer func() { f.readFail = true }()
			}
			if mode == "lost-after-write" {
				if len(f.writes) != 2 || len(f.records) != 1 || f.records[0]["name"] != "new.example.com" || !strings.Contains(err.Error(), "uncertain") {
					t.Fatalf("uncertainty %+v %v", f.records, err)
				}
				return
			}
			if len(f.records) != 1 || f.records[0]["name"] != "old.example.com" || len(f.writes) != 3 || !strings.Contains(err.Error(), "restored") {
				t.Fatalf("restore %+v %v", f.records, err)
			}
		})
	}
}

func TestAcknowledgedReadbackAndFailedRemove(t *testing.T) {
	p, f := newDNSFixture(t, rr("old.example.com", "A", "192.0.2.1", 300))
	zone := dnsprovider.Zone{Name: "example.com"}
	set, _ := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	f.fail["Domain/DnsRecord/Remove"] = "reject"
	after := set.Records[0]
	after.Name = "new.example.com"
	if _, err := p.UpdateRecord(context.Background(), zone, set.Records[0], after); err == nil || len(f.writes) != 1 || len(f.records) != 1 {
		t.Fatalf("failed remove %v %+v", err, f.records)
	}
	f.fail["Domain/DnsRecord/Add"] = "acknowledged-read-failure"
	_, err := p.CreateRecord(context.Background(), zone, dnsprovider.Record{Name: "txt", Type: "TXT", Value: "x", TTL: 300})
	if err == nil || !strings.Contains(err.Error(), "acknowledged") || len(f.records) != 2 || len(f.writes) != 2 {
		t.Fatalf("readback %v %+v", err, f.records)
	}
}

func TestMetadataPreservedAndReplacementRefused(t *testing.T) {
	source := rr("old.example.com", "A", "192.0.2.1", 300)
	source["comment"] = "retain"
	p, f := newDNSFixture(t, source)
	zone := dnsprovider.Zone{Name: "example.com"}
	set, _ := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	after := set.Records[0]
	after.TTL = 600
	changed, err := p.UpdateRecord(context.Background(), zone, set.Records[0], after)
	if err != nil || changed.Extras["comment"] != `"retain"` {
		t.Fatalf("metadata %+v %v", changed, err)
	}
	after = changed
	after.Name = "new.example.com"
	if _, err := p.UpdateRecord(context.Background(), zone, changed, after); err == nil || len(f.writes) != 1 {
		t.Fatalf("replacement metadata %v", err)
	}
}

func TestApplyStaleAndOriginalOrder(t *testing.T) {
	p, f := newDNSFixture(t, rr("old.example.com", "A", "192.0.2.1", 300), rr("change.example.com", "TXT", "old", 300))
	zone := dnsprovider.Zone{Name: "example.com"}
	set, _ := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	stale := set.Records[0]
	stale.TTL = 600
	_, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: zone, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeDelete, Before: stale}}})
	if !errors.Is(err, dnsprovider.ErrStale) || len(f.writes) != 0 {
		t.Fatalf("stale %v", err)
	}
	after := set.Records[1]
	after.Value = "new"
	changes := []dnsprovider.Change{{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Name: "add", Type: "TXT", Value: "created", TTL: 300}}, {Kind: dnsprovider.ChangeModify, Before: set.Records[1], After: after}, {Kind: dnsprovider.ChangeDelete, Before: set.Records[0]}, {Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Name: "bad", Type: "SRV", Value: "10 1 443 target.example.net", TTL: 300}}}
	result, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: zone, Changes: changes})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 4 || result.Results[0].Record.Value != "created" || result.Results[1].Record.Value != "new" || result.Results[2].Err != nil || result.Results[3].Err == nil {
		t.Fatalf("results %+v", result)
	}
	if len(f.writes) != 3 || f.writes[0].Get("Value") != "192.0.2.1" || f.writes[1].Get("NewValue") != "new" || f.writes[2].Get("Value") != "created" {
		t.Fatalf("execution order %+v", f.writes)
	}
}

func TestFailedRestorationReportsRemovedOriginal(t *testing.T) {
	p, f := newDNSFixture(t, rr("old.example.com", "A", "192.0.2.1", 300))
	zone := dnsprovider.Zone{Name: "example.com"}
	set, _ := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	f.fail["Domain/DnsRecord/Add"] = "reject-twice"
	after := set.Records[0]
	after.Name = "new.example.com"
	_, err := p.UpdateRecord(context.Background(), zone, set.Records[0], after)
	if err == nil || !strings.Contains(err.Error(), "restoration failed") || len(f.records) != 0 || len(f.writes) != 3 {
		t.Fatalf("failed restoration %v %+v", err, f.records)
	}
}

func TestUnsupportedStoredRecordCannotBeDeletedByChangingInputType(t *testing.T) {
	p, f := newDNSFixture(t, rr("example.com", "DYNAMIC", "opaque", 300))
	zone := dnsprovider.Zone{Name: "example.com"}
	set, _ := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	before := set.Records[0]
	before.Type = "A"
	if err := p.DeleteRecord(context.Background(), zone, before); err == nil || len(f.writes) != 0 {
		t.Fatalf("unsafe unsupported deletion %v %+v", err, f.writes)
	}
}

func TestInvalidZoneFailsLocallyForRecordOperations(t *testing.T) {
	for _, name := range []string{"", ".", "bad..example.com", "bad name.example.com", "*.example.com"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls++
				_, _ = w.Write([]byte(`{"status":"SUCCESS","total_records":0}`))
			}))
			defer s.Close()
			p, _ := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithBaseURL(s.URL))
			zone := dnsprovider.Zone{Name: name}
			record := dnsprovider.Record{Name: "@", Type: "TXT", Value: "text", TTL: 300}
			if _, err := p.CreateRecord(context.Background(), zone, record); err == nil {
				t.Error("create accepted invalid zone")
			}
			if _, err := p.UpdateRecord(context.Background(), zone, record, record); err == nil {
				t.Error("update accepted invalid zone")
			}
			if err := p.DeleteRecord(context.Background(), zone, record); err == nil {
				t.Error("delete accepted invalid zone")
			}
			if _, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{}); err == nil {
				t.Error("read accepted invalid zone")
			}
			if calls != 0 {
				t.Fatalf("sent %d requests", calls)
			}
		})
	}
}

func TestNativeMXPriorityUpdateSelectsStoredTTLSibling(t *testing.T) {
	first := rr("example.com", "MX", "mail.example.com.", 300)
	first["priority"] = uint32(10)
	second := rr("example.com", "MX", "mail.example.com.", 600)
	second["priority"] = uint32(10)
	p, fixture := newDNSFixture(t, first, second)
	zone := dnsprovider.Zone{Name: "example.com"}
	set, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	after := set.Records[1]
	after.Value = "20 other.example.com."
	after.TTL = 900
	got, err := p.UpdateRecord(context.Background(), zone, set.Records[1], after)
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "20 other.example.com" || got.TTL != 900 || len(fixture.writes) != 1 || fixture.writes[0].Get("CurrentTtl") != "600" || fixture.writes[0].Get("CurrentValue") != "mail.example.com." || fixture.writes[0].Get("CurrentPriority") != "10" || fixture.writes[0].Get("NewPriority") != "20" {
		t.Fatalf("MX update selectors or result incorrect: %+v %v", got, fixture.writes)
	}
	remaining, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil || len(remaining.Records) != 2 || remaining.Records[0].ID != set.Records[0].ID {
		t.Fatalf("sibling changed: %+v %v", remaining, err)
	}
}

func TestUncertainReplacementFailedReadDoesNotRestore(t *testing.T) {
	p, fixture := newDNSFixture(t, rr("old.example.com", "A", "192.0.2.1", 300))
	zone := dnsprovider.Zone{Name: "example.com"}
	set, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	fixture.fail["Domain/DnsRecord/Add"] = "uncertain-read-failure"
	after := set.Records[0]
	after.Name = "new.example.com"
	_, err = p.UpdateRecord(context.Background(), zone, set.Records[0], after)
	if err == nil || !strings.Contains(err.Error(), "completion uncertain") || !strings.Contains(err.Error(), "readback failed") || len(fixture.writes) != 2 || len(fixture.records) != 0 {
		t.Fatalf("unsafe compensation or missing uncertainty: %v %+v", err, fixture.writes)
	}
}
