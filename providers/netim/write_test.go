package netim_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/netim"
)

const createPath = "POST /domain/example.com/zone/"

func TestCreateRecordSendsTheWireFormAndReturnsTheStoredRecord(t *testing.T) {
	tests := []struct {
		name string
		in   dnsprovider.Record
		want record
		wire map[string]any
	}{
		{
			name: "an A record with a relative name",
			in:   dnsprovider.Record{Type: "A", Name: "api", Value: "192.0.2.20", TTL: 3600},
			want: record{"A", "api.example.com", "192.0.2.20", 3600, nil},
			wire: map[string]any{"subdomain": "api", "type": "A", "value": "192.0.2.20", "options": map[string]any{"ttl": 3600.0, "ttlUnit": "S"}},
		},
		{
			name: "an AAAA record at the apex",
			in:   dnsprovider.Record{Type: "aaaa", Name: "@", Value: "2001:db8::20", TTL: 300},
			want: record{"AAAA", "example.com", "2001:db8::20", 300, nil},
			wire: map[string]any{"subdomain": "", "type": "AAAA", "value": "2001:db8::20", "options": map[string]any{"ttl": 300.0, "ttlUnit": "S"}},
		},
		{
			name: "a CNAME record with an absolute name",
			in:   dnsprovider.Record{Type: "CNAME", Name: "shop.example.com.", Value: "shops.example.net", TTL: 600},
			want: record{"CNAME", "shop.example.com", "shops.example.net", 600, nil},
			wire: map[string]any{"subdomain": "shop", "type": "CNAME", "value": "shops.example.net.", "options": map[string]any{"ttl": 600.0, "ttlUnit": "S"}},
		},
		{
			name: "an MX record with its priority as an option",
			in:   dnsprovider.Record{Type: "MX", Name: "example.com", Value: "20 mx2.example.com.", TTL: 3600},
			want: record{"MX", "example.com", "20 mx2.example.com", 3600, nil},
			wire: map[string]any{"subdomain": "", "type": "MX", "value": "mx2.example.com.", "options": map[string]any{"ttl": 3600.0, "ttlUnit": "S", "priority": 20.0}},
		},
		{
			name: "a TXT record as literal text",
			in:   dnsprovider.Record{Type: "TXT", Name: "_dmarc", Value: `v=DMARC1; p=none; "quoted" \ text`, TTL: 3600},
			want: record{"TXT", "_dmarc.example.com", `v=DMARC1; p=none; "quoted" \ text`, 3600, nil},
			wire: map[string]any{"subdomain": "_dmarc", "type": "TXT", "value": `v=DMARC1; p=none; "quoted" \ text`, "options": map[string]any{"ttl": 3600.0, "ttlUnit": "S"}},
		},
		{
			name: "an NS record",
			in:   dnsprovider.Record{Type: "NS", Name: "dev", Value: "ns2.dns-host.example", TTL: 86400},
			want: record{"NS", "dev.example.com", "ns2.dns-host.example", 86400, nil},
			wire: map[string]any{"subdomain": "dev", "type": "NS", "value": "ns2.dns-host.example.", "options": map[string]any{"ttl": 86400.0, "ttlUnit": "S"}},
		},
		{
			name: "an SRV record with its service, protocol and numbers as options",
			in:   dnsprovider.Record{Type: "SRV", Name: "_xmpp._tcp.chat", Value: "5 0 5222 xmpp.example.com", TTL: 3600},
			want: record{"SRV", "_xmpp._tcp.chat.example.com", "5 0 5222 xmpp.example.com", 3600, nil},
			wire: map[string]any{"subdomain": "chat", "type": "SRV", "value": "xmpp.example.com.", "options": map[string]any{
				"ttl": 3600.0, "ttlUnit": "S", "service": "xmpp", "protocol": "TCP", "priority": 5.0, "weight": 0.0, "port": 5222.0,
			}},
		},
		{
			name: "an SRV record at the apex",
			in:   dnsprovider.Record{Type: "SRV", Name: "_sips._TLS.example.com", Value: "10 60 5061 sip.example.com", TTL: 3600},
			want: record{"SRV", "_sips._tls.example.com", "10 60 5061 sip.example.com", 3600, nil},
			wire: map[string]any{"subdomain": "", "type": "SRV", "value": "sip.example.com.", "options": map[string]any{
				"ttl": 3600.0, "ttlUnit": "S", "service": "sips", "protocol": "TLS", "priority": 10.0, "weight": 60.0, "port": 5061.0,
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider()

			got, err := p.CreateRecord(context.Background(), zone, tt.in)
			if err != nil {
				t.Fatal(err)
			}

			if got.ID == "" || !reflect.DeepEqual(record{got.Type, got.Name, got.Value, got.TTL, got.Extras}, tt.want) {
				t.Errorf("CreateRecord = %+v, want %+v", got, tt.want)
			}

			if body := f.body(createPath); !reflect.DeepEqual(body, tt.wire) {
				t.Errorf("create body =\n%v\nwant\n%v", body, tt.wire)
			}

			set, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{Type: tt.want.Type})
			if err != nil {
				t.Fatal(err)
			}

			if !slicesContainID(set.Records, got.ID) {
				t.Errorf("the Zone does not hold the created Record %+v", got)
			}
		})
	}
}

func slicesContainID(rs []dnsprovider.Record, id string) bool {
	for _, r := range rs {
		if r.ID == id {
			return true
		}
	}

	return false
}

func TestCreateRecordOfARecordTheZoneHoldsIsAConflictWithoutAWrite(t *testing.T) {
	f := newFake(t)

	// The Zone holds MX 10 mail.example.com. at the apex, with the Zone's TTL.
	_, err := f.provider().CreateRecord(context.Background(), zone, dnsprovider.Record{Type: "MX", Name: "@", Value: "10 mail.example.com.", TTL: 300})
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("CreateRecord = %v, want ErrConflict", err)
	}

	if n := f.count(createPath); n != 0 {
		t.Fatalf("sent %d creates, want none", n)
	}
}

func TestCreateRecordRefusesLocallyWhatNetimCannotTake(t *testing.T) {
	long := strings.Repeat("a", 151)

	tests := map[string]dnsprovider.Record{
		"a CAA record":                    {Type: "CAA", Name: "@", Value: `0 issue "letsencrypt.org"`, TTL: 3600},
		"a URI record":                    {Type: "URI", Name: "_ftp._tcp", Value: `10 1 "ftp://ftp.example.com/"`, TTL: 3600},
		"a TLSA record, read only":        {Type: "TLSA", Name: "_25._tcp.mail", Value: "3 1 1 0123", TTL: 3600},
		"an unknown type":                 {Type: "SPF", Name: "@", Value: "v=spf1 -all", TTL: 3600},
		"a name outside the Zone":         {Type: "A", Name: "www.example.org.", Value: "192.0.2.1", TTL: 3600},
		"an invalid A value":              {Type: "A", Name: "www", Value: "2001:db8::1", TTL: 3600},
		"an invalid MX value":             {Type: "MX", Name: "@", Value: "mail.example.com", TTL: 3600},
		"a TXT value over 150 characters": {Type: "TXT", Name: "@", Value: long, TTL: 3600},
		"a CNAME target over 150 characters": {
			Type: "CNAME", Name: "long", Value: strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 30) + ".example", TTL: 3600,
		},
		"a TTL below the range":                  {Type: "A", Name: "www", Value: "192.0.2.1", TTL: 29},
		"a TTL above the range":                  {Type: "A", Name: "www", Value: "192.0.2.1", TTL: 86401},
		"an automatic TTL":                       {Type: "A", Name: "www", Value: "192.0.2.1", TTL: dnsprovider.TTLAuto},
		"an SRV name without service":            {Type: "SRV", Name: "sip", Value: "10 60 5060 sip.example.com", TTL: 3600},
		"an SRV name with an unknown protocol":   {Type: "SRV", Name: "_sip._sctp", Value: "10 60 5060 sip.example.com", TTL: 3600},
		"an SRV name whose owner is not in Zone": {Type: "SRV", Name: "_sip._tcp.example.org.", Value: "10 60 5060 sip.example.com", TTL: 3600},
		"record options": {
			Type: "A", Name: "www", Value: "192.0.2.1", TTL: 3600, Extras: map[string]string{dnsprovider.ExtraOther: `{"x":1}`},
		},
	}

	p, err := netim.New(netim.Config{ID: resellerID, Secret: secret}, dnsprovider.WithHTTPClient(nonet.Client(t)))
	if err != nil {
		t.Fatal(err)
	}

	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := p.CreateRecord(context.Background(), zone, r); err == nil {
				t.Fatal("CreateRecord succeeded, want a refusal")
			}
		})
	}
}

func TestTheValueLimitCountsATargetWithoutItsTrailingDot(t *testing.T) {
	target := func(n int) string { // a name of n characters
		return strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", n-136) + ".example"
	}

	f := newFake(t)
	p := f.provider()

	if _, err := p.CreateRecord(context.Background(), zone, dnsprovider.Record{Type: "CNAME", Name: "long", Value: target(150), TTL: 3600}); err != nil {
		t.Fatalf("CreateRecord of a 150-character target = %v", err)
	}

	if _, err := p.CreateRecord(context.Background(), zone, dnsprovider.Record{Type: "CNAME", Name: "longer", Value: target(151), TTL: 3600}); err == nil {
		t.Fatal("CreateRecord of a 151-character target succeeded, want a refusal")
	}

	if n := f.count(createPath); n != 1 {
		t.Fatalf("sent %d creates, want 1", n)
	}
}

// operationReply is a create answered with an operation of that status
// and message.
func operationReply(status, message string) string {
	return fmt.Sprintf(`{"ID_OPE":100009,"STATUS":%q,"MESSAGE":%q,"TYPE":"domainZoneCreate","DATE":"2026-01-01 12:00:00","DATA":"example.com"}`, status, message)
}

func TestCreateRecordReportsWhatNetimDidNotConfirmAsUnconfirmed(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		// readBack lets the fake apply the create and fails its read-back.
		readBack bool
	}{
		{name: "a Pending operation", status: http.StatusOK, body: fixture(t, "operation_pending.json")},
		{name: "an unknown status", status: http.StatusOK, body: operationReply("Queued", "")},
		{name: "a 5xx", status: http.StatusInternalServerError, body: `{"message":"internal error"}`},
		{name: "a lost answer", status: lost},
		{name: "a malformed body", status: http.StatusOK, body: `<html>gateway</html>`},
		{name: "a read-back that does not show the write", status: http.StatusOK, body: fixture(t, "zone_create_done.json")},
		{name: "a read-back that fails", readBack: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider()

			if tt.readBack {
				// The duplicate check reads the zone, the read-back fails.
				f.script("GET /domain/example.com/zone/info/", http.StatusOK, fixture(t, "zone_info.json"))
				f.script("GET /domain/example.com/zone/info/", http.StatusBadRequest, fixture(t, "error_400.json"))
			} else {
				f.script(createPath, tt.status, tt.body)
			}

			_, err := p.CreateRecord(context.Background(), zone, dnsprovider.Record{Type: "A", Name: "api", Value: "192.0.2.20", TTL: 3600})
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("CreateRecord = %v, want ErrUnconfirmed", err)
			}

			if n := f.count(createPath); n != 1 {
				t.Fatalf("sent %d creates, want 1", n)
			}
		})
	}
}

func TestCreateRecordReportsARefusalWithNetimsMessage(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		message string
	}{
		{"a Failed operation", http.StatusOK, fixture(t, "zone_create_failed.json"), "SYNTHETIC: record refused"},
		{"a Cancelled operation", http.StatusOK, fixture(t, "operation_cancelled.json"), "SYNTHETIC: operation cancelled"},
		{"a 400", http.StatusBadRequest, fixture(t, "error_400.json"), "SYNTHETIC: bad request"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.script(createPath, tt.status, tt.body)

			_, err := f.provider().CreateRecord(context.Background(), zone, dnsprovider.Record{Type: "A", Name: "api", Value: "192.0.2.20", TTL: 3600})
			if err == nil || errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("CreateRecord = %v, want a refusal, not ErrUnconfirmed", err)
			}

			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) || !strings.Contains(strings.Join(apiErr.Messages, " "), tt.message) {
				t.Fatalf("CreateRecord = %v, want an APIError with %q", err, tt.message)
			}

			if n := f.count(createPath); n != 1 {
				t.Fatalf("sent %d creates, want 1", n)
			}

			if n := f.count("GET /domain/example.com/zone/info/"); n != 1 {
				t.Fatalf("read the zone %d times, want only the duplicate check", n)
			}
		})
	}
}

func TestCreateRecordWithAnExpiredSessionIsSentOnceMoreWithANewOne(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	listed(t, p) // opens a session
	f.script(createPath, http.StatusUnauthorized, fixture(t, "error_401.json"))

	if _, err := p.CreateRecord(context.Background(), zone, dnsprovider.Record{Type: "A", Name: "api", Value: "192.0.2.20", TTL: 3600}); err != nil {
		t.Fatal(err)
	}

	if opened, _, _ := f.stats(); opened != 2 || f.count(createPath) != 2 {
		t.Fatalf("opened %d sessions and sent %d creates, want 2 and 2", opened, f.count(createPath))
	}
}

const deletePath = "DELETE /domain/example.com/zone/"

// listed is every Record of the fake's zone.
func listed(t *testing.T, p *netim.Provider) []dnsprovider.Record {
	t.Helper()

	set, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	return set.Records
}

func TestDeleteRecordRemovesExactlyTheSelectedRecord(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		wire map[string]any
	}{
		{"an MX at the apex given as @", "MX", map[string]any{"subdomain": "@", "type": "MX", "value": "mail.example.com."}},
		{"an A at the apex given as empty", "A", map[string]any{"subdomain": "", "type": "A", "value": "192.0.2.10"}},
		{"an SRV", "SRV", map[string]any{"subdomain": "", "type": "SRV", "value": "sip.example.com."}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider()

			before := listed(t, p)

			var target dnsprovider.Record

			var siblings []dnsprovider.Record

			for _, r := range before {
				if r.Type == tt.typ {
					target = r
				} else {
					siblings = append(siblings, r)
				}
			}

			if err := p.DeleteRecord(context.Background(), zone, target); err != nil {
				t.Fatal(err)
			}

			if body := f.body(deletePath); !reflect.DeepEqual(body, tt.wire) {
				t.Errorf("delete body = %v, want %v", body, tt.wire)
			}

			if after := listed(t, p); !reflect.DeepEqual(after, siblings) {
				t.Errorf("the Zone holds\n%+v\nwant\n%+v", after, siblings)
			}
		})
	}
}

func TestDeleteRecordOfAStaleRecordIsNotFoundWithoutAWrite(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	var mx dnsprovider.Record

	for _, r := range listed(t, p) {
		if r.Type == "MX" {
			mx = r
		}
	}

	stale := []dnsprovider.Record{
		{Type: "A", Name: "gone.example.com", Value: "192.0.2.99", TTL: 3600},
		func() dnsprovider.Record { r := mx; r.ID = "changed since read"; return r }(),
	}

	for _, r := range stale {
		if err := p.DeleteRecord(context.Background(), zone, r); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Errorf("DeleteRecord(%+v) = %v, want ErrNotFound", r, err)
		}
	}

	if n := f.count(deletePath); n != 0 {
		t.Fatalf("sent %d deletes, want none", n)
	}
}

func TestDeleteRecordRefusesASelectionNetimCouldReadAsSeveralRecords(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	// Two MX records to one host: a delete names only subdomain, type and
	// value, so it would match both.
	info := `{"ttl":1,"ttlUnit":"H","records":[
		{"subdomain":"","type":"MX","value":"mail.example.com.","options":{"priority":10}},
		{"subdomain":"@","type":"MX","value":"mail.example.com","options":{"priority":20}}]}`
	f.script("GET /domain/example.com/zone/info/", http.StatusOK, info)
	f.script("GET /domain/example.com/zone/info/", http.StatusOK, info)

	err := p.DeleteRecord(context.Background(), zone, listed(t, p)[0])
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("DeleteRecord = %v, want an ambiguous selection refused with ErrConflict", err)
	}

	if n := f.count(deletePath); n != 0 {
		t.Fatalf("sent %d deletes, want none", n)
	}
}

func TestDeleteRecordRefusesLocallyTypesItDoesNotWrite(t *testing.T) {
	p, err := netim.New(netim.Config{ID: resellerID, Secret: secret}, dnsprovider.WithHTTPClient(nonet.Client(t)))
	if err != nil {
		t.Fatal(err)
	}

	for _, typ := range []string{"TLSA", "CAA", "URI", "HTTPS"} {
		if err := p.DeleteRecord(context.Background(), zone, dnsprovider.Record{Type: typ, Name: "example.com", Value: "x", TTL: 3600}); err == nil {
			t.Errorf("DeleteRecord of %s succeeded, want a refusal", typ)
		}
	}
}

func TestDeleteRecordReportsUnconfirmedAndRefusedDeletesWithoutRetrying(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		unconfirmed bool
	}{
		{"a 5xx", http.StatusServiceUnavailable, `{"message":"unavailable"}`, true},
		{"a lost answer", lost, "", true},
		{"a Pending operation", http.StatusOK, fixture(t, "operation_pending.json"), true},
		{"a Failed operation", http.StatusOK, operationReply("Failed", "record locked"), false},
		{"a Cancelled operation", http.StatusOK, fixture(t, "operation_cancelled.json"), false},
		{"a 400", http.StatusBadRequest, fixture(t, "error_400.json"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider()
			f.script(deletePath, tt.status, tt.body)

			err := p.DeleteRecord(context.Background(), zone, listed(t, p)[0])
			if err == nil || errors.Is(err, dnsprovider.ErrUnconfirmed) != tt.unconfirmed {
				t.Fatalf("DeleteRecord = %v, want unconfirmed %v", err, tt.unconfirmed)
			}

			if n := f.count(deletePath); n != 1 {
				t.Fatalf("sent %d deletes, want 1", n)
			}
		})
	}
}
