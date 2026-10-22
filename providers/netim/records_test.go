package netim_test

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

var zone = dnsprovider.Zone{ID: "example.com", Name: "example.com"}

// record is a Record without its ID, which is content-derived.
type record struct {
	Type, Name, Value string
	TTL               uint32
	Extras            map[string]string
}

func records(t *testing.T, set dnsprovider.RecordSet) []record {
	t.Helper()

	out := make([]record, 0, len(set.Records))

	for _, r := range set.Records {
		if r.ID == "" {
			t.Errorf("Record %+v has no ID", r)
		}

		out = append(out, record{r.Type, r.Name, r.Value, r.TTL, r.Extras})
	}

	return out
}

func TestListRecordsReturnsEveryRecordInTheSharedForm(t *testing.T) {
	f := newFake(t)

	set, err := f.provider().ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	want := []record{
		{"A", "example.com", "192.0.2.10", 10800, nil},
		{"AAAA", "www.example.com", "2001:db8::10", 10800, nil},
		{"CNAME", "blog.example.com", "www.example.com", 300, nil},
		{"MX", "example.com", "10 mail.example.com", 10800, nil},
		{"TXT", "example.com", "v=spf1 include:_spf.example.net ~all", 10800, nil},
		{"NS", "sub.example.com", "ns1.dns-host.example", 86400, nil},
		{"SRV", "_sip._tcp.example.com", "10 60 5060 sip.example.com", 10800, nil},
		{
			"TLSA", "_25._tcp.mail.example.com", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 10800,
			map[string]string{"certificateUsage": "3", "selector": "1", "matchingType": "1"},
		},
	}
	if got := records(t, set); !reflect.DeepEqual(got, want) {
		t.Fatalf("Records =\n%+v\nwant\n%+v", got, want)
	}

	if set.Partial {
		t.Error("ListRecords is a Partial View, want a Full View")
	}
}

func TestListRecordsFiltersExactly(t *testing.T) {
	f := newFake(t)

	set, err := f.provider().ListRecords(context.Background(), zone, dnsprovider.RecordFilter{Type: "mx", Contains: "EXAMPLE.com."})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := records(t, set), []record{{"MX", "example.com", "10 mail.example.com", 10800, nil}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Records = %+v, want %+v", got, want)
	}
}

func TestRecordTTLsAreEffectiveInEveryUnit(t *testing.T) {
	for _, tt := range []struct {
		name    string
		options string
		want    uint32
	}{
		{"inherited from the Zone", `{"ttl":5,"ttlUnit":"S","customTtl":false}`, 7200},
		{"inherited when not said", `{}`, 7200},
		{"custom seconds", `{"ttl":45,"ttlUnit":"S","customTtl":true}`, 45},
		{"custom without a unit", `{"ttl":45,"customTtl":1}`, 45},
		{"custom minutes", `{"ttl":"5","ttlUnit":"M","customTtl":"1"}`, 300},
		{"custom hours", `{"ttl":2,"ttlUnit":"h","customTtl":true}`, 7200},
		{"custom days", `{"ttl":1,"ttlUnit":"D","customTtl":true}`, 86400},
		{"custom weeks", `{"ttl":1,"ttlUnit":"W","customTtl":true}`, 604800},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.script("GET /domain/example.com/zone/info/", http.StatusOK,
				`{"ttl":2,"ttlUnit":"H","records":[{"subdomain":"@","type":"a","value":"192.0.2.1","options":`+tt.options+`}]}`)

			set, err := f.provider().ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
			if err != nil {
				t.Fatal(err)
			}

			if len(set.Records) != 1 || set.Records[0].TTL != tt.want || set.Records[0].Type != "A" {
				t.Fatalf("Records = %+v, want one A with TTL %d", set.Records, tt.want)
			}
		})
	}
}

func TestRecordValuesReadTolerantly(t *testing.T) {
	f := newFake(t)
	f.script("GET /domain/example.com/zone/info/", http.StatusOK, `[{"ttl":1,"ttlUnit":"H","records":[
		{"subdomain":"","type":"TXT","value":"say \"hi\"  \\ there","options":{"service":null,"priority":""}},
		{"subdomain":"Mail","type":"MX","value":"mx.example.net","options":{"priority":"5"}},
		{"subdomain":"","type":"SRV","value":"xmpp.example.net.","options":{"service":"_xmpp","protocol":"tcp","priority":"0","weight":5,"port":5222}},
		{"subdomain":"","type":"HTTPS","value":"1 . alpn=h2","options":{"svcParams":"alpn=h2"}}
	]}]`)

	set, err := f.provider().ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	want := []record{
		{"TXT", "example.com", `say "hi"  \ there`, 3600, nil},
		{"MX", "mail.example.com", "5 mx.example.net", 3600, nil},
		{"SRV", "_xmpp._tcp.example.com", "0 5 5222 xmpp.example.net", 3600, nil},
		{"HTTPS", "example.com", "1 . alpn=h2", 3600, map[string]string{"svcParams": `"alpn=h2"`}},
	}
	if got := records(t, set); !reflect.DeepEqual(got, want) {
		t.Fatalf("Records =\n%+v\nwant\n%+v", got, want)
	}
}

func TestRecordIDsFollowContent(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	first, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	again, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}

	for i, r := range first.Records {
		if r.ID != again.Records[i].ID {
			t.Errorf("Record %s %s changed ID between reads", r.Type, r.Name)
		}

		if seen[r.ID] {
			t.Errorf("Record ID %s is shared", r.ID)
		}

		seen[r.ID] = true
	}

	f.script("GET /domain/example.com/zone/info/", http.StatusOK, `{"ttl":3,"ttlUnit":"H","records":[{"subdomain":"","type":"A","value":"192.0.2.11","options":{}}]}`)

	changed, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if changed.Records[0].ID == first.Records[0].ID {
		t.Error("a changed Record kept its ID")
	}
}

func TestAChangeOfTheZoneTTLKeepsTheIDsOfRecordsThatInheritIt(t *testing.T) {
	f := newFake(t)
	p := f.provider()
	path := "GET /domain/example.com/zone/info/"
	inherited := `{"subdomain":"","type":"A","value":"192.0.2.10","options":{"customTtl":false}}`
	custom := `{"subdomain":"www","type":"A","value":"192.0.2.20","options":{"ttl":1,"ttlUnit":"H","customTtl":true}}`

	f.script(path, http.StatusOK, `{"ttl":3,"ttlUnit":"H","records":[`+inherited+`,`+custom+`]}`)
	f.script(path, http.StatusOK, `{"ttl":1,"ttlUnit":"D","records":[`+inherited+`,`+custom+`]}`)
	f.script(path, http.StatusOK, `{"ttl":1,"ttlUnit":"D","records":[`+inherited+`,`+strings.Replace(custom, `"ttl":1`, `"ttl":2`, 1)+`]}`)

	var reads [3][]dnsprovider.Record

	for i := range reads {
		set, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{})
		if err != nil {
			t.Fatal(err)
		}

		reads[i] = set.Records
	}

	if reads[0][0].TTL == reads[1][0].TTL {
		t.Fatal("the inherited TTL did not change")
	}

	if reads[0][0].ID != reads[1][0].ID {
		t.Error("a Record without a custom TTL changed ID with the Zone's TTL")
	}

	if reads[0][1].ID != reads[1][1].ID {
		t.Error("a Record with a custom TTL changed ID with the Zone's TTL")
	}

	if reads[1][1].ID == reads[2][1].ID {
		t.Error("a Record whose custom TTL changed kept its ID")
	}
}

func TestAMalformedZoneIsAnError(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":          `{`,
		"no zone TTL":       `{"records":[{"subdomain":"","type":"A","value":"192.0.2.1","options":{}}]}`,
		"an unknown unit":   `{"ttl":1,"ttlUnit":"Y","records":[]}`,
		"no records":        `{"ttl":1,"ttlUnit":"H"}`,
		"a record no type":  `{"ttl":1,"ttlUnit":"H","records":[{"subdomain":"","value":"192.0.2.1"}]}`,
		"an MX no priority": `{"ttl":1,"ttlUnit":"H","records":[{"subdomain":"","type":"MX","value":"mx.example.net","options":{}}]}`,
		"a TTL too long":    `{"ttl":99999,"ttlUnit":"W","records":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.script("GET /domain/example.com/zone/info/", http.StatusOK, body)

			if set, err := f.provider().ListRecords(context.Background(), zone, dnsprovider.RecordFilter{}); err == nil {
				t.Fatalf("ListRecords = %+v, want an error", set)
			}
		})
	}
}
