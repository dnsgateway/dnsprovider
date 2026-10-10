package dnsprovider_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

func TestQualifyName(t *testing.T) {
	cases := []struct {
		zone, name string
		want       string // empty when the name is refused
	}{
		{"example.com", "", "example.com"},
		{"example.com", "@", "example.com"},
		{"example.com.", " @ ", "example.com"},
		{"example.com", "www", "www.example.com"},
		{"example.com", "a.b", "a.b.example.com"},
		{"example.com", "*", "*.example.com"},
		{"example.com", "*.dev", "*.dev.example.com"},
		{"example.com", "_sip._tcp", "_sip._tcp.example.com"},
		{"example.com", "www.example.com", "www.example.com"},
		{"example.com", "example.com", "example.com"},
		{"example.com", "www.example.com.", "www.example.com"},
		{"example.com", "example.com.", "example.com"},
		{"example.com", "WWW.Example.COM.", "WWW.Example.COM"},
		{"Example.com", "www", "www.Example.com"},
		{"example.com", "www.other.org", "www.other.org.example.com"},
		{"example.com", "www.other.org.", ""},
		{"example.com", "notexample.com.", ""},
		{"example.com", "bad name", ""},
		{"example.com", "a..b", ""},
		{"example.com", "dev.*", ""},
		{"example.com", "ünicode", ""},
	}

	for _, c := range cases {
		t.Run(c.zone+" "+c.name, func(t *testing.T) {
			got, err := dnsprovider.QualifyName(c.zone, c.name)

			switch {
			case c.want == "" && err == nil:
				t.Fatalf("QualifyName(%q, %q) = %q, want an error", c.zone, c.name, got)
			case c.want != "" && (err != nil || got != c.want):
				t.Fatalf("QualifyName(%q, %q) = %q, %v, want %q", c.zone, c.name, got, err, c.want)
			}
		})
	}
}

func TestRelativeName(t *testing.T) {
	cases := []struct{ zone, name, want string }{
		{"example.com", "example.com", "@"},
		{"example.com.", "example.com.", "@"},
		{"example.com", "Example.COM", "@"},
		{"example.com", "www.example.com", "www"},
		{"Example.com", "WWW.example.COM", "WWW"},
		{"example.com", "a.b.example.com.", "a.b"},
		{"example.com", "www.other.org", "www.other.org."},
		{"example.com", "notexample.com", "notexample.com."},
		// Lowercasing "Ⱥ" (2 bytes) gives "ⱥ" (3 bytes): the cut must not shift.
		{"example.com", "Ⱥ.example.com", "Ⱥ"},
		{"example.com", "ȺȺȺ.example.com", "ȺȺȺ"},
		{"example.com", "Ⱥ.other.org", "Ⱥ.other.org."},
	}

	for _, c := range cases {
		if got := dnsprovider.RelativeName(c.zone, c.name); got != c.want {
			t.Errorf("RelativeName(%q, %q) = %q, want %q", c.zone, c.name, got, c.want)
		}
	}
}

func TestRelativeNameUndoesQualifyName(t *testing.T) {
	for _, name := range []string{"@", "www", "a.b", "*", "*.dev", "_sip._tcp", "WWW"} {
		abs, err := dnsprovider.QualifyName("example.com", name)
		if err != nil {
			t.Fatalf("QualifyName(%q): %v", name, err)
		}

		if got := dnsprovider.RelativeName("example.com", abs); got != name {
			t.Errorf("RelativeName(QualifyName(%q)) = %q (absolute %q), want %q", name, got, abs, name)
		}
	}
}

func TestCheckValue(t *testing.T) {
	cases := []struct {
		typ, value string
		ok         bool
	}{
		{"A", "192.0.2.1", true},
		{"A", "2001:db8::1", false},
		{"A", "192.0.2", false},
		{"A", "", false},
		{"AAAA", "2001:db8::1", true},
		{"AAAA", "192.0.2.1", false},
		{"AAAA", "::ffff:192.0.2.1", false},
		{"AAAA", "fe80::1%eth0", false},
		{"CNAME", "host.example.com", true},
		{"CNAME", "host.example.com.", true},
		{"CNAME", "two words", false},
		{"NS", "ns1.example.net", true},
		{"NS", "ns1..example.net", false},
		{"MX", "10 mail.example.com", true},
		{"MX", "0 .", true},
		{"MX", "mail.example.com", false},
		{"MX", "70000 mail.example.com", false},
		{"TXT", "v=spf1 -all", true},
		{"TXT", "   ", false},
		{"SRV", "10 5 443 host.example.com", true},
		{"SRV", "10 5 host.example.com", false},
		{"CAA", `0 issue "letsencrypt.org"`, true},
		{"CAA", "256 issue x", false},
		{"CAA", `0 is-sue "x"`, false},
		{"URI", `10 1 "https://example.com/"`, true},
		{"URI", "10 1 https://example.com/", false},
		{"URI", `10 1 ""`, false},
		{"SOA", "ns1.example.com", false},
	}

	for _, c := range cases {
		if err := dnsprovider.CheckValue(c.typ, c.value); (err == nil) != c.ok {
			t.Errorf("CheckValue(%q, %q) = %v, want ok %v", c.typ, c.value, err, c.ok)
		}
	}
}

func TestTTLRangeCheck(t *testing.T) {
	cases := []struct {
		r   dnsprovider.TTLRange
		ttl uint32
		ok  bool
	}{
		{dnsprovider.DefaultTTLRange, dnsprovider.TTLAuto, false},
		{dnsprovider.DefaultTTLRange, 30, true},
		{dnsprovider.DefaultTTLRange, 86400, true},
		{dnsprovider.DefaultTTLRange, 0, false},
		{dnsprovider.DefaultTTLRange, 29, false},
		{dnsprovider.DefaultTTLRange, 86401, false},
		{dnsprovider.TTLRange{Min: 60, Max: 86400}, 1, false},
		{dnsprovider.TTLRange{Min: 60, Max: 86400, Auto: true}, 1, true},
		{dnsprovider.TTLRange{Min: 60, Max: 86400, Auto: true}, 30, false},
		{dnsprovider.TTLRange{Min: 60, Max: 86400}, 30, false},
		{dnsprovider.TTLRange{Min: 60, Max: 86400}, 60, true},
	}

	for _, c := range cases {
		if err := c.r.Check(c.ttl); (err == nil) != c.ok {
			t.Errorf("%+v.Check(%d) = %v, want ok %v", c.r, c.ttl, err, c.ok)
		}
	}
}

func TestMatchRecordMatchesTheTypeAndNamesHoldingTheText(t *testing.T) {
	cases := []struct {
		typ, contains string
		rtype, name   string
		want          bool
	}{
		{"", "", "A", "www.example.com", true},
		{"A", "", "A", "www.example.com", true},
		{"A", "", "AAAA", "www.example.com", false},
		{"mx", "", "MX", "example.com", true},
		{"", "WWW", "A", "www.Example.com", true},
		{"", "mail", "A", "www.example.com", false},
		{"A", "www", "A", "www.example.com", true},
		{"A", "www", "AAAA", "www.example.com", false},
		{"A", "mail", "A", "www.example.com", false},
		// A trailing dot ends the name, as in an absolute name.
		{"", "www.example.com.", "A", "www.example.com", true},
		{"", "example.com.", "A", "www.example.community", false},
		{"", "www.", "A", "www.example.com", true},
	}

	for _, c := range cases {
		r := dnsprovider.Record{Type: c.rtype, Name: c.name, Value: "192.0.2.1", TTL: 300}
		f := dnsprovider.RecordFilter{Type: c.typ, Contains: c.contains}

		if got := dnsprovider.MatchRecord(f, r); got != c.want {
			t.Errorf("MatchRecord(%+v, %s %s) = %v, want %v", f, c.rtype, c.name, got, c.want)
		}
	}
}

func TestSameExtrasTakesAProxyFlagThatIsOffAsNone(t *testing.T) {
	for _, tc := range []struct {
		a, b map[string]string
		want bool
	}{
		{nil, map[string]string{}, true},
		{map[string]string{"proxied": "false"}, nil, true},
		{map[string]string{"proxied": "false", "comment": "x"}, map[string]string{"comment": "x"}, true},
		{map[string]string{"proxied": "true"}, nil, false},
		{map[string]string{"comment": "x"}, map[string]string{"comment": "y"}, false},
		{map[string]string{"comment": ""}, nil, false},
	} {
		if got := dnsprovider.SameExtras(tc.a, tc.b); got != tc.want {
			t.Errorf("SameExtras(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
