package cloudns_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudns"
	"github.com/dnsgateway/dnsprovider/rest"
)

func newProvider(t *testing.T, h http.HandlerFunc) *cloudns.Provider {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	p, err := cloudns.New(cloudns.Config{Password: "secret-password", AuthID: "12345"}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestZonesExhaustPagesAndApplyExactSharedFilters(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("rows-per-page") != "100" {
			t.Error("wrong page size")
		}
		if r.PostForm.Get("page") == "1" {
			zs := make([]map[string]string, 100)
			for i := range zs {
				zs[i] = map[string]string{"name": fmt.Sprintf("z%d.example.com", i), "type": "master"}
			}
			_ = json.NewEncoder(w).Encode(zs)
		} else {
			fmt.Fprint(w, `[{"name":"EXAMPLE.COM","type":"master"},{"name":"notexample.com","type":"slave"}]`)
		}
	})
	ctx := context.Background()
	zs, err := p.Zones(ctx, dnsprovider.ZoneFilter{})
	if err != nil || len(zs) != 102 {
		t.Fatalf("Zones = %d, %v", len(zs), err)
	}
	z, err := p.Zone(ctx, "Example.Com.")
	if err != nil || z.ID != "example.com" || z.Name != "example.com" || z.State != dnsprovider.HostingUnknown {
		t.Fatalf("Zone = %+v, %v", z, err)
	}
	if _, err = p.Zone(ctx, "absent.com"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatal(err)
	}
	f := dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."}
	filtered, err := p.Zones(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, z := range filtered {
		if !dnsprovider.MatchZone(f, z) {
			t.Fatal(z)
		}
	}
}

func TestZonesRejectRepeatedPages(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
		zs := make([]map[string]string, 100)
		for i := range zs {
			zs[i] = map[string]string{"name": fmt.Sprintf("z%d.example.com", i)}
		}
		_ = json.NewEncoder(w).Encode(zs)
	})
	if _, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{}); !errors.Is(err, rest.ErrSamePage) {
		t.Fatal(err)
	}
}

func TestRecordsConvertStructuredValuesAndNativeIDs(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("include-notes") != "1" {
			t.Error("notes omitted")
		}
		fmt.Fprint(w, `{"11":{"id":"11","type":"A","host":"","record":"192.0.2.1","ttl":"300","status":"1"},"12":{"id":"12","type":"MX","host":"","record":"mail.example.net.","priority":"10","ttl":"3600"},"13":{"id":"13","type":"SRV","host":"_sip._tcp","record":"sip.example.net.","priority":"5","weight":"20","port":"5060","ttl":"300"},"14":{"id":"14","type":"CAA","host":"*","caa_flag":"128","caa_type":"issue","caa_value":"letsencrypt.org","ttl":"300"},"15":{"id":"15","type":"TXT","host":"txt","record":"v=spf1 include:example.net -all","ttl":"300","note":"keep"},"16":{"id":"16","type":"TLSA","host":"_443._tcp","record":"abcd","ttl":300,"tlsa_usage":"3"}}`)
	})
	zone := dnsprovider.Zone{ID: "example.com", Name: "example.com"}
	rs, err := p.Records(context.Background(), zone, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	wants := []string{"192.0.2.1", "10 mail.example.net", "5 20 5060 sip.example.net", `128 issue "letsencrypt.org"`, "v=spf1 include:example.net -all", "abcd"}
	if len(rs.Records) != len(wants) {
		t.Fatal(rs)
	}
	for i, r := range rs.Records {
		if r.Value != wants[i] || r.ID != fmt.Sprint(i+11) {
			t.Errorf("record = %+v, want %q", r, wants[i])
		}
	}
	if rs.Records[0].Name != "example.com" || rs.Records[3].Name != "*.example.com" || rs.Records[4].Extras["note"] != "keep" {
		t.Fatal(rs)
	}
	for _, f := range []dnsprovider.RecordFilter{{Type: "NOSUCHTYPE"}, {Type: "mx"}, {Contains: "EXAMPLE.COM."}, {Type: "txt", Contains: "TXT"}} {
		got, err := p.Records(context.Background(), zone, f)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range rs.Records {
			if dnsprovider.MatchRecord(f, r) {
				n++
			}
		}
		if len(got.Records) != n {
			t.Errorf("filter %+v: %+v", f, got)
		}
	}
}

func TestRecordsExhaustPagesAndRejectRepeatedPages(t *testing.T) {
	for _, repeat := range []bool{false, true} {
		p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			if !repeat && r.PostForm.Get("page") == "2" {
				fmt.Fprint(w, `[ ]`)
				return
			}
			raw := map[string]map[string]string{}
			for i := range 100 {
				id := fmt.Sprint(i + 1)
				raw[id] = map[string]string{"id": id, "type": "A", "host": fmt.Sprintf("r%d", i), "record": "192.0.2.1", "ttl": "300"}
			}
			_ = json.NewEncoder(w).Encode(raw)
		})
		rs, err := p.Records(context.Background(), testZone, dnsprovider.RecordFilter{})
		if repeat {
			if !errors.Is(err, rest.ErrSamePage) {
				t.Fatal(err)
			}
		} else if err != nil || len(rs.Records) != 100 {
			t.Fatalf("Records = %d, %v", len(rs.Records), err)
		}
	}
}

func TestEmptyRecordsAndDNSPermissionFailuresRemainDistinct(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/login.json":
			fmt.Fprint(w, `{"status":"Success"}`)
		case "/dns/records.json":
			fmt.Fprint(w, `{}`)
		default:
			fmt.Fprint(w, `{"status":"Failed","statusDescription":"Access denied for this API user."}`)
		}
	})
	if _, err := p.Account(context.Background()); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatal(err)
	}
	if rs, err := p.Records(context.Background(), testZone, dnsprovider.RecordFilter{}); err != nil || len(rs.Records) != 0 {
		t.Fatalf("empty records %+v, %v", rs, err)
	}
	if _, err := p.Zone(context.Background(), "absent.com"); !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatal(err)
	}
}
