package dnsimple_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/rest"
)

func TestDiscoveryExhaustsShortPagesAndAppliesExactFilters(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/12/zones":
			page := r.URL.Query().Get("page")
			if page == "1" {
				fmt.Fprint(w, `{"data":[{"id":7,"account_id":12,"name":"Example.COM","active":true}],"pagination":{"current_page":1,"per_page":1,"total_pages":2}}`)
			} else {
				fmt.Fprint(w, `{"data":[{"id":8,"account_id":12,"name":"example.community","active":false}],"pagination":{"current_page":2,"per_page":1,"total_pages":2}}`)
			}
		case "/12/zones/example.com":
			fmt.Fprint(w, `{"data":{"id":7,"account_id":12,"name":"example.com","active":true}}`)
		case "/12/zones/missing.com":
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		default:
			t.Errorf("unscoped request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	set, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."})
	zs := set.Zones

	if err != nil || len(zs) != 1 || zs[0].ID != "7" || zs[0].State != dnsprovider.HostingActive {
		t.Fatalf("Zones: %+v %v", zs, err)
	}

	if set.Partial {
		t.Error("Zones is a Partial View, want a full view")
	}

	z, err := p.Zone(context.Background(), "EXAMPLE.COM.")
	if err != nil || !reflect.DeepEqual(z, zs[0]) {
		t.Fatalf("Zone: %+v %v", z, err)
	}
	_, err = p.Zone(context.Background(), "missing.com")
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestRecordsExhaustPagesRetainIDsAndFilterCombinedNames(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/12/zones/example.com/records" {
			t.Errorf("wrong account or zone: %s", r.URL.Path)
		}
		if r.URL.Query().Get("page") == "1" {
			fmt.Fprint(w, `{"data":[{"id":1,"zone_id":"example.com","name":"www","type":"A","content":"192.0.2.1","ttl":60,"regions":["global"]}],"pagination":{"current_page":1,"per_page":1,"total_pages":2}}`)
		} else {
			fmt.Fprint(w, `{"data":[{"id":2,"zone_id":"example.com","name":"www","type":"AAAA","content":"2001:db8::1","ttl":60}],"pagination":{"current_page":2,"per_page":1,"total_pages":2}}`)
		}
	})
	for _, typ := range []string{"a", "NOSUCHTYPE"} {
		set, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{Type: typ, Contains: "EXAMPLE.COM."})
		if err != nil {
			t.Fatal(err)
		}
		if typ == "a" && (len(set.Records) != 1 || set.Records[0].ID != "1" || set.Records[0].Name != "www.example.com") {
			t.Fatalf("filtered: %+v", set)
		}
		if typ == "NOSUCHTYPE" && len(set.Records) != 0 {
			t.Fatalf("unsupported filter: %+v", set)
		}
	}
}

func TestRepeatedPagesAndMalformedSuccessesFailExplicitly(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":null}`, `{"message":"failure"}`, `{"data":[{"id":1,"account_id":13,"name":"example.com"}],"pagination":{"current_page":1,"per_page":1,"total_pages":1}}`, `{"data":[],"pagination":{"current_page":1,"per_page":1,"total_pages":3}}`} {
		t.Run(body, func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) })
			if _, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"data":[{"id":1,"account_id":12,"name":"example.com","active":true}],"pagination":{"current_page":%s,"per_page":1,"total_pages":3}}`, r.URL.Query().Get("page"))
	})
	_, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
	if !errors.Is(err, rest.ErrSamePage) {
		t.Fatalf("repeated page: %v", err)
	}
}
