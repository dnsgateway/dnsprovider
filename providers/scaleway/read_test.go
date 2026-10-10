package scaleway_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/scaleway"
	"github.com/dnsgateway/dnsprovider/rest"
)

func TestProjectDiscoveryAndOwnership(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-Token") != "secret" || r.URL.Query().Get("project_id") != project {
			t.Error("unscoped or unauthenticated read")
		}
		if r.URL.Path != "/dns-zones" {
			t.Fatalf("foreign or missing Zone reached record endpoint: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 3, "dns_zones": []any{
			map[string]any{"domain": "example.com", "subdomain": "", "project_id": project, "status": "active", "ns": []string{"ns0.dom.scw.cloud"}},
			map[string]any{"domain": "example.com", "subdomain": "dev", "project_id": project, "status": "pending"},
			map[string]any{"domain": "foreign.com", "subdomain": "", "project_id": "22222222-2222-4222-8222-222222222222", "status": "active"},
		}})
	}))
	defer srv.Close()
	p, err := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, dnsprovider.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	account, err := p.Account(ctx)
	if err != nil || account.Tenant.ID != project || account.Tenant.Name != "" {
		t.Fatalf("account %+v %v", account, err)
	}
	set, err := p.Zones(ctx, dnsprovider.ZoneFilter{})
	zs := set.Zones

	if err != nil || len(zs) != 2 {
		t.Fatalf("zones %+v %v", zs, err)
	}

	if set.Partial {
		t.Error("Zones is a Partial View, want a Full View")
	}

	sub, err := p.Zone(ctx, "DEV.EXAMPLE.COM.")
	if err != nil || sub.ID != "dev.example.com" || sub.Name != "dev.example.com" {
		t.Fatalf("sub %+v %v", sub, err)
	}
	for _, name := range []string{"foreign.com", "missing.example.com"} {
		if _, err = p.Zone(ctx, name); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("lookup %s: %v", name, err)
		}
		if _, err = p.Records(ctx, dnsprovider.Zone{ID: name, Name: name}, dnsprovider.RecordFilter{}); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("records %s: %v", name, err)
		}
		z := dnsprovider.Zone{ID: name, Name: name}
		if _, err = p.CreateRecord(ctx, z, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 600}); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("foreign create: %v", err)
		}
		if err = p.DeleteRecord(ctx, z, dnsprovider.Record{ID: "native"}); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("foreign delete: %v", err)
		}
		if _, err = dnsprovider.Apply(ctx, p, dnsprovider.Changeset{Zone: z, Changes: []dnsprovider.Change{{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 600}}}}); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("foreign apply: %v", err)
		}
	}
}

func TestEmptyAccountDeniedAndMalformedResponses(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"empty", `{"total_count":0,"dns_zones":[]}`, 200, nil},
		{"denied", `{"type":"permissions_denied","message":"secret not permitted"}`, 403, dnsprovider.ErrUnauthorized},
		{"malformed", `{}`, 200, errors.New("malformed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			p, _ := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, dnsprovider.WithBaseURL(srv.URL))
			got, err := p.Account(context.Background())
			if tc.want == nil {
				if err != nil || got.Tenant.ID != project {
					t.Fatalf("empty account: %+v %v", got, err)
				}
			} else if err == nil || (tc.name == "denied" && !errors.Is(err, tc.want)) {
				t.Fatalf("account error %v", err)
			}
		})
	}
}

func TestCompletePaginationAndRepeatedPageDetection(t *testing.T) {
	for _, repeated := range []bool{false, true} {
		t.Run(strconv.FormatBool(repeated), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("project_id") != project {
					t.Error("missing project on page")
				}
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				if repeated {
					page = 1
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 2, "dns_zones": []any{map[string]any{"domain": fmt.Sprintf("page%d.com", page), "subdomain": "", "project_id": project, "status": "unknown"}}})
			}))
			defer srv.Close()
			p, _ := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, dnsprovider.WithBaseURL(srv.URL))
			set, err := p.Zones(context.Background(), dnsprovider.ZoneFilter{})
			zs := set.Zones

			if repeated {
				if !errors.Is(err, rest.ErrSamePage) {
					t.Fatalf("repeated: %v", err)
				}
			} else if err != nil || len(zs) != 2 || zs[1].Name != "page2.com" {
				t.Fatalf("pages: %+v %v", zs, err)
			}
		})
	}
}

func TestFiltersAndStructuredRecordRoundTrips(t *testing.T) {
	f, p := newFixture(t)
	ctx := context.Background()
	f.records = []map[string]any{}
	for _, r := range []dnsprovider.Record{
		{Type: "A", Name: "@", Value: "192.0.2.9", TTL: 600},
		{Type: "AAAA", Name: "*", Value: "2001:db8::1", TTL: 600},
		{Type: "CNAME", Name: "alias", Value: "target.example.net.", TTL: 600},
		{Type: "NS", Name: "delegated", Value: "ns.example.net.", TTL: 600},
		{Type: "MX", Name: "@", Value: "0 .", TTL: 600},
		{Type: "SRV", Name: "_sip._tcp", Value: "0 10 443 target.example.net.", TTL: 600},
		{Type: "TXT", Name: "text", Value: "quotes \"and\" \\slashes", TTL: 600},
		{Type: "CAA", Name: "@", Value: `0 issue "letsencrypt.org"`, TTL: 600},
	} {
		stored, err := p.CreateRecord(ctx, testZone, r)
		if err != nil {
			t.Fatalf("%s: %v", r.Type, err)
		}
		if stored.Value != r.Value || stored.ID == "" || stored.TTL != r.TTL {
			t.Fatalf("%s stored %+v", r.Type, stored)
		}
	}
	set, err := p.Records(ctx, testZone, dnsprovider.RecordFilter{Type: "aaaa", Contains: "*.DEV.EXAMPLE.COM."})
	if err != nil || len(set.Records) != 1 {
		t.Fatalf("filter %+v %v", set, err)
	}

	if set.Partial {
		t.Error("Records is a Partial View, want a Full View")
	}

	unsupported, err := p.Records(ctx, testZone, dnsprovider.RecordFilter{Type: "unsupported"})
	if err != nil || len(unsupported.Records) != 0 {
		t.Fatalf("unsupported: %+v %v", unsupported, err)
	}
	zoneSet, err := p.Zones(ctx, dnsprovider.ZoneFilter{Contains: "EXAMPLE.COM."})
	zones := zoneSet.Zones

	if err != nil || len(zones) != 1 {
		t.Fatalf("zone filter %+v %v", zones, err)
	}
}

func TestRecordsExhaustPagesAndRejectInvalidPagination(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(strconv.FormatBool(invalid), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("project_id") != project {
					t.Error("unscoped page")
				}
				if r.URL.Path == "/dns-zones" {
					fmt.Fprint(w, `{"total_count":1,"dns_zones":[{"domain":"example.com","subdomain":"","project_id":"11111111-1111-4111-8111-111111111111","status":"active"}]}`)
					return
				}
				page, _ := strconv.Atoi(r.URL.Query().Get("page"))
				records := []any{map[string]any{"id": strconv.Itoa(page), "type": "A", "name": "page" + strconv.Itoa(page), "data": "192.0.2.1", "ttl": 600, "priority": 0}}
				if invalid && page == 2 {
					records = []any{}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 2, "records": records})
			}))
			defer srv.Close()
			p, _ := scaleway.New(scaleway.Config{SecretKey: "secret", ProjectID: project}, dnsprovider.WithBaseURL(srv.URL))
			rs, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
			if invalid {
				if err == nil {
					t.Fatal("accepted premature empty page")
				}
			} else if err != nil || len(rs.Records) != 2 || rs.Records[1].ID != "2" {
				t.Fatalf("paged records %+v %v", rs, err)
			}
		})
	}
}
