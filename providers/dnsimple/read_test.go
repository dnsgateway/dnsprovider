package dnsimple_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/dnsimple"
)

func provider(t *testing.T, h http.HandlerFunc) *dnsimple.Provider {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("Bearer token missing")
		}
		h(w, r)
	}))
	t.Cleanup(s.Close)
	p, err := dnsimple.New(dnsimple.Config{Token: "secret", AccountID: "12"}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccountProvesConfiguredAccessForEitherIdentityAndEmptyZones(t *testing.T) {
	for _, identity := range []string{`{"account":{"id":12},"user":null}`, `{"account":null,"user":{"id":99}}`} {
		t.Run(identity, func(t *testing.T) {
			p := provider(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/whoami":
					fmt.Fprintf(w, `{"data":%s}`, identity)
				case "/accounts":
					fmt.Fprint(w, `{"data":[{"id":11,"name":"wrong"},{"id":12,"name":"chosen"}]}`)
				case "/12/zones":
					fmt.Fprint(w, `{"data":[],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
				default:
					t.Errorf("escaped configured Account: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			})
			a, err := p.Account(context.Background())
			if err != nil || a.Tenant.ID != "12" || a.Tenant.Name != "chosen" {
				t.Fatalf("Account: %+v %v", a, err)
			}
		})
	}
}

func TestAccountRejectsInaccessibleAccount(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/whoami" {
			fmt.Fprint(w, `{"data":{"user":{"id":99},"account":null}}`)
		} else {
			fmt.Fprint(w, `{"data":[{"id":13}]}`)
		}
	})
	_, err := p.Account(context.Background())
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("Account: %v", err)
	}
}

func TestFrozenRecordsPreservePresentationUnknownTypesAndSOASerial(t *testing.T) {
	// Literal responses follow ZoneRecord in DNSimple's official OpenAPI schema.
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":[
 {"id":1,"zone_id":"example.com","name":"","type":"SOA","content":"ns1.dnsimple.com admin.dnsimple.com 1458642070 86400 7200 604800 300","ttl":3600,"priority":null,"system_record":true,"regions":["global"]},
 {"id":2,"zone_id":"example.com","name":"","type":"MX","content":"mail.example.net.","ttl":60,"priority":10,"regions":["SV1","IAD"]},
 {"id":3,"zone_id":"example.com","name":"_sip._tcp","type":"SRV","content":"5 443 sip.example.net.","ttl":60,"priority":20},
 {"id":4,"zone_id":"example.com","name":"*","type":"TXT","content":"hello \"world\"","ttl":0,"priority":null},
 {"id":5,"zone_id":"example.com","name":"","type":"CAA","content":"0 issue \"letsencrypt.org\"","ttl":60,"priority":null},
 {"id":6,"zone_id":"example.com","name":"","type":"ALIAS","content":"unknown.example.net","ttl":60,"priority":null}
 ],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
	})
	set, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 6 || set.Serial != 1458642070 {
		t.Fatalf("Records: %+v %v", set, err)
	}

	if set.Partial {
		t.Error("Records is a Partial View, want a full view")
	}

	expected := []string{"ns1.dnsimple.com admin.dnsimple.com 1458642070 86400 7200 604800 300", "10 mail.example.net.", "20 5 443 sip.example.net.", `hello "world"`, `0 issue "letsencrypt.org"`, "unknown.example.net"}
	for i, r := range set.Records {
		if r.Value != expected[i] {
			t.Errorf("Record %d: %+v", i, r)
		}
	}
	if set.Records[3].Name != "*.example.com" || set.Records[1].Extras["regions"] != `["SV1","IAD"]` {
		t.Fatalf("names and metadata: %+v", set.Records)
	}
	for _, r := range set.Records {
		if err := dnsimple.Factory().CheckExtras(r); err != nil {
			t.Errorf("Factory does not declare the extras of %+v: %v", r, err)
		}
	}
}

func TestRecordsRejectMissingNullAndWronglyTypedRequiredFields(t *testing.T) {
	for _, field := range []string{"name", "content", "ttl"} {
		for _, mode := range []string{"missing", "null", "wrong_type"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				row := map[string]any{"id": 1, "zone_id": "example.com", "name": "", "type": "TXT", "content": "", "ttl": 0}
				switch mode {
				case "missing":
					delete(row, field)
				case "null":
					row[field] = nil
				case "wrong_type":
					if field == "ttl" {
						row[field] = "0"
					} else {
						row[field] = 42
					}
				}
				p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
					json.NewEncoder(w).Encode(map[string]any{"data": []any{row}, "pagination": map[string]any{"current_page": 1, "per_page": 100, "total_pages": 1}})
				})
				if _, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{}); err == nil {
					t.Fatal("malformed Record accepted")
				}
			})
		}
	}
}

func TestRecordsKeepExplicitApexEmptyContentAndZeroTTL(t *testing.T) {
	p := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"data":[{"id":1,"zone_id":"example.com","name":"","type":"TXT","content":"","ttl":0}],"pagination":{"current_page":1,"per_page":100,"total_pages":1}}`)
	})
	set, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com"}, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 1 || set.Records[0].Name != "example.com" || set.Records[0].Value != "" || set.Records[0].TTL != 0 {
		t.Fatalf("explicit empty fields: %+v %v", set, err)
	}
}
