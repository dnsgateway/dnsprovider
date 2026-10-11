package porkbun_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
	"github.com/dnsgateway/dnsprovider/rest"
)

func TestZonesReadEveryPageAndRejectRepeatedPages(t *testing.T) {
	for _, repeat := range []bool{false, true} {
		t.Run(fmt.Sprint(repeat), func(t *testing.T) {
			first := make([]map[string]any, 1000)
			for i := range first {
				first[i] = map[string]any{"domain": fmt.Sprintf("domain-%04d.example.net", i), "apiAccess": 1}
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/domain/listAll" {
					ds := first
					if r.URL.Query().Get("start") != "0" && !repeat {
						ds = []map[string]any{{"domain": "last.example.com", "apiAccess": 1}}
					}
					json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "domains": ds})
					return
				}
				w.Write([]byte(`{"status":"SUCCESS","records":[]}`))
			}))
			defer s.Close()
			p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
			set, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "LAST.EXAMPLE.COM."})
			zs := set.Zones

			if repeat {
				if !errors.Is(err, rest.ErrSamePage) {
					t.Fatalf("repeated page error=%v", err)
				}
				return
			}
			if err != nil || len(zs) != 1 || zs[0].Name != "last.example.com" {
				t.Fatalf("Zones=%+v,%v", zs, err)
			}
		})
	}
}

func TestEmptyListsAndExactLookupDoNotHideErrors(t *testing.T) {
	for _, body := range []string{`{"status":"SUCCESS","domains":[]}`, `{"status":"ERROR","code":"INSUFFICIENT_SCOPE","message":"read denied"}`} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer s.Close()
			p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
			set, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{})
			zs := set.Zones

			_, lookup := p.GetZone(context.Background(), "example.com")
			if body[11:18] == "SUCCESS" {
				if err != nil || len(zs) != 0 || !errors.Is(lookup, dnsprovider.ErrNotFound) {
					t.Fatalf("empty=%v,%v,%v", zs, err, lookup)
				}
			} else if !errors.Is(err, dnsprovider.ErrUnauthorized) || !errors.Is(lookup, dnsprovider.ErrUnauthorized) {
				t.Fatalf("permission=%v,%v", err, lookup)
			}
		})
	}
}
