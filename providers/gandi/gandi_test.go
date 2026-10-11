package gandi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
)

func TestRecordsExpandValuesWithStableContentKeys(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pat_test" {
			t.Error("missing bearer auth")
		}
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_ = json.NewEncoder(w).Encode([]any{map[string]any{"rrset_name": "@", "rrset_type": "A", "rrset_ttl": 300, "rrset_values": []string{"192.0.2.1", "192.0.2.2"}}})
	}))
	defer s.Close()
	p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	z := dnsprovider.Zone{ID: "example.org", Name: "example.org"}
	rs, err := p.ListRecords(context.Background(), z, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}

	if rs.Partial {
		t.Error("Records is a Partial View, want a Full View")
	}

	if len(rs.Records) != 2 || rs.Records[0].Name != "example.org" || rs.Records[0].ID == "" || rs.Records[0].ID == rs.Records[1].ID {
		t.Fatalf("Records = %+v", rs)
	}
	again, err := p.ListRecords(context.Background(), z, dnsprovider.RecordFilter{Type: "a"})
	if err != nil || len(again.Records) != 2 || again.Records[0].ID != rs.Records[0].ID {
		t.Fatalf("unstable keys: %+v %v", again, err)
	}
}

func TestCreatePreservesRRsetSiblingAndMetadata(t *testing.T) {
	state := map[string]any{"rrset_name": "@", "rrset_type": "A", "rrset_ttl": 300, "rrset_values": []string{"192.0.2.1"}, "vendor_metadata": map[string]any{"flag": true}}
	writes := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writes++
			if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{"message":"updated"}`))
			return
		}
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		if r.URL.Query().Get("page") != "" {
			_ = json.NewEncoder(w).Encode([]any{state})
			return
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer s.Close()
	p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	z := dnsprovider.Zone{Name: "example.org", ID: "example.org"}
	got, err := p.CreateRecord(context.Background(), z, dnsprovider.Record{Name: "@", Type: "A", Value: "192.0.2.2", TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	if writes != 1 || got.ID == "" || got.Value != "192.0.2.2" || state["vendor_metadata"] == nil {
		t.Fatalf("write lost state: %+v, %+v", state, got)
	}
	rs, err := p.ListRecords(context.Background(), z, dnsprovider.RecordFilter{})
	if err != nil || len(rs.Records) != 2 || rs.Records[0].Value != "192.0.2.1" {
		t.Fatalf("lost sibling: %+v %v", rs, err)
	}
}
