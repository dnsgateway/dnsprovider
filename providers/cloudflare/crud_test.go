package cloudflare_test

// Seam 2, per-record CRUD: CreateRecord, UpdateRecord and DeleteRecord
// against the scripted v4 API.

import (
	"context"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

var crudZone = dnsprovider.Zone{Name: "example.com", ID: "z1"}

func TestCreateRecordPostsItAndReturnsItAsCloudflareStoredIt(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {}}}
	p := newProvider(t, api)

	got, err := p.CreateRecord(context.Background(), crudZone, dnsprovider.Record{
		Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300,
	})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}

	assertWrites(t, api, []write{{Method: "POST", Path: "/client/v4/zones/z1/dns_records", Body: map[string]any{
		"type": "A", "name": "www.example.com", "content": "192.0.2.1", "ttl": 300.0,
	}}})

	// Cloudflare stores an A Record proxiable, unproxied when not asked.
	assertRecords(t, []dnsprovider.Record{got}, []dnsprovider.Record{{
		ID: "new1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "false"},
	}})
}
