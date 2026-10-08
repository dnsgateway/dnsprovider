package cloudflare_test

// Seam 2, per-record CRUD: CreateRecord, UpdateRecord and DeleteRecord
// against the scripted v4 API.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
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

func TestUpdateRecordPatchesItByIDAndKeepsItsCommentAndTags(t *testing.T) {
	stored := cfRecord("r1", "A", "www.example.com", "192.0.2.1", 300, true, true)
	stored["comment"] = "web front"
	stored["tags"] = []any{"team:web", "env:prod"}
	api := &cfAPI{records: map[string][]map[string]any{"z1": {stored}}}
	p := newProvider(t, api)

	before := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "true"}}
	after := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.2", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "true"}}

	got, err := p.UpdateRecord(context.Background(), crudZone, before, after)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	assertWrites(t, api, []write{{Method: "PATCH", Path: "/client/v4/zones/z1/dns_records/r1", Body: map[string]any{
		"type": "A", "name": "www.example.com", "content": "192.0.2.2", "ttl": 300.0, "proxied": true,
	}}})
	assertRecords(t, []dnsprovider.Record{got}, []dnsprovider.Record{after})

	rec := api.records["z1"][0]
	if rec["comment"] != "web front" || !reflect.DeepEqual(rec["tags"], []any{"team:web", "env:prod"}) {
		t.Errorf("comment, tags = %v, %v; want the ones Cloudflare held kept", rec["comment"], rec["tags"])
	}
}

func TestDeleteRecordDeletesItByID(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {cfRecord("r1", "TXT", "example.com", `"hi"`, 300, false, false)}}}
	p := newProvider(t, api)

	if err := p.DeleteRecord(context.Background(), crudZone, dnsprovider.Record{ID: "r1", Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300}); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	assertWrites(t, api, []write{{Method: "DELETE", Path: "/client/v4/zones/z1/dns_records/r1"}})

	if n := len(api.records["z1"]); n != 0 {
		t.Errorf("%d records left, want the Record deleted", n)
	}
}

func TestUpdateAndDeleteOfARecordCloudflareNoLongerHoldsAreNotFound(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {}}}
	p := newProvider(t, api)
	gone := dnsprovider.Record{ID: "r9", Type: "TXT", Name: "example.com", Value: `"9"`, TTL: 300}

	if _, err := p.UpdateRecord(context.Background(), crudZone, gone, gone); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("UpdateRecord: err = %v, want ErrNotFound", err)
	}

	if err := p.DeleteRecord(context.Background(), crudZone, gone); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("DeleteRecord: err = %v, want ErrNotFound", err)
	}
}

func TestUpdateAndDeleteOfARecordWithoutAnIDSendNothing(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {}}}
	p := newProvider(t, api)
	noID := dnsprovider.Record{Type: "TXT", Name: "example.com", Value: `"9"`, TTL: 300}

	if _, err := p.UpdateRecord(context.Background(), crudZone, noID, noID); err == nil {
		t.Error("UpdateRecord: err = nil, want an error for the missing record ID")
	}

	if err := p.DeleteRecord(context.Background(), crudZone, noID); err == nil {
		t.Error("DeleteRecord: err = nil, want an error for the missing record ID")
	}

	if got := api.Requests(); len(got) != 0 {
		t.Errorf("sent %v, want nothing", got)
	}
}

func TestCreateRecordIsNeverRetried(t *testing.T) {
	var posts int

	api := &cfAPI{records: map[string][]map[string]any{"z1": {}}}
	api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			return false
		}

		api.mu.Lock()
		posts++
		api.mu.Unlock()

		serverError(w)

		return true
	}
	p := newProvider(t, api)

	if _, err := p.CreateRecord(context.Background(), crudZone, dnsprovider.Record{Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300}); err == nil {
		t.Error("CreateRecord: err = nil, want the 502")
	}

	if posts != 1 {
		t.Errorf("got %d POSTs, want exactly 1: a create is not retried", posts)
	}
}

func TestDeleteRecordWhoseRetryFindsItGoneSucceeds(t *testing.T) {
	var deletes int

	api := &cfAPI{records: map[string][]map[string]any{"z1": {cfRecord("r1", "TXT", "example.com", `"hi"`, 300, false, false)}}}
	api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodDelete {
			return false
		}

		api.mu.Lock()
		deletes++
		first := deletes == 1

		// The first DELETE is made, but its answer is lost to a 5xx.
		if first {
			api.records["z1"] = nil
		}
		api.mu.Unlock()

		if first {
			serverError(w)
		}

		return first
	}
	p := newProvider(t, api)

	if err := p.DeleteRecord(context.Background(), crudZone, dnsprovider.Record{ID: "r1", Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300}); err != nil {
		t.Errorf("DeleteRecord: %v, want the retry that finds it gone to succeed", err)
	}

	if deletes != 2 {
		t.Errorf("got %d DELETEs, want 2: a delete is retried", deletes)
	}
}

func TestCreateRecordThatCollidesWithOneCloudflareHoldsIsAConflict(t *testing.T) {
	// Cloudflare refuses such a Record with a 400 and its own code, which
	// a 2xx marked "success": false may carry too.
	collisions := []struct {
		code    int
		message string
	}{
		{81057, "Record already exists."},
		{81058, "An identical record already exists."},
		{81053, "An A, AAAA, or CNAME record with that host already exists."},
		{81054, "A CNAME record with that host already exists."},
	}

	for _, c := range collisions {
		for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
			t.Run(fmt.Sprintf("%d/%s", c.code, http.StatusText(status)), func(t *testing.T) {
				api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
					writeErrors(w, status, c.code, c.message)
				}}
				p := newProvider(t, api)

				_, err := p.CreateRecord(context.Background(), crudZone, dnsprovider.Record{Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 300})
				if !errors.Is(err, dnsprovider.ErrConflict) {
					t.Errorf("err = %v, want ErrConflict", err)
				}
			})
		}
	}
}

func TestApplyGoesThroughRecordCRUDNotABatcher(t *testing.T) {
	// Cloudflare writes one Record at a time, so dnsprovider.Apply orders
	// a Changeset's changes itself; the atomic batch endpoint is not used.
	p := newProvider(t, &cfAPI{})

	if _, ok := p.(dnsprovider.Batcher); ok {
		t.Error("the Cloudflare Provider is a dnsprovider.Batcher, want Apply to go through its Record CRUD")
	}
}

func TestDeleteRecordWhoseRetryFindsTheZoneGoneFails(t *testing.T) {
	// Only the Record missing means an earlier try deleted it; a Zone
	// Cloudflare cannot route to is an error, retry or not.
	var deletes int

	api := &cfAPI{records: map[string][]map[string]any{"z1": {cfRecord("r1", "TXT", "example.com", `"hi"`, 300, false, false)}}}
	api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodDelete {
			return false
		}

		api.mu.Lock()
		deletes++
		first := deletes == 1
		api.mu.Unlock()

		if first {
			serverError(w)
		} else {
			writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/z1/dns_records/r1, perhaps your object identifier is invalid?")
		}

		return true
	}
	p := newProvider(t, api)

	err := p.DeleteRecord(context.Background(), crudZone, dnsprovider.Record{ID: "r1", Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300})
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("DeleteRecord: err = %v, want the unroutable Zone's ErrNotFound", err)
	}

	if deletes != 2 {
		t.Errorf("got %d DELETEs, want 2: a delete is retried", deletes)
	}
}

func TestAWriteCloudflareTookWithoutAReadableRecordSucceedsWithTheRecordAsSent(t *testing.T) {
	// The success answer is authoritative (ADR-0001): Cloudflare stored the
	// Record, so the write succeeds even when the answer does not say how.
	// The Record comes back as sent, with the ID the write knows: none for
	// a create, which a later read of the Zone fills in.
	for name, result := range map[string]any{"null": nil, "undecodable": "not a record"} {
		t.Run(name, func(t *testing.T) {
			api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, http.StatusOK, map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
			}}
			p := newProvider(t, api)

			sent := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "true"}}

			got, err := p.CreateRecord(context.Background(), crudZone, sent)
			if err != nil {
				t.Fatalf("CreateRecord: %v, want the write Cloudflare took to succeed", err)
			}

			assertRecords(t, []dnsprovider.Record{got}, []dnsprovider.Record{sent})

			before := sent
			before.ID = "r1"
			after := before
			after.Value = "192.0.2.2"

			got, err = p.UpdateRecord(context.Background(), crudZone, before, after)
			if err != nil {
				t.Fatalf("UpdateRecord: %v, want the write Cloudflare took to succeed", err)
			}

			assertRecords(t, []dnsprovider.Record{got}, []dnsprovider.Record{after})
		})
	}
}

func TestUpdateRecordWithoutAProxyFlagKeepsTheOneCloudflareHolds(t *testing.T) {
	// A Record that does not say whether it is proxied leaves the flag as
	// Cloudflare holds it, as a PATCH keeps what it does not send.
	api := &cfAPI{records: map[string][]map[string]any{"z1": {cfRecord("r1", "A", "www.example.com", "192.0.2.1", 300, true, true)}}}
	p := newProvider(t, api)

	before := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "true"}}
	after := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.2", TTL: 300}

	got, err := p.UpdateRecord(context.Background(), crudZone, before, after)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	assertWrites(t, api, []write{{Method: "PATCH", Path: "/client/v4/zones/z1/dns_records/r1", Body: map[string]any{
		"type": "A", "name": "www.example.com", "content": "192.0.2.2", "ttl": 300.0,
	}}})

	want := after
	want.Extras = map[string]string{cloudflare.ExtraProxied: "true"}
	assertRecords(t, []dnsprovider.Record{got}, []dnsprovider.Record{want})
}

func TestUpdateRecordChangingItsTypeReplacesItAndKeepsItsCommentAndTags(t *testing.T) {
	// A PATCH would keep the old type's fields, such as an MX priority, so
	// a Record changing type is written whole with a PUT, which drops
	// whatever it does not send: the comment and tags Cloudflare holds are
	// read first and sent along.
	stored := cfRecord("r1", "MX", "example.com", "mail.example.com", 300, false, false)
	stored["priority"] = 10
	stored["comment"] = "mail"
	stored["tags"] = []any{"team:mail"}
	api := &cfAPI{records: map[string][]map[string]any{"z1": {stored}}}
	p := newProvider(t, api)

	before := dnsprovider.Record{ID: "r1", Type: "MX", Name: "example.com", Value: "10 mail.example.com", TTL: 300}
	after := dnsprovider.Record{ID: "r1", Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300}

	got, err := p.UpdateRecord(context.Background(), crudZone, before, after)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	assertWrites(t, api, []write{{Method: "PUT", Path: "/client/v4/zones/z1/dns_records/r1", Body: map[string]any{
		"type": "TXT", "name": "example.com", "content": `"hi"`, "ttl": 300.0, "comment": "mail", "tags": []any{"team:mail"},
	}}})
	assertRecords(t, []dnsprovider.Record{got}, []dnsprovider.Record{after})

	rec := api.records["z1"][0]
	if _, ok := rec["priority"]; ok {
		t.Errorf("record = %v, want the MX priority gone", rec)
	}

	if rec["comment"] != "mail" || !reflect.DeepEqual(rec["tags"], []any{"team:mail"}) {
		t.Errorf("comment, tags = %v, %v; want the ones Cloudflare held kept", rec["comment"], rec["tags"])
	}
}

func TestUpdateRecordChangingItsTypeWithoutAProxyFlagKeepsTheOneCloudflareHolds(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {cfRecord("r1", "CNAME", "www.example.com", "example.com", 300, true, true)}}}
	p := newProvider(t, api)

	before := dnsprovider.Record{ID: "r1", Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "true"}}
	after := dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}

	got, err := p.UpdateRecord(context.Background(), crudZone, before, after)
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}

	if w := api.Writes(); len(w) != 1 || w[0].Method != http.MethodPut || w[0].Body["proxied"] != true {
		t.Errorf("writes = %+v, want one PUT keeping the proxy on", w)
	}

	want := after
	want.Extras = map[string]string{cloudflare.ExtraProxied: "true"}
	assertRecords(t, []dnsprovider.Record{got}, []dnsprovider.Record{want})
}
