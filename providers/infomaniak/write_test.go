package infomaniak_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

const createKey = "POST /2/zones/example.ch/records"

func TestCreateRecordReturnsTheStoredRecordAfterOnePost(t *testing.T) {
	f := newFake(t)
	f.script(createKey, http.StatusOK, fixture(t, "record_created.json"))

	got, err := f.provider().CreateRecord(context.Background(), exampleCH, dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.10", TTL: 3600})
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Record{ID: "32824", Type: "A", Name: "new.example.ch", Value: "192.0.2.10", TTL: 3600}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CreateRecord = %+v, want %+v", got, want)
	}

	bodies := f.sent(createKey)
	if len(bodies) != 1 {
		t.Fatalf("sent %d POSTs, want 1", len(bodies))
	}

	var body map[string]any
	if err := json.Unmarshal([]byte(bodies[0]), &body); err != nil {
		t.Fatal(err)
	}

	if wantBody := map[string]any{"source": "new", "type": "A", "target": "192.0.2.10", "ttl": 3600.0}; !reflect.DeepEqual(body, wantBody) {
		t.Fatalf("POST body = %v, want %v", body, wantBody)
	}
}

func TestCreateRecordOfARecordTheZoneHoldsIsErrConflictWithoutAWrite(t *testing.T) {
	f := newFake(t)

	// records.json holds test A 192.0.2.1 with a TTL of 3600.
	_, err := f.provider().CreateRecord(context.Background(), exampleCH, dnsprovider.Record{Type: "A", Name: "TEST.example.ch.", Value: "192.0.2.1", TTL: 600})
	if !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("CreateRecord = %v, want ErrConflict", err)
	}

	if len(f.queries("GET /2/zones/example.ch/records")) == 0 {
		t.Fatal("the duplicate check read no records")
	}

	if n := len(f.sent(createKey)); n != 0 {
		t.Fatalf("sent %d POSTs, want none", n)
	}
}

var newRecord = dnsprovider.Record{Type: "A", Name: "new", Value: "192.0.2.10", TTL: 3600}

func TestCreateRecordRefusalsAreAPIErrors(t *testing.T) {
	for _, tc := range []struct {
		status   int
		file     string
		conflict bool
	}{
		{http.StatusBadRequest, "dns_record_already_exists.json", true},
		{http.StatusBadRequest, "dns_record_mutual_exclusion.json", true},
		{http.StatusBadRequest, "invalid_dns_record.json", false},
		{http.StatusUnprocessableEntity, "validation_failed.json", false},
		{http.StatusOK, "invalid_dns_record.json", false}, // result: error in a success
	} {
		t.Run(tc.file, func(t *testing.T) {
			f := newFake(t)
			f.script(createKey, tc.status, fixture(t, tc.file))

			_, err := f.provider().CreateRecord(context.Background(), exampleCH, newRecord)

			var api *dnsprovider.APIError
			if !errors.As(err, &api) || len(api.Messages) == 0 || !strings.HasPrefix(api.Messages[0], strings.TrimSuffix(tc.file, ".json")+": ") {
				t.Fatalf("CreateRecord = %v, want an APIError with Infomaniak's code", err)
			}

			if errors.Is(err, dnsprovider.ErrConflict) != tc.conflict || errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("CreateRecord = %v: ErrConflict %v, want %v; never ErrUnconfirmed", err, !tc.conflict, tc.conflict)
			}

			if n := len(f.sent(createKey)); n != 1 {
				t.Fatalf("sent %d POSTs, want 1", n)
			}
		})
	}
}

func TestCreateRecordWhoseOutcomeIsUnknownIsUnconfirmedAndNotRetried(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"lost answer":         {lost, ""},
		"5xx":                 {http.StatusInternalServerError, fixture(t, "cannot_create_object.json")},
		"undecodable success": {http.StatusOK, `{"result":"success","data":`},
		"no record":           {http.StatusOK, fixture(t, "record_deleted.json")},
		"malformed record":    {http.StatusOK, `{"result":"success","data":{"id":0,"type":"A"}}`},
		"asynchronous":        {http.StatusAccepted, fixture(t, "asynchronous.json")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.script(createKey, tc.status, tc.body)

			if _, err := f.provider().CreateRecord(context.Background(), exampleCH, newRecord); !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("CreateRecord = %v, want ErrUnconfirmed", err)
			}

			if n := len(f.sent(createKey)); n != 1 {
				t.Fatalf("sent %d POSTs, want 1", n)
			}
		})
	}
}

const deleteKey = "DELETE /2/zones/example.ch/records/22585703"

var heldRecord = dnsprovider.Record{ID: "22585703", Type: "A", Name: "test.example.ch", Value: "192.0.2.1", TTL: 3600}

func TestDeleteRecordDeletesByID(t *testing.T) {
	f := newFake(t)
	f.script(deleteKey, http.StatusOK, fixture(t, "record_deleted.json"))

	if err := f.provider().DeleteRecord(context.Background(), exampleCH, heldRecord); err != nil {
		t.Fatal(err)
	}

	if n, sent := f.count(), len(f.sent(deleteKey)); n != 1 || sent != 1 {
		t.Fatalf("sent %d requests, %d of them the DELETE; want the one DELETE", n, sent)
	}
}

func TestDeleteRecordWithoutAnIDSendsNoRequest(t *testing.T) {
	f := newFake(t)
	r := heldRecord
	r.ID = ""

	if err := f.provider().DeleteRecord(context.Background(), exampleCH, r); err == nil {
		t.Fatal("DeleteRecord succeeded")
	}

	if n := f.count(); n != 0 {
		t.Fatalf("sent %d requests, want none", n)
	}
}

func TestDeleteRecordOfAnAbsentRecordIsErrNotFound(t *testing.T) {
	f := newFake(t)
	f.script(deleteKey, http.StatusNotFound, fixture(t, "object_not_found.json"))

	if err := f.provider().DeleteRecord(context.Background(), exampleCH, heldRecord); !errors.Is(err, dnsprovider.ErrNotFound) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("DeleteRecord = %v, want ErrNotFound", err)
	}
}

func TestDeleteRecordWithALostAnswerIsUnconfirmed(t *testing.T) {
	f := newFake(t)
	f.script(deleteKey, lost, "")

	if err := f.provider().DeleteRecord(context.Background(), exampleCH, heldRecord); !errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("DeleteRecord = %v, want ErrUnconfirmed", err)
	}
}

func TestCreateRecordRefusesLocallyWithoutARequest(t *testing.T) {
	for name, r := range map[string]dnsprovider.Record{
		"URI":           {Type: "URI", Name: "_http._tcp", Value: `10 1 "https://example.ch/"`, TTL: 300},
		"DS":            {Type: "DS", Name: "sub", Value: "2371 13 2 ABCDEF", TTL: 300},
		"out of Zone":   {Type: "A", Name: "www.example.org.", Value: "192.0.2.1", TTL: 300},
		"invalid value": {Type: "A", Name: "www", Value: "2001:db8::1", TTL: 300},
		"invalid MX":    {Type: "MX", Name: "www", Value: "mail.example.test.", TTL: 300},
		"empty value":   {Type: "TXT", Name: "www", Value: " ", TTL: 300},
		"TTL too short": {Type: "A", Name: "www", Value: "192.0.2.1", TTL: 59},
		"TTL too long":  {Type: "A", Name: "www", Value: "192.0.2.1", TTL: 86401},
		"automatic TTL": {Type: "A", Name: "www", Value: "192.0.2.1", TTL: dnsprovider.TTLAuto},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)

			if _, err := f.provider().CreateRecord(context.Background(), exampleCH, r); err == nil {
				t.Fatal("CreateRecord succeeded")
			}

			if n := f.count(); n != 0 {
				t.Fatalf("sent %d requests, want none", n)
			}
		})
	}
}

func TestCreateRecordSendsEachWriteTypeInInfomaniaksForm(t *testing.T) {
	for _, tc := range []struct {
		in             dnsprovider.Record
		source, target string
		value          string // the Value of the Record returned
	}{
		{dnsprovider.Record{Type: "AAAA", Name: "v6", Value: "2001:db8::10", TTL: 300}, "v6", "2001:db8::10", "2001:db8::10"},
		{dnsprovider.Record{Type: "cname", Name: "Alias.example.ch.", Value: "target.example.test.", TTL: 300}, "alias", "target.example.test", "target.example.test."},
		{dnsprovider.Record{Type: "MX", Name: "@", Value: "10 mx.example.test.", TTL: 300}, ".", "10 mx.example.test", "10 mx.example.test."},
		{dnsprovider.Record{Type: "TXT", Name: "", Value: `v=spf1 include:"x" -all`, TTL: 300}, ".", `v=spf1 include:"x" -all`, `v=spf1 include:"x" -all`},
		{dnsprovider.Record{Type: "NS", Name: "sub", Value: "ns1.example.test", TTL: 300}, "sub", "ns1.example.test", "ns1.example.test."},
		{dnsprovider.Record{Type: "SRV", Name: "_sip._tcp", Value: "10 5 5060 sip.example.test.", TTL: 300}, "_sip._tcp", "10 5 5060 sip.example.test", "10 5 5060 sip.example.test."},
		{dnsprovider.Record{Type: "CAA", Name: "", Value: `0 issue "letsencrypt.org"`, TTL: 300}, ".", `0 issue "letsencrypt.org"`, `0 issue "letsencrypt.org"`},
		{dnsprovider.Record{Type: "A", Name: "*", Value: "192.0.2.20", TTL: 60}, "*", "192.0.2.20", "192.0.2.20"},
	} {
		t.Run(tc.in.Type, func(t *testing.T) {
			f := newFake(t)
			stored, _ := json.Marshal(map[string]any{"result": "success", "data": map[string]any{
				"id": 7, "source": tc.source, "type": strings.ToUpper(tc.in.Type), "ttl": tc.in.TTL, "target": tc.target, "updated_at": 1779826643,
			}})
			f.script(createKey, http.StatusOK, string(stored))

			got, err := f.provider().CreateRecord(context.Background(), exampleCH, tc.in)
			if err != nil {
				t.Fatal(err)
			}

			if got.ID != "7" || got.Value != tc.value {
				t.Errorf("CreateRecord = %+v, want ID 7 and Value %q", got, tc.value)
			}

			var body map[string]any
			if bodies := f.sent(createKey); len(bodies) != 1 || json.Unmarshal([]byte(bodies[0]), &body) != nil {
				t.Fatalf("POST bodies = %q", bodies)
			}

			if body["source"] != tc.source || body["target"] != tc.target || body["type"] != strings.ToUpper(tc.in.Type) || body["ttl"] != float64(tc.in.TTL) {
				t.Fatalf("POST body = %v, want source %q, target %q", body, tc.source, tc.target)
			}
		})
	}
}
