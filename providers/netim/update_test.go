package netim_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/nonet"
	"github.com/dnsgateway/dnsprovider/providers/netim"
)

const updatePath = "PATCH /domain/example.com/zone/update/"

// held is the one Record of that type the fake's zone holds.
func held(t *testing.T, p *netim.Provider, typ string) dnsprovider.Record {
	t.Helper()

	set, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{Type: typ})
	if err != nil {
		t.Fatal(err)
	}

	if len(set.Records) != 1 {
		t.Fatalf("the Zone holds %d %s records, want 1", len(set.Records), typ)
	}

	return set.Records[0]
}

func TestUpdateRecordChangesValueOrTTLInOneUpdate(t *testing.T) {
	tests := []struct {
		name   string
		typ    string
		change func(*dnsprovider.Record)
		want   record
		wire   map[string]any
	}{
		{
			name:   "an A record's value",
			typ:    "A",
			change: func(r *dnsprovider.Record) { r.Value = "192.0.2.11" },
			want:   record{"A", "example.com", "192.0.2.11", 10800, nil},
			wire: map[string]any{
				"subdomain": "", "type": "A", "value": "192.0.2.10", "newValue": "192.0.2.11",
				"options": map[string]any{"ttl": 10800.0, "ttlUnit": "S"},
			},
		},
		{
			name:   "a CNAME record's TTL",
			typ:    "CNAME",
			change: func(r *dnsprovider.Record) { r.TTL = 600 },
			want:   record{"CNAME", "blog.example.com", "www.example.com", 600, nil},
			wire: map[string]any{
				"subdomain": "blog", "type": "CNAME", "value": "www.example.com.", "newValue": "www.example.com.",
				"options": map[string]any{"ttl": 600.0, "ttlUnit": "S"},
			},
		},
		{
			name:   "an MX record's priority, selected by its value as held",
			typ:    "MX",
			change: func(r *dnsprovider.Record) { r.Value = "20 mail.example.com" },
			want:   record{"MX", "example.com", "20 mail.example.com", 10800, nil},
			wire: map[string]any{
				"subdomain": "@", "type": "MX", "value": "mail.example.com.", "newValue": "mail.example.com.",
				"options": map[string]any{"ttl": 10800.0, "ttlUnit": "S", "priority": 20.0},
			},
		},
		{
			name:   "an SRV record's numbers and target",
			typ:    "SRV",
			change: func(r *dnsprovider.Record) { r.Value = "20 10 5061 sip2.example.com" },
			want:   record{"SRV", "_sip._tcp.example.com", "20 10 5061 sip2.example.com", 10800, nil},
			wire: map[string]any{
				"subdomain": "", "type": "SRV", "value": "sip.example.com.", "newValue": "sip2.example.com.",
				"options": map[string]any{
					"ttl": 10800.0, "ttlUnit": "S", "service": "sip", "protocol": "TCP", "priority": 20.0, "weight": 10.0, "port": 5061.0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider()

			before := held(t, p, tt.typ)
			after := before
			tt.change(&after)

			got, err := p.UpdateRecord(context.Background(), zone, before, after)
			if err != nil {
				t.Fatal(err)
			}

			if got.ID == "" || got.ID == before.ID || !reflect.DeepEqual(record{got.Type, got.Name, got.Value, got.TTL, got.Extras}, tt.want) {
				t.Errorf("UpdateRecord = %+v, want %+v with a new ID", got, tt.want)
			}

			if body := f.body(updatePath); !reflect.DeepEqual(body, tt.wire) {
				t.Errorf("update body =\n%v\nwant\n%v", body, tt.wire)
			}

			if n := f.count(createPath) + f.count(deletePath); n != 0 {
				t.Errorf("sent %d creates and deletes, want only the update", n)
			}

			if now := held(t, p, tt.typ); now.ID != got.ID {
				t.Errorf("the Zone holds %+v, want %+v", now, got)
			}
		})
	}
}

func TestUpdateRecordMovesARecordToAnotherOwnerOrTypeByDeleteThenCreate(t *testing.T) {
	tests := []struct {
		name   string
		typ    string
		after  dnsprovider.Record
		want   record
		delete map[string]any
		create map[string]any
	}{
		{
			name:   "an A record to another owner",
			typ:    "A",
			after:  dnsprovider.Record{Type: "A", Name: "api", Value: "192.0.2.10", TTL: 3600},
			want:   record{"A", "api.example.com", "192.0.2.10", 3600, nil},
			delete: map[string]any{"subdomain": "", "type": "A", "value": "192.0.2.10"},
			create: map[string]any{"subdomain": "api", "type": "A", "value": "192.0.2.10", "options": map[string]any{"ttl": 3600.0, "ttlUnit": "S"}},
		},
		{
			name:   "a CNAME record to an A record",
			typ:    "CNAME",
			after:  dnsprovider.Record{Type: "A", Name: "blog.example.com", Value: "192.0.2.30", TTL: 300},
			want:   record{"A", "blog.example.com", "192.0.2.30", 300, nil},
			delete: map[string]any{"subdomain": "blog", "type": "CNAME", "value": "www.example.com."},
			create: map[string]any{"subdomain": "blog", "type": "A", "value": "192.0.2.30", "options": map[string]any{"ttl": 300.0, "ttlUnit": "S"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider()

			before := held(t, p, tt.typ)

			got, err := p.UpdateRecord(context.Background(), zone, before, tt.after)
			if err != nil {
				t.Fatal(err)
			}

			if got.ID == "" || !reflect.DeepEqual(record{got.Type, got.Name, got.Value, got.TTL, got.Extras}, tt.want) {
				t.Errorf("UpdateRecord = %+v, want %+v", got, tt.want)
			}

			if body := f.body(deletePath); !reflect.DeepEqual(body, tt.delete) {
				t.Errorf("delete body = %v, want %v", body, tt.delete)
			}

			if body := f.body(createPath); !reflect.DeepEqual(body, tt.create) {
				t.Errorf("create body = %v, want %v", body, tt.create)
			}

			if f.order(deletePath, createPath) != "delete, create" || f.count(updatePath) != 0 {
				t.Errorf("sent %s and %d updates, want a delete, then a create", f.order(deletePath, createPath), f.count(updatePath))
			}

			for _, r := range listed(t, p) {
				if r.ID == before.ID {
					t.Errorf("the Zone still holds %+v", before)
				}
			}
		})
	}
}

func TestUpdateRecordMoveRestoresTheOldRecordWhenTheCreateDidNotTake(t *testing.T) {
	zoneInfo := "GET /domain/example.com/zone/info/"

	tests := []struct {
		name   string
		script func(f *fake)
		// held are the A records the Zone holds afterwards, by name.
		held        []string
		writes      string
		message     string
		unconfirmed bool
	}{
		{
			name:    "a refused create is restored",
			script:  func(f *fake) { f.script(createPath, http.StatusOK, fixture(t, "zone_create_failed.json")) },
			held:    []string{"example.com"},
			writes:  "delete, create, create",
			message: "the old record was restored",
		},
		{
			name:    "a create refused with a 400 is restored",
			script:  func(f *fake) { f.script(createPath, http.StatusBadRequest, fixture(t, "error_400.json")) },
			held:    []string{"example.com"},
			writes:  "delete, create, create",
			message: "the old record was restored",
		},
		{
			name:        "a lost create the Zone does not show is restored",
			script:      func(f *fake) { f.script(createPath, lost, "") },
			held:        []string{"example.com"},
			writes:      "delete, create, create",
			message:     "the old record was restored",
			unconfirmed: true,
		},
		{
			name:        "a lost create the Zone shows is not restored",
			script:      func(f *fake) { f.script(createPath, lostApplied, "") },
			held:        []string{"api.example.com"},
			writes:      "delete, create",
			message:     "nothing was restored",
			unconfirmed: true,
		},
		{
			name: "a Pending create is not restored when the Zone cannot be read",
			script: func(f *fake) {
				f.script(createPath, http.StatusOK, fixture(t, "operation_pending.json"))
				f.script(zoneInfo, http.StatusOK, fixture(t, "zone_info.json"))
				f.script(zoneInfo, http.StatusBadRequest, fixture(t, "error_400.json"))
			},
			held:        nil,
			writes:      "delete, create",
			message:     "nothing was restored",
			unconfirmed: true,
		},
		{
			name: "a refused restore is reported",
			script: func(f *fake) {
				f.script(createPath, http.StatusOK, fixture(t, "zone_create_failed.json"))
				f.script(createPath, http.StatusOK, operationReply("Failed", "record locked"))
			},
			held:    nil,
			writes:  "delete, create, create",
			message: "restoring the old record failed",
		},
		{
			name: "a lost restore is reported as unconfirmed",
			script: func(f *fake) {
				f.script(createPath, http.StatusOK, fixture(t, "zone_create_failed.json"))
				f.script(createPath, lost, "")
			},
			held:        nil,
			writes:      "delete, create, create",
			message:     "restoring the old record failed",
			unconfirmed: true,
		},
		{
			name:    "a refused delete sends no create",
			script:  func(f *fake) { f.script(deletePath, http.StatusOK, operationReply("Failed", "record locked")) },
			held:    []string{"example.com"},
			writes:  "delete",
			message: "move: delete",
		},
		{
			name:        "a lost delete sends no create",
			script:      func(f *fake) { f.script(deletePath, lost, "") },
			held:        []string{"example.com"},
			writes:      "delete",
			message:     "move: delete",
			unconfirmed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider()

			before := held(t, p, "A")
			tt.script(f)

			_, err := p.UpdateRecord(context.Background(), zone, before, dnsprovider.Record{Type: "A", Name: "api", Value: "192.0.2.10", TTL: 3600})
			if err == nil || !strings.Contains(err.Error(), tt.message) || errors.Is(err, dnsprovider.ErrUnconfirmed) != tt.unconfirmed {
				t.Fatalf("UpdateRecord = %v, want an error saying %q, unconfirmed %v", err, tt.message, tt.unconfirmed)
			}

			if got := f.order(deletePath, createPath); got != tt.writes {
				t.Errorf("sent %s, want %s", got, tt.writes)
			}

			set, err := p.ListRecords(context.Background(), zone, dnsprovider.RecordFilter{Type: "A"})
			if err != nil {
				t.Fatal(err)
			}

			var names []string
			for _, r := range set.Records {
				names = append(names, r.Name)

				if r.Name == before.Name && (r.Value != before.Value || r.TTL != before.TTL) {
					t.Errorf("restored %+v, want %+v", r, before)
				}
			}

			if !reflect.DeepEqual(names, tt.held) {
				t.Errorf("the Zone holds A records %v, want %v", names, tt.held)
			}
		})
	}
}

func TestUpdateRecordReportsUnconfirmedAndRefusedUpdatesWithoutRetrying(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		readBack    bool
		unconfirmed bool
	}{
		{name: "a 5xx", status: http.StatusBadGateway, body: `{"message":"bad gateway"}`, unconfirmed: true},
		{name: "a lost answer", status: lost, unconfirmed: true},
		{name: "a Pending operation", status: http.StatusOK, body: fixture(t, "operation_pending.json"), unconfirmed: true},
		{name: "a read-back that fails", readBack: true, unconfirmed: true},
		{name: "a Failed operation", status: http.StatusOK, body: operationReply("Failed", "record locked")},
		{name: "a Cancelled operation", status: http.StatusOK, body: fixture(t, "operation_cancelled.json")},
		{name: "a 400", status: http.StatusBadRequest, body: fixture(t, "error_400.json")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			p := f.provider()

			before := held(t, p, "TXT")
			after := before
			after.Value = "v=spf1 -all"

			if tt.readBack {
				f.script("GET /domain/example.com/zone/info/", http.StatusOK, fixture(t, "zone_info.json"))
				f.script("GET /domain/example.com/zone/info/", http.StatusBadRequest, fixture(t, "error_400.json"))
			} else {
				f.script(updatePath, tt.status, tt.body)
			}

			_, err := p.UpdateRecord(context.Background(), zone, before, after)
			if err == nil || errors.Is(err, dnsprovider.ErrUnconfirmed) != tt.unconfirmed {
				t.Fatalf("UpdateRecord = %v, want unconfirmed %v", err, tt.unconfirmed)
			}

			var apiErr *dnsprovider.APIError
			if !tt.unconfirmed && !errors.As(err, &apiErr) {
				t.Fatalf("UpdateRecord = %v, want an APIError", err)
			}

			if n := f.count(updatePath); n != 1 || f.writes() != 1 {
				t.Fatalf("sent %d updates and %d writes, want one update", n, f.writes())
			}
		})
	}
}

func TestUpdateRecordKeepsRecordOptionsAndRefusesToChangeOrMoveThem(t *testing.T) {
	info := `{"ttl":1,"ttlUnit":"H","records":[{"subdomain":"www","type":"A","value":"192.0.2.1","options":{"ttl":1,"ttlUnit":"H","geo":"EU"}}]}`

	f := newFake(t)
	p := f.provider()

	f.script("GET /domain/example.com/zone/info/", http.StatusOK, info)

	before := held(t, p, "A")
	if len(before.Extras) == 0 {
		t.Fatalf("read %+v, want its options as Extras", before)
	}

	changed := before
	changed.Extras = map[string]string{"geo": `"US"`}

	moved := before
	moved.Name = "api.example.com"

	for name, after := range map[string]dnsprovider.Record{"changed options": changed, "a move": moved} {
		t.Run(name, func(t *testing.T) {
			f.script("GET /domain/example.com/zone/info/", http.StatusOK, info)

			if _, err := p.UpdateRecord(context.Background(), zone, before, after); err == nil || !strings.Contains(err.Error(), "options") {
				t.Fatalf("UpdateRecord = %v, want record options refused", err)
			}
		})
	}

	if n := f.writes(); n != 0 {
		t.Fatalf("sent %d writes, want none", n)
	}
}

func TestApplyWithAStaleChangesetSendsNoWrite(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	stale := held(t, p, "TXT")
	stale.TTL = 600

	_, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: zone, Changes: []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "api", Value: "192.0.2.20", TTL: 3600}},
		{Kind: dnsprovider.ChangeDelete, Before: stale},
	}})
	if !errors.Is(err, dnsprovider.ErrStale) {
		t.Fatalf("Apply = %v, want ErrStale", err)
	}

	if n := f.writes(); n != 0 {
		t.Fatalf("sent %d writes, want none", n)
	}
}

func TestApplyOverCRUDReturnsPerChangeResultsInInputOrder(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	txt, cname, ns := held(t, p, "TXT"), held(t, p, "CNAME"), held(t, p, "NS")

	retimed := txt
	retimed.TTL = 600

	moved := cname
	moved.Name = "news.example.com"

	changes := []dnsprovider.Change{
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "api", Value: "192.0.2.20", TTL: 3600}},
		{Kind: dnsprovider.ChangeModify, Before: txt, After: retimed},
		{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "CAA", Name: "@", Value: `0 issue "letsencrypt.org"`, TTL: 3600}},
		{Kind: dnsprovider.ChangeDelete, Before: ns},
		{Kind: dnsprovider.ChangeModify, Before: cname, After: moved},
	}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: zone, Changes: changes})
	if err != nil {
		t.Fatal(err)
	}

	want := []struct {
		record record
		failed bool
	}{
		{record: record{"A", "api.example.com", "192.0.2.20", 3600, nil}},
		{record: record{"TXT", "example.com", txt.Value, 600, nil}},
		{failed: true},
		{},
		{record: record{"CNAME", "news.example.com", "www.example.com", 300, nil}},
	}

	if len(res.Results) != len(want) {
		t.Fatalf("Apply returned %d results, want %d", len(res.Results), len(want))
	}

	for i, w := range want {
		got := res.Results[i]
		if !reflect.DeepEqual(got.Change, changes[i]) || (got.Err != nil) != w.failed {
			t.Errorf("result %d = %+v, want change %d, failed %v", i, got, i, w.failed)
		}

		if r := got.Record; !reflect.DeepEqual(record{r.Type, r.Name, r.Value, r.TTL, r.Extras}, w.record) {
			t.Errorf("result %d record = %+v, want %+v", i, r, w.record)
		}
	}

	// Apply deletes, then modifies, then adds.
	f.mu.Lock()
	var sent []string

	for _, r := range f.requests {
		if r == createPath || r == updatePath || r == deletePath {
			sent = append(sent, r)
		}
	}
	f.mu.Unlock()

	wantSent := []string{deletePath, updatePath, deletePath, createPath, createPath}
	if !reflect.DeepEqual(sent, wantSent) {
		t.Errorf("sent\n%v\nwant\n%v", sent, wantSent)
	}
}

// order names the requests the fake got for the delete and create keys,
// in order, as "delete" and "create".
func (f *fake) order(del, create string) string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []string

	for _, r := range f.requests {
		switch r {
		case del:
			out = append(out, "delete")
		case create:
			out = append(out, "create")
		}
	}

	return strings.Join(out, ", ")
}

// writes is how many record creates, updates and deletes the fake got.
func (f *fake) writes() int {
	return f.count(createPath) + f.count(updatePath) + f.count(deletePath)
}

func TestUpdateRecordOfAStaleRecordIsNotFoundWithoutAWrite(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	mx := held(t, p, "MX")
	changed := mx
	changed.ID = "changed since read"

	stale := map[string]dnsprovider.Record{
		"a Record the Zone does not hold": {Type: "A", Name: "gone.example.com", Value: "192.0.2.99", TTL: 3600},
		"a Record changed since read":     changed,
	}

	for name, before := range stale {
		t.Run(name, func(t *testing.T) {
			after := before
			after.TTL = 600

			if _, err := p.UpdateRecord(context.Background(), zone, before, after); !errors.Is(err, dnsprovider.ErrNotFound) {
				t.Fatalf("UpdateRecord = %v, want ErrNotFound", err)
			}
		})
	}

	if n := f.writes(); n != 0 {
		t.Fatalf("sent %d writes, want none", n)
	}
}

func TestUpdateRecordToARecordTheZoneHoldsIsAConflictWithoutAWrite(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	// The Zone holds AAAA www 2001:db8::10 with the Zone's TTL.
	before := held(t, p, "A")
	after := dnsprovider.Record{Type: "AAAA", Name: "www", Value: "2001:db8::10", TTL: before.TTL}

	if _, err := p.UpdateRecord(context.Background(), zone, before, after); !errors.Is(err, dnsprovider.ErrConflict) {
		t.Fatalf("UpdateRecord = %v, want ErrConflict", err)
	}

	if n := f.writes(); n != 0 {
		t.Fatalf("sent %d writes, want none", n)
	}
}

func TestUpdateRecordRefusesLocallyWhatNetimCannotTake(t *testing.T) {
	p, err := netim.New(netim.Config{ID: resellerID, Secret: secret}, dnsprovider.WithHTTPClient(nonet.Client(t)))
	if err != nil {
		t.Fatal(err)
	}

	a := dnsprovider.Record{Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 3600}
	tests := map[string]struct{ before, after dnsprovider.Record }{
		"from a TLSA record, read only":  {dnsprovider.Record{Type: "TLSA", Name: "_25._tcp.mail.example.com", Value: "3 1 1 0123", TTL: 3600}, a},
		"to a CAA record":                {a, dnsprovider.Record{Type: "CAA", Name: "@", Value: `0 issue "letsencrypt.org"`, TTL: 3600}},
		"to a value over 150 characters": {a, dnsprovider.Record{Type: "TXT", Name: "www", Value: strings.Repeat("a", 151), TTL: 3600}},
		"to a TTL out of range":          {a, dnsprovider.Record{Type: "A", Name: "www", Value: "192.0.2.1", TTL: 10}},
		"to a name outside the Zone":     {a, dnsprovider.Record{Type: "A", Name: "www.example.org.", Value: "192.0.2.1", TTL: 3600}},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := p.UpdateRecord(context.Background(), zone, tt.before, tt.after); err == nil {
				t.Fatal("UpdateRecord succeeded, want a refusal")
			}
		})
	}
}
