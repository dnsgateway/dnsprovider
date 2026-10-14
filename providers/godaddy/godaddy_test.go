package godaddy_test

// Seam 2: the GoDaddy Provider against an httptest server that speaks
// the GoDaddy v3 Domains API's JSON shapes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/godaddy"
)

const testToken = "test-token"

var testConfig = godaddy.Config{Token: testToken}

// gdAPI is a scripted GoDaddy v3 Domains API. Domain lists are paged
// pageSize domains at a time by an opaque pageToken; record lists
// pageSize records at a time by page number. Each list links its next
// page with rel=next.
type gdAPI struct {
	// pageSize is the page size the Provider asks for; zero leaves its own.
	pageSize int
	// ignorePaging answers every list with its first page, whatever the
	// page or pageToken, linking the same next page.
	ignorePaging bool
	domains      []map[string]any
	records      map[string][]map[string]any // by domain

	// missing, when set, is the error GET /domain-names/{domain} answers
	// for a domain not in domains, instead of 404.
	missing *apiErr
	// deny answers every request with this error, as GoDaddy does for a
	// token it refuses.
	deny *apiErr
	// reject, when it returns a message, fails the write with 422.
	reject func(method string, body map[string]any) string
	// answer, when set, answers each write in place of the API.
	answer func(w http.ResponseWriter)
	// acknowledgeOnly makes writes answer success but change nothing.
	acknowledgeOnly bool
	// onWrite, when set, runs once before the next write is applied: a
	// change by another writer after the Changeset read the records.
	onWrite func(api *gdAPI)
	// barrier, when set, holds every write until snapshots record lists
	// have been answered.
	barrier   chan struct{}
	snapshots int

	mu     sync.Mutex
	nextID int
	// writes records each write.
	writes []write
	// requests records each request's URL.
	requests []*url.URL
}

// write is one record write the API received.
type write struct {
	Method, Path string
	Body         map[string]any
}

func (w write) String() string { return w.Method + " " + w.Path }

// Writes returns the writes received, in order.
func (api *gdAPI) Writes() []write {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.writes)
}

// WriteLines returns the writes received as "METHOD path" lines.
func (api *gdAPI) WriteLines() []string {
	var out []string
	for _, w := range api.Writes() {
		out = append(out, w.String())
	}

	return out
}

// Requests returns each request's URL, in order.
func (api *gdAPI) Requests() []*url.URL {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.requests)
}

// holdWritesUntil makes writes wait until n record lists are answered.
func (api *gdAPI) holdWritesUntil(n int) {
	api.barrier = make(chan struct{})
	api.snapshots = n
}

func newProvider(t *testing.T, api *gdAPI) dnsprovider.Provider {
	t.Helper()

	for _, recs := range api.records {
		for _, rec := range recs {
			api.id(rec)
		}
	}

	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)

	if api.pageSize > 0 {
		godaddy.SetPageSize(t, api.pageSize)
	}

	p, err := godaddy.New(testConfig, dnsprovider.WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return p
}

// id gives a record without one its recordId.
func (api *gdAPI) id(rec map[string]any) {
	if rec["recordId"] == nil {
		api.nextID++
		rec["recordId"] = "rec-" + strconv.Itoa(api.nextID)
	}
}

func (api *gdAPI) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v3/domains/domain-names", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("statuses"); got != "ACTIVE" {
			t.Errorf("statuses = %q, want ACTIVE", got)
		}

		start := 0
		if tok := r.URL.Query().Get("pageToken"); tok != "" && !api.ignorePaging {
			start, _ = strconv.Atoi(strings.TrimPrefix(tok, "t"))
		}

		size := api.size(r)
		end := min(start+size, len(api.domains))

		var links []map[string]string
		if end < len(api.domains) || api.ignorePaging {
			links = append(links, map[string]string{"rel": "next", "href": "https://api.godaddy.com/v3/domains/domain-names?pageToken=t" + strconv.Itoa(end)})
		}

		writeJSON(w, http.StatusOK, map[string]any{"items": append([]map[string]any{}, api.domains[start:end]...), "links": links})
	})

	mux.HandleFunc("GET /v3/domains/domain-names/{domain}", func(w http.ResponseWriter, r *http.Request) {
		i := slices.IndexFunc(api.domains, func(d map[string]any) bool { return d["domain"] == r.PathValue("domain") })
		switch {
		case i < 0 && api.missing != nil:
			writeError(w, api.missing.status, api.missing.name, api.missing.message)
		case i < 0:
			writeError(w, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		default:
			writeJSON(w, http.StatusOK, api.domains[i])
		}
	})

	mux.HandleFunc("GET /v3/domains/zones/{zone}/dns-records", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()

		if api.barrier != nil && api.snapshots > 0 {
			if api.snapshots--; api.snapshots == 0 {
				close(api.barrier)
			}
		}

		records, ok := api.records[r.PathValue("zone")]
		if !ok {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "The zone does not exist")

			return
		}

		var out []map[string]any
		for _, rec := range records {
			if typ := r.URL.Query().Get("type"); typ == "" || rec["type"] == typ {
				out = append(out, maps.Clone(rec))
			}
		}

		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || page < 1 || api.ignorePaging {
			page = 1
		}

		size := api.size(r)
		start := min((page-1)*size, len(out))
		end := min(start+size, len(out))

		var links []map[string]string
		if end < len(out) || api.ignorePaging {
			links = append(links, map[string]string{"rel": "next", "href": "?page=" + strconv.Itoa(page+1)})
		}

		writeJSON(w, http.StatusOK, map[string]any{"items": append([]map[string]any{}, out[start:end]...), "links": links})
	})

	mux.HandleFunc("POST /v3/domains/zones/{zone}/dns-records", api.writeRecord)
	mux.HandleFunc("PUT /v3/domains/zones/{zone}/dns-records/{id}", api.writeRecord)
	mux.HandleFunc("DELETE /v3/domains/zones/{zone}/dns-records/{id}", api.writeRecord)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && api.barrier != nil {
			<-api.barrier
		}

		api.mu.Lock()
		api.requests = append(api.requests, r.URL)
		api.mu.Unlock()

		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q, want the personal access token", got)
		}

		if api.deny != nil {
			writeError(w, api.deny.status, api.deny.name, api.deny.message)

			return
		}

		mux.ServeHTTP(w, r)
	})
}

// sameRecord reports whether two fixture records are one resource record.
func sameRecord(a, b map[string]any) bool {
	for _, k := range []string{"type", "name", "data", "service", "protocol"} {
		if fmt.Sprint(a[k]) != fmt.Sprint(b[k]) {
			return false
		}
	}

	return true
}

// writeRecord creates, replaces or deletes one record as GoDaddy does. A
// POST of a record the zone holds answers 409 (an assumption).
func (api *gdAPI) writeRecord(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Method != http.MethodDelete {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_BODY", "Request body doesn't fulfill schema")

			return
		}
	}

	zone, id := r.PathValue("zone"), r.PathValue("id")

	api.mu.Lock()
	defer api.mu.Unlock()

	api.writes = append(api.writes, write{Method: r.Method, Path: strings.TrimPrefix(r.URL.Path, "/v3/domains/zones/"+zone), Body: maps.Clone(body)})

	if api.answer != nil {
		api.answer(w)

		return
	}

	if api.reject != nil {
		if msg := api.reject(r.Method, body); msg != "" {
			writeError(w, http.StatusUnprocessableEntity, "INVALID_BODY", msg)

			return
		}
	}

	if api.onWrite != nil {
		onWrite := api.onWrite
		api.onWrite = nil
		onWrite(api)
	}

	if api.records == nil {
		api.records = map[string][]map[string]any{}
	}

	records := api.records[zone]
	at := slices.IndexFunc(records, func(rec map[string]any) bool { return rec["recordId"] == id })

	switch r.Method {
	case http.MethodPost:
		if slices.ContainsFunc(records, func(rec map[string]any) bool { return sameRecord(rec, body) }) {
			writeError(w, http.StatusConflict, "DUPLICATE_RECORD", "The record already exists")

			return
		}

		api.id(body)

		if !api.acknowledgeOnly {
			api.records[zone] = append(slices.Clone(records), body)
		}

		writeJSON(w, http.StatusCreated, body)
	case http.MethodPut:
		if at < 0 {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "The record does not exist")

			return
		}

		body["recordId"] = id

		if !api.acknowledgeOnly {
			records = slices.Clone(records)
			records[at] = body
			api.records[zone] = records
		}

		writeJSON(w, http.StatusOK, body)
	case http.MethodDelete:
		if at < 0 {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "The record does not exist")

			return
		}

		if !api.acknowledgeOnly {
			api.records[zone] = slices.Delete(slices.Clone(records), at, at+1)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// size is a list's page size: the client's pageSize.
func (api *gdAPI) size(r *http.Request) int {
	size, err := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if err != nil || size < 1 {
		return 25
	}

	return size
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// apiErr is a scripted GoDaddy error answer.
type apiErr struct {
	status        int
	name, message string
}

// writeError answers with a GoDaddy v3 error body.
func writeError(w http.ResponseWriter, status int, name, message string) {
	writeJSON(w, status, map[string]any{"name": name, "correlationId": "c-1", "message": message})
}

func domain(name string, ns ...string) map[string]any {
	return map[string]any{"domain": name, "status": "ACTIVE", "nameServers": ns}
}

// noIDs is records without their IDs, which the fixture assigns.
func noIDs(rs []dnsprovider.Record) []dnsprovider.Record {
	out := make([]dnsprovider.Record, 0, len(rs))
	for _, r := range rs {
		if r.ID == "" {
			panic("a Record without its recordId")
		}

		r.ID = ""
		out = append(out, r)
	}

	return out
}

var example = dnsprovider.Zone{Name: "example.com", ID: "example.com"}

func TestZonesAreTheAccountsActiveDomainsOnEveryPage(t *testing.T) {
	api := &gdAPI{pageSize: 2, domains: []map[string]any{
		domain("a.example"), domain("b.example"), domain("c.example"),
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	if set.Partial {
		t.Error("Zones is a Partial View, want a Full View")
	}

	var names []string
	for _, z := range set.Zones {
		names = append(names, z.Name+"="+z.ID)
	}

	if want := []string{"a.example=a.example", "b.example=b.example", "c.example=c.example"}; !reflect.DeepEqual(names, want) {
		t.Errorf("Zones = %v, want %v", names, want)
	}

	if reqs := api.Requests(); len(reqs) != 2 || reqs[1].Query().Get("pageToken") != "t2" {
		t.Errorf("requests = %v, want two pages, the second by its pageToken", reqs)
	}
}

func TestZonesFilteredByNameKeepOnlyMatchesFromEveryPage(t *testing.T) {
	api := &gdAPI{pageSize: 2, domains: []map[string]any{
		domain("a.example"), domain("b.other"), domain("Shop.EXAMPLE"), domain("d.other"),
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "Example"})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	var names []string
	for _, z := range set.Zones {
		names = append(names, z.Name)
	}

	if want := []string{"a.example", "Shop.EXAMPLE"}; !reflect.DeepEqual(names, want) {
		t.Errorf("Zones = %v, want %v", names, want)
	}
}

func TestZonesAreActiveOnlyWhileDelegationNamesGoDaddy(t *testing.T) {
	api := &gdAPI{domains: []map[string]any{
		domain("hosted.example", "ns43.domaincontrol.com", "ns44.domaincontrol.com"),
		domain("mixed.example", "ns43.domaincontrol.com", "ns1.example.net"),
		domain("elsewhere.example", "cruz.ns.cloudflare.com", "dee.ns.cloudflare.com"),
		domain("unknown.example"),
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	got := map[string]dnsprovider.HostingState{}
	nameservers := map[string][]string{}

	for _, z := range set.Zones {
		got[z.Name] = z.State
		nameservers[z.Name] = z.Nameservers
	}

	want := map[string]dnsprovider.HostingState{
		"hosted.example": dnsprovider.HostingActive,
		// GoDaddy's nameservers still answer for part of the Delegation.
		"mixed.example": dnsprovider.HostingActive,
		// Delegation left GoDaddy, which no longer serves the domain.
		"elsewhere.example": dnsprovider.HostingMoved,
		// GoDaddy did not say where the domain is delegated.
		"unknown.example": dnsprovider.HostingUnknown,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Hosting States = %v, want %v", got, want)
	}

	wantNS := map[string][]string{
		"hosted.example":    {"ns43.domaincontrol.com", "ns44.domaincontrol.com"},
		"mixed.example":     nil,
		"elsewhere.example": nil,
		"unknown.example":   nil,
	}
	if !reflect.DeepEqual(nameservers, wantNS) {
		t.Errorf("Zone nameservers = %v, want %v", nameservers, wantNS)
	}
}

func TestZoneReadsOneActiveDomainByName(t *testing.T) {
	api := &gdAPI{domains: []map[string]any{
		domain("shop.example.com"),
		domain("example.com", "ns43.domaincontrol.com", "ns44.domaincontrol.com"),
	}}

	got, err := newProvider(t, api).GetZone(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatalf("Zone: %v", err)
	}

	want := dnsprovider.Zone{ID: "example.com", Name: "example.com", State: dnsprovider.HostingActive, Nameservers: []string{"ns43.domaincontrol.com", "ns44.domaincontrol.com"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Zone = %+v, want %+v", got, want)
	}

	if reqs := api.Requests(); len(reqs) != 1 || reqs[0].Path != "/v3/domains/domain-names/example.com" {
		t.Errorf("requests = %v, want one GET /v3/domains/domain-names/example.com", reqs)
	}
}

func TestZoneOfADomainTheAccountDoesNotServeIsNotFound(t *testing.T) {
	canceled := domain("gone.example")
	canceled["status"] = "CANCELLED" //nolint:misspell // Preserve the API's status spelling.
	api := &gdAPI{domains: []map[string]any{domain("example.com"), canceled}}
	p := newProvider(t, api)

	for _, name := range []string{"example.org", "gone.example", ""} {
		if _, err := p.GetZone(context.Background(), name); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Errorf("Zone(%s): err = %v, want ErrNotFound", name, err)
		}
	}
}

func TestZoneOfADomainOfAnotherAccountIsNotFound(t *testing.T) {
	for _, a := range []*apiErr{
		{http.StatusForbidden, "ACCESS_DENIED", "Authenticated user is not allowed access"},
		{http.StatusUnprocessableEntity, "INVALID_DOMAIN", "domain is not valid"},
		{http.StatusNotFound, "NOT_FOUND", "Domain not found"},
	} {
		api := &gdAPI{missing: a, domains: []map[string]any{domain("example.com")}}

		if _, err := newProvider(t, api).GetZone(context.Background(), "example.org"); !errors.Is(err, dnsprovider.ErrNotFound) || errors.Is(err, dnsprovider.ErrUnauthorized) {
			t.Errorf("Zone on %d %s: err = %v, want ErrNotFound alone", a.status, a.name, err)
		}
	}
}

func TestZoneWithATokenGoDaddyRefusesIsUnauthorized(t *testing.T) {
	for _, a := range []*apiErr{
		{http.StatusUnauthorized, "UNABLE_TO_AUTHENTICATE", "Unable to authenticate"},
		{http.StatusForbidden, "ACCESS_DENIED", "Authenticated user is not allowed access"},
	} {
		api := &gdAPI{deny: a, domains: []map[string]any{domain("example.com")}}

		if _, err := newProvider(t, api).GetZone(context.Background(), "example.com"); !errors.Is(err, dnsprovider.ErrUnauthorized) {
			t.Errorf("Zone on %d %s: err = %v, want ErrUnauthorized", a.status, a.name, err)
		}
	}
}

func TestRecordsListsEveryPageWithAbsoluteNamesAndThePriorityFirst(t *testing.T) {
	api := &gdAPI{pageSize: 2, records: map[string][]map[string]any{"example.com": {
		{"recordId": "r1", "type": "A", "name": "@", "data": "192.0.2.1", "ttl": 600},
		{"recordId": "r2", "type": "CNAME", "name": "www", "data": "@", "ttl": 3600},
		{"recordId": "r3", "type": "MX", "name": "@", "data": "mail.example.com", "priority": 10, "ttl": 3600},
		{"recordId": "r4", "type": "TXT", "name": "@", "data": "v=spf1 -all", "ttl": 3600},
		{"recordId": "r5", "type": "SRV", "name": "@", "service": "_sip", "protocol": "_tcp", "data": "sip.example.com", "priority": 10, "weight": 5, "port": 5060, "ttl": 3600},
		{"recordId": "r6", "type": "CAA", "name": "@", "flag": 0, "tag": "issue", "data": "letsencrypt.org", "ttl": 3600},
	}}}

	set, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	if set.Partial || set.Serial != 0 {
		t.Errorf("Records is Partial %v with serial %d, want a Full View and no serial", set.Partial, set.Serial)
	}

	want := []dnsprovider.Record{
		{ID: "r1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 600},
		{ID: "r2", Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 3600},
		{ID: "r3", Type: "MX", Name: "example.com", Value: "10 mail.example.com", TTL: 3600},
		{ID: "r4", Type: "TXT", Name: "example.com", Value: "v=spf1 -all", TTL: 3600},
		{ID: "r5", Type: "SRV", Name: "_sip._tcp.example.com", Value: "10 5 5060 sip.example.com", TTL: 3600},
		{ID: "r6", Type: "CAA", Name: "example.com", Value: `0 issue "letsencrypt.org"`, TTL: 3600},
	}
	if !reflect.DeepEqual(set.Records, want) {
		t.Errorf("Records =\n%v\nwant\n%v", set.Records, want)
	}
}

func TestRecordsFilteredByTypeAskGoDaddyForTheTypeAndByNameFilterHere(t *testing.T) {
	for _, c := range []struct {
		name     string
		filter   dnsprovider.RecordFilter
		wantType string
		want     []string
	}{
		{"type", dnsprovider.RecordFilter{Type: "mx"}, "MX", []string{"MX example.com"}},
		{"name", dnsprovider.RecordFilter{Contains: "WWW."}, "", []string{"A www.example.com", "AAAA www.example.com"}},
		{"type GoDaddy does not hold", dnsprovider.RecordFilter{Type: "HTTPS"}, "", []string{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			api := &gdAPI{records: map[string][]map[string]any{"example.com": {
				{"type": "A", "name": "www", "data": "192.0.2.1", "ttl": 600},
				{"type": "AAAA", "name": "www", "data": "2001:db8::1", "ttl": 600},
				{"type": "MX", "name": "@", "data": "mail.example.com", "priority": 10, "ttl": 3600},
				{"type": "A", "name": "@", "data": "192.0.2.3", "ttl": 600},
			}}}

			set, err := newProvider(t, api).ListRecords(context.Background(), example, c.filter)
			if err != nil {
				t.Fatalf("Records: %v", err)
			}

			got := []string{}
			for _, r := range set.Records {
				got = append(got, r.Type+" "+r.Name)
			}

			if !slices.Equal(got, c.want) {
				t.Errorf("Records = %v, want %v", got, c.want)
			}

			for _, u := range api.Requests() {
				if u.Query().Get("type") != c.wantType {
					t.Errorf("request %s, want type %q", u, c.wantType)
				}
			}
		})
	}
}

func TestRecordsOfADomainWithoutAZoneFileAreNotServed(t *testing.T) {
	api := &gdAPI{domains: []map[string]any{domain("example.com", "ns1.elsewhere.example")}}

	_, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if !errors.Is(err, dnsprovider.ErrNotServed) || !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Records of a held domain: err = %v, want ErrNotServed", err)
	}

	api.domains = nil

	_, err = newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if !errors.Is(err, dnsprovider.ErrNotFound) || errors.Is(err, dnsprovider.ErrNotServed) {
		t.Errorf("Records of a domain gone: err = %v, want ErrNotFound alone", err)
	}
}

func TestRecordsTurnAnAtTargetIntoTheZoneName(t *testing.T) {
	api := &gdAPI{records: map[string][]map[string]any{"example.com": {
		{"type": "MX", "name": "@", "data": "@", "priority": 10, "ttl": 3600},
		{"type": "SRV", "name": "@", "service": "_sip", "protocol": "_tcp", "data": "@", "priority": 1, "weight": 2, "port": 5060, "ttl": 3600},
	}}}

	set, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	want := []dnsprovider.Record{
		{Type: "MX", Name: "example.com", Value: "10 example.com", TTL: 3600},
		{Type: "SRV", Name: "_sip._tcp.example.com", Value: "1 2 5060 example.com", TTL: 3600},
	}
	if got := noIDs(set.Records); !reflect.DeepEqual(got, want) {
		t.Errorf("Records = %v, want %v", got, want)
	}
}

func TestListsStopAtTheLastPage(t *testing.T) {
	var recs []map[string]any
	for i := range 4 {
		recs = append(recs, map[string]any{"type": "A", "name": fmt.Sprint("h", i), "data": "192.0.2.1", "ttl": 600})
	}

	api := &gdAPI{pageSize: 2, records: map[string][]map[string]any{"example.com": recs}}

	set, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if err != nil || len(set.Records) != 4 {
		t.Fatalf("Records = %v, %v; want 4 Records", set.Records, err)
	}

	if n := len(api.Requests()); n != 2 {
		t.Errorf("sent %d requests, want 2: the second page links no next one", n)
	}
}

func TestListsThatIgnorePagingFailInsteadOfLoopingForever(t *testing.T) {
	api := &gdAPI{
		pageSize:     2,
		ignorePaging: true,
		domains:      []map[string]any{domain("a.example"), domain("b.example"), domain("c.example")},
		records: map[string][]map[string]any{"example.com": {
			{"type": "A", "name": "a", "data": "192.0.2.1", "ttl": 600},
			{"type": "A", "name": "b", "data": "192.0.2.1", "ttl": 600},
			{"type": "A", "name": "c", "data": "192.0.2.1", "ttl": 600},
		}},
	}

	p := newProvider(t, api)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := p.ListZones(ctx, dnsprovider.ZoneFilter{}); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Zones = %v, want an error about paging", err)
	}

	if _, err := p.ListRecords(ctx, example, dnsprovider.RecordFilter{}); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Records = %v, want an error about paging", err)
	}
}

func TestGoDaddyTakesTTLsFrom600SecondsWithoutAutomatic(t *testing.T) {
	p := newProvider(t, &gdAPI{})

	if got, want := dnsprovider.TTLRangeOf(p), (dnsprovider.TTLRange{Min: 600, Max: 86400}); got != want {
		t.Errorf("TTL range = %+v, want %+v", got, want)
	}

	if dnsprovider.AutoTTLOf(p) || dnsprovider.ProxiableTypesOf(p) != nil {
		t.Error("GoDaddy has no automatic TTL and no proxy")
	}
}

func TestErrorResponsesAreTypedErrors(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		header string
		body   string
		kind   error // nil: classified by nothing
		retry  time.Duration
		msg    string // a message the error must hold
	}{
		{"bad token", 401, "", `{"name":"UNAUTHORIZED","correlationId":"c","message":"Unable to authenticate"}`, dnsprovider.ErrUnauthorized, 0, "Unable to authenticate"},
		{"not eligible", 403, "", `{"name":"ACCESS_DENIED","correlationId":"c","message":"Account is not eligible"}`, dnsprovider.ErrUnauthorized, 0, "ACCESS_DENIED"},
		{"unknown domain", 404, "", `{"name":"NOT_FOUND","correlationId":"c","message":"Not found"}`, dnsprovider.ErrNotFound, 0, "NOT_FOUND"},
		{"managed record", 409, "", `{"name":"dns_record_not_mutable","correlationId":"c","message":"SOA records are read-only"}`, dnsprovider.ErrConflict, 0, "dns_record_not_mutable"},
		{"rate limited", 429, "42", `{"name":"TOO_MANY_REQUESTS","correlationId":"c","message":"Too many requests"}`, dnsprovider.ErrRateLimited, 42 * time.Second, "Too many requests"},
		{"invalid record", 422, "", `{"name":"INVALID_BODY","correlationId":"c","message":"Invalid","details":[{"field":"/data","issue":"INVALID_VALUE","description":"data must be an IPv4 address"}]}`, nil, 0, "/data: INVALID_VALUE: data must be an IPv4 address"},
		{"edge page", 502, "", `<html>Bad Gateway</html>`, nil, 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if c.header != "" {
					w.Header().Set("Retry-After", c.header)
				}

				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			t.Cleanup(srv.Close)

			p, err := godaddy.New(testConfig, dnsprovider.WithBaseURL(srv.URL))
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, err = p.ListZones(context.Background(), dnsprovider.ZoneFilter{})

			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != c.status {
				t.Fatalf("err = %v, want an APIError with HTTP %d", err, c.status)
			}

			for _, kind := range []error{dnsprovider.ErrUnauthorized, dnsprovider.ErrNotFound, dnsprovider.ErrRateLimited, dnsprovider.ErrConflict} {
				if errors.Is(err, kind) != (kind == c.kind) {
					t.Errorf("errors.Is(%v, %v) = %v", err, kind, kind != c.kind)
				}
			}

			if apiErr.RetryAfter != c.retry {
				t.Errorf("RetryAfter = %v, want %v", apiErr.RetryAfter, c.retry)
			}

			if !strings.Contains(err.Error(), c.msg) {
				t.Errorf("err = %q, want it to hold %q", err, c.msg)
			}
		})
	}
}
