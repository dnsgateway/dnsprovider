package cloudflare_test

// Seam 2: the Cloudflare Provider against an httptest server that speaks
// the Cloudflare v4 API's JSON shapes.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

const testToken = "test-token"

// Cloudflare account IDs, as Tenant IDs: 32 lower-case hex digits.
const (
	acc1     = "0123456789abcdef0123456789abcdef"
	acc2     = "fedcba9876543210fedcba9876543210"
	accOther = "00000000000000000000000000000000"
)

// cfAPI is a scripted Cloudflare v4 API. Lists are paginated pageSize
// items at a time, as Cloudflare does, whatever per_page the client asks for.
type cfAPI struct {
	pageSize int
	zones    []map[string]any
	records  map[string][]map[string]any // by zone ID
	dnssec   map[string]string           // DNSSEC status by zone ID
	hsts     map[string]bool             // HSTS enabled by zone ID
	// sts is the strict_transport_security value written, by zone ID,
	// over hsts.
	sts map[string]map[string]any
	// minTLS is the min_tls_version value by zone ID, as scripted or
	// written; empty when neither, which no TLS version is.
	minTLS map[string]string
	// forbidden are the paths answered 403, as for a token that lacks
	// the permission.
	forbidden []string
	// fail, when set, answers every request instead of the scripted data.
	fail http.HandlerFunc
	// intercept, when set, sees each request first and answers it when it
	// returns true; the scripted data answers the others.
	intercept func(w http.ResponseWriter, r *http.Request) bool
	// writeStatus is the HTTP status of a successful record write; zero
	// means 200.
	writeStatus int
	// reject, when it returns a message, fails the record write with that
	// message, as Cloudflare does for a record it will not take.
	reject func(method string, body map[string]any) string
	nextID int
	// ignoreName, when set, lists Zones without the name filter, as an
	// API that does not honor it would.
	ignoreName bool
	// ignoreRecordFilter, when set, lists Records without the type and
	// name filters, as an API that does not honor them would.
	ignoreRecordFilter bool

	mu sync.Mutex
	// queries records each zone list's query.
	queries []url.Values
	// recordQueries records each record list's query.
	recordQueries []url.Values
	// requests records each request's path and page.
	requests []string
	// writes records each record write.
	writes []write
}

// write is one record or zone setting write the API received.
type write struct {
	Method, Path string
	Body         map[string]any
}

// Writes returns the record and zone setting writes received, in order.
func (api *cfAPI) Writes() []write {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.writes)
}

func (api *cfAPI) record(request string) {
	api.mu.Lock()
	defer api.mu.Unlock()

	api.requests = append(api.requests, request)
}

// ZoneQueries returns each zone list's query, in order.
func (api *cfAPI) ZoneQueries() []url.Values {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.queries)
}

// RecordQueries returns each record list's query, in order.
func (api *cfAPI) RecordQueries() []url.Values {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.recordQueries)
}

// recordsMatching are the Records the type and name.contains filters
// match, as Cloudflare reads them: the type exactly, the name ignoring case.
func (api *cfAPI) recordsMatching(records []map[string]any, q url.Values) []map[string]any {
	if api.ignoreRecordFilter {
		return records
	}

	var out []map[string]any

	for _, r := range records {
		typ, _ := r["type"].(string)
		name, _ := r["name"].(string)

		if q.Has("type") && typ != q.Get("type") ||
			!strings.Contains(strings.ToLower(name), strings.ToLower(q.Get("name.contains"))) {
			continue
		}

		out = append(out, r)
	}

	return out
}

// zonesNamed are the scripted Zones a name filter matches, as Cloudflare
// reads it: "contains:" text, ignoring case, or else the exact name.
func (api *cfAPI) zonesNamed(filter string) []map[string]any {
	if filter == "" || api.ignoreName {
		return api.zones
	}

	var out []map[string]any

	for _, z := range api.zones {
		name, _ := z["name"].(string)

		text, contains := strings.CutPrefix(filter, "contains:")
		if contains && strings.Contains(strings.ToLower(name), strings.ToLower(text)) || !contains && name == filter {
			out = append(out, z)
		}
	}

	return out
}

// Requests returns each request's path and page, in order.
func (api *cfAPI) Requests() []string {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.requests)
}

func newProvider(t *testing.T, api *cfAPI) dnsprovider.Provider {
	t.Helper()

	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)

	p, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: acc1}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return p
}

func (api *cfAPI) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /client/v4/zones", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		api.queries = append(api.queries, r.URL.Query())
		api.mu.Unlock()

		api.page(w, r, api.zonesNamed(r.URL.Query().Get("name")))
	})
	mux.HandleFunc("GET /client/v4/zones/{zone}", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()

		i := slices.IndexFunc(api.zones, func(z map[string]any) bool { return z["id"] == r.PathValue("zone") })
		if i < 0 {
			writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/"+r.PathValue("zone")+", perhaps your object identifier is invalid?")

			return
		}

		writeResult(w, api.zones[i])
	})
	mux.HandleFunc("GET /client/v4/zones/{zone}/dns_records", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		api.recordQueries = append(api.recordQueries, r.URL.Query())
		api.mu.Unlock()

		records, ok := api.records[r.PathValue("zone")]
		if !ok {
			writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/x/dns_records, perhaps your object identifier is invalid?")

			return
		}

		// Cloudflare answers 400 for a type it does not take.
		if typ := r.URL.Query().Get("type"); typ != "" && !slices.Contains(cfRecordTypes, typ) {
			writeErrors(w, http.StatusBadRequest, 9000, "DNS record type is invalid")

			return
		}

		api.page(w, r, api.recordsMatching(records, r.URL.Query()))
	})
	mux.HandleFunc("POST /client/v4/zones/{zone}/dns_records", api.writeRecord)
	mux.HandleFunc("GET /client/v4/zones/{zone}/dns_records/{id}", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()

		i := slices.IndexFunc(api.records[r.PathValue("zone")], func(rec map[string]any) bool { return rec["id"] == r.PathValue("id") })
		if i < 0 {
			writeErrors(w, http.StatusNotFound, 81044, "Record does not exist.")

			return
		}

		writeResult(w, api.records[r.PathValue("zone")][i])
	})
	mux.HandleFunc("PUT /client/v4/zones/{zone}/dns_records/{id}", api.writeRecord)
	mux.HandleFunc("PATCH /client/v4/zones/{zone}/dns_records/{id}", api.writeRecord)
	mux.HandleFunc("DELETE /client/v4/zones/{zone}/dns_records/{id}", api.writeRecord)
	mux.HandleFunc("GET /client/v4/zones/{zone}/dnssec", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()

		writeResult(w, dnssecResult(api.dnssec[r.PathValue("zone")]))
	})
	mux.HandleFunc("PATCH /client/v4/zones/{zone}/dnssec", func(w http.ResponseWriter, r *http.Request) {
		body, ok := api.writeSetting(w, r)
		if !ok {
			return
		}

		api.mu.Lock()
		defer api.mu.Unlock()

		// Cloudflare signs and unsigns a zone over time: it answers with
		// the change pending.
		status := "pending"
		if body["status"] == "disabled" {
			status = "pending-disabled"
		}

		if api.dnssec == nil {
			api.dnssec = map[string]string{}
		}

		api.dnssec[r.PathValue("zone")] = status
		writeResult(w, dnssecResult(status))
	})
	mux.HandleFunc("GET /client/v4/zones/{zone}/settings/min_tls_version", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()

		writeResult(w, minTLSResult(api.minTLS[r.PathValue("zone")]))
	})
	mux.HandleFunc("PATCH /client/v4/zones/{zone}/settings/min_tls_version", func(w http.ResponseWriter, r *http.Request) {
		body, ok := api.writeSetting(w, r)
		if !ok {
			return
		}

		api.mu.Lock()
		defer api.mu.Unlock()

		if api.minTLS == nil {
			api.minTLS = map[string]string{}
		}

		v, _ := body["value"].(string)
		api.minTLS[r.PathValue("zone")] = v
		writeResult(w, minTLSResult(v))
	})
	mux.HandleFunc("GET /client/v4/zones/{zone}/settings/security_header", func(w http.ResponseWriter, r *http.Request) {
		api.mu.Lock()
		defer api.mu.Unlock()

		writeResult(w, securityHeader(api.hstsOf(r.PathValue("zone"))))
	})
	mux.HandleFunc("PATCH /client/v4/zones/{zone}/settings/security_header", func(w http.ResponseWriter, r *http.Request) {
		body, ok := api.writeSetting(w, r)
		if !ok {
			return
		}

		api.mu.Lock()
		defer api.mu.Unlock()

		// Cloudflare replaces the whole value: what the body leaves out is
		// gone.
		value, _ := body["value"].(map[string]any)
		sts, _ := value["strict_transport_security"].(map[string]any)

		if api.sts == nil {
			api.sts = map[string]map[string]any{}
		}

		api.sts[r.PathValue("zone")] = sts
		writeResult(w, securityHeader(sts))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.record(r.URL.Path + "?page=" + r.URL.Query().Get("page"))

		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q, want the Account's API token", got)
		}

		if slices.Contains(api.forbidden, r.URL.Path) {
			writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")

			return
		}

		if api.fail != nil {
			api.fail(w, r)

			return
		}

		if api.intercept != nil && api.intercept(w, r) {
			return
		}

		mux.ServeHTTP(w, r)
	})
}

// dnssecResult is a DNSSEC answer with the status.
func dnssecResult(status string) map[string]any {
	if status == "disabled" || status == "" {
		// Cloudflare holds no key for an unsigned zone.
		return map[string]any{
			"status":              status,
			"algorithm":           nil,
			"digest":              nil,
			"digest_algorithm":    nil,
			"digest_type":         nil,
			"ds":                  nil,
			"flags":               nil,
			"key_tag":             nil,
			"key_type":            nil,
			"public_key":          nil,
			"modified_on":         nil,
			"dnssec_multi_signer": false,
		}
	}

	return map[string]any{
		"status":              status,
		"algorithm":           "13",
		"digest":              testDigest,
		"digest_algorithm":    "SHA256",
		"digest_type":         "2",
		"ds":                  "example.com. 3600 IN DS 16953 13 2 " + testDigest,
		"flags":               257,
		"key_tag":             16953,
		"key_type":            "ECDSAP256SHA256",
		"public_key":          testPublicKey,
		"modified_on":         "2024-01-02T03:04:05.000000Z",
		"dnssec_multi_signer": false,
	}
}

// The key-signing key Cloudflare signs example.com with in the tests, and
// the SHA-256 digest of it that its DS holds, computed with miekg/dns.
const (
	testPublicKey = "oXiGYrSTO+LSCJ3mohc8EP+CzF9KxBj8/ydXJ22pKuZP3VAC3/Md/k7xZfz470CoRyZJ6gV6vml07IC3d8xqhA=="
	testDigest    = "AFF7958770DB6792BD5D485239C72C95F296762586C647BC95CA71E138E69230"
)

// hstsOf is a zone's strict_transport_security value: as last written,
// else as scripted in hsts.
func (api *cfAPI) hstsOf(zone string) map[string]any {
	if sts, ok := api.sts[zone]; ok {
		return sts
	}

	return map[string]any{
		"enabled":            api.hsts[zone],
		"max_age":            86400,
		"include_subdomains": true,
		"preload":            false,
		"nosniff":            true,
	}
}

// minTLSResult is a min_tls_version setting answer with the value.
func minTLSResult(v string) map[string]any {
	return map[string]any{
		"id":          "min_tls_version",
		"value":       v,
		"editable":    true,
		"modified_on": "2024-01-02T03:04:05.000000Z",
	}
}

// securityHeader is a security_header setting answer with the
// strict_transport_security value.
func securityHeader(sts map[string]any) map[string]any {
	return map[string]any{
		"id":          "security_header",
		"value":       map[string]any{"strict_transport_security": sts},
		"editable":    true,
		"modified_on": "2024-01-02T03:04:05.000000Z",
	}
}

// writeSetting decodes a zone setting write's body and records the write.
func (api *cfAPI) writeSetting(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErrors(w, http.StatusBadRequest, 9207, "Request body is invalid.")

		return nil, false
	}

	api.mu.Lock()
	api.writes = append(api.writes, write{Method: r.Method, Path: r.URL.Path, Body: body})
	api.mu.Unlock()

	return body, true
}

// writeRecord creates, updates or deletes a record as Cloudflare does,
// and answers with the record as stored.
func (api *cfAPI) writeRecord(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Method != http.MethodDelete {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErrors(w, http.StatusBadRequest, 9207, "Request body is invalid.")

			return
		}
	}

	api.mu.Lock()
	defer api.mu.Unlock()

	api.writes = append(api.writes, write{Method: r.Method, Path: r.URL.Path, Body: body})

	if api.reject != nil {
		if msg := api.reject(r.Method, body); msg != "" {
			writeErrors(w, http.StatusBadRequest, 9005, msg)

			return
		}
	}

	zone, id := r.PathValue("zone"), r.PathValue("id")
	if api.records == nil {
		api.records = map[string][]map[string]any{}
	}

	records := api.records[zone]
	i := slices.IndexFunc(records, func(rec map[string]any) bool { return rec["id"] == id })

	if id != "" && i < 0 {
		writeErrors(w, http.StatusNotFound, 81044, "Record does not exist.")

		return
	}

	status := api.writeStatus
	if status == 0 {
		status = http.StatusOK
	}

	var stored map[string]any

	switch r.Method {
	case http.MethodDelete:
		api.records[zone] = slices.Delete(records, i, i+1)
		writeJSON(w, status, map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": map[string]any{"id": id}})

		return
	case http.MethodPost:
		api.nextID++
		stored = storedRecord("new"+strconv.Itoa(api.nextID), nil, body)
		api.records[zone] = append(records, stored)
	case http.MethodPut:
		stored = storedRecord(id, nil, body)
		records[i] = stored
	case http.MethodPatch:
		stored = storedRecord(id, records[i], body)
		records[i] = stored
	}

	writeJSON(w, status, map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": stored})
}

// storedRecord is a record as Cloudflare stores it from a write's body,
// patched onto old when old is set. Records written with structured data
// get their content from it, as Cloudflare formats it.
func storedRecord(id string, old, body map[string]any) map[string]any {
	rec := cfRecord(id, "", "", "", 1, false, false)
	maps.Copy(rec, old)
	maps.Copy(rec, body)
	rec["id"] = id

	typ, _ := rec["type"].(string)
	rec["proxiable"] = typ == "A" || typ == "AAAA" || typ == "CNAME"

	if data, ok := body["data"].(map[string]any); ok {
		switch typ {
		case "SRV":
			rec["content"] = fmt.Sprintf("%v %v %v", data["weight"], data["port"], data["target"])
		case "URI":
			rec["content"] = fmt.Sprintf("%v %q", data["weight"], data["target"])
		case "CAA":
			rec["content"] = fmt.Sprintf("%v %v %q", data["flags"], data["tag"], data["value"])
		}
	}

	return rec
}

// page writes one page of items in the v4 list envelope.
func (api *cfAPI) page(w http.ResponseWriter, r *http.Request, items []map[string]any) {
	size := api.pageSize
	if size == 0 {
		size = 20
	}

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	start := min((page-1)*size, len(items))
	end := min(start+size, len(items))
	result := items[start:end]

	if result == nil {
		result = []map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"errors":   []any{},
		"messages": []any{},
		"result":   result,
		"result_info": map[string]any{
			"page":        page,
			"per_page":    size,
			"count":       len(result),
			"total_count": len(items),
			"total_pages": (len(items) + size - 1) / size,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeResult writes a single result in the v4 envelope.
func writeResult(w http.ResponseWriter, result any) {
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"errors":   []any{},
		"messages": []any{},
		"result":   result,
	})
}

func writeErrors(w http.ResponseWriter, status, code int, message string) {
	writeJSON(w, status, map[string]any{
		"success":  false,
		"errors":   []any{map[string]any{"code": code, "message": message}},
		"messages": []any{},
		"result":   nil,
	})
}

func cfZone(id, name string, ns ...string) map[string]any {
	if ns == nil {
		ns = []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	}

	return map[string]any{
		"id":           id,
		"name":         name,
		"status":       "active",
		"paused":       false,
		"type":         "full",
		"name_servers": ns,
		"account":      map[string]any{"id": acc1, "name": "Work"},
		"created_on":   "2024-01-02T03:04:05.000000Z",
		"modified_on":  "2024-01-02T03:04:05.000000Z",
	}
}

func TestZonesListsEveryPage(t *testing.T) {
	api := &cfAPI{pageSize: 2, zones: []map[string]any{
		cfZone("z1", "example.com"),
		cfZone("z2", "example.net"),
		cfZone("z3", "example.org"),
	}}
	p := newProvider(t, api)

	set, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	want := []dnsprovider.Zone{
		{Name: "example.com", ID: "z1", State: dnsprovider.HostingActive, Nameservers: []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}},
		{Name: "example.net", ID: "z2", State: dnsprovider.HostingActive, Nameservers: []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}},
		{Name: "example.org", ID: "z3", State: dnsprovider.HostingActive, Nameservers: []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}},
	}
	if !reflect.DeepEqual(zones, want) {
		t.Fatalf("Zones = %+v, want %+v", zones, want)
	}

	if got := strings.Join(api.Requests(), " "); got != "/client/v4/zones?page=1 /client/v4/zones?page=2" {
		t.Errorf("requests = %s, want one per page", got)
	}
}

func TestZonesPushTheNameFilterToCloudflare(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{
		cfZone("z1", "example.com"),
		cfZone("z2", "shop.example.net"),
		cfZone("z3", "other.org"),
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "EXAMPLE"})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	if got, want := zoneNames(zones), []string{"example.com", "shop.example.net"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}

	q := api.ZoneQueries()
	if len(q) != 1 || q[0].Get("name") != "contains:example" || q[0].Get("account.id") != acc1 {
		t.Errorf("zone list queries = %v, want name=contains:example within the Tenant", q)
	}
}

func TestZonesKeepOnlyMatchesWhenCloudflareIgnoresTheFilter(t *testing.T) {
	api := &cfAPI{ignoreName: true, zones: []map[string]any{
		cfZone("z1", "example.com"),
		cfZone("z2", "other.org"),
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "ample"})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	if got, want := zoneNames(zones), []string{"example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}
}

func zoneNames(zones []dnsprovider.Zone) []string {
	out := []string{}
	for _, z := range zones {
		out = append(out, z.Name)
	}

	return out
}

func TestZonesCarryTheirHostingState(t *testing.T) {
	zone := func(id, name, status string) map[string]any {
		z := cfZone(id, name)
		z["status"] = status

		return z
	}
	api := &cfAPI{zones: []map[string]any{
		zone("z1", "active.example", "active"),
		zone("z2", "pending.example", "pending"),
		zone("z3", "initializing.example", "initializing"),
		zone("z4", "moved.example", "moved"),
		zone("z5", "deactivated.example", "deactivated"),
		zone("z6", "odd.example", "read only"),
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	got := map[string]dnsprovider.HostingState{}
	for _, z := range zones {
		got[z.Name] = z.State
	}

	want := map[string]dnsprovider.HostingState{
		"active.example":       dnsprovider.HostingActive,
		"pending.example":      dnsprovider.HostingPending,
		"initializing.example": dnsprovider.HostingPending,
		"moved.example":        dnsprovider.HostingMoved,
		// Cloudflare no longer serves a deactivated Zone.
		"deactivated.example": dnsprovider.HostingMoved,
		"odd.example":         dnsprovider.HostingUnknown,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Hosting States = %v, want %v", got, want)
	}
}

func TestZoneReadsOneZoneOfTheTenantByItsExactName(t *testing.T) {
	pending := cfZone("z2", "example.com", "cruz.ns.cloudflare.com", "dee.ns.cloudflare.com")
	pending["status"] = "pending"
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "shop.example.com"), pending}}

	got, err := newProvider(t, api).GetZone(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatalf("Zone: %v", err)
	}

	want := dnsprovider.Zone{ID: "z2", Name: "example.com", State: dnsprovider.HostingPending, Nameservers: []string{"cruz.ns.cloudflare.com", "dee.ns.cloudflare.com"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Zone = %+v, want %+v", got, want)
	}

	q := api.ZoneQueries()
	if len(q) != 1 || q[0].Get("name") != "example.com" || q[0].Get("account.id") != acc1 {
		t.Errorf("zone list queries = %v, want name=example.com within the Tenant", q)
	}
}

func TestZoneOfANameTheTenantDoesNotHostIsNotFound(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "shop.example.com")}}

	if _, err := newProvider(t, api).GetZone(context.Background(), "example.com"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Zone: err = %v, want ErrNotFound", err)
	}

	// Cloudflare takes a name it does not know for a filter it ignores.
	api = &cfAPI{ignoreName: true, zones: []map[string]any{cfZone("z1", "shop.example.com")}}
	if _, err := newProvider(t, api).GetZone(context.Background(), "example.com"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Zone with the name ignored: err = %v, want ErrNotFound", err)
	}
}

func TestZonesCarryTheNameserversCloudflareAssignedToEachZone(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{
		cfZone("z1", "example.com", "bob.ns.cloudflare.com", "ada.ns.cloudflare.com"),
		cfZone("z2", "example.net", "cruz.ns.cloudflare.com", "dee.ns.cloudflare.com"),
	}}
	p := newProvider(t, api)

	set, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	got := map[string][]string{}
	for _, z := range zones {
		got[z.Name] = z.Nameservers
	}

	want := map[string][]string{
		"example.com": {"bob.ns.cloudflare.com", "ada.ns.cloudflare.com"},
		"example.net": {"cruz.ns.cloudflare.com", "dee.ns.cloudflare.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Zone nameservers = %v, want %v", got, want)
	}
}

func TestApplyCreatesARecordWithTheProxyFlag(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {}}}
	p := newProvider(t, api)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{
		Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "true"},
	}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{add}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	assertWrites(t, api, []write{{Method: "POST", Path: "/client/v4/zones/z1/dns_records", Body: map[string]any{
		"type": "A", "name": "www.example.com", "content": "192.0.2.1", "ttl": 300.0, "proxied": true,
	}}})

	assertResults(t, res, []dnsprovider.ChangeResult{{Change: add, Record: dnsprovider.Record{
		ID: "new1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "true"},
	}}})
}

func TestApplyUpdatesARecordInPlaceAndTurnsTheProxyOff(t *testing.T) {
	stored := cfRecord("r1", "CNAME", "www.example.com", "example.com", 1, true, true)
	stored["comment"] = "kept by Cloudflare"
	api := &cfAPI{records: map[string][]map[string]any{"z1": {stored}}}
	p := newProvider(t, api)

	// The Records carry the comment as read; it is not written.
	before := dnsprovider.Record{
		ID: "r1", Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 1,
		Extras: map[string]string{cloudflare.ExtraProxied: "true", cloudflare.ExtraComment: "kept by Cloudflare"},
	}
	after := dnsprovider.Record{
		ID: "r1", Type: "CNAME", Name: "www.example.com", Value: "example.net", TTL: 300,
		Extras: map[string]string{cloudflare.ExtraProxied: "false", cloudflare.ExtraComment: "kept by Cloudflare"},
	}
	modify := dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: before, After: after}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{modify}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	assertWrites(t, api, []write{{Method: "PATCH", Path: "/client/v4/zones/z1/dns_records/r1", Body: map[string]any{
		"type": "CNAME", "name": "www.example.com", "content": "example.net", "ttl": 300.0, "proxied": false,
	}}})

	assertResults(t, res, []dnsprovider.ChangeResult{{Change: modify, Record: after}})

	if got := api.records["z1"][0]["comment"]; got != "kept by Cloudflare" {
		t.Errorf("comment = %v, want the fields the module does not model kept", got)
	}
}

func TestApplyTurnsTheProxyOffWhenARecordChangesToATypeThatCannotHaveIt(t *testing.T) {
	// A proxied CNAME that becomes a TXT Record is written whole, and
	// not proxied, which Cloudflare refuses for a TXT Record.
	api := &cfAPI{
		records: map[string][]map[string]any{"z1": {cfRecord("r1", "CNAME", "www.example.com", "example.com", 1, true, true)}},
		reject: func(_ string, body map[string]any) string {
			if body["type"] == "TXT" && body["proxied"] == true {
				return "TXT records cannot be proxied."
			}

			return ""
		},
	}
	p := newProvider(t, api)

	before := dnsprovider.Record{ID: "r1", Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 1, Extras: map[string]string{cloudflare.ExtraProxied: "true"}}
	after := dnsprovider.Record{ID: "r1", Type: "TXT", Name: "www.example.com", Value: "\"hi\"", TTL: 1}
	modify := dnsprovider.Change{Kind: dnsprovider.ChangeModify, Before: before, After: after}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{modify}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	assertResults(t, res, []dnsprovider.ChangeResult{{Change: modify, Record: after}})
	if got := api.records["z1"][0]["proxied"]; got != false {
		t.Errorf("proxied = %v, want the TXT Record not proxied", got)
	}
}

func TestApplyDeletesARecord(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {cfRecord("r1", "TXT", "example.com", "\"old\"", 300, false, false)}}}
	p := newProvider(t, api)

	del := dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: dnsprovider.Record{ID: "r1", Type: "TXT", Name: "example.com", Value: "\"old\"", TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{del}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	assertWrites(t, api, []write{{Method: "DELETE", Path: "/client/v4/zones/z1/dns_records/r1"}})
	assertResults(t, res, []dnsprovider.ChangeResult{{Change: del}})

	if n := len(api.records["z1"]); n != 0 {
		t.Errorf("%d records left, want the Record deleted", n)
	}
}

func TestApplySendsDeletionsFirstAndReportsInChangesetOrder(t *testing.T) {
	// A CNAME replaces an A Record of the same name: deleted first, the A
	// Record does not collide with it.
	api := &cfAPI{records: map[string][]map[string]any{"z1": {
		cfRecord("r1", "A", "www.example.com", "192.0.2.1", 300, true, false),
		cfRecord("r2", "TXT", "example.com", "\"v=1\"", 300, false, false),
	}}}
	p := newProvider(t, api)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 300}}
	modify := dnsprovider.Change{
		Kind:   dnsprovider.ChangeModify,
		Before: dnsprovider.Record{ID: "r2", Type: "TXT", Name: "example.com", Value: "\"v=1\"", TTL: 300},
		After:  dnsprovider.Record{ID: "r2", Type: "TXT", Name: "example.com", Value: "\"v=2\"", TTL: 300},
	}
	del := dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: dnsprovider.Record{ID: "r1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{add, modify, del}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var methods []string
	for _, w := range api.Writes() {
		methods = append(methods, w.Method)
	}

	if want := []string{"DELETE", "PATCH", "POST"}; !slices.Equal(methods, want) {
		t.Errorf("writes = %v, want %v", methods, want)
	}

	assertResults(t, res, []dnsprovider.ChangeResult{
		{Change: add, Record: dnsprovider.Record{ID: "new1", Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "false"}}},
		{Change: modify, Record: modify.After},
		{Change: del},
	})
}

func TestApplyKeepsGoingAfterAChangeFails(t *testing.T) {
	api := &cfAPI{
		records: map[string][]map[string]any{"z1": {}},
		reject: func(_ string, body map[string]any) string {
			if body["name"] == "bad.example.com" {
				return "Content for A record is invalid."
			}

			return ""
		},
	}
	p := newProvider(t, api)

	good1 := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "one.example.com", Value: "\"1\"", TTL: 300}}
	bad := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "A", Name: "bad.example.com", Value: "192.0.2.1", TTL: 300}}
	good2 := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "two.example.com", Value: "\"2\"", TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{good1, bad, good2}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	assertResults(t, res, []dnsprovider.ChangeResult{
		{Change: good1, Record: dnsprovider.Record{ID: "new1", Type: "TXT", Name: "one.example.com", Value: "\"1\"", TTL: 300}},
		{Change: bad, Err: errors.New("Content for A record is invalid.")},
		{Change: good2, Record: dnsprovider.Record{ID: "new2", Type: "TXT", Name: "two.example.com", Value: "\"2\"", TTL: 300}},
	})

	var apiErr *dnsprovider.APIError
	if !errors.As(res.Results[1].Err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("err = %v, want a *dnsprovider.APIError with HTTP 400", res.Results[1].Err)
	}
}

func TestApplyTakesAnySuccessful2xxResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			api := &cfAPI{records: map[string][]map[string]any{"z1": {}}, writeStatus: status}
			p := newProvider(t, api)

			add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "example.com", Value: "\"hi\"", TTL: 300}}

			res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{add}})
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}

			assertResults(t, res, []dnsprovider.ChangeResult{{Change: add, Record: dnsprovider.Record{
				ID: "new1", Type: "TXT", Name: "example.com", Value: "\"hi\"", TTL: 300,
			}}})
		})
	}
}

func TestApplyFailsAChangeCloudflareDoesNotMarkAsSuccess(t *testing.T) {
	api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"success":  false,
			"errors":   []any{map[string]any{"code": 81057, "message": "Record already exists."}},
			"messages": []any{},
			"result":   nil,
		})
	}}
	p := newProvider(t, api)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "example.com", Value: "\"hi\"", TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{add}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	assertResults(t, res, []dnsprovider.ChangeResult{{Change: add, Err: errors.New("Record already exists. (code 81057)")}})

	var apiErr *dnsprovider.APIError
	if !errors.As(res.Results[0].Err, &apiErr) || apiErr.StatusCode != http.StatusOK {
		t.Errorf("err = %v, want a *dnsprovider.APIError with HTTP 200", res.Results[0].Err)
	}
}

func TestApplyTakesA2xxResponseWithoutASuccessField(t *testing.T) {
	api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"result": cfRecord("r1", "TXT", "example.com", `"hi"`, 300, false, false),
		})
	}}
	p := newProvider(t, api)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{add}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	assertResults(t, res, []dnsprovider.ChangeResult{{Change: add, Record: dnsprovider.Record{
		ID: "r1", Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300,
	}}})
}

// serverError answers a request with a 5xx that asks for an immediate
// retry, as a flaky edge might.
func serverError(w http.ResponseWriter) {
	w.Header().Set("Retry-After-Ms", "0")
	writeErrors(w, http.StatusBadGateway, 10000+502, "Bad gateway")
}

func TestApplyDoesNotRetryACreate(t *testing.T) {
	var posts int

	api := &cfAPI{records: map[string][]map[string]any{"z1": {}}}
	api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			return false
		}

		api.mu.Lock()
		posts++
		first := posts == 1
		api.mu.Unlock()

		if first {
			serverError(w)

			return true
		}

		return false
	}
	p := newProvider(t, api)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{add}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()

	if posts != 1 {
		t.Errorf("got %d POSTs, want exactly 1: a create is not retried", posts)
	}

	assertResults(t, res, []dnsprovider.ChangeResult{{Change: add, Err: errors.New("HTTP 502")}})
}

func TestApplyTakesADeleteWhoseRetryFindsTheRecordGone(t *testing.T) {
	var deletes int

	api := &cfAPI{records: map[string][]map[string]any{"z1": {
		cfRecord("r1", "TXT", "example.com", `"hi"`, 300, false, false),
	}}}
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

			return true
		}

		return false
	}
	p := newProvider(t, api)

	del := dnsprovider.Change{Kind: dnsprovider.ChangeDelete, Before: dnsprovider.Record{ID: "r1", Type: "TXT", Name: "example.com", Value: `"hi"`, TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{del}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()

	if deletes != 2 {
		t.Errorf("got %d DELETEs, want 2: a delete is retried", deletes)
	}

	assertResults(t, res, []dnsprovider.ChangeResult{{Change: del}})
}

func TestApplyRejectsCAAFlagsAbove255(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {}}}
	p := newProvider(t, api)

	add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: dnsprovider.Record{Type: "CAA", Name: "example.com", Value: `256 issue "letsencrypt.org"`, TTL: 300}}

	res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: dnsprovider.Zone{Name: "example.com", ID: "z1"}, Changes: []dnsprovider.Change{add}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	assertResults(t, res, []dnsprovider.ChangeResult{{Change: add, Err: errors.New("presentation form")}})
	assertWrites(t, api, nil)
}

func TestApplySplitsThePriorityAndDataOutOfTheValue(t *testing.T) {
	cases := []struct {
		typ, name, value string
		body             map[string]any
	}{
		{"MX", "example.com", "10 mail.example.com", map[string]any{
			"priority": 10.0, "content": "mail.example.com",
		}},
		{"SRV", "_sip._tcp.example.com", "20 5 5060 sip.example.com", map[string]any{
			"priority": 20.0, "data": map[string]any{"priority": 20.0, "weight": 5.0, "port": 5060.0, "target": "sip.example.com"},
		}},
		{"URI", "_ftp._tcp.example.com", `10 1 "ftp://ftp.example.com/public"`, map[string]any{
			"priority": 10.0, "data": map[string]any{"weight": 1.0, "target": "ftp://ftp.example.com/public"},
		}},
		{"CAA", "example.com", `0 issue "letsencrypt.org"`, map[string]any{
			"data": map[string]any{"flags": 0.0, "tag": "issue", "value": "letsencrypt.org"},
		}},
	}

	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			api := &cfAPI{records: map[string][]map[string]any{"z1": {}}}
			p := newProvider(t, api)
			zone := dnsprovider.Zone{Name: "example.com", ID: "z1"}

			rec := dnsprovider.Record{Type: c.typ, Name: c.name, Value: c.value, TTL: 3600}
			add := dnsprovider.Change{Kind: dnsprovider.ChangeAdd, After: rec}

			res, err := dnsprovider.Apply(context.Background(), p, dnsprovider.Changeset{Zone: zone, Changes: []dnsprovider.Change{add}})
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}

			body := map[string]any{"type": c.typ, "name": c.name, "ttl": 3600.0}
			maps.Copy(body, c.body)
			assertWrites(t, api, []write{{Method: "POST", Path: "/client/v4/zones/z1/dns_records", Body: body}})

			// The stored Record, and the Records listed afterwards, have the
			// Value as it was written.
			rec.ID = "new1"
			assertResults(t, res, []dnsprovider.ChangeResult{{Change: add, Record: rec}})

			rs, err := p.Records(context.Background(), zone, dnsprovider.RecordFilter{})
			if err != nil {
				t.Fatalf("Records: %v", err)
			}

			assertRecords(t, rs.Records, []dnsprovider.Record{rec})
		})
	}
}

func assertWrites(t *testing.T, api *cfAPI, want []write) {
	t.Helper()

	if got := api.Writes(); !reflect.DeepEqual(got, want) {
		t.Errorf("writes:\n got %+v\nwant %+v", got, want)
	}
}

func assertResults(t *testing.T, res dnsprovider.ApplyResult, want []dnsprovider.ChangeResult) {
	t.Helper()

	if len(res.Results) != len(want) {
		t.Fatalf("got %d results, want %d: %+v", len(res.Results), len(want), res.Results)
	}

	for i, w := range want {
		g := res.Results[i]
		if !reflect.DeepEqual(g.Change, w.Change) {
			t.Errorf("result %d is for %+v, want %+v", i, g.Change, w.Change)
		}

		assertRecords(t, []dnsprovider.Record{g.Record}, []dnsprovider.Record{w.Record})

		if (g.Err == nil) != (w.Err == nil) || (w.Err != nil && !strings.Contains(g.Err.Error(), w.Err.Error())) {
			t.Errorf("result %d err = %v, want %v", i, g.Err, w.Err)
		}
	}
}

func TestZoneStatusReadsDNSSECAndHSTSFromTheZoneSettings(t *testing.T) {
	tests := []struct {
		dnssec string
		hsts   bool
		want   dnsprovider.ZoneStatus
	}{
		{"active", true, dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.On}},
		{"disabled", false, dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Off, HSTS: dnsprovider.Off}},
		// Being signed or unsigned: neither yet.
		{"pending", false, dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.Off}},
		{"pending-disabled", true, dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Pending, HSTS: dnsprovider.On}},
		// Cloudflare could not sign the zone: unknown, not pending.
		{"error", true, dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Unknown, HSTS: dnsprovider.On}},
	}

	for _, tt := range tests {
		t.Run(tt.dnssec, func(t *testing.T) {
			api := &cfAPI{dnssec: map[string]string{"z1": tt.dnssec}, hsts: map[string]bool{"z1": tt.hsts}}
			p := newProvider(t, api)

			got, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{Name: "example.com", ID: "z1"})
			if err != nil {
				t.Fatalf("ZoneStatus: %v", err)
			}

			if got != tt.want {
				t.Errorf("ZoneStatus = %+v, want %+v", got, tt.want)
			}

			// The settings are read concurrently, in any order.
			want := []string{
				"/client/v4/zones/z1/dnssec?page=",
				"/client/v4/zones/z1/settings/min_tls_version?page=",
				"/client/v4/zones/z1/settings/security_header?page=",
			}
			if reqs := slices.Sorted(slices.Values(api.Requests())); !slices.Equal(reqs, want) {
				t.Errorf("requests = %q, want %q", reqs, want)
			}
		})
	}
}

func TestZoneStatusSettingsTheTokenMayNotReadAreUnknown(t *testing.T) {
	tests := []struct {
		name      string
		forbidden []string
		want      dnsprovider.ZoneStatus
	}{
		{"DNSSEC", []string{"/client/v4/zones/z1/dnssec"}, dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Unknown, HSTS: dnsprovider.On}},
		{"HSTS", []string{"/client/v4/zones/z1/settings/security_header"}, dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.Unknown}},
		{"both", []string{"/client/v4/zones/z1/dnssec", "/client/v4/zones/z1/settings/security_header"}, dnsprovider.ZoneStatus{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &cfAPI{
				dnssec:    map[string]string{"z1": "active"},
				hsts:      map[string]bool{"z1": true},
				forbidden: tt.forbidden,
			}
			p := newProvider(t, api)

			got, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{Name: "example.com", ID: "z1"})
			if err != nil {
				t.Fatalf("ZoneStatus: %v", err)
			}

			if got != tt.want {
				t.Errorf("ZoneStatus = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestZoneStatusReadsDNSSECAndHSTSConcurrently(t *testing.T) {
	// The DNSSEC read is answered only once the HSTS read has arrived.
	hstsAsked := make(chan struct{})

	api := &cfAPI{dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": true}}
	h := api.handler(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/settings/security_header"):
			close(hstsAsked)
		case strings.HasSuffix(r.URL.Path, "/dnssec"):
			select {
			case <-hstsAsked:
			case <-time.After(5 * time.Second):
				writeErrors(w, http.StatusBadRequest, 1004, "HSTS was not read concurrently")

				return
			}
		}

		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	p, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: acc1}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{Name: "example.com", ID: "z1"})
	if err != nil {
		t.Fatalf("ZoneStatus: %v", err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.On}); got != want {
		t.Errorf("ZoneStatus = %+v, want %+v", got, want)
	}
}

func TestAZoneStatusSettingThatFailsToReadIsUnknownOnItsOwn(t *testing.T) {
	tests := []struct {
		name    string
		failing string
		want    dnsprovider.ZoneStatus
	}{
		{"DNSSEC", "/client/v4/zones/z1/dnssec", dnsprovider.ZoneStatus{DNSSEC: dnsprovider.Unknown, HSTS: dnsprovider.On}},
		{"HSTS", "/client/v4/zones/z1/settings/security_header", dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.Unknown}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &cfAPI{dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": true}}
			h := api.handler(t)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tt.failing {
					writeErrors(w, http.StatusBadRequest, 1004, "DNS Validation Error")

					return
				}

				h.ServeHTTP(w, r)
			}))
			t.Cleanup(srv.Close)

			p, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: acc1}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			got, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{Name: "example.com", ID: "z1"})
			if err != nil {
				t.Fatalf("ZoneStatus: %v, want the other setting read", err)
			}

			if got != tt.want {
				t.Errorf("ZoneStatus = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSigningKeysAreTheKeyCloudflareSignsTheZoneWith(t *testing.T) {
	key := dnsprovider.SigningKey{
		DNSKEY: "257 3 13 " + testPublicKey,
		KeyTag: 16953,
		DS:     []string{"16953 13 2 " + testDigest},
	}

	tests := []struct {
		dnssec string
		want   []dnsprovider.SigningKey
	}{
		{"active", []dnsprovider.SigningKey{key}},
		// Being signed: the key is made, waiting for its DS at the registrar.
		{"pending", []dnsprovider.SigningKey{key}},
		// Being unsigned: the zone is signed until the DS is gone.
		{"pending-disabled", []dnsprovider.SigningKey{key}},
		{"disabled", nil},
	}

	for _, tt := range tests {
		t.Run(tt.dnssec, func(t *testing.T) {
			api := &cfAPI{dnssec: map[string]string{"z1": tt.dnssec}}
			p := newProvider(t, api)

			r, ok := p.(dnsprovider.KeyReader)
			if !ok {
				t.Fatal("the Cloudflare Provider is no KeyReader")
			}

			got, err := r.SigningKeys(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"})
			if err != nil {
				t.Fatalf("SigningKeys: %v", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SigningKeys = %+v, want %+v", got, tt.want)
			}

			if reqs := api.Requests(); !slices.Equal(reqs, []string{"/client/v4/zones/z1/dnssec?page="}) {
				t.Errorf("requests = %q, want the DNSSEC read alone", reqs)
			}
		})
	}
}

func TestSigningKeysCarryTheDSDigestInUpperCase(t *testing.T) {
	tests := []struct {
		name   string
		digest any
		wantDS []string
	}{
		{"lower-case digest", strings.ToLower(testDigest), []string{"16953 13 2 " + testDigest}},
		// No digest: no DS to fix the key with, but still the key.
		{"empty digest", "", nil},
		{"no digest", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &cfAPI{intercept: func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodGet || r.URL.Path != "/client/v4/zones/z1/dnssec" {
					return false
				}

				res := dnssecResult("active")
				res["digest"] = tt.digest
				writeResult(w, res)

				return true
			}}
			p := newProvider(t, api)

			got, err := p.(dnsprovider.KeyReader).SigningKeys(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"})
			if err != nil {
				t.Fatalf("SigningKeys: %v", err)
			}

			want := []dnsprovider.SigningKey{{DNSKEY: "257 3 13 " + testPublicKey, KeyTag: 16953, DS: tt.wantDS}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("SigningKeys = %+v, want %+v", got, want)
			}
		})
	}
}

func TestSigningKeysTheTokenMayNotReadAreATypedError(t *testing.T) {
	api := &cfAPI{dnssec: map[string]string{"z1": "active"}, forbidden: []string{"/client/v4/zones/z1/dnssec"}}
	p := newProvider(t, api)

	r, ok := p.(dnsprovider.KeyReader)
	if !ok {
		t.Fatal("the Cloudflare Provider is no KeyReader")
	}

	_, err := r.SigningKeys(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"})
	if !errors.Is(err, dnsprovider.ErrUnauthorized) {
		t.Fatalf("err = %v, want dnsprovider.ErrUnauthorized", err)
	}
}

func TestZoneStatusErrorsOtherThanAMissingPermissionAreTypedErrors(t *testing.T) {
	api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		writeErrors(w, http.StatusTooManyRequests, 971, "Please wait and consider throttling your request speed")
	}}
	p := newProvider(t, api)

	_, err := dnsprovider.ZoneStatusOf(context.Background(), p, dnsprovider.Zone{Name: "example.com", ID: "z1"})

	if !errors.Is(err, dnsprovider.ErrRateLimited) {
		t.Fatalf("err = %v, want dnsprovider.ErrRateLimited", err)
	}
}

func TestRateLimitIsATypedErrorWithoutWaiting(t *testing.T) {
	api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		writeErrors(w, http.StatusTooManyRequests, 971, "Please wait and consider throttling your request speed")
	}}
	p := newProvider(t, api)

	_, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{})

	if !errors.Is(err, dnsprovider.ErrRateLimited) {
		t.Fatalf("err = %v, want dnsprovider.ErrRateLimited", err)
	}

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %T %v, want a *dnsprovider.APIError", err, err)
	}

	if apiErr.RetryAfter != 120*time.Second {
		t.Errorf("RetryAfter = %v, want the server's 2m0s", apiErr.RetryAfter)
	}

	if len(api.Requests()) != 1 {
		t.Errorf("made %d requests, want 1: a rate limit is reported, not waited out", len(api.Requests()))
	}
}

func TestEdgeRateLimitWithoutAJSONBodyIsATypedError(t *testing.T) {
	api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("error code: 1015"))
	}}
	p := newProvider(t, api)

	_, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"}, dnsprovider.RecordFilter{})

	if !errors.Is(err, dnsprovider.ErrRateLimited) {
		t.Fatalf("err = %v, want dnsprovider.ErrRateLimited", err)
	}
}

func TestErrorResponsesAreTypedErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		code    int
		message string
		is      error
	}{
		{"invalid token", http.StatusUnauthorized, 1000, "Invalid API Token", dnsprovider.ErrUnauthorized},
		{"missing permission", http.StatusForbidden, 9109, "Unauthorized to access requested resource", dnsprovider.ErrUnauthorized},
		{"unknown zone", http.StatusNotFound, 7003, "Could not route to /zones/nope/dns_records, perhaps your object identifier is invalid?", dnsprovider.ErrNotFound},
		{"server error", http.StatusInternalServerError, 10001, "Internal server error", nil},
		{"other bad request", http.StatusBadRequest, 9005, "Content for A record is invalid", nil},
		// Cloudflare answers these with HTTP 400: the error code says what went wrong.
		{"invalid request headers", http.StatusBadRequest, 6003, "Invalid request headers", dnsprovider.ErrUnauthorized},
		{"malformed Authorization header", http.StatusBadRequest, 6111, "Invalid format for Authorization header", dnsprovider.ErrUnauthorized},
		{"missing credentials", http.StatusBadRequest, 9106, "Missing X-Auth-Key, X-Auth-Email or Authorization headers", dnsprovider.ErrUnauthorized},
		{"authentication error", http.StatusBadRequest, 10000, "Authentication error", dnsprovider.ErrUnauthorized},
		{"unroutable zone ID", http.StatusBadRequest, 7003, "Could not route to /zones/nope/dns_records, perhaps your object identifier is invalid?", dnsprovider.ErrNotFound},
		{"record does not exist", http.StatusBadRequest, 81044, "Record does not exist.", dnsprovider.ErrNotFound},
		// 1001 is not-found to DeleteZone alone; to any other call it is
		// classified by status, as Cloudflare's docs leave it out.
		{"invalid zone identifier", http.StatusBadRequest, 1001, "Invalid zone identifier", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "0") // keep retries of server errors quick
				writeErrors(w, tt.status, tt.code, tt.message)
			}}
			p := newProvider(t, api)

			_, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "nope"}, dnsprovider.RecordFilter{})

			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %T %v, want a *dnsprovider.APIError", err, err)
			}

			if apiErr.StatusCode != tt.status {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tt.status)
			}

			if tt.is != nil && !errors.Is(err, tt.is) {
				t.Errorf("err = %v, want it to be %v", err, tt.is)
			}

			for _, sentinel := range []error{dnsprovider.ErrRateLimited, dnsprovider.ErrUnauthorized, dnsprovider.ErrNotFound} {
				if sentinel != tt.is && errors.Is(err, sentinel) {
					t.Errorf("err = %v, should not be %v", err, sentinel)
				}
			}

			if !strings.Contains(err.Error(), tt.message) {
				t.Errorf("err = %q, want Cloudflare's message %q", err, tt.message)
			}
		})
	}
}

func TestAStalledConnectionTimesOut(t *testing.T) {
	cloudflare.SetRequestTimeout(t, 50*time.Millisecond)

	stalled := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answer nothing, as a stalled connection does.
		select {
		case <-r.Context().Done():
		case <-stalled:
		}
	}))
	t.Cleanup(srv.Close)
	// Cleanups run last-in first-out: release the handler before Close
	// waits on it.
	t.Cleanup(func() { close(stalled) })

	// The adapter's own client, so its own timeout is what ends the wait.
	p, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: acc1}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan error, 1)

	go func() {
		_, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Zones succeeded against a stalled server")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Zones still waits on a stalled connection")
	}
}

func TestAConsumersClientKeepsItsOwnTimeouts(t *testing.T) {
	cloudflare.SetRequestTimeout(t, 50*time.Millisecond)

	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}}
	h := api.handler(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slower than the adapter's timeout; the consumer's client sets none.
		time.Sleep(300 * time.Millisecond)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	p, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: acc1}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"), dnsprovider.WithHTTPClient(&http.Client{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	set, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones through the consumer's client: %v", err)
	}

	zs := set.Zones

	if len(zs) != 1 {
		t.Errorf("Zones = %+v, want one", zs)
	}
}

func TestErrorsAreNotPrintedToTheTerminal(t *testing.T) {
	api := &cfAPI{fail: func(w http.ResponseWriter, _ *http.Request) {
		writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")
	}}
	p := newProvider(t, api)

	output := captureOutput(t, func() {
		if _, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err == nil {
			t.Error("Zones succeeded, want an error")
		}
	})

	if output != "" {
		t.Errorf("printed %q to the terminal, want nothing", output)
	}
}

// captureOutput returns what fn writes to stdout and stderr.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w

	func() {
		defer func() { os.Stdout, os.Stderr = stdout, stderr }()

		fn()
	}()

	_ = w.Close()

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	return string(out)
}

func cfRecord(id, typ, name, content string, ttl int, proxiable, proxied bool) map[string]any {
	return map[string]any{
		"id":          id,
		"type":        typ,
		"name":        name,
		"content":     content,
		"ttl":         ttl,
		"proxiable":   proxiable,
		"proxied":     proxied,
		"comment":     nil,
		"tags":        []any{},
		"settings":    map[string]any{},
		"meta":        map[string]any{},
		"created_on":  "2024-01-02T03:04:05.000000Z",
		"modified_on": "2024-01-02T03:04:05.000000Z",
	}
}

func TestRecordsListsEveryPageWithTheProxyFlag(t *testing.T) {
	api := &cfAPI{
		pageSize: 2,
		zones:    []map[string]any{cfZone("z1", "example.com")},
		records: map[string][]map[string]any{"z1": {
			cfRecord("r1", "A", "example.com", "192.0.2.1", 1, true, true),
			cfRecord("r2", "CNAME", "www.example.com", "example.com", 300, true, false),
			cfRecord("r3", "TXT", "example.com", "\"v=spf1 -all\"", 3600, false, false),
		}},
	}
	p := newProvider(t, api)

	rs, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	if rs.Partial {
		t.Error("Records is a Partial View, want a Full View")
	}

	want := []dnsprovider.Record{
		{ID: "r1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 1, Extras: map[string]string{cloudflare.ExtraProxied: "true"}},
		{ID: "r2", Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 300, Extras: map[string]string{cloudflare.ExtraProxied: "false"}},
		{ID: "r3", Type: "TXT", Name: "example.com", Value: "\"v=spf1 -all\"", TTL: 3600},
	}
	assertRecords(t, rs.Records, want)

	if got := strings.Join(api.Requests(), " "); !strings.Contains(got, "/client/v4/zones/z1/dns_records?page=2") {
		t.Errorf("requests = %s, want the second page of Records", got)
	}
}

func TestRecordsPutThePriorityInTheValue(t *testing.T) {
	mx := cfRecord("r1", "MX", "example.com", "mail.example.com", 3600, false, false)
	mx["priority"] = 10
	srv := cfRecord("r2", "SRV", "_sip._tcp.example.com", "5 5060 sip.example.com", 3600, false, false)
	srv["priority"] = 20
	srv["data"] = map[string]any{"priority": 20, "weight": 5, "port": 5060, "target": "sip.example.com"}

	uri := cfRecord("r3", "URI", "_ftp._tcp.example.com", `1 "ftp://ftp.example.com/public"`, 3600, false, false)
	uri["priority"] = 10
	uri["data"] = map[string]any{"weight": 1, "target": "ftp://ftp.example.com/public"}

	api := &cfAPI{records: map[string][]map[string]any{"z1": {mx, srv, uri}}}
	p := newProvider(t, api)

	rs, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	assertRecords(t, rs.Records, []dnsprovider.Record{
		{ID: "r1", Type: "MX", Name: "example.com", Value: "10 mail.example.com", TTL: 3600},
		{ID: "r2", Type: "SRV", Name: "_sip._tcp.example.com", Value: "20 5 5060 sip.example.com", TTL: 3600},
		{ID: "r3", Type: "URI", Name: "_ftp._tcp.example.com", Value: `10 1 "ftp://ftp.example.com/public"`, TTL: 3600},
	})
}

func TestRecordsAreOneListingWithNoSerial(t *testing.T) {
	// Cloudflare's v4 API has no SOA serial short of a BIND export of the
	// whole Zone; query the Zone's nameservers for the serial instead.
	api := &cfAPI{records: map[string][]map[string]any{"z1": {cfRecord("r1", "A", "example.com", "192.0.2.1", 1, true, true)}}}
	p := newProvider(t, api)

	rs, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	if rs.Serial != 0 {
		t.Errorf("Serial = %d, want 0 (unknown)", rs.Serial)
	}

	if got, want := api.Requests(), []string{"/client/v4/zones/z1/dns_records?page=1"}; !slices.Equal(got, want) {
		t.Errorf("requests = %q, want %q: one listing, no export", got, want)
	}
}

func assertRecords(t *testing.T, got, want []dnsprovider.Record) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("got %d Records, want %d:\n got %+v\nwant %+v", len(got), len(want), got, want)
	}

	for i := range want {
		g, w := got[i], want[i]
		if g.ID != w.ID || g.Type != w.Type || g.Name != w.Name ||
			g.Value != w.Value || g.TTL != w.TTL || !maps.Equal(g.Extras, w.Extras) {
			t.Errorf("Record %d = %+v, want %+v", i, g, w)
		}

		// The Factory declares every extra a Record carries.
		if err := cloudflare.Factory().CheckExtras(g); err != nil {
			t.Errorf("Record %d: %v", i, err)
		}
	}
}

func TestCloudflareTakesTTLsFrom60SecondsOrAutomatic(t *testing.T) {
	p, err := cloudflare.New(cloudflare.Config{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}

	r := dnsprovider.TTLRangeOf(p)
	if want := (dnsprovider.TTLRange{Min: 60, Max: 86400, Auto: true}); r != want {
		t.Fatalf("TTL range = %+v, want %+v", r, want)
	}

	if err := r.Check(dnsprovider.TTLAuto); err != nil {
		t.Errorf("TTL 1 refused: %v", err)
	}
}

func TestCloudflareTakesTTL1AsAutomatic(t *testing.T) {
	p, err := cloudflare.New(cloudflare.Config{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}

	if !dnsprovider.AutoTTLOf(p) {
		t.Fatal("Cloudflare has no automatic TTL")
	}
}

func TestCloudflareProxyFlagIsTheNeutralExtra(t *testing.T) {
	// A consumer that only knows dnsprovider.ProxyFlag reads and writes the
	// flag under dnsprovider.ExtraProxied, the key Cloudflare's Records use.
	if cloudflare.ExtraProxied != dnsprovider.ExtraProxied {
		t.Fatalf("cloudflare.ExtraProxied = %q, want dnsprovider.ExtraProxied %q", cloudflare.ExtraProxied, dnsprovider.ExtraProxied)
	}
}

func TestCloudflareProxiesAAAAAAndCNAMERecords(t *testing.T) {
	p, err := cloudflare.New(cloudflare.Config{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := dnsprovider.ProxiableTypesOf(p), []string{"A", "AAAA", "CNAME"}; !slices.Equal(got, want) {
		t.Fatalf("proxiable types = %v, want %v", got, want)
	}
}

func TestCloudflareReadsZoneStatus(t *testing.T) {
	if _, ok := newProvider(t, &cfAPI{}).(dnsprovider.ZoneStatusReader); !ok {
		t.Error("Cloudflare is not a ZoneStatusReader")
	}
}

func TestZoneOfANameSeveralZonesShareIsTheOneCloudflareServes(t *testing.T) {
	zone := func(id, status string) map[string]any {
		z := cfZone(id, "example.com")
		z["status"] = status

		return z
	}

	cases := []struct {
		name   string
		zones  []map[string]any
		wantID string
	}{
		{"active first", []map[string]any{zone("z1", "moved"), zone("z2", "pending"), zone("z3", "active")}, "z3"},
		{"pending next", []map[string]any{zone("z1", "moved"), zone("z2", "pending")}, "z2"},
		{"else the first", []map[string]any{zone("z1", "moved"), zone("z2", "moved")}, "z1"},
	}

	for _, c := range cases {
		got, err := newProvider(t, &cfAPI{zones: c.zones}).GetZone(context.Background(), "example.com")
		if err != nil || got.ID != c.wantID {
			t.Errorf("%s: Zone = %+v, %v; want %s", c.name, got, err, c.wantID)
		}
	}
}

func TestZoneOfNoNameIsNotFoundWithoutARequest(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}}

	for _, name := range []string{"", "."} {
		for _, p := range []dnsprovider.Provider{newProvider(t, api), newProviderIn(t, api, acme, "")} {
			if _, err := p.GetZone(context.Background(), name); !errors.Is(err, dnsprovider.ErrNotFound) {
				t.Errorf("Zone(%q): err = %v, want ErrNotFound", name, err)
			}
		}
	}

	if n := len(api.Requests()); n != 0 {
		t.Errorf("sent %d requests, want none", n)
	}
}

func TestZonesFilteredByAnAbsoluteNamePushItWithoutTheDot(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{
		cfZone("z1", "example.com"),
		cfZone("z2", "example.community"),
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "Example.COM."})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	if got, want := zoneNames(zones), []string{"example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}

	if q := api.ZoneQueries(); len(q) != 1 || q[0].Get("name") != "contains:example.com" {
		t.Errorf("zone list queries = %v, want name=contains:example.com", q)
	}
}

func TestRecordsFilteredByTypeAndNamePushBothToCloudflare(t *testing.T) {
	cases := []struct {
		name       string
		filter     dnsprovider.RecordFilter
		wantIDs    []string
		wantType   string
		wantName   string
		hasNameArg bool
	}{
		{"type", dnsprovider.RecordFilter{Type: "MX"}, []string{"r3"}, "MX", "", false},
		{"lower-case type", dnsprovider.RecordFilter{Type: "mx"}, []string{"r3"}, "MX", "", false},
		{"name", dnsprovider.RecordFilter{Contains: "WWW."}, []string{"r1", "r2", "r4"}, "", "www", true},
		{"absolute name", dnsprovider.RecordFilter{Contains: "www.example.com."}, []string{"r1", "r2"}, "", "www.example.com", true},
		{"type and name", dnsprovider.RecordFilter{Type: "A", Contains: "www"}, []string{"r1", "r4"}, "A", "www", true},
		{"type Cloudflare does not take", dnsprovider.RecordFilter{Type: "SPF"}, []string{}, "", "", false},
		{"malformed type", dnsprovider.RecordFilter{Type: "A B", Contains: "www"}, []string{}, "", "www", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, ignore := range []bool{false, true} {
				api := &cfAPI{ignoreRecordFilter: ignore, records: map[string][]map[string]any{"z1": {
					cfRecord("r1", "A", "www.example.com", "192.0.2.1", 300, true, false),
					cfRecord("r2", "AAAA", "www.example.com", "2001:db8::1", 300, true, false),
					mxRecord("r3", "example.com", "10 mail.example.com"),
					cfRecord("r4", "A", "www.example.community", "192.0.2.2", 300, true, false),
					cfRecord("r5", "TXT", "wwwx.example.com", "\"x\"", 300, false, false),
				}}}

				rs, err := newProvider(t, api).Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"}, c.filter)
				if err != nil {
					t.Fatalf("Records: %v", err)
				}

				if got := recordIDs(rs.Records); !slices.Equal(got, c.wantIDs) {
					t.Errorf("ignoring the filter %v: Records = %v, want %v", ignore, got, c.wantIDs)
				}

				q := api.RecordQueries()
				if len(q) != 1 || q[0].Get("type") != c.wantType || q[0].Has("name.contains") != c.hasNameArg || q[0].Get("name.contains") != c.wantName {
					t.Errorf("record list queries = %v, want type=%q name.contains=%q", q, c.wantType, c.wantName)
				}
			}
		})
	}
}

func TestRecordsFilteredLeaveOutARecordTheyCannotReadOutsideTheFilter(t *testing.T) {
	odd := mxRecord("r2", "example.com", "10 mail.example.com")
	odd["priority"] = "ten"

	for _, f := range []dnsprovider.RecordFilter{{Type: "A"}, {Contains: "www"}, {Type: "SPF"}} {
		api := &cfAPI{ignoreRecordFilter: true, records: map[string][]map[string]any{"z1": {
			cfRecord("r1", "A", "www.example.com", "192.0.2.1", 300, true, false),
			odd,
		}}}

		rs, err := newProvider(t, api).Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"}, f)
		if err != nil {
			t.Fatalf("Records(%+v): %v", f, err)
		}

		want := []string{"r1"}
		if f.Type == "SPF" {
			want = []string{}
		}

		if got := recordIDs(rs.Records); !slices.Equal(got, want) {
			t.Errorf("Records(%+v) = %v, want %v", f, got, want)
		}
	}
}

// cfRecordTypes are the record types Cloudflare's record list takes.
var cfRecordTypes = []string{"A", "AAAA", "CAA", "CERT", "CNAME", "DNSKEY", "DS", "HTTPS", "LOC", "MX", "NAPTR", "NS", "OPENPGPKEY", "PTR", "SMIMEA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT", "URI"}

func TestRecordsWithTheZeroFilterSendNoFilter(t *testing.T) {
	api := &cfAPI{records: map[string][]map[string]any{"z1": {cfRecord("r1", "A", "example.com", "192.0.2.1", 1, true, true)}}}

	if _, err := newProvider(t, api).Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"}, dnsprovider.RecordFilter{}); err != nil {
		t.Fatalf("Records: %v", err)
	}

	if q := api.RecordQueries(); len(q) != 1 || q[0].Has("type") || q[0].Has("name.contains") {
		t.Errorf("record list queries = %v, want no type or name filter", q)
	}
}

func mxRecord(id, name, value string) map[string]any {
	prio, target, _ := strings.Cut(value, " ")
	r := cfRecord(id, "MX", name, target, 3600, false, false)
	r["priority"], _ = strconv.Atoi(prio)

	return r
}

func recordIDs(records []dnsprovider.Record) []string {
	ids := make([]string, 0, len(records))
	for _, r := range records {
		ids = append(ids, r.ID)
	}

	return ids
}

func TestZoneStatusReadsTheMinimumTLSVersion(t *testing.T) {
	tests := []struct {
		value string
		want  dnsprovider.TLSVersion
	}{
		{"1.0", dnsprovider.TLS10},
		{"1.2", dnsprovider.TLS12},
		{"1.3", dnsprovider.TLS13},
		// A version dnsprovider does not know is unknown.
		{"1.4", dnsprovider.TLSUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			api := &cfAPI{dnssec: map[string]string{"z1": "active"}, hsts: map[string]bool{"z1": true}, minTLS: map[string]string{"z1": tt.value}}

			got, err := dnsprovider.ZoneStatusOf(context.Background(), newProvider(t, api), dnsprovider.Zone{Name: "example.com", ID: "z1"})
			if err != nil {
				t.Fatalf("ZoneStatus: %v", err)
			}

			if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.On, MinTLS: tt.want}); got != want {
				t.Errorf("ZoneStatus = %+v, want %+v", got, want)
			}
		})
	}
}

func TestZoneStatusMinimumTLSVersionTheTokenMayNotReadIsUnknown(t *testing.T) {
	api := &cfAPI{
		dnssec:    map[string]string{"z1": "active"},
		hsts:      map[string]bool{"z1": true},
		minTLS:    map[string]string{"z1": "1.2"},
		forbidden: []string{"/client/v4/zones/z1/settings/min_tls_version"},
	}

	got, err := dnsprovider.ZoneStatusOf(context.Background(), newProvider(t, api), dnsprovider.Zone{Name: "example.com", ID: "z1"})
	if err != nil {
		t.Fatalf("ZoneStatus: %v", err)
	}

	if want := (dnsprovider.ZoneStatus{DNSSEC: dnsprovider.On, HSTS: dnsprovider.On}); got != want {
		t.Errorf("ZoneStatus = %+v, want %+v", got, want)
	}
}

func TestRecordsCarryTheirCommentAndTags(t *testing.T) {
	commented := cfRecord("r1", "A", "example.com", "192.0.2.1", 300, true, false)
	commented["comment"] = "origin in fra1"
	commented["tags"] = []any{"env:prod", "team:web"}

	api := &cfAPI{
		zones: []map[string]any{cfZone("z1", "example.com")},
		records: map[string][]map[string]any{"z1": {
			commented,
			cfRecord("r2", "TXT", "example.com", "\"v=spf1 -all\"", 3600, false, false),
		}},
	}
	p := newProvider(t, api)

	rs, err := p.Records(context.Background(), dnsprovider.Zone{Name: "example.com", ID: "z1"}, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	// A Record without a comment or tags carries neither.
	want := []dnsprovider.Record{
		{ID: "r1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 300, Extras: map[string]string{
			cloudflare.ExtraProxied: "false", cloudflare.ExtraComment: "origin in fra1", cloudflare.ExtraTags: `["env:prod","team:web"]`,
		}},
		{ID: "r2", Type: "TXT", Name: "example.com", Value: "\"v=spf1 -all\"", TTL: 3600},
	}
	assertRecords(t, rs.Records, want)
}
