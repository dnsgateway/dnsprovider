package ovhcloud_test

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/ovhcloud"
)

const (
	appKey      = "test-app-key"
	appSecret   = "test-app-secret"
	consumerKey = "test-consumer-key"
)

// wireRecord is domain.zone.Record from the official schema.
type wireRecord struct {
	ID        int64  `json:"id"`
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       int64  `json:"ttl"`
	Zone      string `json:"zone"`
}

type fakeZone struct {
	nameServers []string
	serial      int64
	ttl         int64
	// staged is what record reads return; published is what the last
	// refresh made eligible for publication.
	staged    map[int64]wireRecord
	published map[int64]wireRecord
	order     []int64
	refreshes int
}

// fake is a protocol-faithful OVHcloud API: it checks every signature
// against the URL and body it received and keeps staged and published
// Record state apart.
type fake struct {
	t   *testing.T
	mu  sync.Mutex
	srv *httptest.Server
	// prefix is the path the base URL adds, such as "/1.0".
	prefix string

	skew       time.Duration
	timeCalls  int
	timeStatus int
	timeHold   chan struct{}

	nichandle string
	meStatus  int

	zones  map[string]*fakeZone
	nextID int64

	// requests are "METHOD path?query" of the authenticated calls.
	requests   []string
	signatures []string
	timestamps []int64
	// fail answers a "METHOD path" with a status, once per entry.
	fail map[string][]int
	// lose closes the connection of a "METHOD path" after applying it.
	lose map[string]bool
	// normalizeTXT strips quotes from a single TXT chunk on write.
	normalizeTXT bool
	// rejectTarget refuses creates with this target.
	rejectTarget string
}

func newFake(t *testing.T) *fake {
	t.Helper()

	f := &fake{t: t, nichandle: "ab12345-ovh", zones: map[string]*fakeZone{}, nextID: 100, fail: map[string][]int{}, lose: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)

	return f
}

func (f *fake) addZone(name string, records ...wireRecord) *fakeZone {
	z := &fakeZone{nameServers: []string{"dns200.anycast.me.", "ns200.anycast.me"}, serial: 2026101001, ttl: 3600, staged: map[int64]wireRecord{}, published: map[int64]wireRecord{}}
	for _, r := range records {
		if r.ID == 0 {
			f.nextID++
			r.ID = f.nextID
		}

		r.Zone = name
		z.staged[r.ID] = r
		z.published[r.ID] = r
		z.order = append(z.order, r.ID)
	}

	f.zones[name] = z

	return z
}

func (f *fake) provider(t *testing.T, opts ...dnsprovider.Option) *ovhcloud.Provider {
	t.Helper()

	opts = append([]dnsprovider.Option{dnsprovider.WithBaseURL(f.srv.URL + f.prefix), dnsprovider.WithHTTPClient(f.srv.Client())}, opts...)

	p, err := ovhcloud.New(ovhcloud.Config{ApplicationKey: appKey, ApplicationSecret: appSecret, ConsumerKey: consumerKey}, opts...)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func (f *fake) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fake) apiError(w http.ResponseWriter, status int, class, message string) {
	w.Header().Set("X-Ovh-Queryid", "EU.ext-1.test")
	f.writeJSON(w, status, map[string]string{"class": class, "message": message})
}

func sign(method, url, body string, ts int64) string {
	sum := sha1.Sum([]byte(appSecret + "+" + consumerKey + "+" + method + "+" + url + "+" + body + "+" + strconv.FormatInt(ts, 10)))

	return "$1$" + hex.EncodeToString(sum[:])
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, f.prefix)
	if path == "/auth/time" {
		f.serveTime(w, r)

		return
	}

	body, _ := io.ReadAll(r.Body)

	f.mu.Lock()
	defer f.mu.Unlock()

	ts, _ := strconv.ParseInt(r.Header.Get("X-Ovh-Timestamp"), 10, 64)
	f.signatures = append(f.signatures, r.Header.Get("X-Ovh-Signature"))
	f.timestamps = append(f.timestamps, ts)

	serverNow := time.Now().Add(f.skew).Unix()
	if r.Header.Get("X-Ovh-Application") != appKey || r.Header.Get("X-Ovh-Consumer") != consumerKey {
		f.writeJSON(w, http.StatusForbidden, map[string]string{"errorCode": "INVALID_CREDENTIAL", "httpCode": "403 Forbidden", "message": "This credential is not valid"})

		return
	}

	if ts < serverNow-5 || ts > serverNow+5 {
		f.writeJSON(w, http.StatusBadRequest, map[string]string{"errorCode": "QUERY_TIME_OUT", "httpCode": "400 Bad Request", "message": "Query out of time"})

		return
	}

	if r.Header.Get("X-Ovh-Signature") != sign(r.Method, f.srv.URL+r.URL.RequestURI(), string(body), ts) {
		f.writeJSON(w, http.StatusBadRequest, map[string]string{"errorCode": "INVALID_SIGNATURE", "httpCode": "400 Bad Request", "message": "Invalid signature"})

		return
	}

	key := r.Method + " " + path
	f.requests = append(f.requests, key+querySuffix(r))

	// A zero code lets that call through.
	if codes := f.fail[key]; len(codes) > 0 {
		f.fail[key] = codes[1:]
		if codes[0] != 0 {
			f.apiError(w, codes[0], classOf(codes[0]), "injected failure for "+consumerKey)

			return
		}
	}

	f.route(w, r, path, body)

	if f.lose[key] {
		delete(f.lose, key)
		panic(http.ErrAbortHandler)
	}
}

func querySuffix(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}

	return "?" + r.URL.RawQuery
}

func classOf(status int) string {
	switch status {
	case http.StatusForbidden:
		return "Client::Forbidden"
	case http.StatusNotFound:
		return "Client::NotFound"
	case http.StatusConflict:
		return "Client::Conflict"
	case http.StatusTooManyRequests:
		return "Client::TooManyRequests"
	case http.StatusBadRequest:
		return "Client::BadRequest"
	}

	return "Server::InternalServerError"
}

func (f *fake) serveTime(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Ovh-Signature") != "" || r.Header.Get("X-Ovh-Consumer") != "" {
		f.t.Error("the public time request was signed")
	}

	f.mu.Lock()
	f.timeCalls++
	hold, status, skew := f.timeHold, f.timeStatus, f.skew
	f.mu.Unlock()

	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
			return
		}
	}

	if status != 0 {
		f.apiError(w, status, classOf(status), "time unavailable")

		return
	}

	f.writeJSON(w, http.StatusOK, time.Now().Add(skew).Unix())
}

func (f *fake) route(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	if path == "/me" && r.Method == http.MethodGet {
		if f.meStatus != 0 {
			f.apiError(w, f.meStatus, classOf(f.meStatus), "This call has not been granted")

			return
		}

		f.writeJSON(w, http.StatusOK, map[string]any{"nichandle": f.nichandle, "organisation": "Example SAS", "email": "owner@example.com"}) //nolint:misspell // the API's field name

		return
	}

	parts := strings.Split(strings.TrimPrefix(path, "/domain/zone"), "/")
	if !strings.HasPrefix(path, "/domain/zone") {
		f.apiError(w, http.StatusNotFound, "Client::NotFound", "unknown path")

		return
	}

	if len(parts) == 1 {
		names := make([]string, 0, len(f.zones))
		for name := range f.zones {
			names = append(names, name)
		}

		slices.Sort(names)
		f.writeJSON(w, http.StatusOK, names)

		return
	}

	name := parts[1]

	z := f.zones[name]
	if z == nil {
		f.apiError(w, http.StatusNotFound, "Client::NotFound", "This service does not exist")

		return
	}

	switch {
	case len(parts) == 2 && r.Method == http.MethodGet:
		f.writeJSON(w, http.StatusOK, map[string]any{"name": name, "nameServers": z.nameServers, "dnssecSupported": true, "hasDnsAnycast": false, "lastUpdate": "2026-10-10T10:00:00+02:00"})
	case len(parts) == 3 && parts[2] == "soa":
		f.writeJSON(w, http.StatusOK, map[string]any{"server": "dns200.anycast.me", "email": "tech@ovh.net", "serial": z.serial, "refresh": 86400, "nxDomainTtl": 86400, "expire": 3600000, "ttl": z.ttl})
	case len(parts) == 3 && parts[2] == "refresh" && r.Method == http.MethodPost:
		z.refreshes++
		z.published = maps.Clone(z.staged)

		z.serial++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
	case len(parts) == 3 && parts[2] == "record" && r.Method == http.MethodGet:
		f.listRecords(w, r, z)
	case len(parts) == 3 && parts[2] == "record" && r.Method == http.MethodPost:
		f.createRecord(w, z, name, body)
	case len(parts) == 4 && parts[2] == "record":
		f.routeRecord(w, r, z, parts[3], body)
	default:
		f.apiError(w, http.StatusNotFound, "Client::NotFound", "unknown path")
	}
}

// listRecords serves the unpaged record ID array, with its exact filters.
func (f *fake) listRecords(w http.ResponseWriter, r *http.Request, z *fakeZone) {
	ids := []int64{}

	for _, id := range z.order {
		rec, ok := z.staged[id]
		if !ok {
			continue
		}

		if ft := r.URL.Query().Get("fieldType"); ft != "" && ft != rec.FieldType {
			continue
		}

		if sd, ok := r.URL.Query()["subDomain"]; ok && sd[0] != rec.SubDomain {
			continue
		}

		ids = append(ids, id)
	}

	f.writeJSON(w, http.StatusOK, ids)
}

// createRecord stages a new record and answers it as stored.
func (f *fake) createRecord(w http.ResponseWriter, z *fakeZone, name string, body []byte) {
	var in wireRecord
	if err := json.Unmarshal(body, &in); err != nil || in.FieldType == "" || in.Target == "" {
		f.apiError(w, http.StatusBadRequest, "Client::BadRequest", "Invalid body")

		return
	}

	if f.rejectTarget != "" && in.Target == f.rejectTarget {
		f.apiError(w, http.StatusBadRequest, "Client::BadRequest", "Invalid target")

		return
	}

	if f.normalizeTXT && in.FieldType == "TXT" && strings.Count(in.Target, `"`) == 2 {
		in.Target = strings.Trim(in.Target, `"`)
	}

	f.nextID++
	in.ID, in.Zone = f.nextID, name
	z.staged[in.ID] = in
	z.order = append(z.order, in.ID)
	f.writeJSON(w, http.StatusOK, in)
}

// routeRecord serves /domain/zone/{zoneName}/record/{id}.
func (f *fake) routeRecord(w http.ResponseWriter, r *http.Request, z *fakeZone, rawID string, body []byte) {
	id, _ := strconv.ParseInt(rawID, 10, 64)

	rec, ok := z.staged[id]
	if !ok {
		f.apiError(w, http.StatusNotFound, "Client::NotFound", "The requested object (id = "+rawID+") does not exist")

		return
	}

	switch r.Method {
	case http.MethodGet:
		f.writeJSON(w, http.StatusOK, rec)
	case http.MethodDelete:
		delete(z.staged, id)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
	case http.MethodPut:
		var in map[string]json.RawMessage
		if err := json.Unmarshal(body, &in); err != nil {
			f.apiError(w, http.StatusBadRequest, "Client::BadRequest", "Invalid body")

			return
		}

		if _, ok := in["fieldType"]; ok {
			f.apiError(w, http.StatusBadRequest, "Client::BadRequest", "fieldType is read-only")

			return
		}

		if v, ok := in["subDomain"]; ok {
			_ = json.Unmarshal(v, &rec.SubDomain)
		}

		if v, ok := in["target"]; ok {
			_ = json.Unmarshal(v, &rec.Target)
		}

		if v, ok := in["ttl"]; ok {
			_ = json.Unmarshal(v, &rec.TTL)
		}

		z.staged[id] = rec
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
	}
}

// mutations are the authenticated write calls, in order.
func (f *fake) mutations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []string

	for _, r := range f.requests {
		if !strings.HasPrefix(r, http.MethodGet) {
			out = append(out, r)
		}
	}

	return out
}
