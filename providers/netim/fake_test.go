package netim_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/netim"
)

// Test credentials. The secret holds characters a URL escapes.
const (
	resellerID = "RESELLER1"
	secret     = "s3cr&t/pa ss"
)

// fake is a Netim REST 3.0 server in memory. It serves the fixtures in
// testdata, checks Basic credentials when a session opens and the Bearer
// token on every later call, and can be told to expire a session or to
// answer a path once with a scripted status and body. It holds
// example.com's zone, from zone_info.json, and creates and deletes its
// records, updates them in place and deletes them as Netim does,
// answering with a Done operation.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	opened   int                // sessions opened
	closed   int                // sessions closed
	sessions map[string]bool    // live session tokens
	files    map[string]string  // "METHOD path" to a testdata file
	once     map[string][]reply // "METHOD path" to replies, each sent once
	requests []string           // "METHOD path" of every request
	bodies   map[string]string  // last request body, by "METHOD path"
	zones    map[string]*fakeZone
}

// lost is the status of a scripted reply whose answer is lost: the
// connection closes after the request was read.
const lost = -1

// lostApplied is the status of a scripted reply to a zone write that the
// fake applies before its answer is lost.
const lostApplied = -2

type reply struct {
	status int
	body   string
}

// fakeZone is a zone's info: its fields other than records, and its
// records.
type fakeZone struct {
	info    map[string]json.RawMessage
	records []fakeRecord
}

type fakeRecord struct {
	Subdomain string         `json:"subdomain"`
	Type      string         `json:"type"`
	Value     string         `json:"value"`
	Options   map[string]any `json:"options"`
}

func newFake(t *testing.T) *fake {
	t.Helper()

	f := &fake{
		t:        t,
		sessions: map[string]bool{},
		once:     map[string][]reply{},
		bodies:   map[string]string{},
		files: map[string]string{
			"GET /session/":                 "session_info.json",
			"POST /domains/":                "domains_list.json",
			"GET /domain/example.com/info/": "domain_info.json",
			"GET /domain/example.net/info/": "domain_info_external_dns.json",
		},
		zones: map[string]*fakeZone{},
	}

	var z fakeZone
	if err := json.Unmarshal([]byte(fixture(t, "zone_info.json")), &z.info); err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(z.info["records"], &z.records); err != nil {
		t.Fatal(err)
	}

	delete(z.info, "records")
	f.zones["example.com"] = &z

	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)

	return f
}

// provider builds a Provider for the fake with the test credentials.
func (f *fake) provider(opts ...dnsprovider.Option) *netim.Provider {
	f.t.Helper()

	p, err := netim.New(netim.Config{ID: resellerID, Secret: secret}, append([]dnsprovider.Option{dnsprovider.WithBaseURL(f.srv.URL), dnsprovider.WithHTTPClient(f.srv.Client())}, opts...)...)
	if err != nil {
		f.t.Fatal(err)
	}

	return p
}

// fixture is a testdata file's content.
func fixture(t testing.TB, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

// expire ends every live session, as Netim does when one times out.
func (f *fake) expire() {
	f.mu.Lock()
	defer f.mu.Unlock()

	clear(f.sessions)
}

// script answers the next request for "METHOD path" not yet scripted
// with status and body.
func (f *fake) script(key string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.once[key] = append(f.once[key], reply{status, body})
}

// serve sets a file for "METHOD path", replacing or adding a fixture.
func (f *fake) serveFile(key, file string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.files[key] = file
}

func (f *fake) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0

	for _, r := range f.requests {
		if r == key {
			n++
		}
	}

	return n
}

func (f *fake) stats() (opened, closed, live int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.opened, f.closed, len(f.sessions)
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	body, _ := io.ReadAll(r.Body)

	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, key)
	f.bodies[key] = string(body)

	w.Header().Set("Content-Type", "application/json")

	if queue := f.once[key]; len(queue) > 0 {
		rep := queue[0]
		f.once[key] = queue[1:]

		if rep.status == lost || rep.status == lostApplied {
			if rep.status == lostApplied {
				f.zone(httptest.NewRecorder(), r, body)
			}

			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}

			return
		}

		w.WriteHeader(rep.status)
		_, _ = io.WriteString(w, rep.body)

		return
	}

	if key == "POST /session/" {
		f.open(w, r)

		return
	}

	token, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !bearer || !f.sessions[token] {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, fixture(f.t, "error_401.json"))

		return
	}

	if key == "DELETE /session/" {
		delete(f.sessions, token)
		f.closed++
		_, _ = io.WriteString(w, fixture(f.t, "session_close.json"))

		return
	}

	if f.zone(w, r, body) {
		return
	}

	file, ok := f.files[key]
	if !ok {
		// Netim answers 405 for a path it does not have.
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(w, fixture(f.t, "error_405.json"))

		return
	}

	_, _ = io.WriteString(w, fixture(f.t, file))
}

// open opens a session for the test credentials with synchronous
// processing, as POST /session/ does.
func (f *fake) open(w http.ResponseWriter, r *http.Request) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(resellerID+":"+secret))
	if r.Header.Get("Authorization") != want {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, fixture(f.t, "error_401.json"))

		return
	}

	if b := f.bodies["POST /session/"]; !strings.Contains(b, `"sync":1`) {
		f.t.Errorf("session opened without synchronous processing: %s", b)
	}

	f.opened++
	token := fmt.Sprintf("00000000000000000000000000fake%02d", f.opened)
	f.sessions[token] = true

	_, _ = fmt.Fprintf(w, `{"access_token":%q}`, token)
}

// zone serves a held zone's info, record creates, updates and deletes, and
// reports whether the request was one of them.
func (f *fake) zone(w http.ResponseWriter, r *http.Request, body []byte) bool {
	rest, ok := strings.CutPrefix(r.URL.Path, "/domain/")
	if !ok {
		return false
	}

	domain, resource, _ := strings.Cut(rest, "/")

	z := f.zones[domain]
	if z == nil {
		return false
	}

	switch r.Method + " " + resource {
	case "GET zone/info/":
		info := map[string]any{"records": z.records}
		for k, v := range z.info {
			info[k] = v
		}

		_ = json.NewEncoder(w).Encode(info)
	case "POST zone/":
		var rec fakeRecord
		if json.Unmarshal(body, &rec) != nil || rec.Type == "" || rec.Value == "" || rec.Options["ttl"] == nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, fixture(f.t, "error_400.json"))

			return true
		}

		// A record created with a TTL has a custom one.
		rec.Options["customTtl"] = true
		z.records = append(z.records, rec)
		_, _ = io.WriteString(w, fixture(f.t, "zone_create_done.json"))
	case "DELETE zone/":
		var sel fakeRecord
		_ = json.Unmarshal(body, &sel)

		apex := func(s string) string { return strings.TrimPrefix(s, "@") }
		kept := make([]fakeRecord, 0, len(z.records))

		for _, rec := range z.records {
			if apex(rec.Subdomain) != apex(sel.Subdomain) || rec.Type != sel.Type || rec.Value != sel.Value {
				kept = append(kept, rec)
			}
		}

		if len(kept) == len(z.records) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, fixture(f.t, "error_400.json"))

			return true
		}

		z.records = kept
		_, _ = io.WriteString(w, fixture(f.t, "zone_delete_done.json"))
	case "PATCH zone/update/":
		var upd struct {
			fakeRecord

			NewValue string `json:"newValue"`
		}
		if json.Unmarshal(body, &upd) != nil || upd.NewValue == "" || upd.Options["ttl"] == nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, fixture(f.t, "error_400.json"))

			return true
		}

		i := f.find(z, upd.fakeRecord)
		if i < 0 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, fixture(f.t, "error_400.json"))

			return true
		}

		upd.Options["customTtl"] = true
		z.records[i].Value, z.records[i].Options = upd.NewValue, upd.Options
		_, _ = io.WriteString(w, fixture(f.t, "zone_update_done.json"))
	default:
		return false
	}

	return true
}

// find is the index of the first record sel selects by subdomain, type
// and value, or -1.
func (f *fake) find(z *fakeZone, sel fakeRecord) int {
	apex := func(s string) string { return strings.TrimPrefix(s, "@") }

	for i, rec := range z.records {
		if apex(rec.Subdomain) == apex(sel.Subdomain) && rec.Type == sel.Type && rec.Value == sel.Value {
			return i
		}
	}

	return -1
}

// body is the last request body sent to "METHOD path", decoded.
func (f *fake) body(key string) map[string]any {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()

	var out map[string]any
	if err := json.Unmarshal([]byte(f.bodies[key]), &out); err != nil {
		f.t.Fatalf("%s body %q: %v", key, f.bodies[key], err)
	}

	return out
}
