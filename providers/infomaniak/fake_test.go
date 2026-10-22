package infomaniak_test

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/infomaniak"
)

// token is the test API token. It holds characters a URL escapes, so a
// leak shows in any encoding of it.
const token = "tok-S3CR3T/value+1"

// accountID is the Account the fake's domains belong to.
const accountID = "12345"

// fake is an Infomaniak API v2 server in memory. It checks the Bearer
// token, serves the fixtures in testdata in Infomaniak's envelope, pages
// a list when asked for a page, at most perPage items a page, and answers
// a call once with a scripted reply when told to.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	perPage  int                // the most items a page holds
	files    map[string]string  // "METHOD path" to a testdata file
	once     map[string][]reply // "METHOD path" to replies, each sent once
	requests []*http.Request    // every request, in order
	bodies   []string           // the body of every request, in order
}

// lost is the status of a scripted reply whose answer is lost: the fake
// closes the connection without answering.
const lost = -1

type reply struct {
	status int
	body   string
	header http.Header
}

func newFake(t *testing.T) *fake {
	t.Helper()

	f := &fake{
		t:       t,
		perPage: 5,
		once:    map[string][]reply{},
		files: map[string]string{
			"GET /2/domains/domains":          "domains.json",
			"GET /2/zones/example.ch":         "zone.json",
			"GET /2/zones/example.ch/records": "records.json",
		},
	}

	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)

	return f
}

// provider builds a Provider for the fake with the test token.
func (f *fake) provider(opts ...dnsprovider.Option) *infomaniak.Provider {
	f.t.Helper()

	return f.providerFor(infomaniak.Config{Token: token}, opts...)
}

func (f *fake) providerFor(cfg infomaniak.Config, opts ...dnsprovider.Option) *infomaniak.Provider {
	f.t.Helper()

	p, err := infomaniak.New(cfg, append([]dnsprovider.Option{dnsprovider.WithBaseURL(f.srv.URL), dnsprovider.WithHTTPClient(f.srv.Client())}, opts...)...)
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

// script answers the next request for "METHOD path" not yet scripted
// with status and body, and the header pairs given.
func (f *fake) script(key string, status int, body string, header ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	h := http.Header{}
	for i := 0; i+1 < len(header); i += 2 {
		h.Set(header[i], header[i+1])
	}

	f.once[key] = append(f.once[key], reply{status, body, h})
}

// serveFile sets the testdata file answering "METHOD path".
func (f *fake) serveFile(key, file string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.files[key] = file
}

// queries are the queries of every request for "METHOD path", in order.
func (f *fake) queries(key string) []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []url.Values

	for _, r := range f.requests {
		if r.Method+" "+r.URL.Path == key {
			out = append(out, r.URL.Query())
		}
	}

	return out
}

// sent are the bodies of every request for "METHOD path", in order.
func (f *fake) sent(key string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []string

	for i, r := range f.requests {
		if r.Method+" "+r.URL.Path == key {
			out = append(out, f.bodies[i])
		}
	}

	return out
}

// writes are the bodies of every POST request, by path, in order.
func (f *fake) writes() map[string][]string {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := map[string][]string{}

	for i, r := range f.requests {
		if r.Method == http.MethodPost {
			out[r.URL.Path] = append(out[r.URL.Path], f.bodies[i])
		}
	}

	return out
}

func (f *fake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.requests)
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path

	f.mu.Lock()
	defer f.mu.Unlock()

	sent, _ := io.ReadAll(r.Body)

	f.requests = append(f.requests, r)
	f.bodies = append(f.bodies, string(sent))

	w.Header().Set("Content-Type", "application/json")

	if r.Header.Get("Authorization") != "Bearer "+token {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(fixture(f.t, "not_authorized.json")))

		return
	}

	if queue := f.once[key]; len(queue) > 0 {
		rep := queue[0]
		f.once[key] = queue[1:]

		if rep.status == lost {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}

			return
		}

		maps.Copy(w.Header(), rep.header)

		w.WriteHeader(rep.status)
		_, _ = w.Write([]byte(rep.body))

		return
	}

	file, ok := f.files[key]
	if !ok {
		w.WriteHeader(http.StatusNotFound)

		if strings.HasPrefix(r.URL.Path, "/2/zones/") {
			_, _ = w.Write([]byte(fixture(f.t, "zone_does_not_exists.json")))
		} else {
			_, _ = w.Write([]byte(fixture(f.t, "object_not_found.json")))
		}

		return
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fixture(f.t, file)), &body); err != nil {
		f.t.Fatal(err)
	}

	var items []map[string]any
	if json.Unmarshal(body["data"], &items) == nil && items != nil {
		body = f.page(r.URL.Query(), f.filter(r.URL.Query(), items))
	}

	out, _ := json.Marshal(body)
	_, _ = w.Write(out)
}

// filter keeps the items an account_id, search or filter[types][] query
// selects. search keeps the names holding it, as a substring.
func (f *fake) filter(q url.Values, items []map[string]any) []map[string]any {
	out := []map[string]any{}

	for _, it := range items {
		if id := q.Get("account_id"); id != "" && id != accountID {
			continue
		}

		if s := q.Get("search"); s != "" {
			if name, _ := it["name"].(string); !strings.Contains(strings.ToLower(name), strings.ToLower(s)) {
				continue
			}
		}

		if types := q["filter[types][]"]; len(types) > 0 && !contains(types, it["type"]) {
			continue
		}

		out = append(out, it)
	}

	return out
}

func contains(list []string, v any) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}

	return false
}

// page is a list answer: the page asked for with its paging fields when
// the query has a page, or the first per_page items without them.
func (f *fake) page(q url.Values, items []map[string]any) map[string]json.RawMessage {
	size := f.perPage
	if n, err := strconv.Atoi(q.Get("per_page")); err == nil && n > 0 && n < size {
		size = n
	}

	raw := func(v any) json.RawMessage {
		b, _ := json.Marshal(v)

		return b
	}

	if q.Get("page") == "" {
		return map[string]json.RawMessage{"result": raw("success"), "data": raw(items[:min(size, len(items))])}
	}

	page, _ := strconv.Atoi(q.Get("page"))
	pages := (len(items) + size - 1) / size
	from := min(max(page-1, 0)*size, len(items))

	return map[string]json.RawMessage{
		"result": raw("success"), "data": raw(items[from:min(from+size, len(items))]),
		"total": raw(len(items)), "page": raw(page), "pages": raw(pages), "items_per_page": raw(size),
	}
}
