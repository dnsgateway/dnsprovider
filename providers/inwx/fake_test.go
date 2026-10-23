package inwx_test

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is HMAC-SHA1.
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/inwx"
)

// Test credentials. The password holds characters a URL escapes.
const (
	username     = "fakeuser"
	password     = "pa ss&w0rd/x"
	sharedSecret = "JBSWY3DPEHPK3PXP"
)

// lost is the status of a scripted reply whose answer is lost: the
// connection closes after the request was read.
const lost = -1

// messages are DomRobot's result messages, from its API documentation's
// result code table.
var messages = map[int]string{
	1000: "Command completed successfully",
	1001: "Command completed successfully; action pending",
	1500: "Command completed successfully; ending session",
	2000: "Unknown command",
	2003: "Required parameter missing",
	2005: "Parameter value syntax error",
	2200: "Authentication error",
	2201: "Authorization error",
	2202: "Invalid authorization information",
	2302: "Object exists",
	2303: "Object does not exist",
	2400: "Command failed",
	2502: "Session limit exceeded; server closing connection",
}

// reply is a scripted answer: an HTTP status, or lost, and a body.
type reply struct {
	status int
	body   string
}

// call is a request the fake received.
type call struct {
	method string
	params map[string]any
	cookie string
}

// request is a call being answered: a handler reads its params and
// session, and may set response headers.
type request struct {
	call

	header http.Header
}

// handler answers a JSON-RPC method with a JSON body.
type handler func(r *request) string

// fakeZone is a zone INWX hosts: its fields and its records, kept as
// decoded from the fixture so that each keeps its JSON types.
type fakeZone struct {
	fields  map[string]any // roId, domain, type, masterIp, SOAserial
	records []map[string]any
}

func (z *fakeZone) name() string { return z.fields["domain"].(string) }

// fake is a DomRobot JSON-RPC server in memory. It routes on the
// method, models account.login with the domrobot cookie, two-factor
// authentication through account.unlock with a TOTP code for the fake's
// clock and secret, session expiry, logout and a session cap, and holds
// zones, with account-wide record IDs, and registered domains. Each
// method can be scripted to answer once with a status and body, or to
// lose its answer, and replaced with handle.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	tfa         bool            // the account has 2FA
	secret      []byte          // the 2FA shared secret
	sessions    map[string]bool // live session cookie to unlocked
	logins      int
	logouts     int
	maxSessions int // 0 for no cap
	pageCap     int // the largest page nameserver.list answers; 0 for none
	calls       []call
	once        map[string][]reply
	methods     map[string]handler
	zones       []*fakeZone       // in roId order
	registered  map[string]string // domain to its domain.info fixture
	tans        []string          // the TOTP codes account.unlock was sent
}

func newFake(t *testing.T) *fake {
	t.Helper()

	f := &fake{
		t:          t,
		sessions:   map[string]bool{},
		once:       map[string][]reply{},
		registered: map[string]string{"example.net": "domain_info.json"},
	}

	for _, file := range []string{"nameserver_info_example_com.json", "nameserver_info_example_org.json", "nameserver_info_slave_example_net.json"} {
		f.zones = append(f.zones, zoneFixture(t, file))
	}

	f.methods = map[string]handler{
		"account.login":   f.login,
		"account.unlock":  f.unlock,
		"account.logout":  f.logout,
		"account.info":    func(*request) string { return fixture(t, "account_info.json") },
		"nameserver.list": f.list,
		"nameserver.info": f.info,
		"domain.info":     f.domainInfo,
		// Zone writes: zone_writes_fake_test.go.
		"nameserver.create": f.createZone,
		"nameserver.delete": f.deleteZone,
	}

	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)

	return f
}

// zoneFixture is the zone a nameserver.info fixture answers.
func zoneFixture(t testing.TB, file string) *fakeZone {
	t.Helper()

	var answer struct {
		ResData map[string]any `json:"resData"`
	}
	if err := json.Unmarshal([]byte(fixture(t, file)), &answer); err != nil {
		t.Fatal(err)
	}

	z := &fakeZone{fields: answer.ResData}
	for _, r := range answer.ResData["record"].([]any) {
		z.records = append(z.records, r.(map[string]any))
	}

	delete(z.fields, "record")
	delete(z.fields, "count")

	return z
}

func mustURL(t testing.TB, s string) *url.URL {
	t.Helper()

	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}

	return u
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

// enableTFA turns on two-factor authentication for the account, with
// sharedSecret.
func (f *fake) enableTFA() {
	key, err := base32.StdEncoding.DecodeString(sharedSecret)
	if err != nil {
		f.t.Fatal(err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.tfa, f.secret = true, key
}

// provider builds a Provider for the fake with the test credentials,
// and the shared secret when the account has 2FA.
func (f *fake) provider(opts ...dnsprovider.Option) *inwx.Provider {
	f.t.Helper()

	cfg := inwx.Config{Username: username, Password: password}
	if f.tfa {
		cfg.SharedSecret = sharedSecret
	}

	return f.providerWith(cfg, opts...)
}

// providerWith builds a Provider for the fake with cfg.
func (f *fake) providerWith(cfg inwx.Config, opts ...dnsprovider.Option) *inwx.Provider {
	f.t.Helper()

	p, err := inwx.New(cfg, append([]dnsprovider.Option{dnsprovider.WithBaseURL(f.srv.URL + "/jsonrpc/"), dnsprovider.WithHTTPClient(f.srv.Client())}, opts...)...)
	if err != nil {
		f.t.Fatal(err)
	}

	return p
}

// handle replaces the handler of a method.
func (f *fake) handle(method string, h handler) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.methods[method] = h
}

// script answers the next call of method not yet scripted with status
// (or lost) and body. In body, {cookie} stands for the call's session
// cookie and {tan} for the last TOTP code account.unlock took.
func (f *fake) script(method string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.once[method] = append(f.once[method], reply{status, body})
}

// scriptCode answers the next call of method not yet scripted with
// HTTP 200 and the result code, with reason.
func (f *fake) scriptCode(method string, code int, reason string) {
	f.script(method, http.StatusOK, refusal(code, reason))
}

// expire ends every live session, as INWX does when one times out.
func (f *fake) expire() {
	f.mu.Lock()
	defer f.mu.Unlock()

	clear(f.sessions)
}

// count is the number of calls of method.
func (f *fake) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0

	for _, c := range f.calls {
		if c.method == method {
			n++
		}
	}

	return n
}

// methodsCalled is every call's method, in order.
func (f *fake) methodsCalled() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.method)
	}

	return out
}

// params is the params of the last call of method; nil when none.
func (f *fake) params(method string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, c := range slices.Backward(f.calls) {
		if c.method == method {
			return c.params
		}
	}

	return nil
}

// stats is the number of logins, of logouts and of live sessions.
func (f *fake) stats() (logins, logouts, live int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.logins, f.logouts, len(f.sessions)
}

// answer is a DomRobot answer of a result code, with resData when not
// nil.
func answer(code int, resData any) string {
	a := map[string]any{"code": code, "msg": messages[code]}
	if resData != nil {
		a["resData"] = resData
	}

	data, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}

	return string(data)
}

// refusal is a DomRobot answer of a refusal code, with a reason when
// not empty.
func refusal(code int, reason string) string {
	a := map[string]any{"code": code, "msg": messages[code]}
	if reason != "" {
		a["reason"], a["reasonCode"] = reason, "SYNTHETIC"
	}

	data, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}

	return string(data)
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	var rpc struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}

	if r.Method != http.MethodPost || r.URL.Path != "/jsonrpc/" || json.Unmarshal(body, &rpc) != nil {
		f.t.Errorf("not a JSON-RPC call: %s %s %s", r.Method, r.URL.Path, body)
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	cookie := ""
	if c, err := r.Cookie("domrobot"); err == nil {
		cookie = c.Value
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	c := call{method: rpc.Method, params: rpc.Params, cookie: cookie}
	f.calls = append(f.calls, c)

	if tan, ok := rpc.Params["tan"].(string); ok && rpc.Method == "account.unlock" {
		f.tans = append(f.tans, tan)
	}

	if rpc.Params["lang"] != "en" {
		f.t.Errorf("%s sent without lang en: %s", rpc.Method, body)
	}

	w.Header().Set("Content-Type", "application/json")

	if queue := f.once[rpc.Method]; len(queue) > 0 {
		rep := queue[0]
		f.once[rpc.Method] = queue[1:]

		if rep.status == lost {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}

			return
		}

		last := ""
		if len(f.tans) > 0 {
			last = f.tans[len(f.tans)-1]
		}

		w.WriteHeader(rep.status)
		_, _ = io.WriteString(w, strings.NewReplacer("{cookie}", cookie, "{tan}", last).Replace(rep.body))

		return
	}

	h, ok := f.methods[rpc.Method]
	if !ok {
		_, _ = io.WriteString(w, refusal(2000, ""))

		return
	}

	unlocked, live := f.sessions[cookie]

	switch rpc.Method {
	case "account.login":
	case "account.unlock", "account.logout":
		if !live {
			_, _ = io.WriteString(w, refusal(2200, ""))

			return
		}
	default:
		// SYNTHETIC: the code INWX answers for a call without a live,
		// unlocked session is not documented; the fake answers 2200.
		if !live || !unlocked {
			_, _ = io.WriteString(w, refusal(2200, ""))

			return
		}
	}

	_, _ = io.WriteString(w, h(&request{call: c, header: w.Header()}))
}

// login opens a session for the test credentials, locked until
// account.unlock when the account has 2FA.
func (f *fake) login(r *request) string {
	if r.params["user"] != username || r.params["pass"] != password {
		return refusal(2200, "")
	}

	if f.maxSessions > 0 && len(f.sessions) >= f.maxSessions {
		return refusal(2502, "")
	}

	f.logins++
	cookie := fmt.Sprintf("fakecookie%02d", f.logins)
	f.sessions[cookie] = !f.tfa

	r.header.Add("Set-Cookie", (&http.Cookie{Name: "domrobot", Value: cookie, Path: "/", HttpOnly: true}).String())

	if f.tfa {
		return fixture(f.t, "account_login_tfa.json")
	}

	return fixture(f.t, "account_login.json")
}

// unlock unlocks the session with a TOTP code of the shared secret, for
// the fake's clock give or take one step.
func (f *fake) unlock(r *request) string {
	tan, _ := r.params["tan"].(string)

	now := time.Now().Unix() / 30
	for _, step := range []int64{now - 1, now, now + 1} {
		if tan == totp(f.secret, step) {
			f.sessions[r.cookie] = true

			return fixture(f.t, "ok.json")
		}
	}

	// SYNTHETIC: the answer to a wrong code is not documented.
	return refusal(2200, "")
}

// totp is the RFC 6238 code of key for a 30-second step: HMAC-SHA1, six
// digits.
func totp(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	return fmt.Sprintf("%06d", code%1_000_000)
}

func (f *fake) logout(r *request) string {
	delete(f.sessions, r.cookie)
	f.logouts++

	return fixture(f.t, "account_logout.json")
}

// number is a JSON param as an int; def when missing.
func number(v any, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i
		}
	}

	return def
}

// list answers nameserver.list for domain "*", a page at a time, at
// most pageCap zones a page when set.
func (f *fake) list(r *request) string {
	if r.params["domain"] != "*" {
		f.t.Errorf("nameserver.list for domain %v, want *", r.params["domain"])
	}

	page, limit := number(r.params["page"], 1), number(r.params["pagelimit"], 20)
	if f.pageCap > 0 {
		limit = min(limit, f.pageCap)
	}

	domains := []any{}

	for i, z := range f.zones {
		if i >= (page-1)*limit && i < page*limit {
			d := map[string]any{"roId": z.fields["roId"], "domain": z.name(), "type": z.fields["type"]}
			if ip, ok := z.fields["masterIp"]; ok {
				d["masterIp"] = ip
			}

			domains = append(domains, d)
		}
	}

	return answer(1000, map[string]any{"count": len(f.zones), "domains": domains})
}

// zone is the zone of a call's domain or roId param; nil when none.
func (f *fake) zone(params map[string]any) *fakeZone {
	for _, z := range f.zones {
		if d, ok := params["domain"].(string); ok && strings.EqualFold(d, z.name()) {
			return z
		}

		if id, ok := params["roId"]; ok && number(id, -1) == number(z.fields["roId"], -2) {
			return z
		}
	}

	return nil
}

// info answers nameserver.info: the zone and its records, filtered by
// the type, name and recordId params.
func (f *fake) info(r *request) string {
	z := f.zone(r.params)
	if z == nil {
		return refusal(2303, "")
	}

	records := []any{}

	for _, rec := range z.records {
		if typ, ok := r.params["type"].(string); ok && !strings.EqualFold(typ, rec["type"].(string)) {
			continue
		}

		if name, ok := r.params["name"].(string); ok && !strings.EqualFold(name, rec["name"].(string)) {
			continue
		}

		if id, ok := r.params["recordId"]; ok && fmt.Sprint(id) != fmt.Sprint(rec["id"]) {
			continue
		}

		records = append(records, rec)
	}

	res := map[string]any{"count": len(records), "record": records}
	maps.Copy(res, z.fields)

	return answer(1000, res)
}

// domainInfo answers domain.info for a registered domain.
func (f *fake) domainInfo(r *request) string {
	name, _ := r.params["domain"].(string)

	file, ok := f.registered[strings.ToLower(name)]
	if !ok {
		return refusal(2303, "")
	}

	return fixture(f.t, file)
}
