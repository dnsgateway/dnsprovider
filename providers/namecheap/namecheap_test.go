package namecheap_test

// Seam 2: the Namecheap Provider against an httptest server that speaks
// the Namecheap XML API's request parameters and response shapes.

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
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
	"github.com/dnsgateway/dnsprovider/providers/namecheap"
)

var testConfig = namecheap.Config{User: "apiuser", Key: "apikey", ClientIP: "192.0.2.10"}

// ncDomain is one domain of the scripted Account.
type ncDomain struct {
	Name   string
	OurDNS bool
}

// ncHost is one host of a domain, as getHosts answers it.
type ncHost struct {
	ID, Name, Type, Address string
	MXPref, TTL             int
}

// ncError is one error of an ERROR response.
type ncError struct {
	Number int
	Text   string
}

// ncAPI is a scripted Namecheap XML API. getList pages domains PageSize at
// a time by Page, from 1; getHosts answers a domain's whole host list.
type ncAPI struct {
	domains []ncDomain
	hosts   map[string][]ncHost // by domain
	// emailType is a domain's EmailType; "MX" when not set.
	emailType map[string]string

	// servedPageSize, when set, is the page size getList serves whatever
	// PageSize asks for.
	servedPageSize int
	// noPaging leaves the Paging element out of getList answers.
	noPaging bool
	// stuckPage makes getList answer page 1 whatever Page asks for.
	stuckPage bool
	// ignoreSearch makes getList list every domain whatever SearchTerm
	// asks for.
	ignoreSearch bool
	// setHostsFalse makes setHosts answer OK with IsSuccess="false" and
	// change nothing.
	setHostsFalse bool
	// concurrent, when set, is another writer's setHosts landing right
	// after each of ours: the hosts it leaves, given the ones ours set.
	concurrent func(hosts []ncHost) []ncHost

	// fail, when it returns errors, answers the request with Status="ERROR".
	fail func(command string) []ncError
	// httpStatus, when it returns a status, answers the request with it
	// and an HTML page; lostAnswer drops the connection with no answer.
	httpStatus func(command string) int

	mu sync.Mutex
	// requests records each request's parameters, query and form.
	requests []url.Values
}

// Requests returns each request's parameters, in order.
func (api *ncAPI) Requests() []url.Values {
	api.mu.Lock()
	defer api.mu.Unlock()

	return slices.Clone(api.requests)
}

// Commands returns each request's Command, in order.
func (api *ncAPI) Commands() []string {
	var out []string
	for _, r := range api.Requests() {
		out = append(out, r.Get("Command"))
	}

	return out
}

// lostAnswer is an httpStatus that drops the connection with no answer.
const lostAnswer = -1

func newProvider(t *testing.T, api *ncAPI) dnsprovider.Provider {
	t.Helper()

	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)

	p, err := namecheap.New(testConfig, dnsprovider.WithBaseURL(srv.URL+"/xml.response"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return p
}

func (api *ncAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/xml.response" {
			t.Errorf("request to %s, want /xml.response", r.URL.Path)
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}

		api.mu.Lock()
		api.requests = append(api.requests, r.Form)
		api.mu.Unlock()

		cmd := r.Form.Get("Command")

		if api.httpStatus != nil {
			switch status := api.httpStatus(cmd); status {
			case 0:
			case lostAnswer:
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("Hijack: %v", err)

					return
				}

				_ = conn.Close()

				return
			default:
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`<html>error</html>`))

				return
			}
		}

		if api.fail != nil {
			if errs := api.fail(cmd); len(errs) > 0 {
				writeErrors(w, errs...)

				return
			}
		}

		switch cmd {
		case "namecheap.domains.getList":
			api.getList(w, r)
		case "namecheap.domains.dns.getHosts":
			api.getHosts(w, r)
		case "namecheap.domains.dns.setHosts":
			api.setHosts(w, r)
		case "namecheap.users.getBalances":
			writeOK(w, cmd, `<UserGetBalancesResult Currency="USD" AvailableBalance="4932.96" AccountBalance="4932.96" EarnedAmount="381.70" WithdrawableAmount="1243.36" FundsRequiredForAutoRenew="0.00" />`)
		default:
			writeErrors(w, ncError{1010104, "Command " + cmd + " is invalid"})
		}
	})
}

func (api *ncAPI) getList(w http.ResponseWriter, r *http.Request) {
	size, err := strconv.Atoi(r.Form.Get("PageSize"))
	if err != nil || size < 10 || size > 100 {
		size = 20
	}

	if api.servedPageSize > 0 {
		size = api.servedPageSize
	}

	page, err := strconv.Atoi(r.Form.Get("Page"))
	if err != nil || page < 1 || api.stuckPage {
		page = 1
	}

	listed := api.domains
	if term := r.Form.Get("SearchTerm"); term != "" && !api.ignoreSearch {
		listed = nil

		for _, d := range api.domains {
			if strings.Contains(strings.ToLower(d.Name), strings.ToLower(term)) {
				listed = append(listed, d)
			}
		}
	}

	start := min((page-1)*size, len(listed))

	var b strings.Builder

	b.WriteString(`<DomainGetListResult>`)

	for _, d := range listed[start:min(start+size, len(listed))] {
		fmt.Fprintf(&b, `<Domain ID="%d" Name="%s" User="apiuser" Created="02/15/2024" Expires="02/15/2027" IsExpired="false" IsLocked="false" AutoRenew="true" WhoisGuard="ENABLED" IsPremium="false" IsOurDNS="%t"/>`,
			len(d.Name), d.Name, d.OurDNS)
	}

	b.WriteString(`</DomainGetListResult>`)

	if !api.noPaging {
		fmt.Fprintf(&b, `<Paging><TotalItems>%d</TotalItems><CurrentPage>%d</CurrentPage><PageSize>%d</PageSize></Paging>`,
			len(listed), page, size)
	}

	writeOK(w, "namecheap.domains.getList", b.String())
}

func (api *ncAPI) getHosts(w http.ResponseWriter, r *http.Request) {
	domain := r.Form.Get("SLD") + "." + r.Form.Get("TLD")

	hosts, ok := api.hosts[domain]
	if !ok {
		writeErrors(w, ncError{2019166, "Domain not found"})

		return
	}

	var b strings.Builder

	fmt.Fprintf(&b, `<DomainDNSGetHostsResult Domain="%s" EmailType="%s" IsUsingOurDNS="true">`, domain, api.emailTypeOf(domain))

	for _, h := range hosts {
		fmt.Fprintf(&b, `<host HostId="%s" Name="%s" Type="%s" Address="%s" MXPref="%d" TTL="%d" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false"/>`,
			h.ID, xmlEscape(h.Name), h.Type, xmlEscape(h.Address), h.MXPref, h.TTL)
	}

	b.WriteString(`</DomainDNSGetHostsResult>`)

	writeOK(w, "namecheap.domains.dns.getHosts", b.String())
}

func (api *ncAPI) emailTypeOf(domain string) string {
	if t, ok := api.emailType[domain]; ok {
		return t
	}

	return "MX"
}

// setHosts replaces a domain's hosts with the numbered HostNameN,
// RecordTypeN, AddressN, MXPrefN and TTLN form fields, from 1, giving
// each a new HostId as Namecheap does.
func (api *ncAPI) setHosts(w http.ResponseWriter, r *http.Request) {
	domain := r.Form.Get("SLD") + "." + r.Form.Get("TLD")

	if _, ok := api.hosts[domain]; !ok {
		writeErrors(w, ncError{2019166, "Domain not found"})

		return
	}

	if api.setHostsFalse {
		writeOK(w, "namecheap.domains.dns.setHosts",
			fmt.Sprintf(`<DomainDNSSetHostsResult Domain="%s" IsSuccess="false"><Warnings /></DomainDNSSetHostsResult>`, domain))

		return
	}

	hosts := sentHosts(r.Form)
	for i := range hosts {
		hosts[i].ID = strconv.Itoa(1000 + i)
	}

	if api.concurrent != nil {
		hosts = api.concurrent(hosts)
	}

	api.mu.Lock()
	api.hosts[domain] = hosts

	if api.emailType == nil {
		api.emailType = map[string]string{}
	}

	api.emailType[domain] = r.Form.Get("EmailType")
	api.mu.Unlock()

	writeOK(w, "namecheap.domains.dns.setHosts",
		fmt.Sprintf(`<DomainDNSSetHostsResult Domain="%s" IsSuccess="true"><Warnings /></DomainDNSSetHostsResult>`, domain))
}

// sentHost is one host of a setHosts request, as sent. MXPref is "" when
// the request left it out.
type sentHost struct {
	Name, Type, Address, MXPref, TTL string
}

// sentHosts reads the numbered host fields of a setHosts form.
func sentHosts(form url.Values) []ncHost {
	var out []ncHost

	for _, h := range sentHostFields(form) {
		pref, _ := strconv.Atoi(h.MXPref)
		ttl, _ := strconv.Atoi(h.TTL)
		out = append(out, ncHost{Name: h.Name, Type: h.Type, Address: h.Address, MXPref: pref, TTL: ttl})
	}

	return out
}

func sentHostFields(form url.Values) []sentHost {
	var out []sentHost

	for i := 1; form.Has("HostName" + strconv.Itoa(i)); i++ {
		n := strconv.Itoa(i)
		out = append(out, sentHost{
			Name: form.Get("HostName" + n), Type: form.Get("RecordType" + n), Address: form.Get("Address" + n),
			MXPref: form.Get("MXPref" + n), TTL: form.Get("TTL" + n),
		})
	}

	return out
}

// setHostsSent returns the parameters of every setHosts request.
func (api *ncAPI) setHostsSent() []url.Values {
	var out []url.Values

	for _, r := range api.Requests() {
		if r.Get("Command") == "namecheap.domains.dns.setHosts" {
			out = append(out, r)
		}
	}

	return out
}

func xmlEscape(s string) string {
	var b strings.Builder

	_ = xml.EscapeText(&b, []byte(s))

	return b.String()
}

// writeOK answers a command with Status="OK" and its CommandResponse body.
func writeOK(w http.ResponseWriter, command, body string) {
	w.Header().Set("Content-Type", "text/xml")
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors />
  <Warnings />
  <RequestedCommand>%s</RequestedCommand>
  <CommandResponse Type="%s">%s</CommandResponse>
  <Server>PHX01APIEXT01</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>0.01</ExecutionTime>
</ApiResponse>`, command, command, body)
}

// writeErrors answers with Status="ERROR" and HTTP 200, as Namecheap does.
func writeErrors(w http.ResponseWriter, errs ...ncError) {
	var b strings.Builder
	for _, e := range errs {
		fmt.Fprintf(&b, `<Error Number="%d">%s</Error>`, e.Number, xmlEscape(e.Text))
	}

	w.Header().Set("Content-Type", "text/xml")
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
  <Errors>%s</Errors>
  <Warnings />
  <RequestedCommand />
  <Server>PHX01APIEXT01</Server>
  <GMTTimeDifference>--5:00</GMTTimeDifference>
  <ExecutionTime>0.01</ExecutionTime>
</ApiResponse>`, b.String())
}

func TestEveryRequestCarriesTheConfigsAuthParameters(t *testing.T) {
	api := &ncAPI{
		domains: []ncDomain{{"example.com", true}},
		hosts:   map[string][]ncHost{"example.com": {{ID: "1", Name: "@", Type: "A", Address: "192.0.2.1", TTL: 1800}}},
	}
	p := newProvider(t, api)

	if _, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err != nil {
		t.Fatalf("Zones: %v", err)
	}

	if _, err := p.ListRecords(context.Background(), example, dnsprovider.RecordFilter{}); err != nil {
		t.Fatalf("Records: %v", err)
	}

	want := map[string]string{"ApiUser": "apiuser", "UserName": "apiuser", "ApiKey": "apikey", "ClientIp": "192.0.2.10"}

	reqs := api.Requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %v, want one getList and one getHosts", api.Commands())
	}

	for _, r := range reqs {
		for k, v := range want {
			if got := r.Get(k); got != v {
				t.Errorf("%s request: %s = %q, want %q", r.Get("Command"), k, got, v)
			}
		}
	}
}

var example = dnsprovider.Zone{Name: "example.com", ID: "example.com"}

func TestZonesAreTheDomainsOnNamecheapDNSOnEveryPage(t *testing.T) {
	api := &ncAPI{}

	var want []string

	for i := range 205 {
		d := ncDomain{Name: fmt.Sprintf("d%03d.example", i), OurDNS: i%7 != 3}
		api.domains = append(api.domains, d)

		if d.OurDNS {
			want = append(want, d.Name+"="+d.Name)
		}
	}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	if set.Partial {
		t.Error("Zones is a Partial View, want a Full View")
	}

	zones := set.Zones

	var got []string

	for _, z := range zones {
		got = append(got, z.Name+"="+z.ID)

		if z.Nameservers != nil {
			t.Errorf("Zone %s has nameservers %v, want nil", z.Name, z.Nameservers)
		}
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v,\nwant %v", got, want)
	}

	var pages []string
	for _, r := range api.Requests() {
		pages = append(pages, r.Get("Command")+" page "+r.Get("Page")+" of "+r.Get("PageSize"))
	}

	wantPages := []string{
		"namecheap.domains.getList page 1 of 100",
		"namecheap.domains.getList page 2 of 100",
		"namecheap.domains.getList page 3 of 100",
	}
	if !reflect.DeepEqual(pages, wantPages) {
		t.Errorf("requests = %v, want %v", pages, wantPages)
	}
}

// domains returns n domains on Namecheap DNS, and their names.
func domains(n int) ([]ncDomain, []string) {
	var (
		ds    []ncDomain
		names []string
	)

	for i := range n {
		ds = append(ds, ncDomain{Name: fmt.Sprintf("d%03d.example", i), OurDNS: true})
		names = append(names, ds[i].Name)
	}

	return ds, names
}

func zoneNames(zones []dnsprovider.Zone) []string {
	var out []string
	for _, z := range zones {
		out = append(out, z.Name)
	}

	return out
}

func TestZonesPushTheNameFilterToSearchTerm(t *testing.T) {
	api := &ncAPI{domains: []ncDomain{
		{Name: "example.com", OurDNS: true},
		{Name: "shop-example.net", OurDNS: true},
		{Name: "other.org", OurDNS: true},
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "Example"})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	if got, want := zoneNames(zones), []string{"example.com", "shop-example.net"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}

	if reqs := api.Requests(); len(reqs) != 1 || reqs[0].Get("SearchTerm") != "example" {
		t.Errorf("requests = %v, want one getList with SearchTerm example", reqs)
	}
}

func TestZonesKeepOnlyMatchesWhenNamecheapSearchesLoosely(t *testing.T) {
	api := &ncAPI{ignoreSearch: true}
	api.domains, _ = domains(150)

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "d12"})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	want := []string{
		"d120.example", "d121.example", "d122.example", "d123.example", "d124.example",
		"d125.example", "d126.example", "d127.example", "d128.example", "d129.example",
	}
	if got := zoneNames(zones); !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}
}

func TestZonesAreActive(t *testing.T) {
	api := &ncAPI{}
	api.domains, _ = domains(3)

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	for _, z := range zones {
		if z.State != dnsprovider.HostingActive {
			t.Errorf("Zone %s is %v, want Active: Namecheap lists only the domains on its DNS", z.Name, z.State)
		}
	}
}

func TestZoneReadsOneDomainOnNamecheapDNSByItsExactName(t *testing.T) {
	api := &ncAPI{domains: []ncDomain{
		{Name: "shop-example.com", OurDNS: true},
		{Name: "example.com", OurDNS: true},
	}}

	got, err := newProvider(t, api).GetZone(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatalf("Zone: %v", err)
	}

	if want := (dnsprovider.Zone{ID: "example.com", Name: "example.com", State: dnsprovider.HostingActive}); !reflect.DeepEqual(got, want) {
		t.Errorf("Zone = %+v, want %+v", got, want)
	}

	if reqs := api.Requests(); len(reqs) != 1 || reqs[0].Get("Command") != "namecheap.domains.getList" || reqs[0].Get("SearchTerm") != "example.com" {
		t.Errorf("requests = %v, want one getList with SearchTerm example.com", reqs)
	}
}

func TestZoneOfADomainNotOnNamecheapDNSIsNotFound(t *testing.T) {
	api := &ncAPI{domains: []ncDomain{
		{Name: "shop-example.com", OurDNS: true},
		{Name: "elsewhere.com", OurDNS: false},
	}}
	p := newProvider(t, api)

	for _, name := range []string{"example.com", "elsewhere.com"} {
		if _, err := p.GetZone(context.Background(), name); !errors.Is(err, dnsprovider.ErrNotFound) {
			t.Errorf("Zone(%s): err = %v, want ErrNotFound", name, err)
		}
	}
}

func TestZonesReadEveryPageWhenTheAnswerHasNoTotal(t *testing.T) {
	api := &ncAPI{noPaging: true}

	var want []string
	api.domains, want = domains(150)

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	if got := zoneNames(zones); !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %d zones, want %d", len(got), len(want))
	}
}

func TestZonesReadEveryPageWhenNamecheapServesSmallerPages(t *testing.T) {
	api := &ncAPI{servedPageSize: 20}

	var want []string
	api.domains, want = domains(45)

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	if got := zoneNames(zones); !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %d zones, want %d", len(got), len(want))
	}
}

func TestZonesFailWhenTheListAnswersTheSamePageTwice(t *testing.T) {
	api := &ncAPI{stuckPage: true}
	api.domains, _ = domains(250)

	_, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err == nil || !strings.Contains(err.Error(), "same page") {
		t.Errorf("err = %v, want the same page answered twice", err)
	}

	if got := len(api.Commands()); got != 2 {
		t.Errorf("requests = %d, want 2: stop at the repeated page", got)
	}
}

func TestZonesOfAnAccountWithNoDomainsAreNone(t *testing.T) {
	api := &ncAPI{}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	if len(zones) != 0 {
		t.Errorf("Zones = %v, want none", zones)
	}

	if got := api.Commands(); len(got) != 1 {
		t.Errorf("requests = %v, want one getList", got)
	}
}

func TestRecordsAddressTheDomainBySLDAndTLD(t *testing.T) {
	for _, c := range []struct{ zone, sld, tld string }{
		{"example.com", "example", "com"},
		{"example.co.uk", "example", "co.uk"},
	} {
		api := &ncAPI{hosts: map[string][]ncHost{c.zone: nil}}

		if _, err := newProvider(t, api).ListRecords(context.Background(), dnsprovider.Zone{Name: c.zone, ID: c.zone}, dnsprovider.RecordFilter{}); err != nil {
			t.Fatalf("ListRecords(%s): %v", c.zone, err)
		}

		r := api.Requests()[0]
		if r.Get("Command") != "namecheap.domains.dns.getHosts" || r.Get("SLD") != c.sld || r.Get("TLD") != c.tld {
			t.Errorf("ListRecords(%s) sent %s SLD=%q TLD=%q, want getHosts SLD=%q TLD=%q",
				c.zone, r.Get("Command"), r.Get("SLD"), r.Get("TLD"), c.sld, c.tld)
		}
	}
}

func TestRecordsHaveAbsoluteNamesThePriorityFirstAndTheirContentAsID(t *testing.T) {
	api := &ncAPI{hosts: map[string][]ncHost{"example.com": {
		{ID: "11", Name: "@", Type: "A", Address: "192.0.2.1", TTL: 1799},
		{ID: "12", Name: "www", Type: "CNAME", Address: "example.com.", TTL: 1800},
		{ID: "13", Name: "@", Type: "MX", Address: "mx1.example.net.", MXPref: 10, TTL: 3600},
		{ID: "14", Name: "@", Type: "TXT", Address: "v=spf1 include:_spf.example.net ~all", TTL: 1799},
		{ID: "15", Name: "sub", Type: "NS", Address: "ns1.example.net.", TTL: 1800},
		{ID: "16", Name: "@", Type: "CAA", Address: `0 issue "letsencrypt.org"`, TTL: 1800},
		{ID: "17", Name: "*.dev", Type: "AAAA", Address: "2001:db8::1", TTL: 60},
		{ID: "18", Name: "go", Type: "URL", Address: "https://example.org/", TTL: 1800},
		{ID: "19", Name: "old", Type: "URL301", Address: "https://example.org/new", TTL: 1800},
		{ID: "20", Name: "frame", Type: "FRAME", Address: "https://example.org/", TTL: 1800},
		{ID: "21", Name: "alias", Type: "ALIAS", Address: "target.example.net.", TTL: 300},
		{ID: "22", Name: "@", Type: "MXE", Address: "192.0.2.25", TTL: 1800},
		{ID: "23", Name: "Shop", Type: "A", Address: "192.0.2.3", TTL: 300},
	}}}

	set, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	if set.Partial {
		t.Error("Records is a Partial View, want a Full View")
	}

	want := []dnsprovider.Record{
		{ID: "A example.com 1799 192.0.2.1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 1799},
		{ID: "CNAME www.example.com 1800 example.com", Type: "CNAME", Name: "www.example.com", Value: "example.com", TTL: 1800},
		{ID: "MX example.com 3600 10 mx1.example.net", Type: "MX", Name: "example.com", Value: "10 mx1.example.net", TTL: 3600},
		{ID: "TXT example.com 1799 v=spf1 include:_spf.example.net ~all", Type: "TXT", Name: "example.com", Value: "v=spf1 include:_spf.example.net ~all", TTL: 1799},
		{ID: "NS sub.example.com 1800 ns1.example.net", Type: "NS", Name: "sub.example.com", Value: "ns1.example.net", TTL: 1800},
		{ID: `CAA example.com 1800 0 issue "letsencrypt.org"`, Type: "CAA", Name: "example.com", Value: `0 issue "letsencrypt.org"`, TTL: 1800},
		{ID: "AAAA *.dev.example.com 60 2001:db8::1", Type: "AAAA", Name: "*.dev.example.com", Value: "2001:db8::1", TTL: 60},
		{ID: "URL go.example.com 1800 https://example.org/", Type: "URL", Name: "go.example.com", Value: "https://example.org/", TTL: 1800},
		{ID: "URL301 old.example.com 1800 https://example.org/new", Type: "URL301", Name: "old.example.com", Value: "https://example.org/new", TTL: 1800},
		{ID: "FRAME frame.example.com 1800 https://example.org/", Type: "FRAME", Name: "frame.example.com", Value: "https://example.org/", TTL: 1800},
		{ID: "ALIAS alias.example.com 300 target.example.net", Type: "ALIAS", Name: "alias.example.com", Value: "target.example.net", TTL: 300},
		{ID: "MXE example.com 1800 192.0.2.25", Type: "MXE", Name: "example.com", Value: "192.0.2.25", TTL: 1800},
		{ID: "A shop.example.com 300 192.0.2.3", Type: "A", Name: "Shop.example.com", Value: "192.0.2.3", TTL: 300},
	}
	if !reflect.DeepEqual(set.Records, want) {
		t.Errorf("Records =\n%v\nwant\n%v", set.Records, want)
	}

	if set.Serial != 0 {
		t.Errorf("Serial = %d, want 0: Namecheap does not report it", set.Serial)
	}
}

func TestRecordsKeepTheRootTargetAsADot(t *testing.T) {
	api := &ncAPI{hosts: map[string][]ncHost{"example.com": {
		{ID: "31", Name: "@", Type: "MX", Address: ".", MXPref: 0, TTL: 1800},
		{ID: "32", Name: "nil", Type: "CNAME", Address: ".", TTL: 1800},
		{ID: "33", Name: "sub", Type: "NS", Address: ".", TTL: 1800},
		{ID: "34", Name: "alias", Type: "ALIAS", Address: ".", TTL: 300},
	}}}

	set, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	var got []string
	for _, r := range set.Records {
		got = append(got, r.Type+" "+r.Value)
	}

	if want := []string{"MX 0 .", "CNAME .", "NS .", "ALIAS ."}; !reflect.DeepEqual(got, want) {
		t.Errorf("Records = %q, want %q", got, want)
	}
}

func TestSRVRecordsPutTheMXPrefPriorityFirst(t *testing.T) {
	api := &ncAPI{hosts: map[string][]ncHost{"example.com": {
		{ID: "41", Name: "_sip._tcp", Type: "SRV", Address: "5 5060 sip.example.net.", MXPref: 10, TTL: 1800},
		{ID: "42", Name: "_xmpp._tcp.chat", Type: "SRV", Address: "0 5222 xmpp.example.net", MXPref: 20, TTL: 1800},
		{ID: "43", Name: "_none._tcp", Type: "SRV", Address: "0 0 .", MXPref: 0, TTL: 1800},
	}}}

	set, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if err != nil {
		t.Fatalf("Records: %v", err)
	}

	want := []dnsprovider.Record{
		{ID: "SRV _sip._tcp.example.com 1800 10 5 5060 sip.example.net", Type: "SRV", Name: "_sip._tcp.example.com", Value: "10 5 5060 sip.example.net", TTL: 1800},
		{ID: "SRV _xmpp._tcp.chat.example.com 1800 20 0 5222 xmpp.example.net", Type: "SRV", Name: "_xmpp._tcp.chat.example.com", Value: "20 0 5222 xmpp.example.net", TTL: 1800},
		{ID: "SRV _none._tcp.example.com 1800 0 0 0 .", Type: "SRV", Name: "_none._tcp.example.com", Value: "0 0 0 .", TTL: 1800},
	}
	if !reflect.DeepEqual(set.Records, want) {
		t.Errorf("Records =\n%v\nwant\n%v", set.Records, want)
	}
}

func TestRecordsRefuseAnAnswerOverTheSizeLimit(t *testing.T) {
	huge := strings.Repeat("a", 5<<20)
	api := &ncAPI{hosts: map[string][]ncHost{"example.com": {
		{ID: "51", Name: "@", Type: "TXT", Address: huge, TTL: 1800},
	}}}

	set, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})
	if err == nil {
		t.Fatalf("Records = %d records, want an error: the answer is over 4 MiB", len(set.Records))
	}

	if !strings.Contains(err.Error(), "namecheap") {
		t.Errorf("err = %v, want it to name namecheap", err)
	}
}

func TestErrorAnswersAreTypedErrorsWithTheirNumbers(t *testing.T) {
	cases := []struct {
		name string
		errs []ncError
		kind error // nil: classified by nothing
		msg  string
	}{
		{"bad key", []ncError{{1011102, "Parameter APIKey is invalid"}}, dnsprovider.ErrUnauthorized, "1011102: Parameter APIKey is invalid"},
		{"bad user", []ncError{{1011100, "Parameter APIUser is invalid"}}, dnsprovider.ErrUnauthorized, "1011100: Parameter APIUser is invalid"},
		{"API access disabled", []ncError{{1017101, "API access has not been enabled"}}, dnsprovider.ErrUnauthorized, "1017101: API access has not been enabled"},
		{"IP not whitelisted", []ncError{{1011150, "Invalid request IP: 198.51.100.7"}}, dnsprovider.ErrUnauthorized, "1011150: Invalid request IP: 198.51.100.7"},
		{"unknown domain", []ncError{{2019166, "Domain not found"}}, dnsprovider.ErrNotFound, "2019166: Domain not found"},
		{"not the Account's domain", []ncError{{2016166, "Domain is not associated with your account"}}, dnsprovider.ErrNotFound, "2016166: Domain is not associated with your account"},
		{"rate limited", []ncError{{500000, "Too many requests"}}, dnsprovider.ErrRateLimited, "500000: Too many requests"},
		{"domain not on Namecheap DNS", []ncError{{2030288, "Cannot complete this command as this domain is not using proper DNS servers"}}, dnsprovider.ErrNotServed, "2030288: Cannot complete this command"},
		{"unknown number, too many requests", []ncError{{9999901, "Too many requests"}}, dnsprovider.ErrRateLimited, "9999901: Too many requests"},
		{"unknown number, IP not whitelisted", []ncError{{9999902, "Invalid request IP: 198.51.100.7"}}, dnsprovider.ErrUnauthorized, "9999902: Invalid request IP"},
		{"unknown number, IP not on the whitelist", []ncError{{9999903, "Your IP is not whitelisted"}}, dnsprovider.ErrUnauthorized, "9999903: Your IP is not whitelisted"},
		{"unknown number, bad API key", []ncError{{9999904, "API Key is invalid or API access has not been enabled"}}, dnsprovider.ErrUnauthorized, "9999904: API Key is invalid"},
		{"other", []ncError{{3050900, "Unknown error"}, {2030280, "TLD is not supported"}}, nil, "3050900: Unknown error; 2030280: TLD is not supported"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := &ncAPI{
				hosts: map[string][]ncHost{"example.com": nil},
				fail:  func(string) []ncError { return c.errs },
			}

			_, err := newProvider(t, api).ListRecords(context.Background(), example, dnsprovider.RecordFilter{})

			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v, want an APIError", err)
			}

			// A kind matches the kinds it wraps too: ErrNotServed is an ErrNotFound.
			for _, kind := range []error{dnsprovider.ErrUnauthorized, dnsprovider.ErrNotFound, dnsprovider.ErrNotServed, dnsprovider.ErrRateLimited} {
				if want := c.kind != nil && errors.Is(c.kind, kind); errors.Is(err, kind) != want {
					t.Errorf("errors.Is(%v, %v) = %v", err, kind, !want)
				}
			}

			if apiErr.RetryAfter != 0 {
				t.Errorf("RetryAfter = %v, want zero: Namecheap does not say", apiErr.RetryAfter)
			}

			if !strings.Contains(err.Error(), c.msg) {
				t.Errorf("err = %q, want it to hold %q", err, c.msg)
			}

			if strings.Contains(err.Error(), "HTTP") {
				t.Errorf("err = %q, want no HTTP status: the error came in the answer", err)
			}
		})
	}
}

func TestHTTPErrorStatusesAreClassifiedByStatus(t *testing.T) {
	cases := []struct {
		status int
		kind   error
	}{
		{http.StatusTooManyRequests, dnsprovider.ErrRateLimited},
		{http.StatusUnauthorized, dnsprovider.ErrUnauthorized},
		{http.StatusBadGateway, nil},
	}

	for _, c := range cases {
		t.Run(strconv.Itoa(c.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(`<html>error</html>`))
			}))
			t.Cleanup(srv.Close)

			p, err := namecheap.New(testConfig, dnsprovider.WithBaseURL(srv.URL))
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, err = p.ListZones(context.Background(), dnsprovider.ZoneFilter{})

			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != c.status {
				t.Fatalf("err = %v, want an APIError with HTTP %d", err, c.status)
			}

			for _, kind := range []error{dnsprovider.ErrUnauthorized, dnsprovider.ErrNotFound, dnsprovider.ErrRateLimited} {
				if errors.Is(err, kind) != (kind == c.kind) {
					t.Errorf("errors.Is(%v, %v) = %v", err, kind, kind != c.kind)
				}
			}

			if apiErr.RetryAfter != 0 {
				t.Errorf("RetryAfter = %v, want zero", apiErr.RetryAfter)
			}
		})
	}
}

func TestErrorsNeverCarryTheAPIKey(t *testing.T) {
	api := &ncAPI{fail: func(string) []ncError { return []ncError{{1011102, "Parameter APIKey is invalid"}} }}

	_, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err == nil || strings.Contains(err.Error(), "apikey") {
		t.Errorf("err = %v, want an error without the API key", err)
	}

	p, err := namecheap.New(testConfig, dnsprovider.WithBaseURL("http://127.0.0.1:1/xml.response"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := p.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err == nil || strings.Contains(err.Error(), "apikey") {
		t.Errorf("unreachable API: err = %v, want an error without the API key", err)
	}
}

func TestNamecheapTakesTTLsFrom60To60000WithoutAutomaticOrProxy(t *testing.T) {
	p := newProvider(t, &ncAPI{})

	if got, want := dnsprovider.TTLRangeOf(p), (dnsprovider.TTLRange{Min: 60, Max: 60000}); got != want {
		t.Errorf("TTL range = %+v, want %+v", got, want)
	}

	if dnsprovider.AutoTTLOf(p) || dnsprovider.ProxiableTypesOf(p) != nil {
		t.Error("Namecheap has no automatic TTL and no proxy")
	}
}

func TestProvidersOfOneAccountShareItsRateLimit(t *testing.T) {
	srv := httptest.NewServer((&ncAPI{}).handler(t))
	t.Cleanup(srv.Close)

	build := func(cfg namecheap.Config) dnsprovider.Provider {
		p, err := namecheap.New(cfg, dnsprovider.WithBaseURL(srv.URL+"/xml.response"))
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		return p
	}

	first, again := build(testConfig), build(testConfig)

	other := testConfig
	other.User = "otheruser"

	for range namecheap.RequestsPerMinute {
		if _, err := first.ListZones(context.Background(), dnsprovider.ZoneFilter{}); err != nil {
			t.Fatalf("Zones: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if _, err := again.ListZones(ctx, dnsprovider.ZoneFilter{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Zones of a second Provider of the Account = %v, want it held back past the deadline", err)
	}

	if _, err := build(other).ListZones(ctx, dnsprovider.ZoneFilter{}); err != nil {
		t.Errorf("Zones of another Account: %v, want its own rate limit", err)
	}
}

func TestZonesFilteredByAnAbsoluteNameSearchForItWithoutTheDot(t *testing.T) {
	api := &ncAPI{domains: []ncDomain{
		{Name: "example.com", OurDNS: true},
		{Name: "example.community", OurDNS: true},
	}}

	set, err := newProvider(t, api).ListZones(context.Background(), dnsprovider.ZoneFilter{Contains: "Example.COM."})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

	if got, want := zoneNames(zones), []string{"example.com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}

	if reqs := api.Requests(); len(reqs) != 1 || reqs[0].Get("SearchTerm") != "example.com" {
		t.Errorf("requests = %v, want one getList with SearchTerm example.com", reqs)
	}
}

func TestZoneStopsReadingTheListAtItsName(t *testing.T) {
	api := &ncAPI{ignoreSearch: true}
	api.domains, _ = domains(250)

	got, err := newProvider(t, api).GetZone(context.Background(), "d005.example")
	if err != nil || got.Name != "d005.example" {
		t.Fatalf("Zone = %+v, %v; want d005.example", got, err)
	}

	if n := len(api.Requests()); n != 1 {
		t.Errorf("sent %d getList requests, want one: the name is on the first page", n)
	}
}

func TestRecordsAreFilteredByTypeAndNameAfterOneGetHosts(t *testing.T) {
	cases := []struct {
		name   string
		filter dnsprovider.RecordFilter
		want   []string // type and name of each Record
	}{
		{"type", dnsprovider.RecordFilter{Type: "mx"}, []string{"MX example.com"}},
		{"name", dnsprovider.RecordFilter{Contains: "SHOP."}, []string{"A Shop.example.com", "TXT shop.example.com"}},
		{"type and name", dnsprovider.RecordFilter{Type: "A", Contains: "shop.example.com."}, []string{"A Shop.example.com"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := &ncAPI{hosts: map[string][]ncHost{"example.com": {
				{ID: "11", Name: "@", Type: "A", Address: "192.0.2.1", TTL: 1799},
				{ID: "12", Name: "@", Type: "MX", Address: "mx1.example.net.", MXPref: 10, TTL: 3600},
				{ID: "13", Name: "Shop", Type: "A", Address: "192.0.2.3", TTL: 300},
				{ID: "14", Name: "shop", Type: "TXT", Address: "x", TTL: 300},
				{ID: "15", Name: "shopping", Type: "A", Address: "192.0.2.4", TTL: 300},
			}}}

			set, err := newProvider(t, api).ListRecords(context.Background(), example, c.filter)
			if err != nil {
				t.Fatalf("Records: %v", err)
			}

			got := make([]string, 0, len(set.Records))
			for _, r := range set.Records {
				got = append(got, r.Type+" "+r.Name)
			}

			if !slices.Equal(got, c.want) {
				t.Errorf("Records = %v, want %v", got, c.want)
			}

			if cmds := api.Commands(); !slices.Equal(cmds, []string{"namecheap.domains.dns.getHosts"}) {
				t.Errorf("commands = %v, want one getHosts", cmds)
			}
		})
	}
}
