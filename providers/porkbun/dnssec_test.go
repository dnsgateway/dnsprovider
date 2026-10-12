package porkbun_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
)

// registry is a fake Porkbun DNSSEC API for one domain: the DS records
// the registry holds, keyed by key tag as getDnssecRecords returns them.
type registry struct {
	mu     sync.Mutex
	domain string
	ds     map[string]map[string]string
	writes []string
	// refuse answers a call to the named operation with this error body.
	refuse map[string]string
	// deleteAlike makes a delete remove every DS with the algorithm of
	// the deleted key tag too, as registries that delete by key data do.
	deleteAlike bool
}

func registryAPI(t *testing.T, domain string, ds ...map[string]string) (*registry, *porkbun.Provider) {
	t.Helper()
	reg := &registry{domain: domain, ds: map[string]map[string]string{}, refuse: map[string]string{}}
	for _, d := range ds {
		reg.ds[d["keyTag"]] = d
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.mu.Lock()
		defer reg.mu.Unlock()
		if r.Header.Get("X-Api-Key") != "test-key" || r.Header.Get("X-Secret-Api-Key") != "test-secret" {
			t.Error("missing credentials")
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 || parts[0] != "dns" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		op := parts[1]
		if body, ok := reg.refuse[op]; ok {
			w.Write([]byte(body))
			return
		}
		if parts[2] != reg.domain {
			w.Write([]byte(`{"status":"ERROR","code":"INVALID_DOMAIN","message":"Invalid domain.","account":"alice"}`))
			return
		}
		switch op {
		case "getDnssecRecords":
			if r.Method != http.MethodGet {
				t.Error("reads must be safe GET")
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "records": reg.ds})
		case "createDnssecRecord":
			if r.Method != http.MethodPost {
				t.Error("writes must be POST")
			}
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid create JSON")
			}
			reg.writes = append(reg.writes, "create "+body["keyTag"]+" "+body["alg"]+" "+body["digestType"]+" "+body["digest"])
			reg.ds[body["keyTag"]] = body
			w.Write([]byte(`{"status":"SUCCESS"}`))
		case "deleteDnssecRecord":
			if r.Method != http.MethodPost || len(parts) != 4 {
				t.Errorf("unexpected delete %s %s", r.Method, r.URL.Path)
			}
			reg.writes = append(reg.writes, "delete "+parts[3])
			if d, ok := reg.ds[parts[3]]; ok && reg.deleteAlike {
				for tag, other := range reg.ds {
					if other["alg"] == d["alg"] {
						delete(reg.ds, tag)
					}
				}
			}
			delete(reg.ds, parts[3])
			w.Write([]byte(`{"status":"SUCCESS"}`))
		default:
			t.Errorf("unexpected operation %s", op)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	p, err := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	return reg, p
}

func ds(tag, alg, digestType, digest string) map[string]string {
	return map[string]string{"keyTag": tag, "alg": alg, "digestType": digestType, "digest": digest}
}

func TestDelegationSignersReadTheRegistryDS(t *testing.T) {
	fixture, err := os.ReadFile("testdata/dnssec.json")
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/dns/getDnssecRecords/example.com" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Write(fixture)
	}))
	defer s.Close()
	p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))

	if !dnsprovider.Can(p, dnsprovider.CapDSRegistrar) {
		t.Fatal("Porkbun does not declare CapDSRegistrar")
	}

	keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "Example.COM."})
	want := []dnsprovider.SigningKey{{KeyTag: 2371, DS: []string{"2371 13 2 1F987CC6583E92DF0890718C42F1A9A3DA1E4F7A2B3C4D5E6F708192A3B4C5D6"}}}
	if err != nil || !slices.EqualFunc(keys, want, sameKey) {
		t.Fatalf("DelegationSigners=%+v,%v", keys, err)
	}
}

func sameKey(a, b dnsprovider.SigningKey) bool {
	return a.DNSKEY == b.DNSKEY && a.KeyTag == b.KeyTag && slices.Equal(a.DS, b.DS)
}

func TestDelegationSignersAreNoneWhenTheRegistryHoldsNoDS(t *testing.T) {
	for _, body := range []string{`{"status":"SUCCESS","records":[]}`, `{"status":"SUCCESS","records":{}}`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
		keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
		s.Close()
		if err != nil || len(keys) != 0 {
			t.Errorf("%s: DelegationSigners=%+v,%v", body, keys, err)
		}
	}
}

func TestDelegationSignersOfADomainTheAccountDoesNotRegisterAreNotFound(t *testing.T) {
	_, p := registryAPI(t, "example.com")
	keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.org"})
	if !errors.Is(err, dnsprovider.ErrNotFound) || keys != nil {
		t.Fatalf("DelegationSigners=%+v,%v", keys, err)
	}
}

func TestDelegationSignersNotFoundCodes(t *testing.T) {
	for _, tc := range []struct {
		body     string
		notFound bool
	}{
		{`{"status":"ERROR","code":"DOMAIN_NOT_FOUND","message":"not in this account","account":"alice"}`, true},
		{`{"status":"ERROR","code":"DOMAIN_NOT_REGISTERED","message":"not registered here","account":"alice"}`, true},
		{`{"status":"ERROR","code":"INVALID_DOMAIN","message":"Invalid domain.","account":"alice"}`, true},
		{`{"status":"ERROR","code":"INVALID_DOMAIN","message":"invalid domain syntax"}`, false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			reg, p := registryAPI(t, "example.com")
			reg.refuse["getDnssecRecords"] = tc.body
			_, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
			var api *dnsprovider.APIError
			if err == nil || !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrNotFound) != tc.notFound {
				t.Fatalf("DelegationSigners=%v, want not found %v", err, tc.notFound)
			}
		})
	}
}

const (
	digestA = "1F987CC6583E92DF0890718C42F1A9A3DA1E4F7A2B3C4D5E6F708192A3B4C5D6"
	digestB = "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12"
)

func TestSetDelegationSignersPublishesTheSHA256DS(t *testing.T) {
	reg, p := registryAPI(t, "example.com")
	key := dnsprovider.SigningKey{DNSKEY: "257 3 13 AAAA", KeyTag: 2371, DS: []string{"2371 13 2 " + strings.ToLower(digestA), "2371 13 4 " + digestB + digestB[:32]}}
	if err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{key}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"create 2371 13 2 " + digestA}; !slices.Equal(reg.writes, want) {
		t.Fatalf("writes=%q, want %q", reg.writes, want)
	}
	keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
	if err != nil || len(keys) != 1 || keys[0].KeyTag != 2371 || keys[0].DS[0] != "2371 13 2 "+digestA {
		t.Fatalf("DelegationSigners=%+v,%v", keys, err)
	}
}

func TestSetDelegationSignersWithNoKeysRemovesEveryDS(t *testing.T) {
	reg, p := registryAPI(t, "example.com", ds("2371", "13", "2", digestA), ds("40000", "8", "2", digestB))
	if err := p.DeleteDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"delete 2371", "delete 40000"}; !slices.Equal(reg.writes, want) {
		t.Fatalf("writes=%q, want %q", reg.writes, want)
	}
	if len(reg.ds) != 0 {
		t.Fatalf("registry still holds %v", reg.ds)
	}
}

func TestSetDelegationSignersReplacesOnlyWhatDiffers(t *testing.T) {
	// 2371 stays as it is, 40000 goes, 11111 is new, and 5555 changes
	// its digest: it is deleted, then added again once the deletes are
	// done, as Porkbun deletes by key tag.
	reg, p := registryAPI(t, "example.com", ds("2371", "13", "2", digestA), ds("40000", "8", "2", digestB), ds("5555", "13", "2", digestA))
	keys := []dnsprovider.SigningKey{
		{KeyTag: 2371, DS: []string{"2371 13 2 " + digestA}},
		{KeyTag: 11111, DS: []string{"11111 13 2 " + digestB}},
		{KeyTag: 5555, DS: []string{"5555 13 2 " + digestB}},
	}
	if err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, keys); err != nil {
		t.Fatal(err)
	}
	want := []string{"create 11111 13 2 " + digestB, "delete 5555", "delete 40000", "create 5555 13 2 " + digestB}
	if !slices.Equal(reg.writes, want) {
		t.Fatalf("writes=%q, want %q", reg.writes, want)
	}
	got, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
	wantKeys := []dnsprovider.SigningKey{
		{KeyTag: 2371, DS: []string{"2371 13 2 " + digestA}},
		{KeyTag: 5555, DS: []string{"5555 13 2 " + digestB}},
		{KeyTag: 11111, DS: []string{"11111 13 2 " + digestB}},
	}
	if err != nil || !slices.EqualFunc(got, wantKeys, sameKey) {
		t.Fatalf("DelegationSigners=%+v,%v", got, err)
	}
}

func TestSetDelegationSignersToTheHeldSetWritesNothing(t *testing.T) {
	reg, p := registryAPI(t, "example.com", ds("2371", "13", "2", strings.ToLower(digestA)))
	keys := []dnsprovider.SigningKey{{KeyTag: 2371, DS: []string{"2371 13 2 " + digestA}}}
	if err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, keys); err != nil || len(reg.writes) != 0 {
		t.Fatalf("SetDelegationSigners=%v, writes=%q", err, reg.writes)
	}
}

func TestSetDelegationSignersErrors(t *testing.T) {
	key := dnsprovider.SigningKey{KeyTag: 2371, DS: []string{"2371 13 2 " + digestA}}
	cases := []struct {
		name string
		zone string
		op   string
		body string
		keys []dnsprovider.SigningKey
		kind error
	}{
		{name: "a domain the Account does not register is not found", zone: "example.org", keys: []dnsprovider.SigningKey{key}, kind: dnsprovider.ErrNotFound},
		{
			name: "an algorithm the registry no longer takes is unsupported", op: "createDnssecRecord", keys: []dnsprovider.SigningKey{key}, kind: dnsprovider.ErrUnsupported,
			body: `{"status":"ERROR","code":"DNSSEC_ALGORITHM_DEPRECATED","message":"alg 5 is no longer accepted by this registry; use 13"}`,
		},
		{name: "a key without a DS is unsupported, as Porkbun takes only a DS", keys: []dnsprovider.SigningKey{{DNSKEY: "257 3 13 AAAA", KeyTag: 2371}}, kind: dnsprovider.ErrUnsupported},
		{name: "two DS of one key tag are unsupported, as Porkbun holds one per key tag", keys: []dnsprovider.SigningKey{key, {KeyTag: 2371, DS: []string{"2371 13 2 " + digestB}}}, kind: dnsprovider.ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, p := registryAPI(t, "example.com")
			if tc.op != "" {
				reg.refuse[tc.op] = tc.body
			}
			zone := tc.zone
			if zone == "" {
				zone = "example.com"
			}
			err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: zone}, tc.keys)
			if !errors.Is(err, tc.kind) {
				t.Fatalf("SetDelegationSigners=%v, want %v", err, tc.kind)
			}
			if strings.Contains(err.Error(), "test-secret") {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestARegistryFailureIsNotUnsupported(t *testing.T) {
	// DNSSEC_CREATE_FAILED is the registry refusing the DS for any
	// reason, not only its algorithm or digest type.
	for op, body := range map[string]string{
		"createDnssecRecord": `{"status":"ERROR","code":"DNSSEC_CREATE_FAILED","message":"2306 Parameter value policy error"}`,
		"deleteDnssecRecord": `{"status":"ERROR","code":"DNSSEC_DELETE_FAILED","message":"registry unavailable"}`,
	} {
		t.Run(op, func(t *testing.T) {
			reg, p := registryAPI(t, "example.com", ds("40000", "8", "2", digestB))
			reg.refuse[op] = body
			keys := []dnsprovider.SigningKey{{KeyTag: 2371, DS: []string{"2371 13 2 " + digestA}}}
			z := dnsprovider.Zone{Name: "example.com"}
			var err error
			if op == "deleteDnssecRecord" {
				err = p.DeleteDelegationSigners(context.Background(), z)
			} else {
				err = p.SetDelegationSigners(context.Background(), z, keys)
			}
			var api *dnsprovider.APIError
			if err == nil || !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnsupported) || errors.Is(err, dnsprovider.ErrNotFound) {
				t.Fatalf("write=%v", err)
			}
		})
	}
}

func TestSetDelegationSignersRestoresAWantedDSADeleteTookWithIt(t *testing.T) {
	// Deleting 40000 also takes 2371, which shares its algorithm, and
	// changing 5555 takes 6666 along: each wanted DS is added back.
	reg, p := registryAPI(t, "example.com", ds("2371", "8", "2", digestA), ds("40000", "8", "2", digestB), ds("5555", "13", "2", digestA), ds("6666", "13", "2", digestB))
	reg.deleteAlike = true
	keys := []dnsprovider.SigningKey{
		{KeyTag: 2371, DS: []string{"2371 8 2 " + digestA}},
		{KeyTag: 5555, DS: []string{"5555 13 2 " + digestB}},
		{KeyTag: 6666, DS: []string{"6666 13 2 " + digestB}},
	}
	if err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, keys); err != nil {
		t.Fatal(err)
	}
	got, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
	if err != nil || !slices.EqualFunc(got, keys, sameKey) {
		t.Fatalf("DelegationSigners=%+v,%v, want %+v", got, err, keys)
	}
}

func TestMalformedDNSSECRecordsFailExplicitly(t *testing.T) {
	for _, body := range []string{
		`{"status":"SUCCESS"}`, `{"status":"SUCCESS","records":null}`, `{"status":"SUCCESS","records":"none"}`,
		`{"status":"SUCCESS","records":{"2371":{"keyTag":"2371","alg":"13","digestType":"2","digest":"not hex"}}}`,
		`{"status":"SUCCESS","records":{"2371":{"keyTag":"70000","alg":"13","digestType":"2","digest":"AB"}}}`,
		`{"status":"SUCCESS","records":{"2371":{"keyTag":"2372","alg":"13","digestType":"2","digest":"AB"}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer s.Close()
			p, _ := porkbun.New(porkbun.Config{Key: "test-key", Secret: "test-secret"}, dnsprovider.WithBaseURL(s.URL))
			if _, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestSetDelegationSignersFailsWhenADeletedDSStays(t *testing.T) {
	reg, p := registryAPI(t, "example.com", ds("40000", "8", "2", digestB))
	reg.refuse["deleteDnssecRecord"] = `{"status":"SUCCESS","message":"nothing to delete"}`
	if err := p.DeleteDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err == nil || !strings.Contains(err.Error(), "40000") {
		t.Fatalf("SetDelegationSigners=%v", err)
	}
}
