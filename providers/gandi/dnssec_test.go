package gandi_test

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
)

// registry is a fake Gandi Domain API dnskeys endpoint for one domain:
// the keys the registry holds, as the key list returns them.
type registry struct {
	mu     sync.Mutex
	domain string
	keys   []map[string]any
	nextID int
	writes []string
	// refuse answers a request with this method with the status and
	// body.
	refuse map[string]refusal
}

type refusal struct {
	status int
	body   string
}

func registryAPI(t *testing.T, domain string, keys ...map[string]any) (*registry, *gandi.Provider) {
	t.Helper()
	reg := &registry{domain: domain, keys: keys, nextID: 100, refuse: map[string]refusal{}}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.mu.Lock()
		defer reg.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer pat_test" {
			t.Error("missing bearer auth")
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 4 || parts[0] != "domain" || parts[1] != "domains" || parts[3] != "dnskeys" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if f, ok := reg.refuse[r.Method]; ok {
			w.WriteHeader(f.status)
			w.Write([]byte(f.body))
			return
		}
		if parts[2] != reg.domain {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"code":404,"message":"The resource could not be found.","object":"HTTPNotFound","cause":"Not Found"}`))
			return
		}
		switch {
		case r.Method == http.MethodGet && len(parts) == 4:
			if r.URL.Query().Get("page") != "1" {
				w.Write([]byte(`[]`))
				return
			}
			json.NewEncoder(w).Encode(append([]map[string]any{}, reg.keys...))
		case r.Method == http.MethodPut && len(parts) == 4:
			var body struct{ Keys []map[string]any }
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid replace JSON")
			}
			reg.keys = nil
			var sent []string
			for _, k := range body.Keys {
				sent = append(sent, keyWire(k))
				reg.nextID++
				reg.keys = append(reg.keys, map[string]any{
					"id": reg.nextID, "algorithm": k["algorithm"], "type": k["type"], "public_key": k["public_key"],
					"keytag": 1000 + reg.nextID, "digest_type": 2, "digest": "AB",
				})
			}
			reg.writes = append(reg.writes, "replace "+strings.Join(sent, ", "))
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"message":"The DNSSEC keys are being replaced."}`))
		case r.Method == http.MethodDelete && len(parts) == 5:
			reg.writes = append(reg.writes, "delete "+parts[4])
			reg.keys = slices.DeleteFunc(reg.keys, func(k map[string]any) bool { return idOf(k) == parts[4] })
			w.WriteHeader(http.StatusAccepted)
			w.Write([]byte(`{"message":"The DNSSEC key is being deleted."}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(s.Close)
	p, err := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	return reg, p
}

func keyWire(k map[string]any) string {
	return k["type"].(string) + " " + strconv.Itoa(int(k["algorithm"].(float64))) + " " + k["public_key"].(string)
}

func idOf(k map[string]any) string {
	switch id := k["id"].(type) {
	case int:
		return strconv.Itoa(id)
	case string:
		return id
	}
	return ""
}

// heldKey is a signing key as the Gandi key list returns it.
func heldKey(id any, tag, alg int, typ, pub, digest string) map[string]any {
	return map[string]any{
		"id": id, "keytag": tag, "algorithm": alg, "type": typ, "public_key": pub,
		"digest_type": 2, "digest": digest, "href": "https://api.gandi.net/v5/domain/domains/example.com/dnskeys/" + strconv.Itoa(tag),
	}
}

const (
	pubA    = "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
	pubB    = "oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="
	digestA = "1F987CC6583E92DF0890718C42F1A9A3DA1E4F7A2B3C4D5E6F708192A3B4C5D6"
)

func sameKey(a, b dnsprovider.SigningKey) bool {
	return a.DNSKEY == b.DNSKEY && a.KeyTag == b.KeyTag && slices.Equal(a.DS, b.DS)
}

func TestDelegationSignersReadTheRegistryKeys(t *testing.T) {
	_, p := registryAPI(t, "example.com",
		heldKey(7, 40000, 8, "zsk", pubB, strings.ToLower(digestA)),
		heldKey(3, 2371, 13, "ksk", pubA, digestA),
	)
	if !dnsprovider.CanRegisterDS(p) {
		t.Fatal("Gandi is not a DSRegistrar")
	}
	keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "Example.COM."})
	want := []dnsprovider.SigningKey{
		{DNSKEY: "257 3 13 " + pubA, KeyTag: 2371, DS: []string{"2371 13 2 " + digestA}},
		{DNSKEY: "256 3 8 " + pubB, KeyTag: 40000, DS: []string{"40000 8 2 " + digestA}},
	}
	if err != nil || !slices.EqualFunc(keys, want, sameKey) {
		t.Fatalf("DelegationSigners=%+v,%v, want %+v", keys, err, want)
	}
}

func TestDelegationSignersAreNoneWhenTheRegistryHoldsNoKey(t *testing.T) {
	_, p := registryAPI(t, "example.com")
	keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
	if err != nil || len(keys) != 0 {
		t.Fatalf("DelegationSigners=%+v,%v", keys, err)
	}
}

func TestDelegationSignersOfADomainTheAccountDoesNotRegisterAreNotFound(t *testing.T) {
	_, p := registryAPI(t, "example.com")
	keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.org"})
	if !errors.Is(err, dnsprovider.ErrNotFound) || keys != nil {
		t.Fatalf("DelegationSigners=%+v,%v", keys, err)
	}
}

func TestSetDelegationSignersPublishesTheDNSKEYAsASigningKey(t *testing.T) {
	reg, p := registryAPI(t, "example.com")
	// The public key may come split in chunks, as in a zone file.
	key := dnsprovider.SigningKey{DNSKEY: "257 3 13 " + pubA[:40] + " " + pubA[40:], KeyTag: 2371, DS: []string{"2371 13 2 " + digestA}}
	if err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{key}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"replace ksk 13 " + pubA}; !slices.Equal(reg.writes, want) {
		t.Fatalf("writes=%q, want %q", reg.writes, want)
	}
	keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
	if err != nil || len(keys) != 1 || keys[0].DNSKEY != "257 3 13 "+pubA {
		t.Fatalf("DelegationSigners=%+v,%v", keys, err)
	}
}

func TestSetDelegationSignersWithNoKeysDeletesEveryKey(t *testing.T) {
	// The docs give the key id as an integer in the list and a string in
	// the delete path: either is taken.
	reg, p := registryAPI(t, "example.com",
		heldKey("a1b2", 40000, 8, "ksk", pubB, digestA),
		heldKey(3, 2371, 13, "ksk", pubA, digestA),
	)
	if err := p.DeleteDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"delete 3", "delete a1b2"}; !slices.Equal(reg.writes, want) {
		t.Fatalf("writes=%q, want %q", reg.writes, want)
	}
	if len(reg.keys) != 0 {
		t.Fatalf("registry still holds %v", reg.keys)
	}
}

func TestSetDelegationSignersReplacesTheWholeSetInOneWrite(t *testing.T) {
	// A rollover: 2371 stays, 40000 is new, and the "zsk" Gandi held goes.
	reg, p := registryAPI(t, "example.com",
		heldKey(3, 2371, 13, "ksk", pubA, digestA),
		heldKey(4, 5555, 13, "zsk", pubB, digestA),
	)
	keys := []dnsprovider.SigningKey{
		{DNSKEY: "257 3 13 " + pubA, KeyTag: 2371},
		{DNSKEY: "257 3 8 " + pubB, KeyTag: 40000},
	}
	if err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, keys); err != nil {
		t.Fatal(err)
	}
	if want := []string{"replace ksk 13 " + pubA + ", ksk 8 " + pubB}; !slices.Equal(reg.writes, want) {
		t.Fatalf("writes=%q, want %q", reg.writes, want)
	}
}

func TestSetDelegationSignersToTheHeldSetWritesNothing(t *testing.T) {
	reg, p := registryAPI(t, "example.com",
		heldKey(4, 40000, 8, "ksk", pubB, digestA),
		heldKey(3, 2371, 13, "ksk", pubA, digestA),
	)
	keys := []dnsprovider.SigningKey{
		{DNSKEY: "257 3 13 " + pubA, KeyTag: 2371},
		{DNSKEY: "257 3 8 " + pubB, KeyTag: 40000},
		{DNSKEY: "257 3 13 " + pubA, KeyTag: 2371},
	}
	if err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, keys); err != nil || len(reg.writes) != 0 {
		t.Fatalf("SetDelegationSigners=%v, writes=%q", err, reg.writes)
	}
	if err := p.DeleteDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.org"}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("SetDelegationSigners of another domain=%v", err)
	}
}

func TestSetDelegationSignersErrors(t *testing.T) {
	key := dnsprovider.SigningKey{DNSKEY: "257 3 13 " + pubA, KeyTag: 2371}
	refused := `{"code":400,"message":"Validation error pat_test","object":"HTTPBadRequest","cause":"Bad Request","errors":[{"location":"body","name":"keys","description":"algorithm 5 is not supported by the registry"}]}`
	cases := []struct {
		name   string
		method string
		refuse refusal
		held   []map[string]any
		zone   string
		keys   []dnsprovider.SigningKey
		kind   error
	}{
		{name: "a domain the Account does not register is not found", zone: "example.org", keys: []dnsprovider.SigningKey{key}, kind: dnsprovider.ErrNotFound},
		{name: "a key the registry refuses is unsupported", method: http.MethodPut, refuse: refusal{http.StatusBadRequest, refused}, keys: []dnsprovider.SigningKey{key}, kind: dnsprovider.ErrUnsupported},
		{name: "a key without a DNSKEY is unsupported, as Gandi takes no DS", keys: []dnsprovider.SigningKey{{KeyTag: 2371, DS: []string{"2371 13 2 " + digestA}}}, kind: dnsprovider.ErrUnsupported},
		{
			name: "a delete of a domain gone from the Account is not found", method: http.MethodDelete, held: []map[string]any{heldKey(3, 2371, 13, "ksk", pubA, digestA)},
			refuse: refusal{http.StatusNotFound, `{"code":404,"message":"not found","object":"HTTPNotFound","cause":"Not Found"}`}, kind: dnsprovider.ErrNotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, p := registryAPI(t, "example.com", tc.held...)
			if tc.method != "" {
				reg.refuse[tc.method] = tc.refuse
			}
			zone := cmp.Or(tc.zone, "example.com")
			err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: zone}, tc.keys)
			if len(tc.keys) == 0 {
				err = p.DeleteDelegationSigners(context.Background(), dnsprovider.Zone{Name: zone})
			}
			if !errors.Is(err, tc.kind) {
				t.Fatalf("write=%v, want %v", err, tc.kind)
			}
			if strings.Contains(err.Error(), "pat_test") {
				t.Fatal("token leaked")
			}
			if tc.method == http.MethodPut && !strings.Contains(err.Error(), "algorithm 5 is not supported") {
				t.Fatalf("SetDelegationSigners=%v, want the registry's reason", err)
			}
		})
	}
}

func TestSetDelegationSignersFailuresThatAreNotTheKeys(t *testing.T) {
	key := dnsprovider.SigningKey{DNSKEY: "257 3 13 " + pubA, KeyTag: 2371}
	t.Run("a registry outage", func(t *testing.T) {
		reg, p := registryAPI(t, "example.com")
		reg.refuse[http.MethodPut] = refusal{http.StatusInternalServerError, `{"code":500,"message":"registry unavailable"}`}
		err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{key})
		var api *dnsprovider.APIError
		if !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnsupported) || errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("SetDelegationSigners=%v", err)
		}
	})
	t.Run("a malformed DNSKEY", func(t *testing.T) {
		for _, dnskey := range []string{"257 3 13 not*base64", "257 2 13 " + pubA, "257 3 x " + pubA} {
			reg, p := registryAPI(t, "example.com")
			err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{{DNSKEY: dnskey, KeyTag: 2371}})
			if err == nil || errors.Is(err, dnsprovider.ErrUnsupported) || len(reg.writes) != 0 {
				t.Errorf("%s: SetDelegationSigners=%v, writes=%q", dnskey, err, reg.writes)
			}
		}
	})
}

func TestMalformedSigningKeysFailExplicitly(t *testing.T) {
	for _, body := range []string{
		`null`, `{"keys":[]}`,
		`[{"id":3,"keytag":2371,"algorithm":13,"type":"ksk","digest_type":2,"digest":"not hex"}]`,
		`[{"id":3,"keytag":70000,"algorithm":13,"type":"ksk","digest_type":2,"digest":"AB"}]`,
		`[{"id":3,"algorithm":13,"type":"ksk","digest_type":2,"digest":"AB"}]`,
		`[{"keytag":2371,"algorithm":13,"type":"ksk","digest_type":2,"digest":"AB"}]`,
	} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("page") != "1" {
					w.Write([]byte(`[]`))
					return
				}
				w.Write([]byte(body))
			}))
			defer s.Close()
			p, _ := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL))
			if _, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestTheDomainAPIIsTheSiblingOfLiveDNS(t *testing.T) {
	var path string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Write([]byte(`[]`))
	}))
	defer s.Close()
	p, _ := gandi.New(gandi.Config{Token: "pat_test"}, dnsprovider.WithBaseURL(s.URL+"/v5/livedns/"))
	if _, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err != nil || path != "/v5/domain/domains/example.com/dnskeys" {
		t.Fatalf("DelegationSigners read %s, %v", path, err)
	}
}

// Gandi documents no 404 or 400 on the dnskeys routes, so the mapping of
// each is an assumption: the error keeps Gandi's own words for it.
func TestSigningKeyErrorsKeepGandisDescription(t *testing.T) {
	key := dnsprovider.SigningKey{DNSKEY: "257 3 13 " + pubA, KeyTag: 2371}
	cases := []struct {
		name   string
		method string
		refuse refusal
		kind   error
		says   string
	}{
		{
			name: "a domain Gandi does not find", method: http.MethodGet, kind: dnsprovider.ErrNotFound, says: "Domain example.com not found",
			refuse: refusal{http.StatusNotFound, `{"code":404,"message":"The resource could not be found.","errors":[{"location":"path","name":"domain","description":"Domain example.com not found"}]}`},
		},
		{
			name: "a replace Gandi refuses", method: http.MethodPut, kind: dnsprovider.ErrUnsupported, says: "public_key: invalid key",
			refuse: refusal{http.StatusBadRequest, `{"code":400,"message":"Bad Request","errors":[{"location":"body","name":"keys","description":"public_key: invalid key"}]}`},
		},
		{
			// A domain another organization holds may be forbidden, not
			// missing.
			name: "a domain held by another organization", method: http.MethodGet, kind: dnsprovider.ErrUnauthorized, says: "Access was denied to this resource.",
			refuse: refusal{http.StatusForbidden, `{"code":403,"message":"Access was denied to this resource.","object":"HTTPForbidden","cause":"Forbidden"}`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg, p := registryAPI(t, "example.com")
			reg.refuse[tc.method] = tc.refuse
			err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{key})
			if !errors.Is(err, tc.kind) || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("SetDelegationSigners=%v, want %v saying %q", err, tc.kind, tc.says)
			}
			if tc.kind != dnsprovider.ErrNotFound && errors.Is(err, dnsprovider.ErrNotFound) {
				t.Fatalf("SetDelegationSigners=%v is also not found", err)
			}
		})
	}
}
