package internetbs_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/internetbs"
)

const signingPublicKey = "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="

type signingRegistry struct {
	records any
	calls   []string
	writes  []url.Values
	fail    map[string]string
	status  string
	owned   bool
}

func newSigningRegistry(t *testing.T, records any) (*internetbs.Provider, *signingRegistry) {
	t.Helper()
	f := &signingRegistry{records: records, fail: map[string]string{}, status: "SUCCESS", owned: true}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.RawQuery != "" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("ApiKey") != "signing-key" || r.Form.Get("Password") != "signing-password" || r.Form.Get("ResponseFormat") != "json" {
			t.Error("missing form credentials")
		}
		f.calls = append(f.calls, r.URL.Path)
		if r.URL.Path == "/Domain/Update" {
			f.writes = append(f.writes, r.Form)
			for field := range r.Form {
				if !slices.Contains([]string{"ApiKey", "Password", "ResponseFormat", "Domain", "dnssec"}, field) {
					t.Errorf("update changes unrelated field %q", field)
				}
			}
		}
		if body := f.fail[r.URL.Path]; body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		if r.URL.Path != "/Domain/List" && r.Form.Get("Domain") != "example.com" {
			t.Errorf("unexpected Registration name %q", r.Form.Get("Domain"))
		}
		switch r.URL.Path {
		case "/Domain/Info":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "dnssec": f.records})
		case "/Domain/Update":
			values, ok := r.Form["dnssec"]
			if !ok || len(values) != 1 {
				t.Error("dnssec field must be explicit, including when empty")
			}
			if f.status == "SUCCESS" {
				f.records = "disabled"
				if r.Form.Get("dnssec") != "" {
					f.records = strings.Split(r.Form.Get("dnssec"), "\n")
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": f.status})
		case "/Domain/List":
			domains := []map[string]string{}
			if f.owned {
				domains = append(domains, map[string]string{"name": "example.com"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "SUCCESS", "domaincount": len(domains), "domain": domains})
		default:
			t.Errorf("unexpected command %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	p, err := internetbs.New(internetbs.Config{Key: "signing-key", Password: "signing-password"}, dnsprovider.WithBaseURL(s.URL), dnsprovider.WithHTTPClient(s.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return p, f
}

func TestDelegationSignersReadRegistrationSigningKeys(t *testing.T) {
	p, _ := newSigningRegistry(t, []string{
		"example.com. 3600 IN DS 2371 13 1 aa",
		"EXAMPLE.COM. 600 IN DNSKEY 257 3 13 ( " + signingPublicKey + " ); key id = 2371",
		"example.com. 60 IN DS 2371 13 2 ( ab\n cd )",
		"example.com. 600 IN DS 2371 13 2 ABCD",
		"example.com. 600 IN DS 2371 8 2 EE",
	})
	if !dnsprovider.Can(p, dnsprovider.CapDSRegistrar) {
		t.Fatal("Provider does not implement DSRegistrar")
	}
	got, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "Example.COM."})
	want := []dnsprovider.SigningKey{
		{KeyTag: 2371, DS: []string{"2371 8 2 EE"}},
		{KeyTag: 2371, DNSKEY: "257 3 13 " + signingPublicKey, DS: []string{"2371 13 2 ABCD", "2371 13 1 AA"}},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("DelegationSigners = %+v, %v; want %+v", got, err, want)
	}
}

func TestDelegationSignersEmptyAndMalformedStates(t *testing.T) {
	for _, state := range []any{"disabled", []string{}} {
		p, _ := newSigningRegistry(t, state)
		keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
		if err != nil || len(keys) != 0 {
			t.Fatalf("empty state = %+v, %v", keys, err)
		}
	}
	for _, state := range []any{nil, "enabled", 1, []any{nil}, []string{"other.com. 60 IN DS 1 13 2 AA"}, []string{"example.com. x IN DS 1 13 2 AA"}, []string{"example.com. 60 CH DS 1 13 2 AA"}, []string{"example.com. 60 IN DS 65536 13 2 AA"}, []string{"example.com. 60 IN DS 1 13 2 GG"}, []string{"example.com. 60 IN DNSKEY 257 2 13 AA=="}, []string{"example.com. 60 IN DNSKEY 257 3 13 !!!"}, []string{"example.com. 60 IN TXT plain"}} {
		p, f := newSigningRegistry(t, state)
		keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
		if err == nil || keys != nil {
			t.Fatalf("malformed state %v = %+v, %v", state, keys, err)
		}
		if err := p.DeleteDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err == nil || len(f.writes) != 0 {
			t.Fatalf("malformed state permitted mutation: %v", err)
		}
	}
}

func TestSetDelegationSignersReplacesBothFormsAndSkipsUnchangedSet(t *testing.T) {
	p, f := newSigningRegistry(t, "disabled")
	keys := []dnsprovider.SigningKey{{KeyTag: 2371, DNSKEY: "257 3 13 " + signingPublicKey, DS: []string{"2371 13 2 ab cd", "2371 13 1 aa"}}}
	ctx, z := context.Background(), dnsprovider.Zone{Name: "Example.COM."}
	if err := p.SetDelegationSigners(ctx, z, append(keys, keys...)); err != nil {
		t.Fatal(err)
	}
	want := "example.com. 86400 IN DNSKEY 257 3 13 " + signingPublicKey + "\nexample.com. 86400 IN DS 2371 13 1 AA\nexample.com. 86400 IN DS 2371 13 2 ABCD"
	if len(f.writes) != 1 || f.writes[0].Get("dnssec") != want {
		t.Fatalf("writes = %v, want %s", f.writes, want)
	}
	if err := p.SetDelegationSigners(ctx, z, keys); err != nil || len(f.writes) != 1 {
		t.Fatalf("unchanged set wrote again: %v, %v", f.writes, err)
	}
	got, err := p.ListDelegationSigners(ctx, z)
	if err != nil || len(got) != 1 || got[0].DNSKEY != keys[0].DNSKEY || !reflect.DeepEqual(got[0].DS, []string{"2371 13 2 ABCD", "2371 13 1 AA"}) {
		t.Fatalf("readback = %+v, %v", got, err)
	}
	if err := p.DeleteDelegationSigners(ctx, z); err != nil || len(f.writes) != 2 || f.writes[1].Get("dnssec") != "" {
		t.Fatalf("clear = %v, %v", f.writes, err)
	}
	if err := p.DeleteDelegationSigners(ctx, z); err != nil || len(f.writes) != 2 {
		t.Fatalf("already disabled set wrote again: %v", err)
	}
}

func TestSetDelegationSignersValidatesBeforeAnyCall(t *testing.T) {
	for _, key := range []dnsprovider.SigningKey{
		{KeyTag: 2371},
		{KeyTag: 2371, DS: []string{"2372 13 2 AA"}},
		{KeyTag: 2371, DS: []string{"2371 256 2 AA"}},
		{KeyTag: 2371, DS: []string{"2371 13 2 AA", "bad"}},
		{KeyTag: 2371, DNSKEY: "257 3 13 !!!"},
		{KeyTag: 2372, DNSKEY: "257 3 13 " + signingPublicKey},
		{KeyTag: 2371, DNSKEY: "257 3 13 " + signingPublicKey, DS: []string{"2371 8 2 AA"}},
	} {
		p, f := newSigningRegistry(t, "disabled")
		err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{key})
		if err == nil || len(f.calls) != 0 {
			t.Fatalf("invalid key %+v made calls %v: %v", key, f.calls, err)
		}
		if key.DNSKEY == "" && len(key.DS) == 0 && !errors.Is(err, dnsprovider.ErrUnsupported) {
			t.Errorf("key without either form = %v, want ErrUnsupported", err)
		}
	}
	p, f := newSigningRegistry(t, "disabled")
	z := dnsprovider.Zone{Name: "signing-password..example.com"}
	_, readErr := p.ListDelegationSigners(context.Background(), z)
	writeErr := p.DeleteDelegationSigners(context.Background(), z)
	for _, err := range []error{readErr, writeErr} {
		if err == nil || strings.Contains(err.Error(), "signing-password") || len(f.calls) != 0 {
			t.Errorf("invalid Registration name = %v, calls %v", err, f.calls)
		}
	}
}

func TestRegistrationErrorsPreserveRefusalAndProveAbsence(t *testing.T) {
	for _, owned := range []bool{true, false} {
		p, f := newSigningRegistry(t, "disabled")
		f.owned = owned
		f.fail["/Domain/Info"] = `{"status":"FAILURE","code":100005,"message":"Permission denied signing-password"}`
		_, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
		kind := dnsprovider.ErrNotFound
		if owned {
			kind = dnsprovider.ErrUnauthorized
		}
		var api *dnsprovider.APIError
		if !errors.Is(err, kind) || !errors.As(err, &api) || strings.Contains(err.Error(), "signing-password") {
			t.Fatalf("owned=%v error=%v", owned, err)
		}
		if err := p.DeleteDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); !errors.Is(err, kind) || len(f.writes) != 0 {
			t.Fatalf("read refusal allowed mutation: %v", err)
		}
	}
	p, f := newSigningRegistry(t, "disabled")
	f.fail["/Domain/Update"] = `{"status":"FAILURE","code":100002,"message":"Registry refused signing-key"}`
	err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{{KeyTag: 1, DS: []string{"1 13 2 AA"}}})
	var api *dnsprovider.APIError
	if !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnsupported) || len(f.writes) != 1 || strings.Contains(err.Error(), "signing-key") {
		t.Fatalf("generic refusal lost or retried: %v, writes=%v", err, f.writes)
	}
}

func TestSetDelegationSignersAcceptsPendingWithoutRepeatingTheWrite(t *testing.T) {
	p, f := newSigningRegistry(t, "disabled")
	f.status = "PENDING"
	err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{{KeyTag: 1, DS: []string{"1 13 2 AA"}}})
	if err != nil || len(f.writes) != 1 || f.records != "disabled" {
		t.Fatalf("queued update = %v, writes=%v", err, f.writes)
	}
	f.fail["/Domain/Info"] = `{"status":"PENDING","dnssec":"disabled"}`
	if _, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err == nil {
		t.Fatal("pending read was treated as empty")
	}
}

func TestSigningKeyCollisionsAreRefusedBeforeMutation(t *testing.T) {
	// These distinct public keys have the same tag (1040) with flags 257
	// and algorithm 13. A tag alone cannot associate their DS records.
	keys := []dnsprovider.SigningKey{
		{KeyTag: 1040, DNSKEY: "257 3 13 AAEAAQ=="},
		{KeyTag: 1040, DNSKEY: "257 3 13 AAAAAg=="},
	}
	p, f := newSigningRegistry(t, "disabled")
	err := p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, keys)
	if !errors.Is(err, dnsprovider.ErrUnsupported) || len(f.calls) != 0 {
		t.Fatalf("colliding keys = %v, calls=%v", err, f.calls)
	}
	f.records = []string{"example.com. 60 IN DNSKEY " + keys[0].DNSKEY, "example.com. 60 IN DNSKEY " + keys[1].DNSKEY}
	if got, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err == nil || got != nil {
		t.Fatalf("colliding keys were conflated: %+v, %v", got, err)
	}
}

func TestMalformedSigningRecordParenthesesFail(t *testing.T) {
	for _, text := range []string{"( AA", "AA )", "(( AA ))", "( AA ) ( BB )"} {
		p, _ := newSigningRegistry(t, []string{"example.com. 60 IN DS 1 13 2 " + text})
		if keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}); err == nil || keys != nil {
			t.Fatalf("malformed parentheses = %+v, %v", keys, err)
		}
	}
}

func TestSigningKeyReadsHandleOddRDATAAndRSAKeyTags(t *testing.T) {
	// The first key has odd-length RDATA: 257 + 781 + 256 = 1294.
	// RSA/MD5 instead uses the high two bytes of the modulus's last three.
	p, _ := newSigningRegistry(t, []string{
		"example.com. 60 IN DNSKEY 257 3 13 AQ==",
		"example.com. 60 IN DNSKEY 257 3 1 AQIDBA==",
	})
	keys, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
	if err != nil || len(keys) != 2 || keys[0].KeyTag != 515 || keys[1].KeyTag != 1294 {
		t.Fatalf("computed key tags = %+v, %v", keys, err)
	}
}

func TestRegistrationLookupFailuresDoNotInventAbsence(t *testing.T) {
	for _, body := range []string{
		`{"status":"FAILURE","code":107002,"message":"Invalid credentials"}`,
		`{"status":"SUCCESS","domaincount":1,"domain":[]}`,
	} {
		p, f := newSigningRegistry(t, "disabled")
		f.fail["/Domain/Info"] = `{"status":"FAILURE","code":100005,"message":"Permission denied"}`
		f.fail["/Domain/List"] = body
		_, err := p.ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"})
		if !errors.Is(err, dnsprovider.ErrUnauthorized) || errors.Is(err, dnsprovider.ErrNotFound) {
			t.Fatalf("failed inventory became absence: %v", err)
		}
	}
}

func TestSigningKeyWritesNeverRetryHTTPFailures(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/Domain/Info" {
			_, _ = w.Write([]byte(`{"status":"SUCCESS","dnssec":"disabled"}`))
			return
		}
		calls++
		http.Error(w, "lost answer", http.StatusServiceUnavailable)
	}))
	t.Cleanup(s.Close)
	p, err := internetbs.New(internetbs.Config{Key: "key", Password: "password"}, dnsprovider.WithBaseURL(s.URL))
	if err != nil {
		t.Fatal(err)
	}
	err = p.SetDelegationSigners(context.Background(), dnsprovider.Zone{Name: "example.com"}, []dnsprovider.SigningKey{{KeyTag: 1, DS: []string{"1 13 2 AA"}}})
	var api *dnsprovider.APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusServiceUnavailable || calls != 1 {
		t.Fatalf("write error=%v, calls=%d", err, calls)
	}
}
