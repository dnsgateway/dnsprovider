package netim_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// example.net uses other DNS servers, so the registry holds its Signing
// Keys. The ds_list fixtures hold the same two keys, in DS and in DNSKEY
// form.
const (
	dsPath = "/domain/example.net/ds-record/"

	pubA = "d5qGoeJNPcgJwjdJRxPBz+rhTAtJRoOA+zPyp+yHXW5q/yIyLG135RmnY9+gtDI1zjq7R3w2M5voszaLGC+wCw=="
	pubB = "JHMC/ZC4v4Brue3D48RvJVJdNZ2j8umuuZ2XBphNXE+eCDrVOsH0uoZmf0KLPmY1teG6R/Jh2Y3y6N4kOmHnCQ=="
	dsA  = "19095 13 2 B1015584CC155CE4CCF1CCA2DA4775F8C8E882702E59B646BCADF127B558817B"
	dsB  = "45317 13 2 9EB0A04AC50DFD694E4CE45EAF68378B6954A3D638AB9AC366BA4C5F943145A6"
)

var registered = dnsprovider.Zone{ID: "example.net", Name: "example.net"}

func TestNetimDeclaresDSRegistrar(t *testing.T) {
	p := newFake(t).provider()
	if !dnsprovider.Can(p, dnsprovider.CapDSRegistrar) {
		t.Fatal("netim does not declare CapDSRegistrar")
	}
}

func TestListDelegationSignersReadsBothForms(t *testing.T) {
	tests := []struct {
		file string
		want []dnsprovider.SigningKey
	}{
		{"ds_list_ds.json", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{dsA}}, {KeyTag: 45317, DS: []string{dsB}}}},
		{"ds_list_dnskey.json", []dnsprovider.SigningKey{{KeyTag: 19095, DNSKEY: "257 3 13 " + pubA}, {KeyTag: 45317, DNSKEY: "257 3 13 " + pubB}}},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			f := newFake(t)
			f.serveFile("GET "+dsPath, tt.file)

			got, err := f.provider().ListDelegationSigners(context.Background(), dnsprovider.Zone{Name: "Example.NET."})
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ListDelegationSigners = %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

func TestListDelegationSignersOfNoKeysIsEmpty(t *testing.T) {
	f := newFake(t)
	f.serveFile("GET "+dsPath, "ds_list_empty.json")

	got, err := f.provider().ListDelegationSigners(context.Background(), registered)
	if err != nil || len(got) != 0 {
		t.Fatalf("ListDelegationSigners = %+v, %v; want none", got, err)
	}
}

// signerCalls are the Delegation Signer methods, each called with one
// valid key where it takes keys.
var signerCalls = map[string]func(dnsprovider.Provider, dnsprovider.Zone) error{
	"List": func(p dnsprovider.Provider, z dnsprovider.Zone) error {
		_, err := p.ListDelegationSigners(context.Background(), z)

		return err
	},
	"Set": func(p dnsprovider.Provider, z dnsprovider.Zone) error {
		return p.SetDelegationSigners(context.Background(), z, []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{dsA}}})
	},
	"Delete": func(p dnsprovider.Provider, z dnsprovider.Zone) error {
		return p.DeleteDelegationSigners(context.Background(), z)
	},
}

func TestDelegationSignersRefuseDomainsTheRegistryDoesNotHoldKeysFor(t *testing.T) {
	tests := []struct {
		name string
		zone string
		want error
	}{
		{"a domain the Account does not register", "example.info", dnsprovider.ErrNotFound},
		{"a domain on Netim's DNS", "example.com", dnsprovider.ErrUnsupported},
	}

	for _, tt := range tests {
		for method, call := range signerCalls {
			t.Run(tt.name+"/"+method, func(t *testing.T) {
				f := newFake(t)

				if err := call(f.provider(), dnsprovider.Zone{ID: tt.zone, Name: tt.zone}); !errors.Is(err, tt.want) {
					t.Fatalf("%s = %v, want %v", method, err, tt.want)
				}

				f.mu.Lock()
				defer f.mu.Unlock()

				for _, r := range f.requests {
					if strings.Contains(r, "/ds-record/") {
						t.Errorf("sent %s", r)
					}
				}
			})
		}
	}
}

func TestSetDelegationSignersRefusesBadKeysBeforeAnyRequest(t *testing.T) {
	tests := []struct {
		name string
		keys []dnsprovider.SigningKey
		want error // nil for any error
	}{
		{"no keys", nil, dnsprovider.ErrNoSigningKeys},
		{"an empty list", []dnsprovider.SigningKey{}, dnsprovider.ErrNoSigningKeys},
		{"a key with neither form", []dnsprovider.SigningKey{{KeyTag: 19095}}, dnsprovider.ErrUnsupported},
		{"a malformed DS", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{"19095 13 2 XYZ"}}}, nil},
		{"a DS of another key tag", []dnsprovider.SigningKey{{KeyTag: 1, DS: []string{dsA}}}, nil},
		{"a malformed DNSKEY", []dnsprovider.SigningKey{{KeyTag: 19095, DNSKEY: "257 3 13 !!!"}}, nil},
		{"a DNSKEY of another key tag", []dnsprovider.SigningKey{{KeyTag: 1, DNSKEY: "257 3 13 " + pubA}}, nil},
		{"a DS of another algorithm than its DNSKEY", []dnsprovider.SigningKey{{KeyTag: 19095, DNSKEY: "257 3 13 " + pubA, DS: []string{"19095 8 2 AB"}}}, nil},
		{"a DS of RSA/MD5, which RFC 8624 forbids", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{"19095 1 2 AB"}}}, dnsprovider.ErrUnsupported},
		{"a DS of DSA, which RFC 8624 forbids", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{"19095 3 2 AB"}}}, dnsprovider.ErrUnsupported},
		{"a DS of ECC-GOST, which RFC 8624 forbids", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{"19095 12 2 AB"}}}, dnsprovider.ErrUnsupported},
		{"a DS of a private algorithm", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{"19095 253 2 AB"}}}, dnsprovider.ErrUnsupported},
		{"a DS of an unassigned algorithm", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{"19095 100 2 AB"}}}, dnsprovider.ErrUnsupported},
		{"a DNSKEY of DSA", []dnsprovider.SigningKey{{KeyTag: 45318, DNSKEY: "257 3 3 " + pubA}}, dnsprovider.ErrUnsupported},
		{"a DS of digest type 0", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{"19095 13 0 AB"}}}, dnsprovider.ErrUnsupported},
		{"a DS of an unassigned digest type", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{"19095 13 9 AB"}}}, dnsprovider.ErrUnsupported},
		{"a valid key beside a bad one", []dnsprovider.SigningKey{{KeyTag: 19095, DS: []string{dsA}}, {KeyTag: 45317, DS: []string{"45317 13 2"}}}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)

			err := f.provider().SetDelegationSigners(context.Background(), registered, tt.keys)
			if err == nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("SetDelegationSigners = %v, want %v", err, tt.want)
			}

			if f.mu.Lock(); len(f.requests) != 0 {
				t.Errorf("sent %v", f.requests)
			}
			f.mu.Unlock()
		})
	}
}

// keyA and keyB are the fixtures' two Signing Keys, with both forms.
var (
	keyA = dnsprovider.SigningKey{KeyTag: 19095, DNSKEY: "257 3 13 " + pubA, DS: []string{dsA}}
	keyB = dnsprovider.SigningKey{KeyTag: 45317, DNSKEY: "257 3 13 " + pubB, DS: []string{dsB}}
)

// dnskeyOnly and dsOnly are a key with one of its forms.
func dnskeyOnly(k dnsprovider.SigningKey) dnsprovider.SigningKey {
	return dnsprovider.SigningKey{KeyTag: k.KeyTag, DNSKEY: k.DNSKEY}
}

func dsOnly(k dnsprovider.SigningKey) dnsprovider.SigningKey {
	return dnsprovider.SigningKey{KeyTag: k.KeyTag, DS: k.DS}
}

// dsWrites are the ds-record writes the fake received, in order.
func (f *fake) dsWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var out []string

	for _, r := range f.requests {
		if strings.HasSuffix(r, " "+dsPath) && !strings.HasPrefix(r, "GET ") {
			out = append(out, r)
		}
	}

	return out
}

func TestSetDelegationSignersSkipsAnUnchangedSet(t *testing.T) {
	tests := []struct {
		name string
		held string
		keys []dnsprovider.SigningKey
	}{
		{"DS held, DS given", "ds_list_ds.json", []dnsprovider.SigningKey{dsOnly(keyB), dsOnly(keyA)}},
		{"DS held, both forms given", "ds_list_ds.json", []dnsprovider.SigningKey{keyA, keyB, keyA}},
		{"DS held, DNSKEY given", "ds_list_ds.json", []dnsprovider.SigningKey{dnskeyOnly(keyA), dnskeyOnly(keyB)}},
		{"DNSKEY held, DNSKEY given", "ds_list_dnskey.json", []dnsprovider.SigningKey{dnskeyOnly(keyA), dnskeyOnly(keyB)}},
		{"DNSKEY held, DS given", "ds_list_dnskey.json", []dnsprovider.SigningKey{dsOnly(keyA), dsOnly(keyB)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.serveFile("GET "+dsPath, tt.held)

			if err := f.provider().SetDelegationSigners(context.Background(), registered, tt.keys); err != nil {
				t.Fatal(err)
			}

			if got := f.count("GET " + dsPath); got != 1 {
				t.Errorf("read the held keys %d times, want once", got)
			}

			if w := f.dsWrites(); len(w) != 0 {
				t.Errorf("sent %v for an unchanged set", w)
			}
		})
	}
}

// keyC is a new key, given as a DS.
var keyC = dnsprovider.SigningKey{KeyTag: 12345, DS: []string{"12345 13 2 " + strings.Repeat("AB", 32)}}

// Wire entries, as decoded from a request body.
var (
	dsDataA  = map[string]any{"key": 19095.0, "type": 2.0, "algo": 13.0, "digest": "b1015584cc155ce4ccf1cca2da4775f8c8e882702e59b646bcadf127b558817b"}
	dsDataB  = map[string]any{"key": 45317.0, "type": 2.0, "algo": 13.0, "digest": "9eb0a04ac50dfd694e4ce45eaf68378b6954a3d638ab9ac366ba4c5f943145a6"}
	dsDataC  = map[string]any{"key": 12345.0, "type": 2.0, "algo": 13.0, "digest": strings.Repeat("ab", 32)}
	keyDataA = map[string]any{"flags": 257.0, "protocol": 3.0, "algo": 13.0, "pubKey": pubA}
	keyDataB = map[string]any{"flags": 257.0, "protocol": 3.0, "algo": 13.0, "pubKey": pubB}
)

func TestSetDelegationSignersAddsMissingKeysBeforeRemovingUnwantedOnes(t *testing.T) {
	tests := []struct {
		name    string
		held    string // a body for the held list
		keys    []dnsprovider.SigningKey
		added   []any
		removed []any
	}{
		{
			name: "a new DS key replaces a held one", held: fixture(t, "ds_list_ds.json"),
			keys:  []dnsprovider.SigningKey{dsOnly(keyA), keyC},
			added: []any{dsDataC}, removed: []any{dsDataB},
		},
		{
			name: "a key with a DNSKEY is added as its DNSKEY", held: "[" + mustJSON(t, dsDataA) + "]",
			keys:  []dnsprovider.SigningKey{keyA, keyB},
			added: []any{keyDataB},
		},
		{
			name: "held DNSKEYs are removed as Netim gave them", held: fixture(t, "ds_list_dnskey.json"),
			keys:  []dnsprovider.SigningKey{keyC},
			added: []any{dsDataC}, removed: []any{keyDataA, keyDataB},
		},
		{
			name: "every key is added when none is held", held: "[]",
			keys:  []dnsprovider.SigningKey{dsOnly(keyA), dsOnly(keyB)},
			added: []any{dsDataA, dsDataB},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.script("GET "+dsPath, http.StatusOK, tt.held)
			f.serveFile("POST "+dsPath, "ds_create_done.json")
			f.serveFile("DELETE "+dsPath, "ds_delete_done.json")

			if err := f.provider().SetDelegationSigners(context.Background(), registered, tt.keys); err != nil {
				t.Fatal(err)
			}

			want := []string{"POST " + dsPath}
			if tt.removed != nil {
				want = append(want, "DELETE "+dsPath)
			}

			if got := f.dsWrites(); !slices.Equal(got, want) {
				t.Fatalf("writes = %v, want %v", got, want)
			}

			if got := f.body("POST " + dsPath); !reflect.DeepEqual(got, map[string]any{"data": tt.added}) {
				t.Errorf("added %v, want %v", got, tt.added)
			}

			if tt.removed != nil {
				if got := f.body("DELETE " + dsPath); !reflect.DeepEqual(got, map[string]any{"data": tt.removed}) {
					t.Errorf("removed %v, want %v", got, tt.removed)
				}
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func TestSetDelegationSignersReportsRefusalsAndUnconfirmedWrites(t *testing.T) {
	failed := fixture(t, "zone_create_failed.json")
	pending := fixture(t, "operation_pending.json")
	refused := fixture(t, "error_400.json")

	tests := []struct {
		name   string
		path   string // the write that fails
		status int
		body   string
		kind   error // nil for a plain APIError
		writes []string
	}{
		{"an add refused with a 400", "POST", http.StatusBadRequest, refused, nil, []string{"POST"}},
		{"an add Netim failed", "POST", http.StatusOK, failed, nil, []string{"POST"}},
		{"an add left pending", "POST", http.StatusOK, pending, dnsprovider.ErrUnconfirmed, []string{"POST"}},
		{"an add whose answer was lost", "POST", lost, "", dnsprovider.ErrUnconfirmed, []string{"POST"}},
		{"an add answered with a 5xx", "POST", http.StatusBadGateway, "", dnsprovider.ErrUnconfirmed, []string{"POST"}},
		{"a removal refused with a 400", "DELETE", http.StatusBadRequest, refused, nil, []string{"POST", "DELETE"}},
		{"a removal left pending", "DELETE", http.StatusOK, pending, dnsprovider.ErrUnconfirmed, []string{"POST", "DELETE"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.serveFile("GET "+dsPath, "ds_list_ds.json")
			f.serveFile("POST "+dsPath, "ds_create_done.json")
			f.serveFile("DELETE "+dsPath, "ds_delete_done.json")
			f.script(tt.path+" "+dsPath, tt.status, tt.body)

			err := f.provider().SetDelegationSigners(context.Background(), registered, []dnsprovider.SigningKey{keyA, keyC})

			var api *dnsprovider.APIError

			switch {
			case tt.kind != nil && !errors.Is(err, tt.kind):
				t.Fatalf("SetDelegationSigners = %v, want %v", err, tt.kind)
			case tt.kind == nil && (!errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnsupported) || errors.Is(err, dnsprovider.ErrUnconfirmed)):
				t.Fatalf("SetDelegationSigners = %v, want a plain APIError", err)
			case tt.kind == nil && !strings.Contains(err.Error(), "SYNTHETIC"):
				t.Fatalf("SetDelegationSigners = %v, without Netim's message", err)
			case tt.kind == dnsprovider.ErrUnsupported && errors.Is(err, dnsprovider.ErrUnconfirmed),
				tt.kind == dnsprovider.ErrUnconfirmed && errors.Is(err, dnsprovider.ErrUnsupported):
				t.Fatalf("SetDelegationSigners = %v, both unsupported and unconfirmed", err)
			}

			want := make([]string, 0, len(tt.writes))
			for _, m := range tt.writes {
				want = append(want, m+" "+dsPath)
			}

			if got := f.dsWrites(); !slices.Equal(got, want) {
				t.Errorf("writes = %v, want %v", got, want)
			}
		})
	}
}

func TestDelegationSignersRefuseAMalformedHeldSetWithoutWriting(t *testing.T) {
	for _, held := range []string{
		`{}`,
		`[{}]`,
		`[{"key":1,"type":2,"algo":13}]`,
		`[{"key":1,"type":2,"algo":13,"digest":"XYZ"}]`,
		`[{"key":70000,"type":2,"algo":13,"digest":"AB"}]`,
		`[{"flags":257,"protocol":2,"algo":13,"pubKey":"AAAA"}]`,
		`[{"flags":257,"protocol":3,"algo":13,"pubKey":"!!!"}]`,
		`[{"key":1,"type":2,"algo":13,"digest":"AB","flags":257,"protocol":3,"pubKey":"AAAA"}]`,
	} {
		t.Run(held, func(t *testing.T) {
			f := newFake(t)
			f.script("GET "+dsPath, http.StatusOK, held)
			f.script("GET "+dsPath, http.StatusOK, held)

			p := f.provider()
			if keys, err := p.ListDelegationSigners(context.Background(), registered); err == nil || keys != nil {
				t.Errorf("ListDelegationSigners = %+v, %v; want an error", keys, err)
			}

			if err := p.SetDelegationSigners(context.Background(), registered, []dnsprovider.SigningKey{keyA}); err == nil {
				t.Error("SetDelegationSigners accepted a malformed held set")
			}

			if w := f.dsWrites(); len(w) != 0 {
				t.Errorf("sent %v", w)
			}
		})
	}
}

func TestDeleteDelegationSignersDeletesEveryKeyWithNoBody(t *testing.T) {
	f := newFake(t)
	f.serveFile("DELETE "+dsPath, "ds_delete_all_done.json")

	if err := f.provider().DeleteDelegationSigners(context.Background(), dnsprovider.Zone{Name: "EXAMPLE.net."}); err != nil {
		t.Fatal(err)
	}

	if got := f.dsWrites(); !slices.Equal(got, []string{"DELETE " + dsPath}) {
		t.Fatalf("writes = %v", got)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if b := f.bodies["DELETE "+dsPath]; b != "" {
		t.Errorf("delete all sent the body %q", b)
	}
}

func TestDeleteDelegationSignersReportsAPendingOperationAsUnconfirmed(t *testing.T) {
	f := newFake(t)
	f.script("DELETE "+dsPath, http.StatusOK, fixture(t, "operation_pending.json"))

	if err := f.provider().DeleteDelegationSigners(context.Background(), registered); !errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("DeleteDelegationSigners = %v, want ErrUnconfirmed", err)
	}

	if got := f.count("DELETE " + dsPath); got != 1 {
		t.Errorf("sent %d deletes, want one", got)
	}
}
