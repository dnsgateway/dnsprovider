package infomaniak_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// Registrations of the fake's Account: example.ch has an Infomaniak Zone,
// external-dns.com and example.org do not.
var (
	external = dnsprovider.Zone{ID: "external-dns.com", Name: "external-dns.com"}
	unsigned = dnsprovider.Zone{ID: "example.org", Name: "example.org"}
	served   = dnsprovider.Zone{ID: "example.ch", Name: "example.ch"}
	stranger = dnsprovider.Zone{ID: "other.net", Name: "other.net"}
)

const (
	checkPath   = "/2/domains/domains/external-dns.com/dnssec/check"
	enablePath  = "/2/domains/domains/external-dns.com/dnssec/enable"
	disablePath = "/2/domains/domains/external-dns.com/dnssec/disable"

	// The key of RFC 6605 section 6.1, of key tag 55648, with its SHA-256
	// DS at example.net; and RFC 4034 section 5.4's DS.
	rfc6605Key = "257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
	rfc6605DS  = "55648 13 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17"
	rfc4034DS  = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"
)

// dsFake is the fake with the DNSSEC calls of the Account's registrations
// that Infomaniak does not serve: external-dns.com holds the DS data of
// dnssec_check_dsdata.json, and example.org holds none.
func dsFake(t *testing.T) *fake {
	t.Helper()

	f := newFake(t)
	f.serveFile("GET "+checkPath, "dnssec_check_dsdata.json")
	f.serveFile("POST "+enablePath, "dnssec_done.json")
	f.serveFile("POST "+disablePath, "dnssec_done.json")
	f.serveFile("GET /2/domains/domains/example.org/dnssec/check", "dnssec_check_unsigned.json")

	return f
}

func TestListDelegationSignersGroupsDSDataByKeyTagAndAlgorithm(t *testing.T) {
	f := dsFake(t)

	got, err := f.provider().ListDelegationSigners(context.Background(), external)
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.SigningKey{
		{KeyTag: 55648, DS: []string{rfc6605DS, "55648 13 1 0123456789ABCDEF0123456789ABCDEF01234567"}},
		{KeyTag: 60485, DS: []string{rfc4034DS}},
	}
	if !equalKeys(got, want) {
		t.Fatalf("ListDelegationSigners = %+v, want %+v", got, want)
	}
}

func TestListDelegationSignersComputesTheKeyTagOfKeyData(t *testing.T) {
	f := dsFake(t)
	f.serveFile("GET "+checkPath, "dnssec_check_keydata.json")

	got, err := f.provider().ListDelegationSigners(context.Background(), external)
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key}}
	if !equalKeys(got, want) {
		t.Fatalf("ListDelegationSigners = %+v, want %+v", got, want)
	}
}

func TestDelegationSignersResolveTheZoneAsRecordCallsDo(t *testing.T) {
	for _, zone := range []dnsprovider.Zone{{ID: "external-dns.com"}, {Name: "External-DNS.com."}} {
		f := dsFake(t)

		got, err := f.provider().ListDelegationSigners(context.Background(), zone)
		if err != nil || len(got) != 2 {
			t.Errorf("%+v: ListDelegationSigners = %+v, %v; want the two held keys", zone, got, err)
		}
	}
}

func TestListDelegationSignersOfAnUnsignedRegistrationIsEmpty(t *testing.T) {
	f := dsFake(t)

	got, err := f.provider().ListDelegationSigners(context.Background(), unsigned)
	if err != nil || len(got) != 0 {
		t.Fatalf("ListDelegationSigners = %+v, %v; want none", got, err)
	}
}

func TestDelegationSignersOfADomainTheAccountDoesNotRegisterAreNotFound(t *testing.T) {
	f := dsFake(t)
	p := f.provider()
	ctx := context.Background()

	if _, err := p.ListDelegationSigners(ctx, stranger); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("List = %v, want ErrNotFound", err)
	}

	if err := p.SetDelegationSigners(ctx, stranger, []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key}}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Set = %v, want ErrNotFound", err)
	}

	if err := p.DeleteDelegationSigners(ctx, stranger); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("Delete = %v, want ErrNotFound", err)
	}

	if w := f.writes(); len(w) != 0 {
		t.Fatalf("writes = %v, want none", w)
	}
}

func TestDelegationSignersOfADomainInfomaniakServesAreUnsupported(t *testing.T) {
	f := dsFake(t)
	p := f.provider()
	ctx := context.Background()

	if _, err := p.ListDelegationSigners(ctx, served); !errors.Is(err, dnsprovider.ErrUnsupported) {
		t.Errorf("List = %v, want ErrUnsupported", err)
	}

	if err := p.SetDelegationSigners(ctx, served, []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key}}); !errors.Is(err, dnsprovider.ErrUnsupported) {
		t.Errorf("Set = %v, want ErrUnsupported", err)
	}

	if err := p.DeleteDelegationSigners(ctx, served); !errors.Is(err, dnsprovider.ErrUnsupported) {
		t.Errorf("Delete = %v, want ErrUnsupported", err)
	}

	if w := f.writes(); len(w) != 0 {
		t.Fatalf("writes = %v, want none", w)
	}
}

func TestSetDelegationSignersOfTheHeldSetSendsNoWrite(t *testing.T) {
	ctx := context.Background()

	// The RFC 6605 key's DS is of example.net, which this Account
	// registers instead.
	exampleNet := dnsprovider.Zone{ID: "example.net", Name: "example.net"}

	for _, tc := range []struct {
		name, check string
		keys        []dnsprovider.SigningKey
	}{
		{"DS as held, in another order and case", "dnssec_check_dsdata.json", []dnsprovider.SigningKey{
			{KeyTag: 60485, DS: []string{rfc4034DS}},
			{KeyTag: 55648, DS: []string{"55648 13 1 0123456789abcdef0123456789abcdef01234567", rfc6605DS}},
		}},
		{"DNSKEY for held DS data", "dnssec_check_rfc6605_ds.json", []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key}}},
		{"DNSKEY for held key data", "dnssec_check_keydata.json", []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key}}},
		{"DS for held key data", "dnssec_check_keydata.json", []dnsprovider.SigningKey{{KeyTag: 55648, DS: []string{rfc6605DS}}}},
	} {
		f := dsFake(t)
		f.serveFile("GET /2/domains/domains", "domains_example_net.json")
		f.serveFile("GET /2/domains/domains/example.net/dnssec/check", tc.check)

		if err := f.provider().SetDelegationSigners(ctx, exampleNet, tc.keys); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		if w := f.writes(); len(w) != 0 {
			t.Fatalf("%s: writes = %v, want none", tc.name, w)
		}
	}
}

func TestSetDelegationSignersOfAChangedSetWrites(t *testing.T) {
	f := dsFake(t)

	// The held set less its digest-1 DS of key 55648.
	keys := []dnsprovider.SigningKey{{KeyTag: 55648, DS: []string{rfc6605DS}}, {KeyTag: 60485, DS: []string{rfc4034DS}}}
	if err := f.provider().SetDelegationSigners(context.Background(), external, keys); err != nil {
		t.Fatal(err)
	}

	if w := f.writes(); len(w) != 1 || len(w[enablePath]) != 1 {
		t.Fatalf("writes = %v, want one enable call", w)
	}
}

func TestSetDelegationSignersSendsTheWholeNewSetInOneEnableCall(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		keys []dnsprovider.SigningKey
		want []string
	}{
		{"DS form when every key has DS records", []dnsprovider.SigningKey{
			{KeyTag: 55648, DNSKEY: rfc6605Key, DS: []string{"55648 13 2 b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17"}},
			{KeyTag: 60485, DS: []string{rfc4034DS}},
		}, []string{rfc6605DS, rfc4034DS}},
		{"DNSKEY form when a key has no DS", []dnsprovider.SigningKey{
			{KeyTag: 55648, DNSKEY: rfc6605Key},
		}, []string{rfc6605Key}},
	} {
		f := dsFake(t)
		f.serveFile("GET "+checkPath, "dnssec_check_unsigned.json")

		if err := f.provider().SetDelegationSigners(ctx, external, tc.keys); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		w := f.writes()
		if len(w) != 1 || len(w[enablePath]) != 1 {
			t.Fatalf("%s: writes = %v, want one enable call", tc.name, w)
		}

		var body struct {
			DNSSECData []string `json:"dnssec_data"`
		}
		if err := json.Unmarshal([]byte(w[enablePath][0]), &body); err != nil || !slices.Equal(body.DNSSECData, tc.want) {
			t.Fatalf("%s: enable body = %s, want dnssec_data %q", tc.name, w[enablePath][0], tc.want)
		}
	}
}

func TestSetDelegationSignersChecksEveryKeyBeforeAnyRequest(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name        string
		keys        []dnsprovider.SigningKey
		unsupported bool
	}{
		{"no keys", nil, false},
		{"DSA algorithm", []dnsprovider.SigningKey{{KeyTag: 1, DS: []string{"1 3 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17"}}}, true},
		{"unassigned digest type", []dnsprovider.SigningKey{{KeyTag: 1, DS: []string{"1 13 9 B4C8C1FE"}}}, true},
		{"no DNSKEY or DS", []dnsprovider.SigningKey{{KeyTag: 1}}, true},
		{"wrong key tag", []dnsprovider.SigningKey{{KeyTag: 1, DNSKEY: rfc6605Key}}, false},
		{"malformed DS", []dnsprovider.SigningKey{{KeyTag: 1, DS: []string{"1 13 2 not-hex"}}}, false},
		{"one bad key among good", []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key}, {KeyTag: 1, DS: []string{"1 3 2 B4C8"}}}, true},
	} {
		f := dsFake(t)

		err := f.provider().SetDelegationSigners(ctx, external, tc.keys)

		switch {
		case tc.keys == nil && !errors.Is(err, dnsprovider.ErrNoSigningKeys):
			t.Errorf("%s: %v, want ErrNoSigningKeys", tc.name, err)
		case tc.unsupported && !errors.Is(err, dnsprovider.ErrUnsupported):
			t.Errorf("%s: %v, want ErrUnsupported", tc.name, err)
		case err == nil:
			t.Errorf("%s: no error", tc.name)
		}

		if n := f.count(); n != 0 {
			t.Errorf("%s: %d requests, want none", tc.name, n)
		}
	}
}

func TestDeleteDelegationSignersSendsTheDisableCall(t *testing.T) {
	f := dsFake(t)

	if err := f.provider().DeleteDelegationSigners(context.Background(), external); err != nil {
		t.Fatal(err)
	}

	if w := f.writes(); len(w) != 1 || len(w[disablePath]) != 1 {
		t.Fatalf("writes = %v, want one disable call", w)
	}
}

func TestDelegationSignerWritesFollowTheUnconfirmedWriteRules(t *testing.T) {
	ctx := context.Background()
	keys := []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DS}}}

	for _, tc := range []struct {
		name        string
		status      int
		body        string
		unconfirmed bool
	}{
		{"500 dnssec_management_failed", http.StatusInternalServerError, fixture(t, "dnssec_management_failed.json"), true},
		{"asynchronous", http.StatusAccepted, `{"result":"asynchronous","data":true}`, true},
		{"undecodable success", http.StatusOK, `{"result":`, true},
		{"error in a 2xx", http.StatusOK, fixture(t, "dnssec_management_failed.json"), false},
		{"422 refusal", http.StatusUnprocessableEntity, fixture(t, "validation_failed.json"), false},
	} {
		for _, call := range []struct {
			path string
			run  func(f *fake) error
		}{
			{enablePath, func(f *fake) error { return f.provider().SetDelegationSigners(ctx, external, keys) }},
			{disablePath, func(f *fake) error { return f.provider().DeleteDelegationSigners(ctx, external) }},
		} {
			f := dsFake(t)
			f.script("POST "+call.path, tc.status, tc.body)

			err := call.run(f)

			var apiErr *dnsprovider.APIError

			switch {
			case err == nil:
				t.Errorf("%s %s: no error", tc.name, call.path)
			case errors.Is(err, dnsprovider.ErrUnconfirmed) != tc.unconfirmed:
				t.Errorf("%s %s: %v, unconfirmed = %v", tc.name, call.path, err, !tc.unconfirmed)
			case !tc.unconfirmed && !errors.As(err, &apiErr):
				t.Errorf("%s %s: %v, want an APIError", tc.name, call.path, err)
			}

			if n := len(f.writes()[call.path]); n != 1 {
				t.Errorf("%s %s: %d writes, want exactly one", tc.name, call.path, n)
			}
		}
	}
}

func TestDelegationSignerWritesMapErrorResultsAsRecordWritesDo(t *testing.T) {
	ctx := context.Background()
	keys := []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DS}}}

	for _, call := range []struct {
		path string
		run  func(f *fake) error
	}{
		{enablePath, func(f *fake) error { return f.provider().SetDelegationSigners(ctx, external, keys) }},
		{disablePath, func(f *fake) error { return f.provider().DeleteDelegationSigners(ctx, external) }},
	} {
		f := dsFake(t)
		f.script("POST "+call.path, http.StatusOK, fixture(t, "too_many_requests.json"))

		err := call.run(f)

		var apiErr *dnsprovider.APIError
		if !errors.Is(err, dnsprovider.ErrRateLimited) || !errors.As(err, &apiErr) || apiErr.StatusCode != 0 {
			t.Errorf("%s: %v, want an APIError of status 0 and ErrRateLimited", call.path, err)
		}
	}
}

func TestDelegationSignerWriteErrorsNameTheProviderOnce(t *testing.T) {
	ctx := context.Background()
	keys := []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DS}}}

	for _, body := range []string{`{"result":`, `{"result":"asynchronous","data":true}`} {
		f := dsFake(t)
		f.script("POST "+enablePath, http.StatusOK, body)

		if err := f.provider().SetDelegationSigners(ctx, external, keys); err == nil || strings.Count(err.Error(), "infomaniak:") != 1 {
			t.Errorf("%s: %v, want the provider named once", body, err)
		}
	}
}

func equalKeys(a, b []dnsprovider.SigningKey) bool {
	return slices.EqualFunc(a, b, func(x, y dnsprovider.SigningKey) bool {
		return x.KeyTag == y.KeyTag && x.DNSKEY == y.DNSKEY && slices.Equal(x.DS, y.DS)
	})
}
