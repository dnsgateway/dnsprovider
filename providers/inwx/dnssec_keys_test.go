package inwx_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// Domains of the DS fake: example.net is registered without an INWX
// zone, example.com is registered and hosted, and other.net is neither.
var (
	registration = dnsprovider.Zone{Name: "example.net"}
	hosted       = dnsprovider.Zone{ID: "1001", Name: "example.com"}
	stranger     = dnsprovider.Zone{Name: "other.net"}
)

const (
	// The key of RFC 6605 section 6.1, of key tag 55648, and its SHA-256
	// DS at example.net; RFC 4034 section 5.4's DS; and the DNSKEY of RFC
	// 4034 section 5.4, of key tag 60485, as a second key.
	rfc6605Key = "257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
	rfc6605DS  = "55648 13 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17"
	rfc4034DS  = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"

	// Made-up SHA-256 and SHA-384 DS records of key tag 60485, which
	// INWX takes.
	rfc4034DSSHA256 = "60485 5 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A"
	rfc4034DSSHA384 = "60485 5 4 72D7B62976CE06438E9C0BF319013CF801F09ECC84B8D7E9495F27E305C6A9B0563A9B5F4D288405C3008A946DF983D6"
)

func TestListDelegationSignersReadsTheActiveKeysOfTheRegistration(t *testing.T) {
	f := dsFake(t)

	got, err := f.provider().ListDelegationSigners(context.Background(), registration)
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key, DS: []string{rfc6605DS}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListDelegationSigners = %+v, want %+v", got, want)
	}

	if p := f.params("dnssec.listkeys"); p["domainName"] != "example.net" {
		t.Fatalf("dnssec.listkeys params = %v, want domainName example.net", p)
	}
}

func TestListDelegationSignersReadsDSAndDNSKEYEntriesInEitherAnswerShape(t *testing.T) {
	f := dsFake(t)
	f.script("dnssec.listkeys", http.StatusOK, fixture(t, "dnssec_listkeys_dnskey_form.json"))

	got, err := f.provider().ListDelegationSigners(context.Background(), registration)
	if err != nil {
		t.Fatal(err)
	}

	want := []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key}, {KeyTag: 60485, DS: []string{rfc4034DS}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListDelegationSigners = %+v, want %+v", got, want)
	}
}

func TestListDelegationSignersOfAnUnsignedRegistrationIsEmpty(t *testing.T) {
	for _, body := range []string{answer(1000, []any{}), answer(1000, nil), answer(1000, map[string]any{"dnskey": []any{}})} {
		f := dsFake(t)
		f.script("dnssec.listkeys", http.StatusOK, body)

		got, err := f.provider().ListDelegationSigners(context.Background(), registration)
		if err != nil || len(got) != 0 {
			t.Fatalf("%s: ListDelegationSigners = %+v, %v; want none", body, got, err)
		}
	}
}

// dsWrites are the DNSSEC writes the fake received, in order.
func dsWrites(f *fake) []string {
	var out []string

	for _, m := range f.methodsCalled() {
		switch m {
		case "dnssec.adddnskey", "dnssec.deletednskey", "dnssec.deleteall":
			out = append(out, m)
		}
	}

	return out
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

	if w := dsWrites(f); len(w) != 0 || f.count("dnssec.listkeys") != 0 {
		t.Fatalf("sent %v and %d listkeys for a domain the Account does not register", w, f.count("dnssec.listkeys"))
	}
}

func TestDelegationSignersOfADomainINWXHostsAreUnsupportedWithoutAWrite(t *testing.T) {
	f := dsFake(t)
	p := f.provider()
	ctx := context.Background()

	if _, err := p.ListDelegationSigners(ctx, hosted); !errors.Is(err, dnsprovider.ErrUnsupported) {
		t.Errorf("List = %v, want ErrUnsupported", err)
	}

	if err := p.SetDelegationSigners(ctx, hosted, []dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: rfc6605Key}}); !errors.Is(err, dnsprovider.ErrUnsupported) {
		t.Errorf("Set = %v, want ErrUnsupported", err)
	}

	if err := p.DeleteDelegationSigners(ctx, hosted); !errors.Is(err, dnsprovider.ErrUnsupported) {
		t.Errorf("Delete = %v, want ErrUnsupported", err)
	}

	if w := dsWrites(f); len(w) != 0 {
		t.Fatalf("sent %v for a domain INWX hosts", w)
	}
}

func TestDelegationSignersReturnAFailedDomainReadAsItIs(t *testing.T) {
	f := dsFake(t)
	f.scriptCode("domain.info", 2400, "SYNTHETIC: failed")

	_, err := f.provider().ListDelegationSigners(context.Background(), registration)

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("List = %v, want the APIError of domain.info, not ErrNotFound", err)
	}
}

func TestDeleteDelegationSignersSendsDeleteAll(t *testing.T) {
	f := dsFake(t)
	p := f.provider()

	if err := p.DeleteDelegationSigners(context.Background(), registration); err != nil {
		t.Fatal(err)
	}

	if w := dsWrites(f); !slices.Equal(w, []string{"dnssec.deleteall"}) {
		t.Fatalf("writes = %v, want one dnssec.deleteall", w)
	}

	if p := f.params("dnssec.deleteall"); p["domainName"] != "example.net" {
		t.Fatalf("dnssec.deleteall params = %v", p)
	}

	if got, err := p.ListDelegationSigners(context.Background(), registration); err != nil || len(got) != 0 {
		t.Fatalf("after delete: List = %+v, %v; want none", got, err)
	}
}

func TestSetDelegationSignersSkipsAnUnchangedSetInEitherForm(t *testing.T) {
	for _, keys := range [][]dnsprovider.SigningKey{
		{{KeyTag: 55648, DNSKEY: rfc6605Key}},
		{{KeyTag: 55648, DS: []string{rfc6605DS}}},
		{{KeyTag: 55648, DNSKEY: rfc6605Key, DS: []string{rfc6605DS}}},
	} {
		f := dsFake(t)

		if err := f.provider().SetDelegationSigners(context.Background(), registration, keys); err != nil {
			t.Fatal(err)
		}

		if w := dsWrites(f); len(w) != 0 {
			t.Fatalf("%+v: writes = %v, want none for the held set", keys, w)
		}
	}
}

func TestSetDelegationSignersAddsTheNewKeyBeforeRemovingTheOld(t *testing.T) {
	f := dsFake(t)
	p := f.provider()

	if err := p.SetDelegationSigners(context.Background(), registration, []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DSSHA256}}}); err != nil {
		t.Fatal(err)
	}

	if w := dsWrites(f); !slices.Equal(w, []string{"dnssec.adddnskey", "dnssec.deletednskey"}) {
		t.Fatalf("writes = %v, want an add, then a delete", w)
	}

	add := f.params("dnssec.adddnskey")
	if add["domainName"] != "example.net" || add["ds"] != "example.net. IN DS "+rfc4034DSSHA256 || add["dnskey"] != nil {
		t.Fatalf("dnssec.adddnskey params = %v, want the DS alone", add)
	}

	if del := f.params("dnssec.deletednskey"); del["key"] != "7001" {
		t.Fatalf("dnssec.deletednskey params = %v, want key 7001 as listkeys gave it", del)
	}

	got, err := p.ListDelegationSigners(context.Background(), registration)
	if want := []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DSSHA256}}}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("after set: List = %+v, %v; want %+v", got, err, want)
	}
}

func TestSetDelegationSignersSendsADNSKEYWithItsDigestCalculated(t *testing.T) {
	f := dsFake(t)
	f.script("dnssec.listkeys", http.StatusOK, answer(1000, []any{}))

	key := dnsprovider.SigningKey{KeyTag: 55648, DNSKEY: rfc6605Key, DS: []string{rfc6605DS}}
	if err := f.provider().SetDelegationSigners(context.Background(), registration, []dnsprovider.SigningKey{key}); err != nil {
		t.Fatal(err)
	}

	if w := dsWrites(f); !slices.Equal(w, []string{"dnssec.adddnskey"}) {
		t.Fatalf("writes = %v, want one add", w)
	}

	add := f.params("dnssec.adddnskey")
	if add["dnskey"] != "example.net. IN DNSKEY "+rfc6605Key || add["calculateDigest"] != true || add["ds"] != nil {
		t.Fatalf("dnssec.adddnskey params = %v, want the DNSKEY with calculateDigest", add)
	}
}

func TestSetDelegationSignersSendsEachDSOfAKeyWithoutADNSKEY(t *testing.T) {
	f := dsFake(t)
	f.script("dnssec.listkeys", http.StatusOK, answer(1000, []any{}))

	key := dnsprovider.SigningKey{KeyTag: 60485, DS: []string{rfc4034DSSHA256, rfc4034DSSHA384}}
	if err := f.provider().SetDelegationSigners(context.Background(), registration, []dnsprovider.SigningKey{key}); err != nil {
		t.Fatal(err)
	}

	if w := dsWrites(f); !slices.Equal(w, []string{"dnssec.adddnskey", "dnssec.adddnskey"}) {
		t.Fatalf("writes = %v, want one add per DS", w)
	}
}

func TestSetDelegationSignersOfNoKeysSendsNothing(t *testing.T) {
	f := dsFake(t)

	for _, keys := range [][]dnsprovider.SigningKey{nil, {}} {
		if err := f.provider().SetDelegationSigners(context.Background(), registration, keys); !errors.Is(err, dnsprovider.ErrNoSigningKeys) {
			t.Fatalf("Set(%v) = %v, want ErrNoSigningKeys", keys, err)
		}
	}

	if calls := f.methodsCalled(); len(calls) != 0 {
		t.Fatalf("sent %v", calls)
	}
}

func TestSetDelegationSignersRefusesWhatINWXDoesNotTakeBeforeAnyRequest(t *testing.T) {
	for name, key := range map[string]dnsprovider.SigningKey{
		// INWX's documented dnssecAlgorithm values stop at 16, and its
		// dnssecDigestType values are 2 and 4.
		"algorithm 23":           {KeyTag: 60485, DS: []string{"60485 23 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A"}},
		"digest type 1":          {KeyTag: 60485, DS: []string{rfc4034DS}},
		"unsignable algorithm 3": {KeyTag: 60485, DS: []string{"60485 3 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A"}},
		"no DS or DNSKEY":        {KeyTag: 60485},
	} {
		f := dsFake(t)

		err := f.provider().SetDelegationSigners(context.Background(), registration, []dnsprovider.SigningKey{key})
		if !errors.Is(err, dnsprovider.ErrUnsupported) {
			t.Errorf("%s: Set = %v, want ErrUnsupported", name, err)
		}

		if calls := f.methodsCalled(); len(calls) != 0 {
			t.Errorf("%s: sent %v", name, calls)
		}
	}
}

func TestSetDelegationSignersReportsAPartialFailureWithoutUndoingIt(t *testing.T) {
	f := dsFake(t)
	f.scriptCode("dnssec.deletednskey", 2304, "SYNTHETIC: status prohibits")

	err := f.provider().SetDelegationSigners(context.Background(), registration, []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DSSHA256}}})

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnconfirmed) || !strings.Contains(err.Error(), "added 1") {
		t.Fatalf("Set = %v, want the refusal, saying the key was added", err)
	}

	if w := dsWrites(f); !slices.Equal(w, []string{"dnssec.adddnskey", "dnssec.deletednskey"}) {
		t.Fatalf("writes = %v, want the add kept and no undo", w)
	}
}

func TestSetDelegationSignersCountsWhatAPartialFailureDid(t *testing.T) {
	// One key of two DS forms to add, and the held key 7001 to remove.
	keys := []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DSSHA256, rfc4034DSSHA384}}}

	f := dsFake(t)
	f.script("dnssec.adddnskey", http.StatusOK, `{"code":1000,"msg":"Command completed successfully"}`)
	f.scriptCode("dnssec.adddnskey", 2304, "SYNTHETIC: status prohibits")

	err := f.provider().SetDelegationSigners(context.Background(), registration, keys)
	if err == nil || !strings.Contains(err.Error(), "added 1 of 2 forms, removed 0 of 1") {
		t.Fatalf("Set with the second add refused = %v, want added 1 of 2, removed 0 of 1", err)
	}

	f = dsFake(t)
	f.scriptCode("dnssec.deletednskey", 2304, "SYNTHETIC: status prohibits")

	err = f.provider().SetDelegationSigners(context.Background(), registration, keys)
	if err == nil || !strings.Contains(err.Error(), "added 2 of 2 forms, removed 0 of 1") {
		t.Fatalf("Set with the removal refused = %v, want added 2 of 2, removed 0 of 1", err)
	}
}

func TestDelegationSignerWritesWhoseOutcomeIsUnknownAreUnconfirmedAndNotRetried(t *testing.T) {
	for name, script := range map[string]func(f *fake, method string){
		"lost":        func(f *fake, m string) { f.script(m, lost, "") },
		"HTTP 502":    func(f *fake, m string) { f.script(m, http.StatusBadGateway, "") },
		"undecodable": func(f *fake, m string) { f.script(m, http.StatusOK, "<html>") },
		"2400":        func(f *fake, m string) { f.scriptCode(m, 2400, "SYNTHETIC: failed") },
		"2500": func(f *fake, m string) {
			f.script(m, http.StatusOK, `{"code":2500,"msg":"Command failed; server closing connection"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := dsFake(t)
			script(f, "dnssec.adddnskey")

			err := f.provider().SetDelegationSigners(context.Background(), registration, []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DSSHA256}}})
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("Set = %v, want ErrUnconfirmed", err)
			}

			if w := dsWrites(f); !slices.Equal(w, []string{"dnssec.adddnskey"}) {
				t.Fatalf("writes = %v, want the one add, not retried, and no removal", w)
			}

			f = dsFake(t)
			script(f, "dnssec.deleteall")

			if err := f.provider().DeleteDelegationSigners(context.Background(), registration); !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("Delete = %v, want ErrUnconfirmed", err)
			}

			if n := f.count("dnssec.deleteall"); n != 1 {
				t.Fatalf("sent %d deleteall, want 1", n)
			}
		})
	}
}

func TestDelegationSignerWritesPendingAtTheRegistryAreTaken(t *testing.T) {
	f := dsFake(t)
	f.script("dnssec.adddnskey", http.StatusOK, answer(1001, nil))
	f.script("dnssec.deletednskey", http.StatusOK, answer(1001, nil))
	f.script("dnssec.deleteall", http.StatusOK, answer(1001, nil))
	p := f.provider()

	if err := p.SetDelegationSigners(context.Background(), registration, []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DSSHA256}}}); err != nil {
		t.Fatalf("Set = %v, want 1001 taken", err)
	}

	if err := p.DeleteDelegationSigners(context.Background(), registration); err != nil {
		t.Fatalf("Delete = %v, want 1001 taken", err)
	}
}

func TestDelegationSignerWritesRefusedByINWXArePlainAPIErrors(t *testing.T) {
	f := dsFake(t)
	f.scriptCode("dnssec.adddnskey", 2306, "SYNTHETIC: policy")

	err := f.provider().SetDelegationSigners(context.Background(), registration, []dnsprovider.SigningKey{{KeyTag: 60485, DS: []string{rfc4034DSSHA256}}})

	var api *dnsprovider.APIError
	if !errors.As(err, &api) || errors.Is(err, dnsprovider.ErrUnconfirmed) || errors.Is(err, dnsprovider.ErrUnsupported) || !strings.Contains(err.Error(), "2306") {
		t.Fatalf("Set = %v, want a plain APIError carrying 2306", err)
	}

	if w := dsWrites(f); !slices.Equal(w, []string{"dnssec.adddnskey"}) {
		t.Fatalf("writes = %v, want the refused add and no removal", w)
	}
}

func TestDelegationSignerWritesRefusedForTheSessionAreResentOnceWithAFreshOne(t *testing.T) {
	f := dsFake(t)
	f.scriptCode("dnssec.deleteall", 2200, "")

	if err := f.provider().DeleteDelegationSigners(context.Background(), registration); err != nil {
		t.Fatal(err)
	}

	if logins, _, _ := f.stats(); logins != 2 || f.count("dnssec.deleteall") != 2 {
		t.Fatalf("logged in %d times and sent %d deleteall, want 2 of each", logins, f.count("dnssec.deleteall"))
	}
}
