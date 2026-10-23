package dnssec_test

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/internal/dnssec"
)

// rdata is a DNSKEY's RDATA from its flags, protocol, algorithm and
// base64 key.
func rdata(t *testing.T, flags uint16, protocol, algorithm uint8, key string) []byte {
	t.Helper()

	pub, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}

	return append([]byte{byte(flags >> 8), byte(flags), protocol, algorithm}, pub...)
}

// The keys of RFC 4034 section 5.4 and RFC 6605 section 6.1, with the key
// tags and DS digests those RFCs give.
const (
	rfc4034Key = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw=="
	rfc6605Key = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
)

func TestKeyTagMatchesTheRFCExamples(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want uint16
	}{
		{"RFC 4034 RSASHA1", rdata(t, 256, 3, 5, rfc4034Key), 60485},
		{"RFC 6605 ECDSAP256SHA256", rdata(t, 257, 3, 13, rfc6605Key), 55648},
	} {
		got, err := dnssec.KeyTag(tc.data)
		if err != nil || got != tc.want {
			t.Errorf("%s: KeyTag = %d, %v; want %d", tc.name, got, err, tc.want)
		}
	}
}

func TestKeyTagOfRSAMD5IsTheModulusTail(t *testing.T) {
	// RFC 4034 Appendix B.1: the third-to-last and second-to-last octets.
	got, err := dnssec.KeyTag([]byte{1, 0, 3, 1, 9, 9, 0xAB, 0xCD, 0xEF})
	if err != nil || got != 0xABCD {
		t.Fatalf("KeyTag = %#x, %v; want 0xabcd", got, err)
	}

	if _, err := dnssec.KeyTag([]byte{1, 0, 3, 1, 9}); err == nil {
		t.Fatal("a short RSA/MD5 key has a key tag")
	}

	if _, err := dnssec.KeyTag([]byte{1, 0, 3}); err == nil {
		t.Fatal("RDATA without an algorithm has a key tag")
	}
}

func TestDigestMatchesTheRFCExamples(t *testing.T) {
	for _, tc := range []struct {
		name, owner string
		data        []byte
		digestType  uint8
		want        string
	}{
		{"RFC 4034 SHA-1", "dskey.example.com", rdata(t, 256, 3, 5, rfc4034Key), 1, "2BB183AF5F22588179A53B0A98631FAD1A292118"},
		{"RFC 6605 SHA-256", "Example.NET.", rdata(t, 257, 3, 13, rfc6605Key), 2, "B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17"},
	} {
		got, err := dnssec.Digest(tc.owner, tc.data, tc.digestType)
		if err != nil || got != tc.want {
			t.Errorf("%s: Digest = %s, %v; want %s", tc.name, got, err, tc.want)
		}
	}

	if _, err := dnssec.Digest("example.net", rdata(t, 257, 3, 13, rfc6605Key), 3); err == nil {
		t.Error("GOST R 34.11-94 (digest type 3) has a digest")
	}
}

func TestSignableAndAssigned(t *testing.T) {
	for alg := range 256 {
		want := false

		switch alg {
		case 5, 7, 8, 10, 13, 14, 15, 16, 17, 23:
			want = true
		}

		if got := dnssec.Signable(uint8(alg)); got != want {
			t.Errorf("Signable(%d) = %v", alg, got)
		}
	}

	for dt := range 256 {
		if got, want := dnssec.DigestAssigned(uint8(dt)), dt >= 1 && dt <= 6; got != want {
			t.Errorf("DigestAssigned(%d) = %v", dt, got)
		}
	}
}

func TestParseNormalisesADSAndComputesADNSKEYsKeyTag(t *testing.T) {
	ds, err := dnssec.Parse(dnssec.DS, "55648 13 2 b4c8c1fe2e7477127b27115656ad6256 f424625bf5c1e2770ce6d6e37df61d17")
	if err != nil {
		t.Fatal(err)
	}

	if want := "55648 13 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17"; ds.Value != want || ds.Tag != 55648 || ds.DigestType != 2 {
		t.Errorf("DS = %+v, want %s", ds, want)
	}

	key, err := dnssec.Parse(dnssec.DNSKEY, "257 3 13 "+rfc6605Key)
	if err != nil {
		t.Fatal(err)
	}

	if key.Tag != 55648 || key.Algorithm != 13 || key.Form != dnssec.DNSKEY || key.Form.String() != "DNSKEY" {
		t.Errorf("DNSKEY = %+v, want key tag 55648 and algorithm 13", key)
	}
}

func TestParseRefusesAnUnknownForm(t *testing.T) {
	if s, err := dnssec.Parse(dnssec.Form(0), "55648 13 2 B4C8"); err == nil || !strings.Contains(err.Error(), "unexpected signing record type") {
		t.Fatalf("Parse = %+v, %v; want an unexpected signing record type error", s, err)
	}
}

func TestGroupMakesOneKeyPerKeyTagAndAlgorithmSHA256First(t *testing.T) {
	var signers []dnssec.Signer

	for _, v := range []struct {
		form  dnssec.Form
		value string
	}{
		{dnssec.DS, "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"},
		{dnssec.DS, "55648 13 1 0123456789ABCDEF0123456789ABCDEF01234567"},
		{dnssec.DNSKEY, "257 3 13 " + rfc6605Key},
		{dnssec.DS, "55648 13 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17"},
	} {
		s, err := dnssec.Parse(v.form, v.value)
		if err != nil {
			t.Fatal(err)
		}

		signers = append(signers, s)
	}

	keys, err := dnssec.Group(signers)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 || keys[0].KeyTag != 55648 || keys[0].DNSKEY != "257 3 13 "+rfc6605Key || len(keys[0].DS) != 2 ||
		keys[0].DS[0] != "55648 13 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17" || keys[1].KeyTag != 60485 {
		t.Fatalf("Group = %+v", keys)
	}

	other, err := dnssec.Parse(dnssec.DNSKEY, "257 3 13 "+rfc4034Key)
	if err != nil {
		t.Fatal(err)
	}

	other.Tag = 55648

	if _, err := dnssec.Group(append(signers, other)); err == nil {
		t.Fatal("distinct DNSKEYs of one key tag and algorithm grouped")
	}
}

func TestCheckKeysRefusesWhatNoRegistryTakes(t *testing.T) {
	for name, key := range map[string]dnsprovider.SigningKey{
		"no form":          {KeyTag: 1},
		"algorithm 1":      {KeyTag: 1, DS: []string{"1 1 2 ABCD"}},
		"digest type 9":    {KeyTag: 1, DS: []string{"1 13 9 ABCD"}},
		"DNSKEY algorithm": {KeyTag: 1, DNSKEY: "257 3 3 " + rfc6605Key},
	} {
		if _, err := dnssec.CheckKeys([]dnsprovider.SigningKey{key}); !errors.Is(err, dnsprovider.ErrUnsupported) {
			t.Errorf("%s: CheckKeys = %v, want ErrUnsupported", name, err)
		}
	}

	if _, err := dnssec.CheckKeys([]dnsprovider.SigningKey{{KeyTag: 1, DNSKEY: "257 3 13 " + rfc6605Key}}); err == nil || errors.Is(err, dnsprovider.ErrUnsupported) {
		t.Errorf("a DNSKEY of another key tag: CheckKeys = %v, want a plain error", err)
	}
}

func TestDiffTakesAKeyHeldInAnyFormAsHeld(t *testing.T) {
	// The registry holds the RFC 6605 key's SHA-256 DS, computed for
	// example.net, and an RSASHA1 key no wanted key is a form of.
	held := [][]string{
		{"DS 55648 13 2 B4C8C1FE2E7477127B27115656AD6256F424625BF5C1E2770CE6D6E37DF61D17"},
		{"DNSKEY 256 3 5 " + rfc4034Key, "DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"},
	}

	want, err := dnssec.CheckKeys([]dnsprovider.SigningKey{
		{KeyTag: 55648, DNSKEY: "257 3 13 " + rfc6605Key},
		{KeyTag: 2371, DS: []string{"2371 13 2 1F987CC6583E92DF0890718C42"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	plan := dnssec.Diff("example.net", parsed(t, held), func(h []dnssec.Signer) []dnssec.Signer { return h }, want)
	if !slices.Equal(plan.Add, []int{1}) || !slices.Equal(plan.Remove, []int{1}) || plan.Same() {
		t.Fatalf("Diff = %+v, want Add [1] and Remove [1]", plan)
	}

	plan = dnssec.Diff("example.net", parsed(t, held[:1]), func(h []dnssec.Signer) []dnssec.Signer { return h }, want[:1])
	if !plan.Same() {
		t.Fatalf("Diff = %+v, want the DNSKEY held as its DS", plan)
	}
}

func TestDiffAgainstNothingHeldAddsEveryKey(t *testing.T) {
	want, err := dnssec.CheckKeys([]dnsprovider.SigningKey{{KeyTag: 55648, DNSKEY: "257 3 13 " + rfc6605Key}})
	if err != nil {
		t.Fatal(err)
	}

	plan := dnssec.Diff("example.net", []dnssec.Signer(nil), func(s dnssec.Signer) []dnssec.Signer { return []dnssec.Signer{s} }, want)
	if !slices.Equal(plan.Add, []int{0}) || len(plan.Remove) != 0 {
		t.Fatalf("Diff = %+v, want Add [0]", plan)
	}
}

// parsed is each held entry's forms, each form "TYPE value".
func parsed(t *testing.T, held [][]string) [][]dnssec.Signer {
	t.Helper()

	out := make([][]dnssec.Signer, 0, len(held))

	for _, entry := range held {
		var forms []dnssec.Signer

		for _, f := range entry {
			typ, value, _ := strings.Cut(f, " ")

			form := dnssec.DS
			if typ == "DNSKEY" {
				form = dnssec.DNSKEY
			}

			s, err := dnssec.Parse(form, value)
			if err != nil {
				t.Fatal(err)
			}

			forms = append(forms, s)
		}

		out = append(out, forms)
	}

	return out
}
