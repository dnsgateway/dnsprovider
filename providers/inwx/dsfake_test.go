package inwx_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/dnssec"
)

// dsRegistry is the DNSSEC keys INWX holds for the Account's
// registrations, as the fake's dnssec.* methods keep them: entries of
// dnssec.listkeys by domain.
type dsRegistry struct {
	keys   map[string][]map[string]any
	nextID int
}

// dsFake is the fake with INWX's DNSSEC key calls: example.net is
// registered without an INWX zone and holds the key of
// dnssec_listkeys_example_net.json; example.com is registered and hosted.
// Every handler runs under the fake's lock.
func dsFake(t *testing.T) *fake {
	t.Helper()

	f := newFake(t)
	f.registered["example.com"] = "domain_info.json"

	var seed struct {
		ResData []map[string]any `json:"resData"`
	}
	if err := json.Unmarshal([]byte(fixture(t, "dnssec_listkeys_example_net.json")), &seed); err != nil {
		t.Fatal(err)
	}

	reg := &dsRegistry{keys: map[string][]map[string]any{"example.net": seed.ResData}, nextID: 8000}

	domain := func(r *request) (string, bool) {
		name, _ := r.params["domainName"].(string)
		name = strings.ToLower(name)
		_, ok := f.registered[name]

		return name, ok
	}

	f.handle("dnssec.listkeys", func(r *request) string {
		if r.params["active"] != float64(1) {
			t.Errorf("dnssec.listkeys sent active %v, want 1", r.params["active"])
		}

		name, ok := domain(r)
		if !ok {
			return answer(1000, []any{})
		}

		entries := reg.keys[name]
		if entries == nil {
			entries = []map[string]any{}
		}

		return answer(1000, entries)
	})

	f.handle("dnssec.adddnskey", func(r *request) string {
		name, ok := domain(r)
		if !ok {
			return refusal(2303, "")
		}

		entry, err := reg.entry(name, r.params)
		if err != nil {
			t.Errorf("dnssec.adddnskey: %v", err)

			return refusal(2005, "")
		}

		reg.keys[name] = append(reg.keys[name], entry)

		return answer(1000, map[string]any{"dnskey": r.params["dnskey"], "ds": fmt.Sprintf("%s %s %s %s", entry["keyTag"], entry["algorithmId"], entry["digestTypeId"], entry["digest"])})
	})

	f.handle("dnssec.deletednskey", func(r *request) string {
		for name, entries := range reg.keys {
			for i, e := range entries {
				if fmt.Sprint(e["id"]) == fmt.Sprint(r.params["key"]) {
					reg.keys[name] = append(entries[:i:i], entries[i+1:]...)

					return answer(1000, nil)
				}
			}
		}

		return refusal(2303, "")
	})

	f.handle("dnssec.deleteall", func(r *request) string {
		name, ok := domain(r)
		if !ok {
			return refusal(2303, "")
		}

		delete(reg.keys, name)

		return answer(1000, nil)
	})

	return f
}

// entry is the listkeys entry an adddnskey call makes: from a DNSKEY,
// with its SHA-256 digest when calculateDigest is set, or from a DS.
func (reg *dsRegistry) entry(name string, params map[string]any) (map[string]any, error) {
	reg.nextID++
	e := map[string]any{"ownerName": name, "id": fmt.Sprint(reg.nextID), "status": "OK", "active": "1", "publicKey": "", "digest": "", "digestTypeId": ""}

	value := func(param, typ string) (string, error) {
		s, _ := params[param].(string)
		f := strings.Fields(s)

		if len(f) < 4 || f[0] != name+"." || f[1] != "IN" || f[2] != typ {
			return "", fmt.Errorf("%s %q is not %q. IN %s ...", param, s, name, typ)
		}

		return strings.Join(f[3:], " "), nil
	}

	if _, ok := params["dnskey"]; ok {
		v, err := value("dnskey", "DNSKEY")
		if err != nil {
			return nil, err
		}

		s, err := dnssec.Parse(dnssec.DNSKEY, v)
		if err != nil {
			return nil, err
		}

		f := strings.Fields(s.Value)
		e["keyTag"], e["flagId"], e["algorithmId"], e["publicKey"] = fmt.Sprint(s.Tag), f[0], f[2], f[3]

		if params["calculateDigest"] == true {
			digest, err := dnssec.Digest(name, s.RDATA, 2)
			if err != nil {
				return nil, err
			}

			e["digestTypeId"], e["digest"] = "2", digest
		}

		return e, nil
	}

	v, err := value("ds", "DS")
	if err != nil {
		return nil, err
	}

	s, err := dnssec.Parse(dnssec.DS, v)
	if err != nil {
		return nil, err
	}

	f := strings.Fields(s.Value)
	e["keyTag"], e["flagId"], e["algorithmId"], e["digestTypeId"], e["digest"] = f[0], "257", f[1], f[2], f[3]

	return e, nil
}
