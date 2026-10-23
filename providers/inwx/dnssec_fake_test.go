package inwx_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// dnssecFake is the fake with INWX's automated DNSSEC: each hosted zone's
// dnssec.info status, the keys dnssec.listkeys answers for a zone, and
// the switch through dnssec.enablednssec and dnssec.disablednssec.
type dnssecFake struct {
	*fake

	status   map[string]string // zone to its dnssecStatus; absent for no entry
	field    string            // the JSON name of the status field dnssec.info answers
	keys     map[string]string // zone to its dnssec.listkeys fixture
	settleOn map[bool]string   // the status a switch on (true) or off (false) leaves; the asked one when absent
}

// newDNSSECFake is the fake with example.com signed by INWX (AUTO, with
// the keys of dnssec_listkeys_example_com.json), example.org unsigned
// (NONE) and slave.example.net without a dnssec.info entry.
func newDNSSECFake(t *testing.T) *dnssecFake {
	t.Helper()

	d := &dnssecFake{
		fake:     newFake(t),
		status:   map[string]string{"example.com": "AUTO", "example.org": "NONE"},
		field:    "dnssecStatus",
		keys:     map[string]string{"example.com": "dnssec_listkeys_example_com.json"},
		settleOn: map[bool]string{},
	}

	d.handle("dnssec.info", d.info)
	d.handle("dnssec.listkeys", d.listKeys)
	d.handle("dnssec.enablednssec", func(r *request) string { return d.toggle(r, true) })
	d.handle("dnssec.disablednssec", func(r *request) string { return d.toggle(r, false) })

	return d
}

// setStatus sets a zone's dnssecStatus; empty removes its entry.
func (d *dnssecFake) setStatus(zone, status string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if status == "" {
		delete(d.status, zone)

		return
	}

	d.status[zone] = status
}

// info answers dnssec.info for its domains: an entry for each one with a
// status.
func (d *dnssecFake) info(r *request) string {
	domains, _ := r.params["domains"].([]any)
	data := []any{}

	for _, v := range domains {
		name, _ := v.(string)
		if status, ok := d.status[strings.ToLower(name)]; ok {
			keyCount := 0
			if status == "AUTO" {
				keyCount = 2
			}

			data = append(data, map[string]any{"domain": name, "keyCount": keyCount, d.field: status})
		}
	}

	return answer(1000, map[string]any{"data": data})
}

// listKeys answers dnssec.listkeys for its domainName from the zone's
// fixture, or with no keys.
func (d *dnssecFake) listKeys(r *request) string {
	name, _ := r.params["domainName"].(string)
	if file, ok := d.keys[strings.ToLower(name)]; ok {
		return fixture(d.t, file)
	}

	return answer(1000, []any{})
}

// toggle switches a hosted zone's automated DNSSEC on or off.
func (d *dnssecFake) toggle(r *request, on bool) string {
	name, _ := r.params["domainName"].(string)
	if d.zone(map[string]any{"domain": name}) == nil {
		return refusal(2303, "")
	}

	status, ok := d.settleOn[on]

	switch {
	case ok:
	case on:
		status = "AUTO"
	default:
		status = "NONE"
	}

	d.status[strings.ToLower(name)] = status

	return fixture(d.t, "ok.json")
}

// dnskeyForm is a dnssec.listkeys fixture with its keys under dnskey,
// the form INWX's documentation and goinwx give, instead of a bare array.
func dnskeyForm(t *testing.T, file string) string {
	t.Helper()

	var a map[string]any
	if err := json.Unmarshal([]byte(fixture(t, file)), &a); err != nil {
		t.Fatal(err)
	}

	a["resData"] = map[string]any{"dnskey": a["resData"]}

	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}
