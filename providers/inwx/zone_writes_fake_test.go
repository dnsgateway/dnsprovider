package inwx_test

import (
	"fmt"
	"strings"
)

// createZone answers nameserver.create: a new master zone with the next
// roId, an SOA and an apex NS record for each nameserver given. A zone
// INWX already hosts is refused with 2302.
func (f *fake) createZone(r *request) string {
	name, _ := r.params["domain"].(string)
	name = strings.ToLower(name)

	if f.zone(map[string]any{"domain": name}) != nil {
		return refusal(2302, "")
	}

	roID := 1000
	for _, z := range f.zones {
		roID = max(roID, number(z.fields["roId"], 0))
	}

	roID++

	z := &fakeZone{fields: map[string]any{"roId": float64(roID), "domain": name, "type": r.params["type"], "SOAserial": "2026102201"}}
	z.records = append(z.records, map[string]any{
		"id": fmt.Sprint(roID*10 + 1), "name": name, "type": "SOA",
		"content": "ns.inwx.de hostmaster.inwx.de 2026102201 10800 3600 604800 3600", "ttl": float64(86400), "prio": float64(0),
	})

	ns, _ := r.params["ns"].([]any)
	for i, n := range ns {
		z.records = append(z.records, map[string]any{
			"id": fmt.Sprint(roID*10 + 2 + i), "name": name, "type": "NS", "content": n, "ttl": float64(86400), "prio": float64(0),
		})
	}

	f.zones = append(f.zones, z)

	return answer(1000, map[string]any{"roId": roID})
}

// deleteZone answers nameserver.delete: the zone of the domain or roId
// param and its records are gone; an unknown zone is refused with 2303.
func (f *fake) deleteZone(r *request) string {
	z := f.zone(r.params)
	if z == nil {
		return refusal(2303, "")
	}

	for i, held := range f.zones {
		if held == z {
			f.zones = append(f.zones[:i], f.zones[i+1:]...)

			break
		}
	}

	return fixture(f.t, "ok.json")
}
