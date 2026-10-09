package cloudflare_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

// offboard is a Cloudflare account's DELETE /zones/{id}: it drops the
// zone, as Cloudflare does, and answers with its ID; an unknown ID is
// answered as Cloudflare answers a zone it cannot route to.
type offboard struct {
	api *cfAPI
	// answer, when set, answers each DELETE instead, given which try it
	// is, counted from 1.
	answer func(w http.ResponseWriter, r *http.Request, try int) bool
	tries  int
}

// install makes api answer DELETE /zones/{id} through o.
func (o *offboard) install() {
	next := o.api.intercept
	o.api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		id, ok := zoneDeletePath(r)
		if !ok {
			return next != nil && next(w, r)
		}

		o.api.mu.Lock()
		o.tries++
		try := o.tries
		o.api.writes = append(o.api.writes, write{Method: r.Method, Path: r.URL.Path})
		o.api.mu.Unlock()

		if o.answer != nil && o.answer(w, r, try) {
			return true
		}

		o.api.mu.Lock()
		i := slices.IndexFunc(o.api.zones, func(z map[string]any) bool { return z["id"] == id })
		if i >= 0 {
			o.api.zones = slices.Delete(o.api.zones, i, i+1)
		}
		o.api.mu.Unlock()

		if i < 0 {
			writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/"+id+", perhaps your object identifier is invalid?")

			return true
		}

		writeResult(w, map[string]any{"id": id})

		return true
	}
}

// zoneDeletePath is the zone ID of a DELETE /zones/{id}.
func zoneDeletePath(r *http.Request) (string, bool) {
	const prefix = "/client/v4/zones/"

	if r.Method != http.MethodDelete || len(r.URL.Path) <= len(prefix) || r.URL.Path[:len(prefix)] != prefix {
		return "", false
	}

	id := r.URL.Path[len(prefix):]
	if slices.Contains([]byte(id), '/') {
		return "", false
	}

	return id, true
}

// newOffboarding builds the Provider scoped to acc1, Offboarding through o.
func newOffboarding(t *testing.T, o *offboard) dnsprovider.ZoneDeleter {
	t.Helper()

	if o.api == nil {
		o.api = &cfAPI{zones: []map[string]any{cfZone("z1", "example.com"), cfZone("z2", "example.org")}}
	}

	o.install()

	p := newProvider(t, o.api)

	d, ok := p.(dnsprovider.ZoneDeleter)
	if !ok {
		t.Fatal("Cloudflare is not a ZoneDeleter")
	}

	return d
}

var offboardZone = dnsprovider.Zone{ID: "z1", Name: "example.com", State: dnsprovider.HostingPending}

func TestCloudflareDeletesZonesAndItsFactorySaysSo(t *testing.T) {
	if !dnsprovider.CanDeleteZone(newProvider(t, &cfAPI{})) {
		t.Error("Cloudflare does not delete Zones")
	}

	if !cloudflare.Factory().Can(dnsprovider.CapZoneDeleter) {
		t.Error("Cloudflare's Factory does not declare ZoneDeleter")
	}
}

func TestDeleteZoneDeletesTheZoneByItsID(t *testing.T) {
	o := &offboard{}
	d := newOffboarding(t, o)

	if err := d.DeleteZone(context.Background(), offboardZone); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	assertWrites(t, o.api, []write{{Method: "DELETE", Path: "/client/v4/zones/z1"}})

	zones, err := d.(dnsprovider.Provider).Zones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	if got := zoneNames(zones); !slices.Equal(got, []string{"example.org"}) {
		t.Errorf("Zones after DeleteZone = %v, want only example.org", got)
	}
}

func TestDeleteZoneWithoutAnIDFailsWithoutARequest(t *testing.T) {
	o := &offboard{}

	err := newOffboarding(t, o).DeleteZone(context.Background(), dnsprovider.Zone{Name: "example.com"})
	if err == nil {
		t.Fatal("DeleteZone of a Zone without an ID succeeded")
	}

	if len(o.api.Writes()) != 0 {
		t.Errorf("DeleteZone without an ID sent %v", o.api.Writes())
	}
}

func TestDeleteZoneWhoseRetryFindsTheZoneGoneSucceeds(t *testing.T) {
	// The first try deletes the zone but its answer is lost to a server
	// error; the retry finds no zone of that ID, which means the first
	// try Offboarded it.
	for name, gone := range map[string]func(http.ResponseWriter){
		"unroutable": func(w http.ResponseWriter) {
			writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/z1, perhaps your object identifier is invalid?")
		},
		"invalid zone identifier": func(w http.ResponseWriter) {
			writeErrors(w, http.StatusBadRequest, 1001, "Invalid zone identifier")
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := &offboard{answer: func(w http.ResponseWriter, _ *http.Request, try int) bool {
				if try == 1 {
					serverError(w)
				} else {
					gone(w)
				}

				return true
			}}

			if err := newOffboarding(t, o).DeleteZone(context.Background(), offboardZone); err != nil {
				t.Errorf("DeleteZone: %v, want the retry finding the Zone gone to succeed", err)
			}

			if o.tries != 2 {
				t.Errorf("got %d DELETEs, want 2: a delete is retried", o.tries)
			}
		})
	}
}

func TestDeleteZoneOfAZoneCloudflareDoesNotKnowOnTheFirstTryIsNotFound(t *testing.T) {
	// Nothing this call sent before could have Offboarded it, so it is
	// not taken as done.
	for name, unknown := range map[string]func(http.ResponseWriter){
		"unroutable": func(w http.ResponseWriter) {
			writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/gone, perhaps your object identifier is invalid?")
		},
		"invalid zone identifier": func(w http.ResponseWriter) {
			writeErrors(w, http.StatusBadRequest, 1001, "Invalid zone identifier")
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := &offboard{answer: func(w http.ResponseWriter, _ *http.Request, _ int) bool {
				unknown(w)

				return true
			}}

			err := newOffboarding(t, o).DeleteZone(context.Background(), dnsprovider.Zone{ID: "gone", Name: "example.net"})
			if !errors.Is(err, dnsprovider.ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound", err)
			}

			if o.tries != 1 {
				t.Errorf("got %d DELETEs, want 1: a not-found is not retried", o.tries)
			}
		})
	}
}

func TestDeleteZoneCloudflareRefusesIsAnError(t *testing.T) {
	for name, refuse := range map[string]func(http.ResponseWriter){
		"forbidden": func(w http.ResponseWriter) {
			writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")
		},
		"2xx without success": func(w http.ResponseWriter) {
			writeJSON(w, http.StatusOK, map[string]any{"success": false, "errors": []any{map[string]any{"code": 1000, "message": "nope"}}, "messages": []any{}, "result": nil})
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := &offboard{answer: func(w http.ResponseWriter, _ *http.Request, _ int) bool {
				refuse(w)

				return true
			}}

			if err := newOffboarding(t, o).DeleteZone(context.Background(), offboardZone); err == nil {
				t.Error("DeleteZone Cloudflare refused succeeded")
			}
		})
	}
}

func TestDeleteZoneCloudflareTookWithoutAReadableAnswerSucceeds(t *testing.T) {
	// The success answer is authoritative (ADR-0001).
	o := &offboard{answer: func(w http.ResponseWriter, _ *http.Request, _ int) bool {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "result": "not a zone"})

		return true
	}}

	if err := newOffboarding(t, o).DeleteZone(context.Background(), offboardZone); err != nil {
		t.Errorf("DeleteZone: %v, want the delete Cloudflare took to succeed", err)
	}
}
