package cloudflare_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
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
func newOffboarding(t *testing.T, o *offboard) dnsprovider.Provider {
	t.Helper()

	if o.api == nil {
		o.api = &cfAPI{zones: []map[string]any{cfZone("z1", "example.com"), cfZone("z2", "example.org")}}
	}

	o.install()

	p := newProvider(t, o.api)

	return p
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

	set, err := d.ListZones(context.Background(), dnsprovider.ZoneFilter{})
	if err != nil {
		t.Fatalf("Zones: %v", err)
	}

	zones := set.Zones

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
			// The Tenant's zone is read, then gone by the DELETE.
			o := &offboard{api: &cfAPI{zones: []map[string]any{cfZone("gone", "example.net")}}, answer: func(w http.ResponseWriter, _ *http.Request, _ int) bool {
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

func TestDeleteZoneNotFoundAfterTriesCloudflareAnsweredWithoutActingIsNotFound(t *testing.T) {
	// A 409 answers a try Cloudflare did not act on: the retry finding no
	// zone is no sign this call Offboarded it.
	o := &offboard{answer: func(w http.ResponseWriter, _ *http.Request, try int) bool {
		if try == 1 {
			w.Header().Set("Retry-After-Ms", "0")
			writeErrors(w, http.StatusConflict, 1000, "Conflict")
		} else {
			writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/z1, perhaps your object identifier is invalid?")
		}

		return true
	}}

	err := newOffboarding(t, o).DeleteZone(context.Background(), offboardZone)
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}

	if o.tries != 2 {
		t.Errorf("got %d DELETEs, want 2: a conflict is retried", o.tries)
	}
}

func TestDeleteZoneWhoseRetryFindsTheZoneGoneAfterAnUnansweredTrySucceeds(t *testing.T) {
	// The first try reaches Cloudflare, but the connection drops before
	// the answer: it may have Offboarded the zone.
	o := &offboard{answer: func(w http.ResponseWriter, _ *http.Request, try int) bool {
		if try == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)

				return true
			}

			_ = conn.Close()

			return true
		}

		writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/z1, perhaps your object identifier is invalid?")

		return true
	}}

	if err := newOffboarding(t, o).DeleteZone(context.Background(), offboardZone); err != nil {
		t.Errorf("DeleteZone: %v, want the retry finding the Zone gone to succeed", err)
	}
}

// unsentFirst fails the first DELETE before sending any of it, as a
// refused connection does, and sends the other requests.
type unsentFirst struct {
	mu    sync.Mutex
	tries int
}

func (u *unsentFirst) RoundTrip(r *http.Request) (*http.Response, error) {
	u.mu.Lock()
	if r.Method == http.MethodDelete {
		u.tries++
	}
	try := u.tries
	u.mu.Unlock()

	if try == 1 && r.Method == http.MethodDelete {
		return nil, errors.New("connection refused")
	}

	return http.DefaultTransport.RoundTrip(r)
}

func TestDeleteZoneNotFoundAfterATryNeverSentIsNotFound(t *testing.T) {
	api := &cfAPI{zones: []map[string]any{cfZone("z1", "example.com")}}
	o := &offboard{api: api, answer: func(w http.ResponseWriter, _ *http.Request, _ int) bool {
		writeErrors(w, http.StatusNotFound, 7003, "Could not route to /zones/z1, perhaps your object identifier is invalid?")

		return true
	}}
	o.install()

	srv := httptest.NewServer(api.handler(t))
	t.Cleanup(srv.Close)

	p, err := cloudflare.New(cloudflare.Config{Token: testToken, TenantID: acc1},
		dnsprovider.WithBaseURL(srv.URL+"/client/v4/"), dnsprovider.WithHTTPClient(&http.Client{Transport: &unsentFirst{}}))
	if err != nil {
		t.Fatal(err)
	}

	err = p.DeleteZone(context.Background(), offboardZone)
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound: the try that failed never reached Cloudflare", err)
	}

	if o.tries != 1 {
		t.Errorf("got %d DELETEs at Cloudflare, want 1", o.tries)
	}
}

// zoneOf is a Cloudflare zone of another account than the Tenant.
func zoneOf(id, name, account string) map[string]any {
	z := cfZone(id, name)
	z["account"] = map[string]any{"id": account, "name": "Other"}

	return z
}

func TestDeleteZoneRefusesAZoneOfAnotherAccountThanTheTenantWithoutDeleting(t *testing.T) {
	o := &offboard{api: &cfAPI{zones: []map[string]any{zoneOf("z1", "example.com", acc2)}}}

	err := newOffboarding(t, o).DeleteZone(context.Background(), offboardZone)
	if err == nil || !strings.Contains(err.Error(), acc2) {
		t.Errorf("err = %v, want a refusal naming the zone's account", err)
	}

	if o.tries != 0 {
		t.Errorf("got %d DELETEs, want none", o.tries)
	}

	if got := o.api.Requests(); !slices.Contains(got, "/client/v4/zones/z1?page=") {
		t.Errorf("requests = %q, want the zone read by its ID first", got)
	}
}

func TestDeleteZoneOfAZoneTheTenantCannotReadIsNotFoundWithoutDeleting(t *testing.T) {
	o := &offboard{}

	err := newOffboarding(t, o).DeleteZone(context.Background(), dnsprovider.Zone{ID: "gone", Name: "example.net"})
	if !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}

	if o.tries != 0 {
		t.Errorf("got %d DELETEs, want none", o.tries)
	}
}

func TestDeleteZoneWithoutATenantDeletesWithoutReadingTheZone(t *testing.T) {
	// Unscoped, every account the token reaches is the Provider's: the
	// caller owns the check that the Zone is the one it means.
	o := &offboard{api: &cfAPI{zones: []map[string]any{zoneOf("z1", "example.com", acc2)}}}
	o.install()

	srv := httptest.NewServer(o.api.handler(t))
	t.Cleanup(srv.Close)

	p, err := cloudflare.New(cloudflare.Config{Token: testToken}, dnsprovider.WithBaseURL(srv.URL+"/client/v4/"))
	if err != nil {
		t.Fatal(err)
	}

	if err := p.DeleteZone(context.Background(), offboardZone); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	if got := o.api.Requests(); !slices.Equal(got, []string{"/client/v4/zones/z1?page="}) || o.tries != 1 {
		t.Errorf("requests = %q, want the DELETE alone", got)
	}
}
