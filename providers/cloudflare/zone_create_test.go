package cloudflare_test

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// onboard is a Cloudflare account's POST /zones: it Onboards a zone name
// in the account the body names, as Cloudflare does, answering with the
// new zone pending and the nameservers it assigned.
type onboard struct {
	api *cfAPI
	// answer, when set, answers the POST instead.
	answer http.HandlerFunc
	nextID int
}

// install makes api answer POST /zones through o.
func (o *onboard) install() {
	next := o.api.intercept
	o.api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != "/client/v4/zones" {
			return next != nil && next(w, r)
		}

		body, ok := o.api.writeSetting(w, r)
		if !ok {
			return true
		}

		if o.answer != nil {
			o.answer(w, r)

			return true
		}

		o.nextID++

		zone := cfZone("new"+string(rune('0'+o.nextID)), body["name"].(string), "cruz.ns.cloudflare.com", "dina.ns.cloudflare.com")
		zone["status"] = "pending"

		o.api.mu.Lock()
		o.api.zones = append(o.api.zones, zone)
		o.api.mu.Unlock()

		writeResult(w, zone)

		return true
	}
}

// newOnboarding builds the Provider scoped to acc1, Onboarding through o.
func newOnboarding(t *testing.T, o *onboard) dnsprovider.ZoneCreator {
	t.Helper()

	if o.api == nil {
		o.api = &cfAPI{}
	}

	o.install()

	p := newProvider(t, o.api)

	c, ok := p.(dnsprovider.ZoneCreator)
	if !ok {
		t.Fatal("Cloudflare is not a ZoneCreator")
	}

	return c
}

func TestCloudflareCreatesZones(t *testing.T) {
	if !dnsprovider.CanCreateZone(newProvider(t, &cfAPI{})) {
		t.Error("Cloudflare does not create Zones")
	}
}

func TestCreateZonePostsTheNameInTheTenantAndReturnsItPendingWithItsNameservers(t *testing.T) {
	o := &onboard{}

	got, err := newOnboarding(t, o).CreateZone(context.Background(), "Example.ORG.")
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	want := dnsprovider.Zone{
		ID:          "new1",
		Name:        "example.org",
		State:       dnsprovider.HostingPending,
		Nameservers: []string{"cruz.ns.cloudflare.com", "dina.ns.cloudflare.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CreateZone = %+v, want %+v", got, want)
	}

	assertWrites(t, o.api, []write{{Method: "POST", Path: "/client/v4/zones", Body: map[string]any{
		"account": map[string]any{"id": acc1},
		"name":    "example.org",
		"type":    "full",
	}}})
}

func TestCreateZoneOfANameCloudflareHoldsIsAConflict(t *testing.T) {
	// Cloudflare refuses a zone name its account already has, or that
	// another account holds, with code 1061.
	for _, msg := range []string{"example.org already exists", "A zone with this name already exists in another account"} {
		o := &onboard{answer: func(w http.ResponseWriter, _ *http.Request) {
			writeErrors(w, http.StatusBadRequest, 1061, msg)
		}}

		_, err := newOnboarding(t, o).CreateZone(context.Background(), "example.org")
		if !errors.Is(err, dnsprovider.ErrConflict) {
			t.Errorf("%s: err = %v, want ErrConflict", msg, err)
		}
	}
}

func TestCreateZoneWithoutATenantIsErrNoTenantWithoutARequest(t *testing.T) {
	api := &cfAPI{}

	if _, err := newProviderIn(t, api, acme, "").CreateZone(context.Background(), "example.org"); !errors.Is(err, dnsprovider.ErrNoTenant) {
		t.Errorf("err = %v, want ErrNoTenant", err)
	}

	if reqs := api.Requests(); len(reqs) != 0 {
		t.Errorf("requests = %v, want none", reqs)
	}
}

func TestCreateZoneOfNoNameFailsWithoutARequest(t *testing.T) {
	o := &onboard{}
	p := newOnboarding(t, o)

	for _, name := range []string{"", ".", " "} {
		if _, err := p.CreateZone(context.Background(), name); err == nil {
			t.Errorf("CreateZone(%q) succeeded", name)
		}
	}

	if reqs := o.api.Requests(); len(reqs) != 0 {
		t.Errorf("requests = %v, want none", reqs)
	}
}

func TestCreateZoneIsNotRetried(t *testing.T) {
	o := &onboard{answer: func(w http.ResponseWriter, _ *http.Request) {
		writeErrors(w, http.StatusInternalServerError, 1000, "Internal error")
	}}

	if _, err := newOnboarding(t, o).CreateZone(context.Background(), "example.org"); err == nil {
		t.Fatal("CreateZone succeeded")
	}

	if got := len(o.api.Writes()); got != 1 {
		t.Errorf("sent %d POSTs, want 1", got)
	}
}

func TestCreateZoneWhoseAnswerHoldsNoZoneReadsItBack(t *testing.T) {
	pending := cfZone("new9", "example.org", "cruz.ns.cloudflare.com", "dina.ns.cloudflare.com")
	pending["status"] = "pending"

	o := &onboard{api: &cfAPI{zones: []map[string]any{pending}}, answer: func(w http.ResponseWriter, _ *http.Request) {
		writeResult(w, nil)
	}}

	got, err := newOnboarding(t, o).CreateZone(context.Background(), "example.org")
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	want := dnsprovider.Zone{
		ID:          "new9",
		Name:        "example.org",
		State:       dnsprovider.HostingPending,
		Nameservers: []string{"cruz.ns.cloudflare.com", "dina.ns.cloudflare.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CreateZone = %+v, want %+v", got, want)
	}
}

func TestCreateZoneWhoseAnswerHoldsNoZoneAndCannotBeReadBackStillSucceedsPendingWithoutAnID(t *testing.T) {
	// Cloudflare took the create (ADR-0001): a failed read-back does not
	// make it a failure. Nothing lists the Zone yet, or the list fails.
	for name, list := range map[string]http.HandlerFunc{
		"not listed": nil,
		"list fails": func(w http.ResponseWriter, _ *http.Request) {
			writeErrors(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := &cfAPI{}
			if list != nil {
				api.intercept = func(w http.ResponseWriter, r *http.Request) bool {
					if r.Method != http.MethodGet || r.URL.Path != "/client/v4/zones" {
						return false
					}

					list(w, r)

					return true
				}
			}

			o := &onboard{api: api, answer: func(w http.ResponseWriter, _ *http.Request) { writeResult(w, nil) }}

			got, err := newOnboarding(t, o).CreateZone(context.Background(), "Example.ORG")
			if err != nil {
				t.Fatalf("CreateZone: %v, want success", err)
			}

			if want := (dnsprovider.Zone{Name: "example.org", State: dnsprovider.HostingPending}); !reflect.DeepEqual(got, want) {
				t.Errorf("CreateZone = %+v, want %+v", got, want)
			}
		})
	}
}
