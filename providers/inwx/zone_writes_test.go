package inwx_test

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/providers/inwx"
)

// inwxNameservers are the nameservers a zone INWX hosts is served by.
var inwxNameservers = []string{"ns.inwx.de", "ns2.inwx.de", "ns3.inwx.eu"}

func TestCreateZoneOnboardsAMasterZoneOnINWXNameservers(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	z, err := p.CreateZone(context.Background(), "New.Example.  ")
	if err != nil {
		t.Fatal(err)
	}

	want := dnsprovider.Zone{ID: "1004", Name: "new.example", Nameservers: inwxNameservers, State: dnsprovider.HostingUnknown}
	if !reflect.DeepEqual(z, want) {
		t.Fatalf("CreateZone = %+v, want %+v", z, want)
	}

	if n := f.count("nameserver.create"); n != 1 {
		t.Fatalf("sent %d nameserver.create, want 1", n)
	}

	params := maps.Clone(f.params("nameserver.create"))
	delete(params, "lang")

	if want := map[string]any{"domain": "new.example", "type": "MASTER", "ns": []any{"ns.inwx.de", "ns2.inwx.de", "ns3.inwx.eu"}}; !reflect.DeepEqual(params, want) {
		t.Fatalf("nameserver.create params = %v, want only %v", params, want)
	}

	got, err := p.GetZone(context.Background(), "new.example")
	if err != nil {
		t.Fatal(err)
	}

	if got.ID != z.ID {
		t.Fatalf("GetZone after CreateZone = %+v, want ID %s", got, z.ID)
	}

	noDomainCalls(t, f)
}

func TestTraitsDeclareZoneCreateAndDelete(t *testing.T) {
	f := newFake(t)

	for _, c := range []dnsprovider.Capability{dnsprovider.CapZoneCreator, dnsprovider.CapZoneDeleter} {
		if !dnsprovider.Can(f.provider(), c) || !inwx.Factory().Can(c) {
			t.Errorf("the Traits do not declare %s", c)
		}
	}
}

// noDomainCalls fails the test when any domain.* method was called.
func noDomainCalls(t *testing.T, f *fake) {
	t.Helper()

	for _, m := range f.methodsCalled() {
		if strings.HasPrefix(m, "domain.") {
			t.Fatalf("called %s; Zone writes never touch the Registration", m)
		}
	}
}

func TestCreateZoneOfAHostedZoneIsAConflict(t *testing.T) {
	f := newFake(t)

	_, err := f.provider().CreateZone(context.Background(), "EXAMPLE.com.")
	if !errors.Is(err, dnsprovider.ErrConflict) || errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("CreateZone of a hosted zone = %v, want ErrConflict", err)
	}

	if n := f.count("nameserver.create"); n != 1 {
		t.Fatalf("sent %d nameserver.create, want 1", n)
	}

	noDomainCalls(t, f)
}

func TestZoneWritesWithoutANameAreNotFoundWithoutARequest(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if _, err := p.CreateZone(context.Background(), " . "); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("CreateZone without a name = %v, want ErrNotFound", err)
	}

	if err := p.DeleteZone(context.Background(), dnsprovider.Zone{ID: "1001"}); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("DeleteZone without a name = %v, want ErrNotFound", err)
	}

	if calls := f.methodsCalled(); len(calls) != 0 {
		t.Fatalf("sent %v", calls)
	}
}

func TestCreateZoneWithoutADecodableRoIDReturnsTheBareNameZone(t *testing.T) {
	for name, body := range map[string]string{
		"no resData":     `{"code":1000,"msg":"Command completed successfully"}`,
		"no roId":        `{"code":1000,"msg":"Command completed successfully","resData":{}}`,
		"malformed roId": `{"code":1000,"msg":"Command completed successfully","resData":{"roId":"x"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.script("nameserver.create", http.StatusOK, body)

			z, err := f.provider().CreateZone(context.Background(), "new.example")
			if err != nil {
				t.Fatal(err)
			}

			if want := (dnsprovider.Zone{Name: "new.example", State: dnsprovider.HostingUnknown}); !reflect.DeepEqual(z, want) {
				t.Fatalf("CreateZone = %+v, want %+v", z, want)
			}
		})
	}
}

func TestCreateZoneWhoseOutcomeIsUnknownIsUnconfirmedAndNotRepeated(t *testing.T) {
	for name, rep := range map[string]reply{
		"lost answer":    {lost, ""},
		"server error":   {http.StatusBadGateway, ""},
		"undecodable":    {http.StatusOK, "<html>"},
		"command failed": {http.StatusOK, refusal(2400, "SYNTHETIC: failed")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.script("nameserver.create", rep.status, rep.body)

			_, err := f.provider().CreateZone(context.Background(), "new.example")
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("CreateZone = %v, want ErrUnconfirmed", err)
			}

			if n := f.count("nameserver.create"); n != 1 {
				t.Fatalf("sent %d nameserver.create, want 1", n)
			}
		})
	}
}

func TestCreateZoneRefusedIsAPlainAPIError(t *testing.T) {
	f := newFake(t)
	f.scriptCode("nameserver.create", 2005, "SYNTHETIC: bad name")

	_, err := f.provider().CreateZone(context.Background(), "new.example")

	var apiErr *dnsprovider.APIError
	if !errors.As(err, &apiErr) || errors.Is(err, dnsprovider.ErrUnconfirmed) || !strings.Contains(err.Error(), "2005") {
		t.Fatalf("CreateZone = %v, want a plain APIError carrying 2005", err)
	}
}

func TestCreateZoneOfABlankNameSendsNothing(t *testing.T) {
	f := newFake(t)

	if _, err := f.provider().CreateZone(context.Background(), " . "); err == nil {
		t.Fatal("CreateZone of a blank name succeeded")
	}

	if calls := f.methodsCalled(); len(calls) != 0 {
		t.Fatalf("sent %v, want nothing", calls)
	}
}

func TestCreateZoneAfterTheSessionExpiredLogsInAgainAndSendsItOnce(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if _, err := p.Account(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.expire()

	if _, err := p.CreateZone(context.Background(), "new.example"); err != nil {
		t.Fatal(err)
	}

	if logins, _, _ := f.stats(); logins != 2 {
		t.Fatalf("logged in %d times, want 2", logins)
	}

	if _, err := p.GetZone(context.Background(), "new.example"); err != nil {
		t.Fatalf("GetZone after CreateZone = %v", err)
	}
}

// exampleOrg is the zone example.org as GetZone reads it.
var exampleOrg = dnsprovider.Zone{ID: "1002", Name: "example.org", State: dnsprovider.HostingUnknown}

func TestDeleteZoneOffboardsTheZone(t *testing.T) {
	f := newFake(t)
	p := f.provider()

	if err := p.DeleteZone(context.Background(), exampleOrg); err != nil {
		t.Fatal(err)
	}

	if n := f.count("nameserver.delete"); n != 1 {
		t.Fatalf("sent %d nameserver.delete, want 1", n)
	}

	if d := f.params("nameserver.delete")["domain"]; d != "example.org" {
		t.Fatalf("nameserver.delete for domain %v, want example.org", d)
	}

	noDomainCalls(t, f)

	if _, err := p.GetZone(context.Background(), "example.org"); !errors.Is(err, dnsprovider.ErrNotFound) {
		t.Fatalf("GetZone after DeleteZone = %v, want ErrNotFound", err)
	}
}

func TestDeleteZoneOfAStaleOrGoneZoneIsNotFoundWithoutADelete(t *testing.T) {
	for name, zone := range map[string]dnsprovider.Zone{
		"another roId": {ID: "999", Name: "example.org"},
		"no ID":        {Name: "example.org"},
		"gone":         {ID: "1004", Name: "gone.example"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)

			err := f.provider().DeleteZone(context.Background(), zone)
			if !errors.Is(err, dnsprovider.ErrNotFound) {
				t.Fatalf("DeleteZone = %v, want ErrNotFound", err)
			}

			if n := f.count("nameserver.delete"); n != 0 {
				t.Fatalf("sent %d nameserver.delete, want none", n)
			}

			noDomainCalls(t, f)
		})
	}
}

// goneAfterDelete makes nameserver.info answer 2303 once nameserver.delete
// was called, as when the delete took though its answer said otherwise.
func goneAfterDelete(f *fake) {
	f.handle("nameserver.info", func(r *request) string {
		for _, c := range f.calls {
			if c.method == "nameserver.delete" {
				return refusal(2303, "")
			}
		}

		return f.info(r)
	})
}

func TestDeleteZoneWhoseOutcomeIsUnknownSucceedsWhenTheZoneIsGone(t *testing.T) {
	for name, rep := range map[string]reply{
		"lost answer":    {lost, ""},
		"server error":   {http.StatusBadGateway, ""},
		"undecodable":    {http.StatusOK, "<html>"},
		"command failed": {http.StatusOK, refusal(2400, "SYNTHETIC: failed")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			goneAfterDelete(f)
			f.script("nameserver.delete", rep.status, rep.body)

			if err := f.provider().DeleteZone(context.Background(), exampleOrg); err != nil {
				t.Fatalf("DeleteZone = %v, want success as the zone is gone", err)
			}

			if n := f.count("nameserver.delete"); n != 1 {
				t.Fatalf("sent %d nameserver.delete, want 1", n)
			}

			noDomainCalls(t, f)
		})
	}
}

func TestDeleteZoneWhoseOutcomeIsUnknownIsUnconfirmedWhenTheZoneIsStillThere(t *testing.T) {
	for name, rep := range map[string]reply{
		"lost answer":    {lost, ""},
		"command failed": {http.StatusOK, refusal(2400, "SYNTHETIC: failed")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.script("nameserver.delete", rep.status, rep.body)

			err := f.provider().DeleteZone(context.Background(), exampleOrg)
			if !errors.Is(err, dnsprovider.ErrUnconfirmed) {
				t.Fatalf("DeleteZone = %v, want ErrUnconfirmed", err)
			}

			if n := f.count("nameserver.delete"); n != 1 {
				t.Fatalf("sent %d nameserver.delete, want 1", n)
			}

			if n := f.count("nameserver.info"); n != 2 {
				t.Fatalf("read the zone %d times, want 2: before and once after", n)
			}
		})
	}
}

func TestDeleteZoneWhoseReReadFailsIsUnconfirmed(t *testing.T) {
	f := newFake(t)
	f.script("nameserver.delete", lost, "")
	f.handle("nameserver.info", func(r *request) string {
		for _, c := range f.calls {
			if c.method == "nameserver.delete" {
				return refusal(2400, "SYNTHETIC: failed")
			}
		}

		return f.info(r)
	})

	if err := f.provider().DeleteZone(context.Background(), exampleOrg); !errors.Is(err, dnsprovider.ErrUnconfirmed) {
		t.Fatalf("DeleteZone = %v, want ErrUnconfirmed", err)
	}
}

func TestDeleteZoneRefusedIsAPlainErrorWithoutAReRead(t *testing.T) {
	for name, tc := range map[string]struct {
		code     int
		notFound bool
	}{
		"status refusal": {2304, false},
		"no such object": {2303, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.scriptCode("nameserver.delete", tc.code, "")

			err := f.provider().DeleteZone(context.Background(), exampleOrg)

			var apiErr *dnsprovider.APIError
			if !errors.As(err, &apiErr) || errors.Is(err, dnsprovider.ErrUnconfirmed) || errors.Is(err, dnsprovider.ErrNotFound) != tc.notFound {
				t.Fatalf("DeleteZone = %v, want a plain APIError (ErrNotFound %v)", err, tc.notFound)
			}

			if n := f.count("nameserver.info"); n != 1 {
				t.Fatalf("read the zone %d times, want 1", n)
			}
		})
	}
}
