package delegation_test

import (
	"context"
	"testing"

	dp "github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/delegation"
)

type host struct {
	dp.Provider
	zone    dp.Zone
	missing bool
	writes  int
}

func (h *host) GetZone(context.Context, string) (dp.Zone, error) {
	if h.missing {
		return dp.Zone{}, dp.ErrNotFound
	}
	return h.zone, nil
}

func (h *host) Capabilities() []dp.Capability {
	return []dp.Capability{dp.CapZoneCreator, dp.CapZoneDeleter}
}

func (h *host) ZoneStatus(context.Context, dp.Zone) (dp.ZoneStatus, error) {
	return dp.ZoneStatus{DNSSEC: dp.Off}, nil
}

func (h *host) CreateZone(context.Context, string) (dp.Zone, error) { h.writes++; return h.zone, nil }

type registrar struct {
	keys   []dp.SigningKey
	err    error
	writes int
}

func (r *registrar) DelegationSigners(context.Context, dp.Zone) ([]dp.SigningKey, error) {
	return r.keys, r.err
}

func (r *registrar) SetDelegationSigners(context.Context, dp.Zone, []dp.SigningKey) error {
	r.writes++
	return nil
}

type observer struct {
	parent       delegation.Parent
	verification delegation.Verification
}

func (o observer) Parent(context.Context, string) (delegation.Parent, error) { return o.parent, nil }

func (o observer) Authoritative(context.Context, string, []string, []dp.SigningKey) (delegation.Verification, error) {
	return o.verification, nil
}

func TestOnboardingPlanIsReadOnlyAndReportsManualDelegation(t *testing.T) {
	h := &host{zone: dp.Zone{ID: "hosting", Name: "example.com", Nameservers: []string{"ns.new.example"}}}
	r := &registrar{}
	w := delegation.Workflow{Hosting: h, Registrar: r, DNS: observer{parent: delegation.Parent{Nameservers: []string{"ns.old.example"}, Conclusive: true}, verification: delegation.Verification{Serving: true, Conclusive: true, TrustValid: true}}}
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com", ID: "registration"}})
	if err != nil || h.writes != 0 || r.writes != 0 {
		t.Fatalf("plan=%+v error=%v writes=%d/%d", p, err, h.writes, r.writes)
	}
	if len(p.Prerequisites) != 1 || p.Prerequisites[0].Code != delegation.ManualNameservers {
		t.Fatalf("prerequisites=%+v", p.Prerequisites)
	}
	if len(p.Steps) != 2 || p.Steps[0].Kind != delegation.SetNameservers || p.Steps[1].Kind != delegation.VerifyDelegation {
		t.Fatalf("steps=%+v", p.Steps)
	}
}

func TestPlanningBlocksRemovingExistingTrustPath(t *testing.T) {
	h := &host{zone: dp.Zone{ID: "hosting", Name: "example.com", Nameservers: []string{"ns.new.example"}}}
	keys := []dp.SigningKey{{KeyTag: 123, DS: []string{"123 13 2 ABCDEF"}}}
	w := delegation.Workflow{Hosting: h, Registrar: &registrar{keys: keys}, DNS: observer{parent: delegation.Parent{Nameservers: []string{"ns.old.example"}, SigningKeys: keys, Conclusive: true}, verification: delegation.Verification{Serving: true, Conclusive: true, TrustValid: true}}}
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Offboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, ReplacementNameservers: []string{"ns.new.example"}, DS: delegation.RemoveDS})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pre := range p.Prerequisites {
		if pre.Code == delegation.UnsafeDNSSEC {
			found = true
		}
	}
	if !found {
		t.Fatalf("unsafe removal was not blocked: %+v", p)
	}
}

func TestPlanValidatesIntentBeforeReading(t *testing.T) {
	for _, r := range []delegation.Request{
		{Action: delegation.Onboard, Name: "bad name", Registration: dp.Zone{Name: "bad name"}},
		{Action: delegation.Offboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, ReplacementNameservers: []string{""}},
		{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "other.com"}},
	} {
		_, err := (delegation.Workflow{Hosting: &host{}}).Plan(context.Background(), r)
		if err != delegation.ErrInvalidRequest {
			t.Fatalf("request=%+v error=%v", r, err)
		}
	}
}

func TestOffboardingRequiresOldIdentityAndNameservers(t *testing.T) {
	h := &host{zone: dp.Zone{Name: "example.com"}}
	w := delegation.Workflow{Hosting: h, Registrar: &registrar{}, DNS: observer{parent: delegation.Parent{Nameservers: []string{"ns.new.example"}, Conclusive: true}, verification: delegation.Verification{Serving: true, Conclusive: true}}}
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Offboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, ReplacementNameservers: []string{"ns.new.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Prerequisites) < 2 {
		t.Fatalf("missing old metadata allowed deletion: %+v", p)
	}
}

func TestPlanOwnsAllCallerAndAdapterSlices(t *testing.T) {
	keys := []dp.SigningKey{{DS: []string{"123 13 2 ABCDEF"}}}
	h := &host{zone: dp.Zone{ID: "hosting", Name: "example.com", Nameservers: []string{"ns.new.example"}}}
	w := delegation.Workflow{Hosting: h, Registrar: &registrar{keys: keys}, DNS: observer{parent: delegation.Parent{Nameservers: []string{"ns.old.example"}, SigningKeys: keys, Conclusive: true}, verification: delegation.Verification{Serving: true, Conclusive: true, TrustValid: true}}}
	req := delegation.Request{Action: delegation.Onboard, Name: "EXAMPLE.COM.", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: keys}
	p, err := w.Plan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	keys[0].DS[0] = "changed"
	h.zone.Nameservers[0] = "changed"
	if p.Request.Name != "example.com" || p.Request.SigningKeys[0].DS[0] != "123 13 2 ABCDEF" || p.Observations.RegistrationKeys[0].DS[0] != "123 13 2 ABCDEF" || p.Observations.Hosting.Zone.Nameservers[0] != "ns.new.example" {
		t.Fatalf("plan aliases input: %+v", p)
	}
}

func TestPublicationWithoutOldDSFollowsNameserverVerification(t *testing.T) {
	h := &host{zone: dp.Zone{ID: "hosting", Name: "example.com", Nameservers: []string{"ns.new.example"}}}
	w := delegation.Workflow{Hosting: h, Registrar: &registrar{}, DNS: observer{parent: delegation.Parent{Nameservers: []string{"ns.old.example"}, Conclusive: true}, verification: delegation.Verification{Serving: true, Conclusive: true, TrustValid: true}}}
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: []dp.SigningKey{{DS: []string{"123 13 2 ABCDEF"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 4 || p.Steps[0].Kind != delegation.SetNameservers || p.Steps[1].Kind != delegation.VerifyDelegation || len(p.Steps[1].SigningKeys) != 0 || p.Steps[2].Kind != delegation.SetSigners {
		t.Fatalf("publication ordered unsafely: %+v", p.Steps)
	}
}
