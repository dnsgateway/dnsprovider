package delegation_test

import (
	"context"
	"testing"

	dp "github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/delegation"
)

type nsRegistrar struct {
	ns         []string
	writes     int
	observer   *observer
	err        error
	afterWrite func()
}

func (n *nsRegistrar) Nameservers(context.Context, dp.Zone) ([]string, error) { return n.ns, nil }
func (n *nsRegistrar) SetNameservers(_ context.Context, _ dp.Zone, ns []string) error {
	n.writes++
	n.ns = ns
	if n.observer != nil {
		n.observer.parent.Nameservers = ns
	}
	if n.afterWrite != nil {
		n.afterWrite()
	}
	return n.err
}

func executionFixture() (delegation.Workflow, *host, *nsRegistrar, *observer) {
	h := &host{zone: dp.Zone{ID: "hosting", Name: "example.com", Nameservers: []string{"ns.new.example"}}}
	o := &observer{parent: delegation.Parent{Nameservers: []string{"ns.old.example"}, Conclusive: true}, verification: delegation.Verification{Serving: true, Conclusive: true, TrustValid: true}}
	n := &nsRegistrar{ns: []string{"ns.old.example"}, observer: o}
	return delegation.Workflow{Hosting: h, Registrar: &registrar{}, NS: n, DNS: o}, h, n, o
}

func TestExecuteCompletesReviewedDelegation(t *testing.T) {
	w, _, n, _ := executionFixture()
	p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if e != nil {
		t.Fatal(e)
	}
	progress, e := w.Execute(context.Background(), p)
	if e != nil || len(progress.Remaining) != 0 || n.writes != 1 || progress.Results[1].Outcome != delegation.Confirmed {
		t.Fatalf("progress=%+v err=%v writes=%d", progress, e, n.writes)
	}
	progress, e = w.Resume(context.Background(), progress)
	if e != nil || n.writes != 1 {
		t.Fatalf("resume=%+v err=%v writes=%d", progress, e, n.writes)
	}
}

func TestReviewedPlanCannotBeUsedWithAnotherAccount(t *testing.T) {
	w, host, _, _ := executionFixture()
	_ = host
	p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if e != nil {
		t.Fatal(e)
	}
	w.Registrar = &registrar{}
	_, e = w.Execute(context.Background(), p)
	if e != delegation.ErrStalePlan {
		t.Fatalf("different registrar accepted: %v", e)
	}
}

func TestEditingReturnedPlanCannotRedirectResumption(t *testing.T) {
	w, _, n, o := executionFixture()
	n.observer = nil
	p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if e != nil {
		t.Fatal(e)
	}
	progress, e := w.Execute(context.Background(), p)
	if e == nil {
		t.Fatal("expected pending propagation")
	}
	progress.Plan.Request.Name = "attacker.example"
	progress.Plan.Request.Registration.Name = "attacker.example"
	progress.Plan.Steps[1].Nameservers[0] = "attacker.example"
	o.parent.Nameservers = []string{"ns.new.example"}
	progress, e = w.Resume(context.Background(), progress)
	if e != nil || progress.Plan.Request.Name != "example.com" || progress.Results[1].Step.Nameservers[0] != "ns.new.example" {
		t.Fatalf("edited result redirected workflow: %+v %v", progress, e)
	}
}

type executionHost struct {
	*host
	creates     int
	deletes     int
	createErr   error
	readErr     error
	afterCreate func()
	afterDelete func()
	deleteErr   error
}

func (h *executionHost) GetZone(ctx context.Context, name string) (dp.Zone, error) {
	if h.readErr != nil {
		return dp.Zone{}, h.readErr
	}
	return h.host.GetZone(ctx, name)
}

func (h *executionHost) CreateZone(context.Context, string) (dp.Zone, error) {
	h.creates++
	if h.afterCreate != nil {
		h.afterCreate()
	}
	return h.zone, h.createErr
}

func (h *executionHost) DeleteZone(context.Context, dp.Zone) error {
	h.deletes++
	if h.afterDelete != nil {
		h.afterDelete()
	}
	return h.deleteErr
}

func TestAcceptedCreationSurvivesMissingMetadataAndReadFailure(t *testing.T) {
	w, base, _, _ := executionFixture()
	base.missing = true
	base.zone = dp.Zone{Name: "example.com", State: dp.HostingPending}
	h := &executionHost{host: base}
	w.Hosting = h
	p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if e != nil {
		t.Fatal(e)
	}
	h.afterCreate = func() { h.readErr = dp.ErrNotFound }
	progress, e := w.Execute(context.Background(), p)
	if e == nil || h.creates != 1 || progress.Results[0].Outcome != delegation.Confirmed {
		t.Fatalf("progress=%+v error=%v creates=%d", progress, e, h.creates)
	}
	progress, e = w.Resume(context.Background(), progress)
	if e == nil || h.creates != 1 {
		t.Fatalf("retry duplicated accepted creation: %+v %v", progress, e)
	}
	h.readErr = nil
	h.missing = false
	h.zone = dp.Zone{ID: "created", Name: "example.com", Nameservers: []string{"ns.new.example"}}
	progress, e = w.Resume(context.Background(), progress)
	if e != nil || h.creates != 1 || len(progress.Remaining) != 0 {
		t.Fatalf("creation could not finish: %+v %v", progress, e)
	}
}

func TestOffboardingRejectsReplacementSharingAnyOldNameserver(t *testing.T) {
	w, base, n, _ := executionFixture()
	h := &executionHost{host: base}
	w.Hosting = h
	p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Offboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, ReplacementNameservers: []string{"ns.new.example", "ns.replacement.example"}})
	if e != nil {
		t.Fatal(e)
	}
	progress, e := w.Execute(context.Background(), p)
	if e == nil || n.writes != 0 || h.deletes != 0 {
		t.Fatalf("overlap must stop all migration writes: %+v %v writes=%d deletes=%d", progress, e, n.writes, h.deletes)
	}
}

type signingRegistrar struct {
	keys   []dp.SigningKey
	writes int
	set    func([]dp.SigningKey) error
}

func (r *signingRegistrar) DelegationSigners(context.Context, dp.Zone) ([]dp.SigningKey, error) {
	return r.keys, nil
}

func (r *signingRegistrar) SetDelegationSigners(_ context.Context, _ dp.Zone, keys []dp.SigningKey) error {
	r.writes++
	if r.set != nil {
		return r.set(keys)
	}
	r.keys = keys
	return nil
}

func TestExistingSignerChangesAreBlockedBeforeAnyWrite(t *testing.T) {
	for _, desired := range [][]dp.SigningKey{
		{{DS: []string{"123 13 2 FEDCBA"}}},
		{{DS: []string{"234 13 2 ABCDEF"}}},
		{{DS: []string{"123 13 2 ABCDEF"}}, {DS: []string{"234 13 2 ABCDEF"}}},
	} {
		w, _, n, o := executionFixture()
		old := []dp.SigningKey{{DS: []string{"123 13 2 ABCDEF"}}}
		r := &signingRegistrar{keys: old}
		w.Registrar = r
		o.parent.SigningKeys = old
		p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: desired})
		if err != nil {
			t.Fatal(err)
		}
		blocked := false
		for _, pre := range p.Prerequisites {
			if pre.Code == delegation.UnsafeDNSSEC && pre.Step == delegation.SetSigners {
				blocked = true
			}
		}
		if !blocked {
			t.Fatal("reviewed plan did not expose unsupported intermediate signer sequence")
		}
		progress, err := w.Execute(context.Background(), p)
		if err != delegation.ErrPending || r.writes != 0 || n.writes != 0 || progress.Remaining[0].Code != delegation.UnsafeDNSSEC {
			t.Fatalf("unsafe intermediate replacement accepted: %+v %v DS=%d NS=%d", progress, err, r.writes, n.writes)
		}
	}
}

func TestManualNameserverWorkCanResumeFromFreshParentObservation(t *testing.T) {
	w, _, _, o := executionFixture()
	w.NS = nil
	p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if e != nil {
		t.Fatal(e)
	}
	progress, e := w.Execute(context.Background(), p)
	if e != dp.ErrNotImplemented || progress.Remaining[0].Code != delegation.ManualNameservers {
		t.Fatalf("manual work=%+v %v", progress, e)
	}
	o.parent.Nameservers = []string{"ns.new.example"}
	progress, e = w.Resume(context.Background(), progress)
	if e != nil || len(progress.Remaining) != 0 {
		t.Fatalf("manual change not recognized: %+v %v", progress, e)
	}
}

func TestOffboardingRequiresRegistrarAndParentToAgreeOnReplacement(t *testing.T) {
	w, base, _, o := executionFixture()
	base.zone.Nameservers = []string{"ns.old.example"}
	h := &executionHost{host: base}
	w.Hosting = h
	o.parent.Nameservers = []string{"ns.new.example"}
	p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Offboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, ReplacementNameservers: []string{"ns.new.example"}})
	if e != nil {
		t.Fatal(e)
	}
	progress, e := w.Execute(context.Background(), p)
	if e == nil || h.deletes != 0 {
		t.Fatalf("conflicting registrar/parent permitted deletion: %+v %v", progress, e)
	}
}

func TestCancellationRetainsAcceptedNameserverWrite(t *testing.T) {
	w, _, n, _ := executionFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, e := w.Plan(ctx, delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if e != nil {
		t.Fatal(e)
	}
	n.afterWrite = cancel
	progress, e := w.Execute(ctx, p)
	if e != context.Canceled || progress.Results[0].Outcome != delegation.Confirmed || n.writes != 1 {
		t.Fatalf("cancel lost accepted write: %+v %v", progress, e)
	}
	progress, e = w.Resume(context.Background(), progress)
	if e != nil || n.writes != 1 || progress.Results[1].Outcome != delegation.Confirmed {
		t.Fatalf("resume repeated accepted write: %+v %v", progress, e)
	}
}

func TestExecutionRejectsChangedRegistrarAndParentBeforeWrites(t *testing.T) {
	for _, change := range []string{"registrar keys", "registrar nameservers", "parent"} {
		t.Run(change, func(t *testing.T) {
			w, _, n, o := executionFixture()
			p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
			if e != nil {
				t.Fatal(e)
			}
			switch change {
			case "registrar keys":
				w.Registrar.(*registrar).keys = []dp.SigningKey{{DS: []string{"123 13 2 ABCDEF"}}}
			case "registrar nameservers":
				n.ns = []string{"ns.intervening.example"}
			case "parent":
				o.parent.Nameservers = []string{"ns.intervening.example"}
			}
			progress, e := w.Execute(context.Background(), p)
			if e != delegation.ErrStalePlan || n.writes != 0 {
				t.Fatalf("stale preconditions permitted write: %+v %v", progress, e)
			}
		})
	}
}

func TestLostCreationAnswerNeverRepeatsWhileHostingIsNotFound(t *testing.T) {
	w, base, _, _ := executionFixture()
	base.missing = true
	h := &executionHost{host: base, createErr: context.DeadlineExceeded}
	w.Hosting = h
	p, e := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if e != nil {
		t.Fatal(e)
	}
	progress, e := w.Execute(context.Background(), p)
	if e != context.DeadlineExceeded || progress.Results[0].Outcome != delegation.OutcomeUnknown {
		t.Fatalf("lost creation=%+v %v", progress, e)
	}
	progress, e = w.Resume(context.Background(), progress)
	if e == nil || h.creates != 1 || progress.Results[0].Err != context.DeadlineExceeded {
		t.Fatalf("unknown creation repeated: %+v %v creates=%d", progress, e, h.creates)
	}
	h.missing = false
	progress, e = w.Resume(context.Background(), progress)
	if e != nil || h.creates != 1 {
		t.Fatalf("observed creation could not finish: %+v %v", progress, e)
	}
}

func TestRefreshRejectsChangedKnownHostingIdentity(t *testing.T) {
	w, h, ns, _ := executionFixture()
	h.zone.Nameservers = nil
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	h.zone = dp.Zone{ID: "another-hosting", Name: "example.com", Nameservers: []string{"ns.attacker.example"}}
	progress, err := w.Execute(context.Background(), p)
	if err != delegation.ErrStalePlan || ns.writes != 0 || progress.Observed.Hosting.Zone.ID != "another-hosting" {
		t.Fatalf("changed identity accepted: %+v %v writes=%d", progress, err, ns.writes)
	}
}
