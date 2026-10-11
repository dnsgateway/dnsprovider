package delegation_test

import (
	"context"
	"errors"
	"testing"

	dp "github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/delegation"
	"github.com/dnsgateway/dnsprovider/providertest"
)

func scriptedHosting(t *testing.T, details dp.ZoneDetails) (dp.Provider, *providertest.Provider) {
	t.Helper()
	script := providertest.New()
	script.AddZone(dp.Zone{ID: "hosting", Name: "example.com", Nameservers: []string{"ns.new.example"}})
	script.SetZoneDetails("hosting", details)
	script.SetZoneDeleter(true)
	p, err := script.Factory().New(map[string]string{"token": "test"})
	if err != nil {
		t.Fatal(err)
	}
	return p, script
}

func TestFailedSigningObservationStopsExistingHostingDelegation(t *testing.T) {
	w, _, ns, _ := executionFixture()
	w.Hosting, _ = scriptedHosting(t, dp.ZoneDetails{Properties: dp.ZoneDetailProperties{
		SigningKeys: dp.PropertyResult{State: dp.PropertyFailed, Err: dp.ErrUnauthorized},
	}})
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := w.Execute(context.Background(), p)
	if !errors.Is(err, dp.ErrUnauthorized) || ns.writes != 0 || len(progress.Remaining) == 0 {
		t.Fatalf("failed signing read permitted delegation: %+v %v writes=%d", progress, err, ns.writes)
	}
}

func TestUnknownProviderPropertiesAndUnrelatedSettingsDoNotBlockUnsignedHosting(t *testing.T) {
	for _, details := range []dp.ZoneDetails{
		{Properties: dp.ZoneDetailProperties{DNSSEC: dp.PropertyResult{State: dp.PropertyRead}, SigningKeys: dp.PropertyResult{State: dp.PropertyRead}}},
		{Properties: dp.ZoneDetailProperties{DNSSEC: dp.PropertyResult{State: dp.PropertyUnsupported}, SigningKeys: dp.PropertyResult{State: dp.PropertyUnsupported}}},
		{Properties: dp.ZoneDetailProperties{HSTS: dp.PropertyResult{State: dp.PropertyFailed, Err: dp.ErrUnauthorized}, MinTLS: dp.PropertyResult{State: dp.PropertyFailed, Err: dp.ErrRateLimited}}},
	} {
		w, _, ns, _ := executionFixture()
		w.Hosting, _ = scriptedHosting(t, details)
		p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
		if err != nil {
			t.Fatal(err)
		}
		progress, err := w.Execute(context.Background(), p)
		if err != nil || ns.writes != 1 || len(progress.Remaining) != 0 {
			t.Fatalf("unsigned observed hosting blocked: %+v %v", progress, err)
		}
	}
}

func TestExistingHostingCanResumeAfterAssignedNameserversAppear(t *testing.T) {
	w, _, ns, _ := executionFixture()
	provider, script := scriptedHosting(t, dp.ZoneDetails{})
	script.RemoveZone("hosting")
	script.AddZone(dp.Zone{ID: "hosting", Name: "example.com"})
	w.Hosting = provider
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := w.Execute(context.Background(), p)
	if !errors.Is(err, delegation.ErrPending) || ns.writes != 0 || progress.Remaining[0].Code != delegation.MissingNameservers {
		t.Fatalf("missing NS: %+v %v", progress, err)
	}
	script.RemoveZone("hosting")
	script.AddZone(dp.Zone{ID: "hosting", Name: "example.com", Nameservers: []string{"ns.new.example"}})
	progress, err = w.Resume(context.Background(), progress)
	if err != nil || ns.writes != 1 || len(progress.Remaining) != 0 {
		t.Fatalf("assigned NS not refreshed: %+v %v", progress, err)
	}
	for _, call := range script.Calls() {
		if call.Op == providertest.OpCreateZone {
			t.Fatal("existing hosting recreated")
		}
	}
}

func TestPublicationUsesRegistryDSProjectionAndDistinctVerificationSteps(t *testing.T) {
	w, _, ns, initial := executionFixture()
	observer := &recordingObserver{observer: initial}
	w.DNS = observer
	w.Hosting, _ = scriptedHosting(t, dp.ZoneDetails{})
	desired := []dp.SigningKey{{DNSKEY: "257 3 13 TEST", DS: []string{"123 13 1 AABBCC", "123 13 2 ABCDEF"}}, {DNSKEY: "257 3 13 OTHER", DS: []string{"234 13 2 DDEEFF"}}}
	registrar := &signingRegistrar{}
	w.Registrar = registrar
	registrar.set = func(keys []dp.SigningKey) error {
		if ns.writes != 1 {
			t.Fatal("initial DS published before nameservers were verified")
		}
		registrar.keys = []dp.SigningKey{{DS: []string{keys[0].DS[1]}}, {DS: keys[1].DS}}
		observer.parent.SigningKeys = registrar.keys
		return nil
	}
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: desired})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := w.Execute(context.Background(), p)
	if err != nil || len(progress.Results) != 4 || progress.Results[1].Outcome != delegation.Confirmed || progress.Results[3].Outcome != delegation.Confirmed {
		t.Fatalf("publication: %+v %v", progress, err)
	}
	if len(observer.lastKeys) != 2 || observer.lastKeys[0].DNSKEY != "" || len(observer.lastKeys[0].DS) != 1 || observer.lastKeys[0].DS[0] != "123 13 2 ABCDEF" {
		t.Fatalf("trust checked requested keys instead of actual published material: %+v", observer.lastKeys)
	}
	if len(progress.Results[1].Step.SigningKeys) != 0 || len(progress.Results[3].Step.SigningKeys) != 2 {
		t.Fatal("two trust verification phases were collapsed")
	}
	progress, err = w.Resume(context.Background(), progress)
	if err != nil || registrar.writes != 1 || ns.writes != 1 {
		t.Fatalf("DS projection repeated write: %+v %v", progress, err)
	}
}

func TestUnknownNameserverAnswerReconcilesWithoutRepeatingWrite(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		w, _, ns, _ := executionFixture()
		ns.err = context.DeadlineExceeded
		if !accepted {
			ns.afterWrite = func() { ns.ns = []string{"ns.old.example"}; ns.observer.parent.Nameservers = ns.ns }
		}
		p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
		if err != nil {
			t.Fatal(err)
		}
		progress, err := w.Execute(context.Background(), p)
		if !errors.Is(err, context.DeadlineExceeded) || progress.Results[0].Outcome != delegation.OutcomeUnknown {
			t.Fatalf("lost NS answer: %+v %v", progress, err)
		}
		progress, err = w.Resume(context.Background(), progress)
		if ns.writes != 1 || accepted && (err != nil || len(progress.Remaining) != 0) || !accepted && !errors.Is(err, delegation.ErrPending) {
			t.Fatalf("NS reconciliation: %+v %v writes=%d", progress, err, ns.writes)
		}
	}
}

func TestUnknownDeletionAnswerReconcilesWithoutRepeatingWrite(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		w, base, ns, observer := executionFixture()
		base.zone.Nameservers = []string{"ns.old.example"}
		ns.ns = []string{"ns.new.example"}
		observer.parent.Nameservers = ns.ns
		h := &executionHost{host: base, deleteErr: context.DeadlineExceeded}
		if accepted {
			h.afterDelete = func() { base.missing = true }
		}
		w.Hosting = h
		p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Offboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, ReplacementNameservers: []string{"ns.new.example"}})
		if err != nil {
			t.Fatal(err)
		}
		progress, err := w.Execute(context.Background(), p)
		if !errors.Is(err, context.DeadlineExceeded) || progress.Results[len(progress.Results)-1].Outcome != delegation.OutcomeUnknown {
			t.Fatalf("lost delete answer: %+v %v", progress, err)
		}
		progress, err = w.Resume(context.Background(), progress)
		if h.deletes != 1 || accepted && err != nil || !accepted && !errors.Is(err, delegation.ErrPending) {
			t.Fatalf("delete reconciliation: %+v %v", progress, err)
		}
	}
}

func TestCancellationPreservesAcceptedCreation(t *testing.T) {
	w, base, ns, _ := executionFixture()
	base.missing = true
	h := &executionHost{host: base}
	w.Hosting = h
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := w.Plan(ctx, delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	h.afterCreate = func() { base.missing = false; cancel() }
	progress, err := w.Execute(ctx, p)
	if !errors.Is(err, context.Canceled) || progress.Results[0].Outcome != delegation.Confirmed || ns.writes != 0 {
		t.Fatalf("creation acceptance lost: %+v %v", progress, err)
	}
	progress, err = w.Resume(context.Background(), progress)
	if err != nil || h.creates != 1 || ns.writes != 1 {
		t.Fatalf("creation resume: %+v %v", progress, err)
	}
}

type failingObserver struct {
	observer
	parentErr        error
	authoritativeErr error
	reads            int
	afterParent      func()
}

func (o *failingObserver) Parent(context.Context, string) (delegation.Parent, error) {
	o.reads++
	if o.afterParent != nil {
		o.afterParent()
	}
	return o.parent, o.parentErr
}

func (o *failingObserver) Authoritative(context.Context, string, []string, []dp.SigningKey) (delegation.Verification, error) {
	o.reads++
	return o.verification, o.authoritativeErr
}

func TestUnsafeOffboardingObservationsNeverDeleteHosting(t *testing.T) {
	for _, scenario := range []string{"resolver failure", "not serving", "inconclusive parent", "inconclusive authoritative", "invalid trust"} {
		t.Run(scenario, func(t *testing.T) {
			w, base, ns, initial := executionFixture()
			base.zone.Nameservers = []string{"ns.old.example"}
			ns.ns = []string{"ns.new.example"}
			initial.parent.Nameservers = ns.ns
			o := &failingObserver{observer: *initial}
			h := &executionHost{host: base}
			w.Hosting = h
			w.DNS = o
			if scenario == "invalid trust" {
				keys := []dp.SigningKey{{DS: []string{"123 13 2 ABCDEF"}}}
				w.Registrar = &registrar{keys: keys}
				o.parent.SigningKeys = keys
			}
			p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Offboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, ReplacementNameservers: []string{"ns.new.example"}})
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "resolver failure":
				o.parentErr = dp.ErrRateLimited
			case "not serving":
				o.verification.Serving = false
			case "inconclusive parent":
				o.parent.Conclusive = false
			case "inconclusive authoritative":
				o.verification.Conclusive = false
			case "invalid trust":
				o.verification.TrustValid = false
			}
			o.reads = 0
			progress, err := w.Execute(context.Background(), p)
			if err == nil || h.deletes != 0 || len(progress.Remaining) == 0 || o.reads > 2 {
				t.Fatalf("unsafe observations: %+v %v deletes=%d reads=%d", progress, err, h.deletes, o.reads)
			}
			if scenario == "resolver failure" && !errors.Is(err, dp.ErrRateLimited) {
				t.Fatal("typed resolver error lost")
			}
		})
	}
}

func TestPartialInitialPublicationPreservesProgressWithoutUnsafeRepair(t *testing.T) {
	for _, scenario := range []string{"propagating", "published", "unrelated"} {
		t.Run(scenario, func(t *testing.T) {
			w, _, ns, observer := executionFixture()
			old := []dp.SigningKey(nil)
			desired := []dp.SigningKey{{DS: []string{"234 13 2 ABCDEF"}}, {DS: []string{"345 13 2 ABCDEF"}}}
			registrar := &signingRegistrar{keys: old}
			w.Registrar = registrar
			observer.parent.SigningKeys = old
			diagnostic := &dp.APIError{Provider: "test", StatusCode: 422, Kind: dp.ErrUnsupported}
			registrar.set = func(keys []dp.SigningKey) error { registrar.keys = keys[:1]; return diagnostic }
			p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: desired})
			if err != nil {
				t.Fatal(err)
			}
			progress, err := w.Execute(context.Background(), p)
			var apiErr *dp.APIError
			if !errors.Is(err, dp.ErrUnsupported) || !errors.As(err, &apiErr) || apiErr != diagnostic || ns.writes != 1 {
				t.Fatalf("registry diagnostic: %+v %v", progress, err)
			}
			if scenario == "published" {
				observer.parent.SigningKeys = registrar.keys
			}
			if scenario == "unrelated" {
				registrar.keys = []dp.SigningKey{{DS: []string{"999 13 2 ABCDEF"}}}
				observer.parent.SigningKeys = registrar.keys
			}
			progress, err = w.Resume(context.Background(), progress)
			if err == nil || registrar.writes != 1 || ns.writes != 1 || progress.Results[2].Err != diagnostic {
				t.Fatalf("unsafe partial repair: %+v %v", progress, err)
			}
		})
	}
}

func TestMissingRegistrationPreventsHostingAndDelegationWrites(t *testing.T) {
	w, base, ns, _ := executionFixture()
	base.missing = true
	w.Registrar = &registrar{err: dp.ErrNotFound}
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{ID: "absent", Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pre := range p.Prerequisites {
		if pre.Code == delegation.MissingRegistration && errors.Is(pre.Err, dp.ErrNotFound) {
			found = true
		}
	}
	progress, err := w.Execute(context.Background(), p)
	if !found || !errors.Is(err, dp.ErrNotFound) || base.writes != 0 || ns.writes != 0 {
		t.Fatalf("missing registration: %+v %v", progress, err)
	}
}

func TestOffboardingDeletesOnlyHostingAndRetainsRegistration(t *testing.T) {
	w, _, ns, observer := executionFixture()
	_, script := scriptedHosting(t, dp.ZoneDetails{})
	script.SetRegistration("hosting")
	provider, err := script.Factory().New(map[string]string{"token": "test"})
	if err != nil {
		t.Fatal(err)
	}
	registrar := provider.(dp.DSRegistrar)
	w.Hosting = provider
	w.Registrar = registrar
	ns.ns = []string{"ns.replacement.example"}
	observer.parent.Nameservers = ns.ns
	registration := dp.Zone{ID: "hosting", Name: "example.com"}
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Offboard, Name: "example.com", Registration: registration, ReplacementNameservers: ns.ns})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := w.Execute(context.Background(), p)
	if err != nil || len(progress.Remaining) != 0 {
		t.Fatalf("offboarding: %+v %v", progress, err)
	}
	if _, err = provider.GetZone(context.Background(), registration.Name); !errors.Is(err, dp.ErrNotFound) {
		t.Fatalf("hosting remains: %v", err)
	}
	if _, err = registrar.DelegationSigners(context.Background(), registration); err != nil {
		t.Fatalf("registration was removed: %v", err)
	}
}

func TestManualNameserverVerificationPreservesObservationErrors(t *testing.T) {
	for _, diagnostic := range []error{context.Canceled, context.DeadlineExceeded, &dp.APIError{Provider: "test", StatusCode: 429, Kind: dp.ErrRateLimited}} {
		for _, source := range []string{"parent", "authoritative"} {
			w, _, _, initial := executionFixture()
			w.NS = nil
			o := &failingObserver{observer: *initial}
			w.DNS = o
			p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
			if err != nil {
				t.Fatal(err)
			}
			if source == "parent" {
				o.parentErr = diagnostic
			} else {
				o.parent.Nameservers = []string{"ns.new.example"}
				o.authoritativeErr = diagnostic
			}
			progress, err := w.Execute(context.Background(), p)
			if !errors.Is(err, diagnostic) || progress.Remaining[0].Code != delegation.ObservationUnavailable {
				t.Fatalf("manual NS hid %s diagnostic: %+v %v", source, progress, err)
			}
			var want, got *dp.APIError
			if errors.As(diagnostic, &want) && (!errors.As(err, &got) || got != want) {
				t.Fatal("typed observation diagnostic lost")
			}
		}
	}
}

// Capture the public DNS observation boundary so reduced registrar forms must
// be independently verified rather than inheriting trust from the request.
type recordingObserver struct {
	*observer
	lastKeys  []dp.SigningKey
	invalidDS string
}

func (o *recordingObserver) Authoritative(_ context.Context, _ string, _ []string, keys []dp.SigningKey) (delegation.Verification, error) {
	o.lastKeys = keys
	v := o.verification
	if len(keys) == 1 && len(keys[0].DS) == 1 && keys[0].DS[0] == o.invalidDS {
		v.TrustValid = false
	}
	return v, nil
}

func TestInitialPublicationVerifiesEveryPartialTrustPath(t *testing.T) {
	w, _, ns, initial := executionFixture()
	o := &recordingObserver{observer: initial, invalidDS: "234 13 2 BADBAD"}
	w.DNS = o
	r := &signingRegistrar{}
	w.Registrar = r
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: []dp.SigningKey{{DS: []string{"123 13 2 ABCDEF"}}, {DS: []string{"234 13 2 BADBAD"}}}})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := w.Execute(context.Background(), p)
	if err != delegation.ErrPending || r.writes != 0 || ns.writes != 1 || progress.Remaining[0].Code != delegation.UnsafeDNSSEC {
		t.Fatalf("aggregate trust authorized invalid partial publication: %+v %v", progress, err)
	}
}

func TestRegistryDigestSelectionMustRepresentEveryReviewedKeyAndNoOthers(t *testing.T) {
	for _, selected := range [][]dp.SigningKey{
		{{DS: []string{"123 13 2 ABCDEF"}}},
		{{DS: []string{"123 13 2 ABCDEF"}}, {DS: []string{"234 13 2 DDEEFF"}}, {DS: []string{"999 13 2 BADBAD"}}},
	} {
		w, _, _, o := executionFixture()
		r := &signingRegistrar{}
		w.Registrar = r
		r.set = func([]dp.SigningKey) error { r.keys = selected; o.parent.SigningKeys = selected; return nil }
		p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: []dp.SigningKey{{DS: []string{"123 13 1 AABBCC", "123 13 2 ABCDEF"}}, {DS: []string{"234 13 2 DDEEFF"}}}})
		if err != nil {
			t.Fatal(err)
		}
		progress, err := w.Execute(context.Background(), p)
		if err == nil || r.writes != 1 || len(progress.Remaining) == 0 {
			t.Fatalf("unexpected key set confirmed: %+v %v", progress, err)
		}
		_, err = w.Resume(context.Background(), progress)
		if err == nil || r.writes != 1 {
			t.Fatalf("unexpected key set repeated write: %v writes=%d", err, r.writes)
		}
	}
}

func TestExistingRegistryDigestChangeInvalidatesPlan(t *testing.T) {
	w, _, ns, o := executionFixture()
	keys := []dp.SigningKey{{DS: []string{"123 13 1 AABBCC", "123 13 2 ABCDEF"}}}
	r := &signingRegistrar{keys: keys}
	w.Registrar = r
	o.parent.SigningKeys = keys
	p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	r.keys = []dp.SigningKey{{DS: []string{"123 13 2 ABCDEF"}}}
	o.parent.SigningKeys = r.keys
	_, err = w.Execute(context.Background(), p)
	if err != delegation.ErrStalePlan || ns.writes != 0 {
		t.Fatalf("changed snapshot authorized write: %v writes=%d", err, ns.writes)
	}
}

func TestCancellationDuringManualNameserverObservationIsPreserved(t *testing.T) {
	w, _, _, initial := executionFixture()
	w.NS = nil
	o := &failingObserver{observer: *initial}
	w.DNS = o
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, err := w.Plan(ctx, delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	o.afterParent = cancel
	progress, err := w.Execute(ctx, p)
	if !errors.Is(err, context.Canceled) || progress.Remaining[0].Code != delegation.ObservationUnavailable {
		t.Fatalf("cancellation became manual pending: %+v %v", progress, err)
	}
}

func TestComputedRegistryFormsRejectMissingOrUnrelatedDNSKEYs(t *testing.T) {
	for _, held := range [][]dp.SigningKey{
		{{DNSKEY: "257 3 13 FIRST", DS: []string{"123 13 2 ABCDEF"}}},
		{{DNSKEY: "257 3 13 FIRST", DS: []string{"123 13 2 ABCDEF"}}, {DNSKEY: "257 3 13 SECOND", DS: []string{"234 13 2 DDEEFF"}}, {DNSKEY: "257 3 13 EXTRA", DS: []string{"999 13 2 AABBCC"}}},
		{{DNSKEY: "257 3 13 FIRST", DS: []string{"123 13 2 ABCDEF"}}, {DNSKEY: "257 3 13 UNRELATED", DS: []string{"234 13 2 DDEEFF"}}},
	} {
		w, _, _, o := executionFixture()
		r := &signingRegistrar{}
		w.Registrar = r
		r.set = func([]dp.SigningKey) error { r.keys = held; o.parent.SigningKeys = held; return nil }
		p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: []dp.SigningKey{{DNSKEY: "257 3 13 FIRST"}, {DNSKEY: "257 3 13 SECOND"}}})
		if err != nil {
			t.Fatal(err)
		}
		progress, err := w.Execute(context.Background(), p)
		if err == nil || r.writes != 1 || len(progress.Remaining) == 0 {
			t.Fatalf("unexpected computed key set confirmed: %+v %v", progress, err)
		}
		_, err = w.Resume(context.Background(), progress)
		if err == nil || r.writes != 1 {
			t.Fatalf("unexpected computed key set repeated write: %v writes=%d", err, r.writes)
		}
	}
}

func TestComputedRegistryReadbackBecomesStrictHeldSnapshot(t *testing.T) {
	for _, changed := range []dp.SigningKey{
		{DNSKEY: "257 3 13 REVIEWED", DS: []string{"123 13 2 FEDCBA"}},
		{DNSKEY: "257 3 13 CHANGED", DS: []string{"123 13 2 ABCDEF"}},
	} {
		w, _, _, o := executionFixture()
		r := &signingRegistrar{}
		w.Registrar = r
		r.set = func([]dp.SigningKey) error {
			r.keys = []dp.SigningKey{{DNSKEY: "257 3 13 REVIEWED", DS: []string{"123 13 2 ABCDEF"}}}
			return nil
		}
		p, err := w.Plan(context.Background(), delegation.Request{Action: delegation.Onboard, Name: "example.com", Registration: dp.Zone{Name: "example.com"}, DS: delegation.PublishDS, SigningKeys: []dp.SigningKey{{DNSKEY: "257 3 13 REVIEWED"}}})
		if err != nil {
			t.Fatal(err)
		}
		progress, err := w.Execute(context.Background(), p)
		if err != delegation.ErrPending || r.writes != 1 {
			t.Fatalf("expected computed DS awaiting propagation: %+v %v", progress, err)
		}
		r.keys = []dp.SigningKey{changed}
		o.parent.SigningKeys = r.keys
		_, err = w.Resume(context.Background(), progress)
		if err != delegation.ErrStalePlan || r.writes != 1 {
			t.Fatalf("changed computed snapshot accepted: %v writes=%d", err, r.writes)
		}
	}
}
