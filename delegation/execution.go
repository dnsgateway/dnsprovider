package delegation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	dp "github.com/dnsgateway/dnsprovider"
)

// ErrStalePlan requires reviewing new intent or changed remote preconditions.
var ErrStalePlan = errors.New("delegation plan is stale or belongs to different Accounts")

// ErrPending means observation or manual work is required before continuing.
var ErrPending = errors.New("delegation work remains pending")

type execution struct {
	plan         Plan
	results      []StepResult
	hosting      dp.Zone
	target       []string
	keys         []dp.SigningKey
	ns           []string
	parent       Parent
	observed     Observations
	awaitingKeys bool
}

// Execute applies a reviewed Plan, stopping at the first unresolved dependency.
// Each call makes one observation attempt per step and never waits for propagation.
// Errors retain remote progress; pass the returned Progress to Resume.
func (w Workflow) Execute(ctx context.Context, p Plan) (Progress, error) {
	if p.reviewed == nil || p.accounts == nil || !sameAccounts(w, *p.accounts) || !reflect.DeepEqual(clonePlan(p), *p.reviewed) {
		return Progress{Plan: p}, ErrStalePlan
	}
	p = sealedClone(p)
	e := &execution{
		plan: p, hosting: cloneZone(p.Observations.Hosting.Zone),
		keys: cloneKeys(p.Observations.RegistrationKeys),
		ns:   slices.Clone(p.Observations.RegistrarNameservers), parent: cloneParent(p.Observations.Parent),
	}
	e.observed = clonePlan(p).Observations
	if w.NS == nil {
		e.ns = slices.Clone(e.parent.Nameservers)
	}
	e.target = slices.Clone(p.Observations.Hosting.Zone.Nameservers)
	if p.Request.Action == Offboard {
		e.target = slices.Clone(p.Request.ReplacementNameservers)
	}
	for _, s := range p.Steps {
		e.results = append(e.results, StepResult{Step: s, Outcome: NotStarted})
	}
	e.results = cloneResults(e.results)
	return w.run(ctx, e)
}

// Resume inspects fresh state using the private evidence returned by Execute.
// Editing exported results cannot authorize writes or erase accepted creation.
func (w Workflow) Resume(ctx context.Context, progress Progress) (Progress, error) {
	if progress.evidence == nil || progress.evidence.plan.accounts == nil || !sameAccounts(w, *progress.evidence.plan.accounts) {
		return progress, ErrStalePlan
	}
	old := progress.evidence
	e := *old
	e.observed = clonePlan(Plan{Observations: old.observed}).Observations
	e.results = cloneResults(old.results)
	e.target = slices.Clone(old.target)
	e.keys = cloneKeys(old.keys)
	e.ns = slices.Clone(old.ns)
	e.parent = cloneParent(old.parent)
	e.hosting = cloneZone(old.hosting)
	return w.run(ctx, &e)
}

func sameAccounts(a, b Workflow) bool {
	return sameAdapter(a.Hosting, b.Hosting) && sameAdapter(a.Registrar, b.Registrar) && sameAdapter(a.NS, b.NS) && sameAdapter(a.DNS, b.DNS)
}

func sameAdapter(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	aa, bb := reflect.ValueOf(a), reflect.ValueOf(b)
	if aa.Type() != bb.Type() {
		return false
	}
	if aa.Kind() == reflect.Pointer {
		return aa.Pointer() == bb.Pointer()
	}
	// Value adapters may contain slices. Never compare interfaces directly.
	return reflect.DeepEqual(a, b)
}

func sealedClone(p Plan) Plan {
	out := clonePlan(p)
	out.reviewed = p.reviewed
	out.accounts = p.accounts
	return out
}

func cloneResults(in []StepResult) []StepResult {
	out := slices.Clone(in)
	for i := range out {
		out[i].Step.Nameservers = slices.Clone(out[i].Step.Nameservers)
		out[i].Step.SigningKeys = cloneKeys(out[i].Step.SigningKeys)
		out[i].Zone = cloneZone(out[i].Zone)
	}
	return out
}

func (e *execution) progress(pre ...Prerequisite) Progress {
	return Progress{Plan: sealedClone(e.plan), Observed: clonePlan(Plan{Observations: e.observed}).Observations, Results: cloneResults(e.results), Remaining: pre, evidence: e}
}

func (e *execution) stop(i int, code PrerequisiteCode, err error) (Progress, error) {
	if err == nil {
		err = ErrPending
	}
	return e.progress(Prerequisite{Code: code, Step: e.results[i].Step.Kind, Message: err.Error(), Err: err}), err
}

func (w Workflow) run(ctx context.Context, e *execution) (Progress, error) {
	if e.plan.Request.Action == Offboard && (!validNameservers(e.hosting.Nameservers) || e.hosting.ID == "" || overlappingNameservers(e.hosting.Nameservers, e.target)) {
		return e.progress(Prerequisite{
			Code: ReplacementUnverified, Step: DeleteHosting,
			Message: "replacement must exclude every old Nameserver and old identity must be known", Err: ErrPending,
		}), ErrPending
	}

	for i := 0; i < len(e.results); i++ { //nolint:intrange // Refresh may insert a newly assigned Nameserver step.
		r := &e.results[i]
		if r.Outcome == Confirmed {
			continue
		}
		if err := ctx.Err(); err != nil {
			return e.stop(i, ObservationUnavailable, err)
		}
		code, err := w.executeStep(ctx, e, i)
		if err != nil {
			r = &e.results[i]
			if r.Outcome == NotStarted {
				r.Outcome = Failed
			}
			if r.Err == nil {
				r.Err = err
			}
			return e.stop(i, code, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return e.progress(Prerequisite{Code: ObservationUnavailable, Step: VerifyDelegation, Message: err.Error(), Err: err}), err
	}
	return e.progress(), nil
}

func (w Workflow) checkHosting(ctx context.Context, e *execution) error {
	details, err := dp.ZoneDetailsOf(ctx, w.Hosting, e.plan.Request.Name, dp.ZoneDetailRequest{SigningKeys: true})
	if err = coordinationReadError(ctx, details, err); err != nil {
		return err
	}
	e.observed.Hosting = cloneDetails(details)
	e.observed.HostingExists = true
	z := details.Zone
	if z.ID != e.hosting.ID || !sameNameservers(z.Nameservers, e.hosting.Nameservers) {
		return ErrStalePlan
	}
	return nil
}

func (w Workflow) checkRegistrar(ctx context.Context, e *execution) error {
	if w.Registrar == nil {
		return dp.ErrNotImplemented
	}
	keys, err := w.Registrar.DelegationSigners(ctx, cloneZone(e.plan.Request.Registration))
	if err != nil {
		return err
	}
	e.observed.RegistrationKeys = cloneKeys(keys)
	e.observed.RegistrationRead = true
	if e.awaitingKeys {
		if !registryRepresents(keys, e.keys) {
			return ErrPending
		}
		e.keys = cloneKeys(keys)
		e.awaitingKeys = false
	} else if !sameRegistryKeys(keys, e.keys) {
		return ErrStalePlan
	}
	if w.NS != nil {
		ns, readErr := w.NS.Nameservers(ctx, cloneZone(e.plan.Request.Registration))
		if readErr != nil {
			return readErr
		}
		e.observed.RegistrarNameservers = slices.Clone(ns)
		e.observed.RegistrarNSRead = true
		if !sameNameservers(ns, e.ns) {
			return ErrStalePlan
		}
	}
	return nil
}

func (w Workflow) checkDelegation(ctx context.Context, e *execution) error {
	if err := w.checkRegistrar(ctx, e); err != nil {
		return err
	}
	if w.DNS == nil {
		return ErrPending
	}
	parent, err := w.DNS.Parent(ctx, e.plan.Request.Name)
	if err != nil {
		return err
	}
	e.observed.Parent = cloneParent(parent)
	e.observed.ParentRead = parent.Conclusive
	if !parent.Conclusive {
		return ErrPending
	}
	// Accepted earlier writes may still be propagating. Do not issue the next
	// dependent write until their published state has been observed.
	if !sameNameservers(parent.Nameservers, e.ns) || !sameRegistryKeys(parent.SigningKeys, e.keys) {
		return ErrStalePlan
	}
	e.parent = cloneParent(parent)
	return nil
}

func (w Workflow) trust(ctx context.Context, e *execution, ns []string, keys []dp.SigningKey) error {
	if w.DNS == nil || !validNameservers(ns) {
		return ErrPending
	}
	v, err := w.DNS.Authoritative(ctx, e.plan.Request.Name, slices.Clone(ns), cloneKeys(keys))
	if err != nil {
		return err
	}
	if !v.Conclusive || !v.Serving || (len(keys) > 0 && !v.TrustValid) {
		return ErrPending
	}
	return nil
}

func (w Workflow) verify(ctx context.Context, e *execution, ns []string, keys []dp.SigningKey, deleting bool) error {
	if err := w.checkRegistrar(ctx, e); err != nil {
		return err
	}
	if w.DNS == nil || !validNameservers(ns) {
		return ErrPending
	}
	if w.NS != nil && !sameNameservers(e.observed.RegistrarNameservers, ns) {
		return ErrPending
	}
	parent, err := w.DNS.Parent(ctx, e.plan.Request.Name)
	if err != nil {
		return err
	}
	e.observed.Parent = cloneParent(parent)
	e.observed.ParentRead = parent.Conclusive
	if !parent.Conclusive || !sameNameservers(parent.Nameservers, ns) || !sameRegistryKeys(parent.SigningKeys, e.keys) || !registryRepresents(e.keys, keys) {
		return ErrPending
	}
	if deleting && overlappingNameservers(e.hosting.Nameservers, parent.Nameservers) {
		return fmt.Errorf("%w: parent still uses old hosting", ErrPending)
	}
	if err = w.trust(ctx, e, ns, parent.SigningKeys); err != nil {
		return err
	}
	e.parent = cloneParent(parent)
	return nil
}

// A DS-only registry can report the DS projection of DNSKEY+DS input. Accept
// that projection only when complete DS material exists on both sides; never
// infer equivalence from key tags or collapse unrelated DNSKEY-only forms.
func sameRegistryKeys(a, b []dp.SigningKey) bool {
	if sameKeys(a, b) {
		return true
	}
	hasDNSKEY := func(keys []dp.SigningKey) bool {
		return slices.ContainsFunc(keys, func(k dp.SigningKey) bool { return k.DNSKEY != "" })
	}
	// Two full held snapshots must preserve DNSKEY as well as DS material.
	// Projection is only a comparison across forms with a DS-only observation.
	if hasDNSKEY(a) && hasDNSKEY(b) {
		return false
	}
	project := func(keys []dp.SigningKey) ([]dp.SigningKey, bool) {
		out := make([]dp.SigningKey, 0, len(keys))
		for _, k := range keys {
			if len(k.DS) == 0 {
				return nil, false
			}
			for _, ds := range k.DS {
				out = append(out, dp.SigningKey{DS: []string{ds}})
			}
		}
		return out, true
	}
	aa, okA := project(a)
	bb, okB := project(b)
	return okA && okB && sameKeys(aa, bb)
}

// registryRepresents reconciles a reviewed request with a registrar's form
// translation: digest selection or computed DS for an identical DNSKEY. Every requested key must be represented, and every observed
// key must belong to the request. Generated DS is authorized by the identical
// reviewed DNSKEY. This must never compare stale snapshots.
func registryRepresents(observed, requested []dp.SigningKey) bool {
	if sameRegistryKeys(observed, requested) {
		return true
	}
	if len(observed) == 0 || len(requested) == 0 {
		return false
	}
	matched := make([]bool, len(requested))
	for _, held := range observed {
		if held.DNSKEY != "" {
			found := false
			for i, key := range requested {
				if key.DNSKEY != "" && len(key.DS) == 0 && sameKeys([]dp.SigningKey{{DNSKEY: held.DNSKEY}}, []dp.SigningKey{{DNSKEY: key.DNSKEY}}) {
					matched[i] = true
					found = true
				}
			}
			if found {
				continue
			}
		}
		if held.DNSKEY != "" || len(held.DS) == 0 {
			return false
		}
		for _, ds := range held.DS {
			found := false
			for i, key := range requested {
				for _, candidate := range key.DS {
					if sameKeys([]dp.SigningKey{{DS: []string{ds}}}, []dp.SigningKey{{DS: []string{candidate}}}) {
						matched[i] = true
						found = true
					}
				}
			}
			if !found {
				return false
			}
		}
	}
	for _, found := range matched {
		if !found {
			return false
		}
	}
	return true
}

func overlappingNameservers(a, b []string) bool {
	for _, aa := range a {
		for _, bb := range b {
			if canonicalName(aa) == canonicalName(bb) {
				return true
			}
		}
	}
	return false
}

func (w Workflow) executeStep(ctx context.Context, e *execution, i int) (PrerequisiteCode, error) {
	switch e.results[i].Step.Kind {
	case CreateHosting:
		return w.executeCreateHosting(ctx, e, i)
	case RefreshHosting:
		return w.executeRefreshHosting(ctx, e, i)
	case SetNameservers:
		return w.executeSetNameservers(ctx, e, i)
	case SetSigners:
		return w.executeSetSigners(ctx, e, i)
	case VerifyDelegation:
		return w.executeVerifyDelegation(ctx, e, i)
	case DeleteHosting:
		return w.executeDeleteHosting(ctx, e, i)
	}
	return ObservationUnavailable, ErrInvalidRequest
}

func (w Workflow) executeCreateHosting(ctx context.Context, e *execution, i int) (PrerequisiteCode, error) {
	r := &e.results[i]
	var err error
	code := MissingCapability
	if !dp.CanCreateZone(w.Hosting) {
		err = dp.ErrNotImplemented
		return code, err
	}
	z, readErr := w.Hosting.GetZone(ctx, e.plan.Request.Name)
	if readErr == nil {
		// Existing hosting after an uncertain create proves acceptance, but an
		// unrelated new Zone invalidates a plan that had not attempted creation.
		if r.Outcome != OutcomeUnknown {
			err = ErrStalePlan
			return code, err
		}
		e.hosting = cloneZone(z)
		r.Zone = cloneZone(z)
		r.Outcome = Confirmed
		return code, err
	}
	if !errors.Is(readErr, dp.ErrNotFound) {
		err = readErr
		return code, err
	}
	if r.Outcome == OutcomeUnknown {
		err = ErrPending
		return code, err
	}
	if err = w.checkDelegation(ctx, e); err != nil {
		return code, err
	}
	if err = ctx.Err(); err != nil {
		return code, err
	}
	z, err = w.Hosting.CreateZone(ctx, e.plan.Request.Name)
	r.Zone = cloneZone(z)
	if err != nil {
		r.Outcome = OutcomeUnknown
		r.Err = err
		return code, err
	}
	e.hosting = cloneZone(z)
	r.Outcome = Confirmed
	return code, err
}

func (w Workflow) executeRefreshHosting(ctx context.Context, e *execution, i int) (PrerequisiteCode, error) {
	r := &e.results[i]
	var err error
	code := ObservationUnavailable

	details, readErr := dp.ZoneDetailsOf(ctx, w.Hosting, e.plan.Request.Name, dp.ZoneDetailRequest{SigningKeys: true})
	readErr = coordinationReadError(ctx, details, readErr)
	if readErr != nil {
		err = readErr
		r.Outcome = PendingVerification
		return code, err
	}
	e.observed.Hosting = cloneDetails(details)
	e.observed.HostingExists = true
	if e.hosting.ID != "" && details.Zone.ID != e.hosting.ID {
		return code, ErrStalePlan
	}
	if !validNameservers(details.Zone.Nameservers) {
		err = ErrPending
		code = MissingNameservers
		r.Outcome = PendingVerification
		return code, err
	}
	e.hosting = cloneZone(details.Zone)
	e.target = slices.Clone(details.Zone.Nameservers)
	r.Zone = cloneZone(details.Zone)
	r.Outcome = Confirmed
	// Plans made before hosting exists explicitly authorize using its future
	// assigned Nameservers, but cannot name those Nameservers during review.
	hasNS := false
	for j := i + 1; j < len(e.results); j++ {
		if e.results[j].Step.Kind == SetNameservers {
			hasNS = true
		}
		if e.results[j].Step.Kind == VerifyDelegation {
			e.results[j].Step.Nameservers = slices.Clone(e.target)
		}
	}
	if !hasNS && !sameNameservers(e.target, e.parent.Nameservers) {
		next := StepResult{Step: Step{Kind: SetNameservers, Nameservers: slices.Clone(e.target)}, Outcome: NotStarted}
		e.results = slices.Insert(e.results, i+1, next)
	}
	return code, err
}

func (w Workflow) executeSetNameservers(ctx context.Context, e *execution, i int) (PrerequisiteCode, error) {
	r := &e.results[i]
	var err error
	code := ManualNameservers
	if w.NS == nil {
		if observationErr := w.verify(ctx, e, r.Step.Nameservers, e.keys, false); observationErr == nil {
			e.ns = slices.Clone(r.Step.Nameservers)
			r.Outcome = Confirmed
		} else {
			err = observationErr
			code = ObservationUnavailable
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if errors.Is(observationErr, ErrPending) {
				err = dp.ErrNotImplemented
				code = ManualNameservers
			}
			r.Outcome = PendingVerification
		}
		return code, err
	}
	target := r.Step.Nameservers
	if !validNameservers(target) {
		err = ErrPending
		code = MissingNameservers
		return code, err
	}
	current, readErr := w.NS.Nameservers(ctx, cloneZone(e.plan.Request.Registration))
	if readErr != nil {
		err = readErr
		return code, err
	}
	e.observed.RegistrarNameservers = slices.Clone(current)
	e.observed.RegistrarNSRead = true
	if sameNameservers(current, target) {
		e.ns = slices.Clone(target)
		r.Outcome = Confirmed
		return code, err
	}
	if !sameNameservers(current, e.ns) {
		err = ErrStalePlan
		return code, err
	}
	if r.Outcome == OutcomeUnknown || r.Outcome == PendingVerification {
		err = ErrPending
		return code, err
	}
	if err = w.checkDelegation(ctx, e); err != nil {
		return code, err
	}
	if err = w.checkHosting(ctx, e); err != nil {
		return code, err
	}
	if err = w.trust(ctx, e, target, e.keys); err != nil {
		code = UnsafeDNSSEC
		return code, err
	}
	if err = ctx.Err(); err != nil {
		return code, err
	}
	err = w.NS.SetNameservers(ctx, cloneZone(e.plan.Request.Registration), slices.Clone(target))
	if err != nil {
		r.Outcome = OutcomeUnknown
		r.Err = err
		return code, err
	}
	e.ns = slices.Clone(target)
	r.Outcome = Confirmed
	return code, err
}

func (w Workflow) executeSetSigners(ctx context.Context, e *execution, i int) (PrerequisiteCode, error) {
	r := &e.results[i]
	var err error
	code := MissingRegistration
	if w.Registrar == nil {
		err = dp.ErrNotImplemented
		return code, err
	}
	current, readErr := w.Registrar.DelegationSigners(ctx, cloneZone(e.plan.Request.Registration))
	if readErr != nil {
		err = readErr
		return code, err
	}
	e.observed.RegistrationKeys = cloneKeys(current)
	e.observed.RegistrationRead = true
	if registryRepresents(current, r.Step.SigningKeys) {
		if r.Outcome != OutcomeUnknown && !sameRegistryKeys(current, e.keys) {
			return code, ErrStalePlan
		}
		e.keys = cloneKeys(current)
		r.Outcome = Confirmed
		return code, err
	}
	if r.Outcome == OutcomeUnknown {
		// A changed held set is progress, not evidence that another replacement
		// preserves trust throughout the registrar's intermediate writes.
		return UnsafeDNSSEC, ErrPending
	}
	if !sameRegistryKeys(current, e.keys) {
		err = ErrStalePlan
		return code, err
	}
	if err = w.checkDelegation(ctx, e); err != nil {
		return code, err
	}
	if err = w.checkHosting(ctx, e); err != nil {
		return code, err
	}
	code = UnsafeDNSSEC
	if len(current) > 0 {
		err = ErrPending
		return code, err
	}
	if err = w.trust(ctx, e, e.target, r.Step.SigningKeys); err != nil {
		return code, err
	}
	// Registrars may publish only part of a request before failing. Every
	// independently publishable form must establish trust on its own.
	for _, key := range r.Step.SigningKeys {
		forms := []dp.SigningKey{key}
		if len(key.DS) > 0 {
			forms = nil
			for _, ds := range key.DS {
				forms = append(forms, dp.SigningKey{DS: []string{ds}})
			}
		}
		for _, form := range forms {
			if err = w.trust(ctx, e, e.target, []dp.SigningKey{form}); err != nil {
				return code, err
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return code, err
	}
	err = w.Registrar.SetDelegationSigners(ctx, cloneZone(e.plan.Request.Registration), cloneKeys(r.Step.SigningKeys))
	if err != nil {
		r.Outcome = OutcomeUnknown
		r.Err = err
		return code, err
	}
	e.keys = cloneKeys(r.Step.SigningKeys)
	e.awaitingKeys = true
	r.Outcome = Confirmed
	return code, err
}

func (w Workflow) executeVerifyDelegation(ctx context.Context, e *execution, i int) (PrerequisiteCode, error) {
	r := &e.results[i]
	var err error
	code := ReplacementUnverified
	err = w.verify(ctx, e, r.Step.Nameservers, r.Step.SigningKeys, false)
	if err == nil {
		r.Outcome = Confirmed
	} else {
		r.Outcome = PendingVerification
	}
	return code, err
}

func (w Workflow) executeDeleteHosting(ctx context.Context, e *execution, i int) (PrerequisiteCode, error) {
	r := &e.results[i]
	var err error
	code := ReplacementUnverified
	// A disappeared Zone after an attempted deletion confirms the earlier
	// outcome. A present Zone after a lost answer is never blindly deleted.
	z, readErr := w.Hosting.GetZone(ctx, e.plan.Request.Name)
	if errors.Is(readErr, dp.ErrNotFound) && r.Outcome == OutcomeUnknown {
		r.Outcome = Confirmed
		return code, err
	}
	if readErr != nil {
		err = readErr
		return code, err
	}
	if z.ID != e.hosting.ID || !sameNameservers(z.Nameservers, e.hosting.Nameservers) {
		err = ErrStalePlan
		return code, err
	}
	if r.Outcome == OutcomeUnknown {
		err = ErrPending
		return code, err
	}
	if !dp.CanDeleteZone(w.Hosting) {
		err = dp.ErrNotImplemented
		code = MissingCapability
		return code, err
	}
	if err = w.checkHosting(ctx, e); err != nil {
		return code, err
	}
	if err = w.checkRegistrar(ctx, e); err != nil {
		return code, err
	}
	if err = w.verify(ctx, e, e.target, e.keys, true); err != nil {
		return code, err
	}
	if err = ctx.Err(); err != nil {
		return code, err
	}
	err = w.Hosting.DeleteZone(ctx, cloneZone(e.hosting))
	if err != nil {
		r.Outcome = OutcomeUnknown
		r.Err = err
		return code, err
	}
	r.Outcome = Confirmed
	return code, err
}

// Unrelated HSTS and TLS diagnostics do not block hosting coordination.
// Identity, Provider signing diagnostics and context interruption still do.
func coordinationReadError(ctx context.Context, d dp.ZoneDetails, err error) error {
	if d.Zone.Name == "" {
		return err
	}
	return errors.Join(d.Properties.DNSSEC.Err, d.Properties.SigningKeys.Err, ctx.Err())
}
