// Package delegation coordinates opt-in hosting and Registration work. Planning
// is read-only; ordinary Provider CRUD retains its hosting-only contract.
package delegation

import (
	"context"
	"errors"
	"slices"
	"strings"

	dp "github.com/dnsgateway/dnsprovider"
)

// NameserverRegistrar is a caller-supplied, provisional Registration adapter.
// No production vendor adapter is supplied by this package.
type NameserverRegistrar interface {
	Nameservers(context.Context, dp.Zone) ([]string, error)
	SetNameservers(context.Context, dp.Zone, []string) error
}

// Observer performs bounded DNS reads. Conclusive must be false for ambiguous,
// conflicting or incomplete observations. TrustValid means the supplied keys
// validate the intended authoritative Zone, not merely that key tags match.
type Observer interface {
	Parent(context.Context, string) (Parent, error)
	Authoritative(context.Context, string, []string, []dp.SigningKey) (Verification, error)
}

// Parent is observed parent Delegation, including registry-published DS.
type Parent struct {
	Nameservers []string
	SigningKeys []dp.SigningKey
	Conclusive  bool
}

// Verification describes intended authoritative hosting at one point in time.
// It is not a guarantee of global propagation or freedom from later races.
// TrustValid establishes a valid path using the supplied actual key material.
// A set can validate through one key; initial DS publication also checks each
// independently publishable form to prevent an unsafe partial publication.
type Verification struct {
	Serving    bool
	TrustValid bool
	Conclusive bool
}

// Action is the explicit hosting lifecycle intent.
type Action string

const (
	Onboard  Action = "onboard"
	Offboard Action = "offboard"
)

// DSIntent explicitly authorizes registrar-held Signing Key replacement.
type DSIntent string

const (
	PreserveDS DSIntent = ""
	PublishDS  DSIntent = "publish"
	RemoveDS   DSIntent = "remove"
)

// Request selects the name and Registration explicitly. For offboarding,
// ReplacementNameservers identify the hosting that must serve before deletion.
// PublishDS uses SigningKeys exactly as reviewed, never inferred Provider keys.
type Request struct {
	Action                 Action
	Name                   string
	Registration           dp.Zone
	ReplacementNameservers []string
	DS                     DSIntent
	SigningKeys            []dp.SigningKey
}

// StepKind identifies intended work in dependency order.
type StepKind string

const (
	CreateHosting    StepKind = "create-hosting"
	RefreshHosting   StepKind = "refresh-hosting"
	SetSigners       StepKind = "set-signers"
	SetNameservers   StepKind = "set-nameservers"
	VerifyDelegation StepKind = "verify-delegation"
	DeleteHosting    StepKind = "delete-hosting"
)

// Step describes a reviewed change or required observation.
type Step struct {
	Kind        StepKind
	Nameservers []string
	SigningKeys []dp.SigningKey
}

// PrerequisiteCode distinguishes actionable outstanding work.
type PrerequisiteCode string

const (
	ManualNameservers      PrerequisiteCode = "manual-nameservers"
	MissingNameservers     PrerequisiteCode = "missing-nameservers"
	MissingRegistration    PrerequisiteCode = "missing-registration"
	MissingCapability      PrerequisiteCode = "missing-capability"
	ObservationUnavailable PrerequisiteCode = "observation-unavailable"
	UnsafeDNSSEC           PrerequisiteCode = "unsafe-dnssec"
	ReplacementUnverified  PrerequisiteCode = "replacement-unverified"
)

// Prerequisite is work required before its dependent step; Err retains typed errors.
type Prerequisite struct {
	Code    PrerequisiteCode
	Step    StepKind
	Message string
	Err     error
}

// Observations are fresh planning inputs retained for stale execution checks.
type Observations struct {
	Hosting              dp.ZoneDetails
	HostingExists        bool
	RegistrationKeys     []dp.SigningKey
	RegistrationRead     bool
	RegistrarNameservers []string
	RegistrarNSRead      bool
	Parent               Parent
	ParentRead           bool
	Replacement          Verification
	CurrentTrust         Verification
}

// Plan is a reviewable read-only snapshot. Callers must review a fresh plan when
// intent or observations change; execution must never trust edited observations.
type Plan struct {
	Request              Request
	Observations         Observations
	Steps                []Step
	RequiredCapabilities []dp.Capability
	Prerequisites        []Prerequisite
	reviewed             *Plan
	accounts             *Workflow
}

// Outcome preserves known progress across interruption or partial remote writes.
type Outcome string

const (
	NotStarted          Outcome = "not-started"
	Confirmed           Outcome = "confirmed"
	PendingVerification Outcome = "pending-verification"
	Failed              Outcome = "failed"
	OutcomeUnknown      Outcome = "outcome-unknown"
)

// StepResult records one remote outcome, including an accepted Pending Zone.
type StepResult struct {
	Step    Step
	Outcome Outcome
	Zone    dp.Zone
	Err     error
}

// Progress is returned on every execution path and supplied on resume. It is
// evidence of accepted writes, never a substitute for fresh remote observations.
type Progress struct {
	Plan Plan
	// Observed retains the latest remote reads, separately from the reviewed Plan.
	Observed  Observations
	Results   []StepResult
	Remaining []Prerequisite
	evidence  *execution
}

// Workflow binds caller-selected hosting and registrar Accounts. Registrar must
// refer to the selected Registration; it is never inferred from Hosting.
type Workflow struct {
	Hosting   dp.Provider
	Registrar dp.DSRegistrar
	NS        NameserverRegistrar
	DNS       Observer
}

// ErrInvalidRequest rejects invalid intent before any reads or writes.
var ErrInvalidRequest = errors.New("invalid Delegation request")

// Plan reads selected Accounts and DNS without making remote writes.
func (w Workflow) Plan(ctx context.Context, r Request) (Plan, error) {
	r.Name = canonicalName(r.Name)
	r.Registration.Name = canonicalName(r.Registration.Name)
	// Clone before canonicalizing caller-owned slices.
	r = cloneRequest(r)
	for i := range r.ReplacementNameservers {
		r.ReplacementNameservers[i] = canonicalName(r.ReplacementNameservers[i])
	}
	p := Plan{Request: cloneRequest(r)}
	if w.Hosting == nil || !validRequest(r) {
		return p, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return p, err
	}
	details, err := dp.ZoneDetailsOf(ctx, w.Hosting, r.Name, dp.ZoneDetailRequest{SigningKeys: true})
	err = coordinationReadError(ctx, details, err)
	switch {
	case err == nil:
		p.observeHosting(details)
	case errors.Is(err, dp.ErrNotFound) && r.Action == Onboard:
		p.Steps = append(p.Steps, Step{Kind: CreateHosting}, Step{Kind: RefreshHosting})
		p.RequiredCapabilities = append(p.RequiredCapabilities, dp.CapZoneCreator)
		if !dp.CanCreateZone(w.Hosting) {
			p.add(MissingCapability, CreateHosting, "hosting Account cannot create Zones", dp.ErrNotImplemented)
		}
	default:
		p.Observations.Hosting = cloneDetails(details)
		p.Observations.HostingExists = details.Zone.Name != ""
		p.add(ObservationUnavailable, RefreshHosting, "hosting observation failed", err)
	}
	w.readDelegation(ctx, &p)

	target := w.targetNameservers(&p)
	if !validNameservers(target) {
		p.add(MissingNameservers, SetNameservers, "refresh assigned Nameservers before dependent writes", nil)
	}
	keys := p.Observations.RegistrationKeys
	if r.DS == PublishDS {
		keys = r.SigningKeys
	}
	if r.DS == RemoveDS {
		keys = nil
	}
	if len(target) > 0 && w.DNS != nil {
		v, e := w.DNS.Authoritative(ctx, r.Name, slices.Clone(target), cloneKeys(keys))
		p.Observations.Replacement = v
		if e != nil || !v.Conclusive || !v.Serving {
			p.add(ReplacementUnverified, VerifyDelegation, "intended authoritative hosting is not verified", e)
		}
	}
	publishFirst := w.planDNSSEC(ctx, &p, keys)

	if r.DS != PreserveDS && (r.DS != PublishDS || publishFirst) {
		p.Steps = append(p.Steps, Step{Kind: SetSigners, SigningKeys: cloneKeys(keys)})
	}
	if len(target) > 0 && !sameNameservers(target, p.Observations.Parent.Nameservers) {
		p.Steps = append(p.Steps, Step{Kind: SetNameservers, Nameservers: slices.Clone(target)})
		if w.NS == nil {
			p.add(ManualNameservers, SetNameservers, "change Nameservers at the selected registrar manually", dp.ErrNotImplemented)
		}
	}
	verificationKeys := keys
	if r.DS == PublishDS && !publishFirst {
		verificationKeys = p.Observations.RegistrationKeys
	}
	p.Steps = append(p.Steps, Step{Kind: VerifyDelegation, Nameservers: slices.Clone(target), SigningKeys: cloneKeys(verificationKeys)})
	if r.DS == PublishDS && !publishFirst {
		p.Steps = append(p.Steps, Step{Kind: SetSigners, SigningKeys: cloneKeys(keys)}, Step{Kind: VerifyDelegation, Nameservers: slices.Clone(target), SigningKeys: cloneKeys(keys)})
	}
	if r.Action == Offboard {
		p.Steps = append(p.Steps, Step{Kind: DeleteHosting})
	}
	if err := ctx.Err(); err != nil {
		return p, err
	}
	snapshot := clonePlan(p)
	p.reviewed = &snapshot
	p.accounts = &w
	return p, nil
}

func (p *Plan) add(code PrerequisiteCode, step StepKind, message string, err error) {
	p.Prerequisites = append(p.Prerequisites, Prerequisite{Code: code, Step: step, Message: message, Err: err})
}

func cloneKeys(keys []dp.SigningKey) []dp.SigningKey {
	out := slices.Clone(keys)
	for i := range out {
		out[i].DS = slices.Clone(out[i].DS)
	}
	return out
}
func cloneZone(z dp.Zone) dp.Zone { z.Nameservers = slices.Clone(z.Nameservers); return z }
func cloneDetails(d dp.ZoneDetails) dp.ZoneDetails {
	d.Zone = cloneZone(d.Zone)
	d.SigningKeys = cloneKeys(d.SigningKeys)
	return d
}

func cloneRequest(r Request) Request {
	r.Registration = cloneZone(r.Registration)
	r.ReplacementNameservers = slices.Clone(r.ReplacementNameservers)
	r.SigningKeys = cloneKeys(r.SigningKeys)
	return r
}

func cloneParent(p Parent) Parent {
	p.Nameservers = slices.Clone(p.Nameservers)
	p.SigningKeys = cloneKeys(p.SigningKeys)
	return p
}

func sameNameservers(a, b []string) bool {
	normalize := func(in []string) []string {
		out := make([]string, len(in))
		for i, n := range in {
			out[i] = strings.ToLower(strings.TrimSuffix(n, "."))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(normalize(a), normalize(b))
}

// sameKeys compares the full advertised key form, never key tags alone. Different
// forms remain conservatively unequal because DS cannot reconstruct DNSKEY.
func sameKeys(a, b []dp.SigningKey) bool {
	normalize := func(in []dp.SigningKey) []string {
		out := make([]string, 0, len(in))
		for _, k := range in {
			ds := slices.Clone(k.DS)
			for i := range ds {
				ds[i] = strings.ToUpper(strings.Join(strings.Fields(ds[i]), " "))
			}
			slices.Sort(ds)
			out = append(out, strings.Join(strings.Fields(k.DNSKEY), " ")+"|"+strings.Join(ds, "|"))
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return slices.Equal(normalize(a), normalize(b))
}

func canonicalName(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }
func validName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func validNameservers(ns []string) bool {
	if len(ns) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, n := range ns {
		n = canonicalName(n)
		if !validName(n) || seen[n] {
			return false
		}
		seen[n] = true
	}
	return true
}

// clonePlan creates a snapshot without an execution seal.
func clonePlan(p Plan) Plan {
	p.Request = cloneRequest(p.Request)
	p.Observations.Hosting = cloneDetails(p.Observations.Hosting)
	p.Observations.RegistrationKeys = cloneKeys(p.Observations.RegistrationKeys)
	p.Observations.RegistrarNameservers = slices.Clone(p.Observations.RegistrarNameservers)
	p.Observations.Parent = cloneParent(p.Observations.Parent)
	p.Steps = slices.Clone(p.Steps)
	for i := range p.Steps {
		p.Steps[i].Nameservers = slices.Clone(p.Steps[i].Nameservers)
		p.Steps[i].SigningKeys = cloneKeys(p.Steps[i].SigningKeys)
	}
	p.RequiredCapabilities = slices.Clone(p.RequiredCapabilities)
	p.Prerequisites = slices.Clone(p.Prerequisites)
	p.reviewed = nil
	p.accounts = nil
	return p
}

func validRequest(r Request) bool {
	return validName(r.Name) && r.Registration.Name == r.Name &&
		(r.Action == Onboard || r.Action == Offboard) &&
		(r.DS == PreserveDS || r.DS == PublishDS || r.DS == RemoveDS) &&
		(r.DS != PublishDS || len(r.SigningKeys) > 0) &&
		(r.DS == PublishDS || len(r.SigningKeys) == 0) &&
		(r.Action != Offboard || validNameservers(r.ReplacementNameservers))
}

func (w Workflow) planDNSSEC(ctx context.Context, p *Plan, keys []dp.SigningKey) bool {
	r := p.Request
	if p.Observations.RegistrationRead && p.Observations.ParentRead && !sameRegistryKeys(p.Observations.RegistrationKeys, p.Observations.Parent.SigningKeys) {
		p.add(UnsafeDNSSEC, SetSigners, "registrar and parent Signing Keys disagree; await propagation", nil)
	}
	if len(keys) > 0 && (!p.Observations.Replacement.Conclusive || !p.Observations.Replacement.TrustValid) {
		p.add(UnsafeDNSSEC, SetNameservers, "intended hosting has no verified trust path for held Signing Keys", nil)
	}
	if r.DS == RemoveDS && (len(p.Observations.RegistrationKeys) > 0 || len(p.Observations.Parent.SigningKeys) > 0) {
		p.add(UnsafeDNSSEC, SetSigners, "removing an existing trust path is not a supported migration sequence", nil)
	}
	publishFirst := r.DS == PublishDS && len(p.Observations.RegistrationKeys) > 0
	if publishFirst && !registryRepresents(p.Observations.RegistrationKeys, r.SigningKeys) {
		p.add(UnsafeDNSSEC, SetSigners, "selected DSRegistrar cannot establish safe intermediate writes for changing existing Signing Keys", nil)
	}
	if publishFirst && w.DNS != nil {
		v, e := w.DNS.Authoritative(ctx, r.Name, slices.Clone(p.Observations.Parent.Nameservers), cloneKeys(keys))
		p.Observations.CurrentTrust = v
		if e != nil || !v.Conclusive || !v.Serving || !v.TrustValid {
			p.add(UnsafeDNSSEC, SetSigners, "reviewed Signing Keys must also validate current hosting before replacement", e)
		}
	}
	return publishFirst
}

func (w Workflow) readDelegation(ctx context.Context, p *Plan) {
	r := p.Request
	if w.Registrar == nil {
		p.add(MissingRegistration, SetSigners, "selected registrar cannot read Registration Signing Keys", dp.ErrNotImplemented)
	} else {
		keys, e := w.Registrar.DelegationSigners(ctx, cloneZone(r.Registration))
		if e != nil {
			p.add(MissingRegistration, SetSigners, "Registration Signing Keys unavailable", e)
		} else {
			p.Observations.RegistrationRead = true
			p.Observations.RegistrationKeys = cloneKeys(keys)
		}
	}
	if w.NS != nil {
		ns, e := w.NS.Nameservers(ctx, cloneZone(r.Registration))
		if e != nil {
			p.add(ObservationUnavailable, SetNameservers, "registrar Nameservers unavailable", e)
		} else {
			p.Observations.RegistrarNSRead = true
			p.Observations.RegistrarNameservers = slices.Clone(ns)
		}
	}
	if w.DNS == nil {
		p.add(ObservationUnavailable, VerifyDelegation, "DNS observer is required", nil)
	} else {
		parent, e := w.DNS.Parent(ctx, r.Name)
		p.Observations.Parent = cloneParent(parent)
		p.Observations.ParentRead = e == nil && parent.Conclusive
		if !p.Observations.ParentRead {
			p.add(ObservationUnavailable, VerifyDelegation, "parent Delegation unavailable or inconclusive", e)
		}
	}
}

func (w Workflow) targetNameservers(p *Plan) []string {
	r := p.Request
	details := p.Observations.Hosting
	target := details.Zone.Nameservers
	if r.Action == Offboard {
		target = r.ReplacementNameservers
		if overlappingNameservers(details.Zone.Nameservers, target) {
			p.add(ReplacementUnverified, DeleteHosting, "replacement must exclude every old Nameserver", nil)
		}
		if details.Zone.ID == "" {
			p.add(ObservationUnavailable, DeleteHosting, "refresh old Zone identity before deletion", nil)
		}
		if !validNameservers(details.Zone.Nameservers) {
			p.add(MissingNameservers, DeleteHosting, "old Nameservers required to prove Delegation left hosting", nil)
		}
		p.RequiredCapabilities = append(p.RequiredCapabilities, dp.CapZoneDeleter)
		if !dp.CanDeleteZone(w.Hosting) {
			p.add(MissingCapability, DeleteHosting, "hosting Account cannot delete Zones", dp.ErrNotImplemented)
		}
	}
	return target
}

func (p *Plan) observeHosting(details dp.ZoneDetails) {
	p.Observations.HostingExists = true
	p.Observations.Hosting = cloneDetails(details)
	if p.Request.Action == Onboard && !validNameservers(details.Zone.Nameservers) {
		p.Steps = append(p.Steps, Step{Kind: RefreshHosting})
	}
}
