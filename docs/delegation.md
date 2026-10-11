# Explicit Delegation coordination

Import `github.com/dnsgateway/dnsprovider/delegation` to coordinate hosting and
Registration work explicitly. `Workflow.Plan` is read-only; review its Request,
Observations, ordered Steps, RequiredCapabilities and Prerequisites before
calling `Execute`. Ordinary `CreateZone` and `DeleteZone` still manage hosting
only. The workflow never buys, renews, transfers or cancels a Registration,
copies Records, or changes Provider signing settings.

Bind `Hosting` to the intended hosting Account and `Registrar` to the intended
Registration's `DSRegistrar`. Pass that Registration explicitly in the Request;
it must name the same domain. The workflow never finds a registrar by probing
Accounts. `PreserveDS` is the default; `PublishDS` requires explicit reviewed
Signing Keys, and `RemoveDS` explicitly requests removal. Provider Signing Keys
are observed separately and are never substituted for registrar-held keys or
inferred as publication intent.

## Caller dependencies

Supply an `Observer` that reads parent Nameservers and published DS, and checks
that the intended authoritative Nameservers actually serve the name. Set
`Conclusive` false for conflicts, incomplete observations and uncertainty.
`TrustValid` must establish that the supplied keys validate that authoritative
Zone, rather than merely compare key tags or inspect a Provider's signing flag.
Unknown or unsupported Provider properties alone do not establish signing is
off; safe unsigned hosting can proceed with empty registrar/parent DS and
conclusive authoritative observations. Failed supported DNSSEC/key reads remain
errors; unrelated HSTS/TLS diagnostics do not prevent coordination.

The caller owns DNS query implementation, validation policy, deadlines and
bounded attempts inside each adapter method. Execution makes one observation
attempt for each check in a step and returns without waiting for propagation;
a step can read several independent resources or validate both current and
replacement hosting. A resumed call makes fresh attempts. There is no polling
worker, scheduler, or guarantee of global propagation. Observations establish
safety at a point in time and cannot eliminate a race with another writer.

`Workflow.NS` accepts a provisional caller-supplied `NameserverRegistrar` for
Registration NS reads and replacement writes. No production vendor NS adapter
ships with this feature. Without it, execution reports `ManualNameservers` and
`ErrNotImplemented` until the caller changes NS at the selected registrar and
fresh parent and authoritative observations confirm the change. Observation
errors and context interruption retain their error classification. Keep using the
same Workflow when resuming. Adding or replacing an adapter requires a new plan.
An NS adapter should respect context, report uncertain responses, and return the
actual held set when asked to read; apex Record CRUD is not this registrar seam.

## Example: review, execute, and retain progress

This helper is compiled as part of the workflow tests. Supply configured
Providers, your Observer, and a review callback that displays the plan and obtains
confirmation. The helper deliberately leaves NS changes as manual work.

```go
package example

import (
    "context"

    dp "github.com/dnsgateway/dnsprovider"
    "github.com/dnsgateway/dnsprovider/delegation"
)

func reviewedOnboarding(
	ctx context.Context,
	hosting dp.Provider,
	registrar dp.DSRegistrar,
	dns delegation.Observer,
	registration dp.Zone,
	review func(delegation.Plan) error,
) (delegation.Workflow, delegation.Progress, error) {
	workflow := delegation.Workflow{Hosting: hosting, Registrar: registrar, DNS: dns}
	plan, err := workflow.Plan(ctx, delegation.Request{
		Action:       delegation.Onboard,
		Name:         registration.Name,
		Registration: registration,
		DS:           delegation.PreserveDS,
	})
	if err != nil {
		return workflow, delegation.Progress{}, err
	}
	if err = review(plan); err != nil {
		return workflow, delegation.Progress{}, err
	}
	progress, err := workflow.Execute(ctx, plan)
	return workflow, progress, err
}
```

Inspect `progress.Results`, `progress.Observed`, `progress.Remaining` and the
returned error together. After performing outstanding manual work or allowing
propagation, call `workflow.Resume(ctx, progress)` with a fresh context. A resumed
call returns a new Progress; retain that result even on error. Use `errors.Is`
for `delegation.ErrPending`, `delegation.ErrStalePlan` and root typed errors, and
`errors.As` for adapter `APIError` diagnostics. When intent or preconditions
change, obtain and review a new plan rather than editing the old one.

## Supported ordering and limits

For onboarding, absent hosting is created once, then refreshed to obtain identity
and assigned Nameservers. An accepted Pending Zone remains a confirmed hosting
step even when metadata or subsequent reads are missing. Existing hosting with
unknown Nameservers is refreshed too. Plans authorize use of future assigned
Nameservers for the selected hosting; callers requiring an exact NS list before
approval should establish hosting first and then plan again. Refresh rejects a
changed known Zone identity; accepted creation without an ID may establish its
first known identity from a later observation.

With no held DS, publication verifies the target serves without DS after NS
changes, verifies every independently publishable reviewed key form against the
target, publishes the selected keys, then verifies the actual signed parent
Delegation. Each form must validate on its own because a registrar can accept only
part of a request before failing. These are separate verification steps.
Preserving DS requires the target to validate against the actual retained keys.

Changing any existing held DS set is blocked, including additive publication:
`DSRegistrar` does not guarantee that its intermediate writes retain a trust path.
An unchanged requested set can be confirmed without a write. These conservative
sequences are not an arbitrary key rollover engine. `RemoveDS` only confirms an
already empty registrar/parent DS set. The workflow never automatically disables
signing or clears DS to make migration easier.

Registrar-held and parent-published DS must agree before dependent writes. Real
DS adapters keep their existing form translation, algorithm refusal and typed
errors. A DS-only registrar may select a supported digest from each reviewed key;
every reviewed key must be represented and extra material is rejected. A registrar
that accepts DNSKEY-only input may return the identical DNSKEY with its computed
DS; that form is reconciled before comparing the actual held DS to the parent.
Trust is
verified against actual held/published keys, and later snapshot comparisons remain
strict. A partial initial publication is reread after failure and retained in
observed progress. Execution confirms a complete observed publication without
repeating it, but does not repair a partial set through an unsupported existing-set
replacement. Unchanged, empty, unrelated or still propagating outcomes remain
outstanding for review or later observation.

For offboarding, pass `ReplacementNameservers`. Every old Nameserver must be
excluded from the replacement, the old identity must be known, registrar NS
(where available) and parent Delegation must agree with the replacement, and
replacement serving/trust must be verified before deleting old hosting. Missing
Registration, overlapping Nameservers, resolver errors, inconclusive propagation,
invalid trust or a target that does not serve prevent deletion. Registration and
its held keys remain intact unless a separately reviewed DS step changes them.

## Progress and nontransactional outcomes

Results distinguish `NotStarted`, `Confirmed`, `PendingVerification`, `Failed`
and `OutcomeUnknown`; errors retain completed writes and remaining prerequisites.
Writes across Accounts are not a transaction, and there is no automatic rollback.
Confirmed creation is never repeated because a later read fails. A lost create
answer remains uncertain until hosting is observed, even when it is still absent.
Lost NS or deletion answers are reconciled from fresh state without blindly
repeating the write. Cancellation returns known progress and the context error.

Execution rereads dependent preconditions and rejects changed observations with
`ErrStalePlan`. Plans are sealed and bound to the exact selected adapter instances;
editing exported fields cannot authorize a different execution. Progress retains
private accepted-write evidence, so editing the displayed results cannot erase
accepted creation or redirect resumption. Plans and progress are process-local:
JSON persistence, reconstruction from exported fields, or use with replacement
Account instances does not preserve their execution authority. Consumers requiring
durable jobs must implement their own recovery and review policy.

The [architecture decision](adr/0001-opt-in-delegation-coordination.md) records
this intentional expansion from consumer-only coordination.
