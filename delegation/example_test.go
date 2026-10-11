package delegation_test

import (
	"context"

	dp "github.com/dnsgateway/dnsprovider"
	"github.com/dnsgateway/dnsprovider/delegation"
)

// reviewedOnboarding is the compilable example from docs/delegation.md.
// The caller supplies configured Accounts, DNS observations and its review UI.
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
