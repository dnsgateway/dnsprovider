package dnsprovider_test

import (
	"context"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// oneTenant is a Provider whose credentials act within one Tenant alone.
type oneTenant struct{ dnsprovider.Provider }

// manyTenants is a Provider whose credentials can reach several Tenants.
type manyTenants struct{ dnsprovider.Provider }

func (manyTenants) Tenants(context.Context) ([]dnsprovider.Tenant, error) {
	return []dnsprovider.Tenant{{ID: "acc1", Name: "Acme Ltd"}}, nil
}

func TestCanListTenantsOnlyForATenantLister(t *testing.T) {
	if dnsprovider.CanListTenants(oneTenant{}) {
		t.Error("a Provider without Tenants lists them")
	}

	if !dnsprovider.CanListTenants(manyTenants{}) {
		t.Error("a TenantLister does not list Tenants")
	}
}
