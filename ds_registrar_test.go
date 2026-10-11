package dnsprovider_test

import (
	"context"
	"testing"

	"github.com/dnsgateway/dnsprovider"
)

// registrar is a Provider that registers domains and can replace the DS
// records the registry publishes for them.
type registrar struct{ dnsprovider.Provider }

func (registrar) DelegationSigners(context.Context, dnsprovider.Zone) ([]dnsprovider.SigningKey, error) {
	return nil, dnsprovider.ErrNotFound
}

func (registrar) SetDelegationSigners(context.Context, dnsprovider.Zone, []dnsprovider.SigningKey) error {
	return dnsprovider.ErrUnsupported
}

func TestCanRegisterDSOnlyForADSRegistrar(t *testing.T) {
	if dnsprovider.CanRegisterDS(oneTenant{}) {
		t.Error("a Provider that cannot write DS records registers them")
	}

	if !dnsprovider.CanRegisterDS(registrar{}) {
		t.Error("a DSRegistrar does not register DS records")
	}
}
