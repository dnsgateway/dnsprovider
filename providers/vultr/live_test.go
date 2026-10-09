package vultr_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/vultr"
)

// TestLive reads the Account of DNSPROVIDER_VULTR_API_KEY, without writing
// to it; DNSPROVIDER_VULTR_BASE_URL overrides the endpoint.
func TestLive(t *testing.T) {
	livetest.Run(t, "vultr", vultr.Factory())
}
