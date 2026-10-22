package netim_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/netim"
)

// TestLive only reads DNS and skips unless DNSPROVIDER_NETIM_ID and
// DNSPROVIDER_NETIM_SECRET are set; DNSPROVIDER_NETIM_BASE_URL may point
// it at OT&E. livetest.Run closes its session when it ends.
func TestLive(t *testing.T) {
	livetest.Run(t, "netim", netim.Factory())
}
