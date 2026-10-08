package godaddy_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/godaddy"
)

// TestLive reads a real GoDaddy Account, without writing to it. It is
// skipped unless the credentials are set; see livetest.Run.
func TestLive(t *testing.T) {
	livetest.Run(t, "godaddy", godaddy.Factory())
}
