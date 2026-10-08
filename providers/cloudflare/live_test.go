package cloudflare_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/cloudflare"
)

// TestLive reads a real Cloudflare Account, without writing to it. It is
// skipped unless the credentials are set; see livetest.Run.
func TestLive(t *testing.T) {
	livetest.Run(t, "cloudflare", cloudflare.Factory())
}
