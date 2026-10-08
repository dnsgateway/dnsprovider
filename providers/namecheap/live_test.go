package namecheap_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/namecheap"
)

// TestLive reads a real Namecheap Account, without writing to it. It is
// skipped unless the credentials are set; see livetest.Run.
func TestLive(t *testing.T) {
	livetest.Run(t, "namecheap", namecheap.Factory())
}
