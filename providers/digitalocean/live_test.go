package digitalocean_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/digitalocean"
)

// TestLive reads the Account of DNSPROVIDER_DIGITALOCEAN_TOKEN, without
// writing to it; DNSPROVIDER_DIGITALOCEAN_BASE_URL overrides the endpoint.
func TestLive(t *testing.T) {
	livetest.Run(t, "digitalocean", digitalocean.Factory())
}
