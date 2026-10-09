package dnsimple_test

import (
	"os"
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/dnsimple"
)

// TestLive reads only, and needs both the token and explicit Account ID.
func TestLive(t *testing.T) {
	if os.Getenv(livetest.Env("dnsimple", "account_id")) == "" {
		t.Skip("DNSPROVIDER_DNSIMPLE_ACCOUNT_ID is not set")
	}
	livetest.Run(t, "dnsimple", dnsimple.Factory())
}
