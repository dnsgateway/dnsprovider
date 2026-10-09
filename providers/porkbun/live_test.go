package porkbun_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/porkbun"
)

// TestLive performs read-only compatibility checks and skips without credentials.
func TestLive(t *testing.T) { livetest.Run(t, "porkbun", porkbun.Factory()) }
