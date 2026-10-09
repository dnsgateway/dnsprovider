package internetbs_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/internetbs"
)

// TestLive only reads DNS and skips unless both secret fields are configured.
func TestLive(t *testing.T) {
	livetest.Run(t, "internetbs", internetbs.Factory())
}
