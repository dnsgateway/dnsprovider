package scaleway_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/scaleway"
)

func TestLive(t *testing.T) { livetest.Run(t, "scaleway", scaleway.Factory()) }
