package hetzner_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/hetzner"
)

func TestLive(t *testing.T) { livetest.Run(t, "hetzner", hetzner.Factory()) }
