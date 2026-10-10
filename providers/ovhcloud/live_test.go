package ovhcloud_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/ovhcloud"
)

func TestLive(t *testing.T) { livetest.Run(t, "ovhcloud", ovhcloud.Factory()) }
