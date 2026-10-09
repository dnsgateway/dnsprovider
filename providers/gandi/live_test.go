package gandi_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/gandi"
)

func TestLiveReadOnly(t *testing.T) { livetest.Run(t, "gandi", gandi.Factory()) }
