package infomaniak_test

import (
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/infomaniak"
)

// TestLive only reads DNS and skips unless DNSPROVIDER_INFOMANIAK_TOKEN
// is set; DNSPROVIDER_INFOMANIAK_ACCOUNT_ID scopes it to one Account.
func TestLive(t *testing.T) {
	livetest.Run(t, "infomaniak", infomaniak.Factory())
}
