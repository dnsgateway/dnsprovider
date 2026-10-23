package inwx_test

import (
	"os"
	"testing"

	"github.com/dnsgateway/dnsprovider/internal/livetest"
	"github.com/dnsgateway/dnsprovider/providers/inwx"
)

// TestLive only reads DNS and skips unless DNSPROVIDER_INWX_USERNAME and
// DNSPROVIDER_INWX_PASSWORD are set. DNSPROVIDER_INWX_SHARED_SECRET is
// optional, for an account with 2FA; DNSPROVIDER_INWX_BASE_URL may point
// it at OT&E. livetest.Run logs the session out when it ends.
func TestLive(t *testing.T) {
	f := inwx.Factory()

	// livetest.Run skips unless every secret field is set; the shared
	// secret is optional, so it is left out when unset.
	if os.Getenv(livetest.Env("inwx", inwx.FieldSharedSecret)) == "" {
		kept := f.Fields[:0:0]
		for _, fd := range f.Fields {
			if fd.Name != inwx.FieldSharedSecret {
				kept = append(kept, fd)
			}
		}

		f.Fields = kept
	}

	livetest.Run(t, "inwx", f)
}
