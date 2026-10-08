package cloudflare

import (
	"testing"
	"time"
)

// SetRequestTimeout makes the Providers built for the rest of the test
// bound their requests by d instead of DefaultRequestTimeout.
func SetRequestTimeout(t testing.TB, d time.Duration) {
	t.Helper()

	old := requestTimeout
	requestTimeout = d

	t.Cleanup(func() { requestTimeout = old })
}
