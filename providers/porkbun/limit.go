package porkbun

import (
	"crypto/sha256"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// The generic per-key budget is twenty calls per two seconds. A shared,
// paced limiter also bounds several Providers using the same credentials.
// Hashing keeps credentials out of the limiter's identity and diagnostics.
var limits = struct {
	sync.Mutex

	byKey map[[32]byte]*rate.Limiter
}{byKey: map[[32]byte]*rate.Limiter{}}

func keyLimit(endpoint, key string) *rate.Limiter {
	id := sha256.Sum256([]byte(endpoint + "\x00" + key))
	limits.Lock()
	defer limits.Unlock()
	if l := limits.byKey[id]; l != nil {
		return l
	}
	l := rate.NewLimiter(rate.Every(100*time.Millisecond), 1)
	limits.byKey[id] = l
	return l
}
