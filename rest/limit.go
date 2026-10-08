package rest

import (
	"time"

	"golang.org/x/time/rate"
)

// PerMinute is a limiter for a Provider that takes n calls a minute. A
// tenth of them may go at once, and the bucket refills at the rest of n
// a minute, so the calls keep up close to n a minute and no minute ever
// holds more than n, however they bunch up: a window under a minute holds
// fewer than burst+refill = n+1 calls.
func PerMinute(n int) *rate.Limiter {
	burst := max(1, n/10)
	refill := max(1, n+1-burst)

	// Rounding the interval up keeps the rate at or under refill a minute.
	every := (time.Minute + time.Duration(refill) - 1) / time.Duration(refill)

	return rate.NewLimiter(rate.Every(every), burst)
}
