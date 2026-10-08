package rest

import (
	"time"

	"golang.org/x/time/rate"
)

// PerMinute is a limiter for a Provider that takes n calls a minute. Half
// of them may go at once, and the rest come back over the minute, so no
// minute ever holds more than n calls, however they bunch up.
func PerMinute(n int) *rate.Limiter {
	burst := max(1, n/2)
	refill := max(1, n-burst)

	return rate.NewLimiter(rate.Every(time.Minute/time.Duration(refill)), burst)
}
