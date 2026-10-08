package rest

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Limiter holds a call back until the Provider's rate limit lets it go,
// or fails when ctx ends first. A *rate.Limiter is one.
type Limiter interface {
	Wait(ctx context.Context) error
}

// Window is a sliding-window Limiter: at most n calls in any window of
// per. Unlike a token bucket it lets the whole window's calls go at once
// and still keeps up n calls a window.
type Window struct {
	n   int
	per time.Duration

	mu sync.Mutex
	// sent are the times of the calls in the last window, oldest first.
	sent []time.Time
}

// PerMinute is a limiter for a Provider that takes n calls a minute: up
// to n may go at once, and no minute ever holds more than n, however they
// bunch up.
func PerMinute(n int) *Window {
	return &Window{n: max(1, n), per: time.Minute}
}

// AllowN reports whether k calls may go at now, and counts them sent if
// so.
func (w *Window) AllowN(now time.Time, k int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	ok, _ := w.take(now, k)

	return ok
}

// Wait implements Limiter. A wait that would outlast ctx's deadline fails
// at once, with context.DeadlineExceeded.
func (w *Window) Wait(ctx context.Context) error {
	for {
		w.mu.Lock()
		ok, next := w.take(time.Now(), 1)
		w.mu.Unlock()

		if ok {
			return nil
		}

		if d, has := ctx.Deadline(); has && d.Before(next) {
			return fmt.Errorf("the rate limit lets the call go at %v, past the deadline: %w", next.Format(time.RFC3339), context.DeadlineExceeded)
		}

		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()

			return ctx.Err()
		case <-t.C:
		}
	}
}

// take counts k calls sent at now if the window has room for them; if
// not, next is when it may. The caller holds mu.
func (w *Window) take(now time.Time, k int) (ok bool, next time.Time) {
	i := 0
	for i < len(w.sent) && now.Sub(w.sent[i]) >= w.per {
		i++
	}

	w.sent = w.sent[i:]

	if k > w.n {
		return false, time.Time{}
	}

	if len(w.sent)+k <= w.n {
		for range k {
			w.sent = append(w.sent, now)
		}

		return true, time.Time{}
	}

	return false, w.sent[len(w.sent)+k-w.n-1].Add(w.per)
}
