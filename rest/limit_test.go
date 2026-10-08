package rest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/dnsgateway/dnsprovider/rest"
)

func TestDoWaitsForTheRateLimiter(t *testing.T) {
	f := &flaky{}
	c := newClient(t, f)
	c.Limit = rate.NewLimiter(rate.Every(time.Hour), 1)

	if err := c.Do(context.Background(), http.MethodGet, "/things", nil, nil, nil); err != nil {
		t.Fatalf("first Do: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := c.Do(ctx, http.MethodGet, "/things", nil, nil, nil); err == nil {
		t.Error("second Do succeeded, want it held back by the limiter until the context ended")
	}

	if got := f.calls.Load(); got != 1 {
		t.Errorf("sent %d requests, want 1", got)
	}
}

func TestPerMinuteKeepsABurstUnderTheLimit(t *testing.T) {
	for _, n := range []int{1, 2, 20, 60} {
		l := rest.PerMinute(n)

		// A caller tries every 10ms for three minutes; no minute-long
		// window may hold more than n calls.
		start := time.Now()

		var sent []time.Time

		for at := start; at.Before(start.Add(3 * time.Minute)); at = at.Add(10 * time.Millisecond) {
			if l.AllowN(at, 1) {
				sent = append(sent, at)
			}
		}

		if len(sent) == 0 {
			t.Fatalf("PerMinute(%d) allowed no calls", n)
		}

		for i, from := range sent {
			in := 0
			for _, at := range sent[i:] {
				if at.Sub(from) < time.Minute {
					in++
				}
			}

			if in > n {
				t.Fatalf("PerMinute(%d) allowed %d calls in the minute from %v", n, in, from.Sub(start))
			}
		}

		if len(sent) < n {
			t.Errorf("PerMinute(%d) allowed %d calls in three minutes, want at least %d", n, len(sent), n)
		}
	}
}

