package rest_test

import (
	"context"
	"errors"
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

	if err := c.Do(ctx, http.MethodGet, "/things", nil, nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("second Do = %v, want it held back by the limiter and the context's deadline reported", err)
	}

	if got := f.calls.Load(); got != 1 {
		t.Errorf("sent %d requests, want 1", got)
	}
}

func TestPerMinuteKeepsEveryMinuteUnderTheLimit(t *testing.T) {
	for _, n := range []int{1, 2, 7, 20, 60, 100} {
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

		// Once the burst is spent, nearly n calls a minute still go.
		later := 0
		for _, at := range sent {
			if at.Sub(start) >= time.Minute {
				later++
			}
		}

		if want := n * 2 * 9 / 10; later < want {
			t.Errorf("PerMinute(%d) allowed %d calls in the last two minutes, want at least %d", n, later, want)
		}
	}
}
