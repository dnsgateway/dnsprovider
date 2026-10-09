package cloudns

import (
	"context"
	"sync"
	"time"

	"github.com/dnsgateway/dnsprovider/rest"
	"golang.org/x/time/rate"
)

// ClouDNS publishes per-IP quotas of 20/second, 600/minute and
// 36,000/hour. A shared, paced 10/second limit with a one-request burst
// satisfies all three; the minute window also bounds long-running clients.
// Clients to the same endpoint share the budget across all credentials.
var endpointLimits = struct {
	sync.Mutex
	limits map[string]*quota
}{limits: map[string]*quota{}}

type quota struct {
	pace   *rate.Limiter
	minute *rest.Window
}

func (q *quota) Wait(ctx context.Context) error {
	if err := q.pace.Wait(ctx); err != nil {
		return err
	}
	return q.minute.Wait(ctx)
}

func endpointQuota(endpoint string) *quota {
	endpointLimits.Lock()
	defer endpointLimits.Unlock()
	if q := endpointLimits.limits[endpoint]; q != nil {
		return q
	}
	q := &quota{pace: rate.NewLimiter(rate.Every(100*time.Millisecond), 1), minute: rest.PerMinute(600)}
	endpointLimits.limits[endpoint] = q
	return q
}
