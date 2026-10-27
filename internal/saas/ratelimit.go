package saas

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// How the providers say "slow down", as they document it:
//
//   - GitHub: 403 or 429 for its primary limit (5,000 requests an hour for
//     a token, shared with every other tool using it) and its secondary
//     limits (concurrency, points per minute, abuse detection). Wait for
//     retry-after if given; else, if x-ratelimit-remaining is 0, until
//     x-ratelimit-reset; else at least a minute, then longer. Requests are
//     sent one at a time, as GitHub asks.
//   - Cloudflare: 429 past 1,200 requests in 5 minutes per user, shared
//     with the dashboard, and every call is then refused for the next 5
//     minutes. The Ratelimit header (r=remaining, t=seconds to reset)
//     says when to stop before that happens.
//
// A read is sent again after the wait; a write never is, only paced.

// rateWaitCap bounds one wait. GitHub's primary limit resets hourly; a
// capture does not sit out an hour: it reports the read as throttled,
// naming when the limit resets.
var rateWaitCap = 15 * time.Minute

// rateTries is how many times a throttled read is sent in all.
const rateTries = 5

var (
	clock     = time.Now
	sleepCtx  = func(ctx context.Context, d time.Duration) error { return sleepFor(ctx, d) }
	cfResetRE = regexp.MustCompile(`(?:^|[;,\s])t=(\d+)`)
	cfLeftRE  = regexp.MustCompile(`(?:^|[;,\s])r=(\d+)`)
	limitRE   = regexp.MustCompile(`(?i)rate limit|abuse detection`)
)

func sleepFor(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// pacer holds the time before which no request is sent: a response that
// said the budget is spent sets it to the reset.
type pacer struct {
	mu    sync.Mutex
	until time.Time
}

func (p *pacer) wait(ctx context.Context) error {
	p.mu.Lock()
	d := p.until.Sub(clock())
	p.mu.Unlock()
	if d <= 0 {
		return nil
	}
	if d > rateWaitCap {
		return fmt.Errorf("API rate limit exceeded: it resets at %s, past the %s a capture waits", p.until.UTC().Format(time.RFC3339), rateWaitCap)
	}
	return sleepCtx(ctx, d)
}

func (p *pacer) hold(until time.Time) {
	p.mu.Lock()
	if until.After(p.until) {
		p.until = until
	}
	p.mu.Unlock()
}

// limited reports a response that is a rate limit, and how long the
// provider asks to wait (0: not said).
func limited(resp *http.Response, body []byte) (bool, time.Duration) {
	wait := retryAfter(resp)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
	case resp.StatusCode == http.StatusForbidden && (resp.Header.Get("x-ratelimit-remaining") == "0" || wait > 0 || limitRE.Match(body)):
	default:
		return false, 0
	}
	if wait == 0 {
		wait = untilReset(resp)
	}
	return true, wait
}

// retryAfter reads Retry-After, in seconds or as an HTTP date.
func retryAfter(resp *http.Response) time.Duration {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(clock()), 0)
	}
	return 0
}

// untilReset is how long until the budget refills, when a response says
// it is spent: GitHub's x-ratelimit-reset (epoch seconds), or
// Cloudflare's Ratelimit t= (seconds).
func untilReset(resp *http.Response) time.Duration {
	if resp.Header.Get("x-ratelimit-remaining") == "0" {
		if s, err := strconv.ParseInt(resp.Header.Get("x-ratelimit-reset"), 10, 64); err == nil {
			return max(time.Unix(s, 0).Sub(clock())+time.Second, 0)
		}
	}
	rl := resp.Header.Get("Ratelimit")
	if m := cfLeftRE.FindStringSubmatch(rl); m != nil && m[1] == "0" {
		if t := cfResetRE.FindStringSubmatch(rl); t != nil {
			s, _ := strconv.Atoi(t[1])
			return time.Duration(s+1) * time.Second
		}
	}
	return 0
}
