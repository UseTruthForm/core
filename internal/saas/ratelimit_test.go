package saas

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackdna/core/internal/snapshot"
)

// rateServer answers with each step in turn, and records when (on the
// fake clock) each request arrived.
type rateServer struct {
	mu    sync.Mutex
	steps []func(w http.ResponseWriter)
	at    []time.Duration
}

func fakeTime(t *testing.T) (elapsed func() time.Duration, slept *[]time.Duration) {
	base := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	var now time.Duration
	var waits []time.Duration
	oldClock, oldSleep := clock, sleepCtx
	t.Cleanup(func() { clock, sleepCtx = oldClock, oldSleep })
	clock = func() time.Time { mu.Lock(); defer mu.Unlock(); return base.Add(now) }
	sleepCtx = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		waits = append(waits, d)
		now += d
		return nil
	}
	return func() time.Duration { mu.Lock(); defer mu.Unlock(); return now }, &waits
}

func rateClient(t *testing.T, elapsed func() time.Duration, steps ...func(w http.ResponseWriter)) (*Client, *rateServer) {
	rs := &rateServer{steps: steps}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		i := len(rs.at)
		rs.at = append(rs.at, elapsed())
		rs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if i < len(rs.steps) {
			rs.steps[i](w)
			return
		}
		w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)
	return &Client{P: Provider{Base: srv.URL}, HTTP: srv.Client(), pace: &pacer{}}, rs
}

func ok(w http.ResponseWriter) { w.Write([]byte(`[{"id":1}]`)) }

func refuse(status int, body string, headers ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}
}

// Each provider's documented answer is waited out as it asks, and the
// read sent again.
func TestRateLimitsAreWaitedOut(t *testing.T) {
	for name, c := range map[string]struct {
		step func(w http.ResponseWriter)
		want time.Duration
	}{
		// GitHub, secondary limit: retry-after.
		"github secondary": {refuse(403, `{"message":"You have exceeded a secondary rate limit."}`, "retry-after", "30"), 30 * time.Second},
		// GitHub, primary limit: remaining 0, wait for the reset (+1s).
		"github primary": {refuse(403, `{"message":"API rate limit exceeded for user."}`, "x-ratelimit-remaining", "0", "x-ratelimit-reset", "1800000120"), 121 * time.Second},
		// No hint: at least a minute.
		"no hint": {refuse(429, `{"message":"slow down"}`), time.Minute},
		// Cloudflare: 429 with retry-after.
		"cloudflare": {refuse(429, `{"success":false,"errors":[{"code":10000,"message":"Rate limited"}]}`, "retry-after", "45"), 45 * time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			elapsed, slept := fakeTime(t)
			cl, rs := rateClient(t, elapsed, c.step, ok)
			if _, _, err := cl.do(context.Background(), "GET", "/x", nil); err != nil {
				t.Fatal(err)
			}
			if len(rs.at) != 2 || len(*slept) != 1 || (*slept)[0] != c.want {
				t.Errorf("requests at %v, waits %v; want one wait of %s", rs.at, *slept, c.want)
			}
		})
	}
}

// A response that says the budget is spent holds the next request until
// the reset, before Cloudflare refuses (and locks the account out for 5
// minutes) or GitHub does.
func TestSpentBudgetPacesTheNextRequest(t *testing.T) {
	elapsed, _ := fakeTime(t)
	spent := func(w http.ResponseWriter) {
		w.Header().Set("Ratelimit", `"default";r=0;t=40`)
		ok(w)
	}
	cl, rs := rateClient(t, elapsed, spent, ok)
	for range 2 {
		if _, _, err := cl.do(context.Background(), "GET", "/x", nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(rs.at) != 2 || rs.at[1] < 41*time.Second {
		t.Errorf("requests at %v: the second must wait for the reset", rs.at)
	}
}

// A limit that resets later than a capture waits (GitHub's hourly one) is
// reported at once, saying when, and reads as throttled; a write is never
// sent twice; a refusal that is not a limit is not retried.
func TestRateLimitsThatCannotBeWaitedOut(t *testing.T) {
	elapsed, slept := fakeTime(t)
	hour := refuse(403, `{"message":"API rate limit exceeded for user."}`, "x-ratelimit-remaining", "0", "x-ratelimit-reset", fmt.Sprint(1_800_000_000+3600))
	cl, rs := rateClient(t, elapsed, hour)
	_, _, err := cl.do(context.Background(), "GET", "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "resets in") || !snapshot.Throttled(err.Error()) || len(rs.at) != 1 || len(*slept) != 0 {
		t.Errorf("hour-long limit: %v after %d requests, waits %v", err, len(rs.at), *slept)
	}
	cl, rs = rateClient(t, elapsed, refuse(429, `{}`), ok)
	if _, _, err := cl.do(context.Background(), "POST", "/x", map[string]any{"a": 1}); err == nil || len(rs.at) != 1 {
		t.Errorf("a refused write: %v after %d requests", err, len(rs.at))
	}
	cl, rs = rateClient(t, elapsed, refuse(403, `{"message":"Resource not accessible by integration"}`), ok)
	if _, _, err := cl.do(context.Background(), "GET", "/x", nil); err == nil || len(rs.at) != 1 {
		t.Errorf("a refusal: %v after %d requests", err, len(rs.at))
	}
	waits := len(*slept)
	cl, rs = rateClient(t, elapsed, refuse(429, `{}`), refuse(429, `{}`), refuse(429, `{}`), refuse(429, `{}`), refuse(429, `{}`))
	if _, _, err := cl.do(context.Background(), "GET", "/x", nil); err == nil || len(rs.at) != rateTries || !snapshot.Throttled(err.Error()) {
		t.Errorf("throttled every time: %v after %d requests", err, len(rs.at))
	}
	if got := (*slept)[waits:]; len(got) != rateTries-1 || got[0] != time.Minute || got[1] != 2*time.Minute {
		t.Errorf("waits %v: a minute, then longer", got)
	}
}
