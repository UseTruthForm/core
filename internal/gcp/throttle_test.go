package gcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/usetruthform/core/internal/snapshot"
)

// stepServer answers each request with the next step, then 200.
func stepServer(t *testing.T, steps ...func(w http.ResponseWriter)) (s *SDK, url string, calls *int) {
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		i := n
		n++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if i < len(steps) {
			steps[i](w)
			return
		}
		w.Write([]byte(`{"name":"x"}`))
	}))
	t.Cleanup(srv.Close)
	return &SDK{project: "p", hc: srv.Client()}, srv.URL + "/v1/x", &n
}

func answer(status int, body string, headers ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}
}

func recordWaits(t *testing.T) *[]time.Duration {
	var waits []time.Duration
	oldSleep, oldJitter := sleepCtx, jitter
	t.Cleanup(func() { sleepCtx, jitter = oldSleep, oldJitter })
	sleepCtx = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	jitter = func() time.Duration { return 0 }
	return &waits
}

const (
	exhausted = `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"Quota exceeded for quota metric 'Read requests' and limit 'Read requests per minute'","details":[{"reason":"RATE_LIMIT_EXCEEDED"}]}}`
	computeRL = `{"error":{"code":403,"message":"Rate Limit Exceeded","errors":[{"reason":"rateLimitExceeded","domain":"usageLimits"}]}}`
	denied    = `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Permission denied on resource"}}`
	perDay    = `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"Quota exceeded for quota metric 'Queries' and limit 'Queries per day'"}}`
)

// Google's documented throttling is waited out with truncated exponential
// backoff and sent again; a refusal, a spent daily quota and a write that
// may have started are not.
func TestThrottlingIsBackedOffAsGoogleAsks(t *testing.T) {
	type step = func(w http.ResponseWriter)
	for name, c := range map[string]struct {
		method string
		steps  []step
		calls  int
		waits  []time.Duration
	}{
		"429 twice":               {"GET", []step{answer(429, exhausted), answer(429, exhausted)}, 3, []time.Duration{time.Second, 2 * time.Second}},
		"compute 403 rate limit":  {"GET", []step{answer(403, computeRL)}, 2, []time.Duration{time.Second}},
		"retry-after":             {"GET", []step{answer(429, exhausted, "Retry-After", "7")}, 2, []time.Duration{7 * time.Second}},
		"503 read":                {"GET", []step{answer(503, `{}`)}, 2, []time.Duration{time.Second}},
		"429 write":               {"POST", []step{answer(429, exhausted)}, 2, []time.Duration{time.Second}},
		"503 write: not resent":   {"POST", []step{answer(503, `{}`)}, 1, nil},
		"permission: not resent":  {"GET", []step{answer(403, denied)}, 1, nil},
		"daily quota: not resent": {"GET", []step{answer(429, perDay)}, 1, nil},
		// A name is not a quota (review of #38).
		"429 naming daily-backups": {"GET", []step{answer(429, `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","message":"rate limit on bucket daily-backups"}}`)}, 2, []time.Duration{time.Second}},
		// Server errors: a read is sent again, a write is not (review of #38).
		"500 read":              {"GET", []step{answer(500, `{}`)}, 2, []time.Duration{time.Second}},
		"502 read":              {"GET", []step{answer(502, `{}`)}, 2, []time.Duration{time.Second}},
		"500 write: not resent": {"PATCH", []step{answer(500, `{}`)}, 1, nil},
	} {
		t.Run(name, func(t *testing.T) {
			waits := recordWaits(t)
			s, u, n := stepServer(t, c.steps...)
			var body any
			if c.method != http.MethodGet {
				body = map[string]any{"a": 1}
			}
			var out map[string]any
			err := s.do(context.Background(), c.method, u, body, &out)
			if *n != c.calls || !reflect.DeepEqual(*waits, c.waits) {
				t.Errorf("%d calls, waits %v; want %d calls, waits %v (err %v)", *n, *waits, c.calls, c.waits, err)
			}
			if (c.calls == 1) != (err != nil) {
				t.Errorf("err %v", err)
			}
		})
	}
}

// Throttled every time, the waits double up to 64 seconds, and the last
// error names the rate limit, so it reads as throttled, not denied; a
// daily quota reads as a failure, since a rerun soon will not help.
func TestThrottlingThatDoesNotClear(t *testing.T) {
	waits := recordWaits(t)
	var steps []func(http.ResponseWriter)
	for range maxAttempts {
		steps = append(steps, answer(403, computeRL))
	}
	s, u, n := stepServer(t, steps...)
	err := s.do(context.Background(), http.MethodGet, u, nil, nil)
	want := []time.Duration{1, 2, 4, 8, 16, 32, 64}
	for i := range want {
		want[i] *= time.Second
	}
	if *n != maxAttempts || !reflect.DeepEqual(*waits, want) {
		t.Errorf("%d calls, waits %v; want %d calls, waits %v", *n, *waits, maxAttempts, want)
	}
	if err == nil || !snapshot.Throttled(err.Error()) {
		t.Errorf("last error %v must read as throttled", err)
	}
	s, u, _ = stepServer(t, answer(429, perDay))
	if err := s.do(context.Background(), http.MethodGet, u, nil, nil); err == nil || snapshot.Throttled(err.Error()) {
		t.Errorf("a daily quota: %v must read as a failure", err)
	}
}

// Cancelled while waiting, the error says so (review of #38).
func TestCancelledWhileBackingOff(t *testing.T) {
	old := sleepCtx
	t.Cleanup(func() { sleepCtx = old })
	sleepCtx = func(context.Context, time.Duration) error { return context.Canceled }
	s, u, _ := stepServer(t, answer(429, exhausted))
	if err := s.do(context.Background(), http.MethodGet, u, nil, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err %v must be a cancellation", err)
	}
}
