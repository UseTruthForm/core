package azarm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/stackdna/core/internal/readonly"
)

// A list filtered by kind keeps its filter and gets the API version after
// it, on every page; an unfiltered one that needs a kind says so (review
// of #34).
func TestListByKindOverHTTP(t *testing.T) {
	var mu sync.Mutex
	var queries []url.Values
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Query().Get("$filter") == "":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":{"code":"KindNotSpecified","message":"Must specify a valid kind filter."}}`))
		case r.URL.Query().Get("page") == "":
			w.Write([]byte(`{"value":[{"id":"/x/dataSources/a","kind":"WindowsEvent"}],"nextLink":"` + srv.URL + r.URL.Path + "?" + r.URL.RawQuery + `&page=2"}`))
		default:
			w.Write([]byte(`{"value":[{"id":"/x/dataSources/b","kind":"WindowsEvent"}]}`))
		}
	}))
	defer srv.Close()
	pl := runtime.NewPipeline("stackdna", "v0.1.0", runtime.PipelineOptions{}, &policy.ClientOptions{Transport: readonly.Client()})
	s := &SDK{sub: "s", pl: pl, ep: srv.URL}
	if _, err := s.List(context.Background(), "/x/dataSources", "2025-07-01"); !errors.Is(err, ErrNeedsKind) {
		t.Fatalf("unfiltered list: %v", err)
	}
	items, err := s.List(context.Background(), "/x/dataSources?$filter=kind%20eq%20%27WindowsEvent%27", "2025-07-01")
	if err != nil || len(items) != 2 {
		t.Fatalf("filtered list: %v, %v", items, err)
	}
	for _, q := range queries[1:] {
		if q.Get("$filter") != "kind eq 'WindowsEvent'" || q.Get("api-version") != "2025-07-01" {
			t.Errorf("query %v", q)
		}
	}
}

// The retry policy honours a Retry-After the SDK's default 60-second cap
// would have refused, and keeps the SDK's own count and pace otherwise,
// so a server error costs what it did (review of #36).
func TestClientOptionsWaitOutThrottling(t *testing.T) {
	o := clientOptions(true)
	if o.Retry.MaxRetries != 0 || o.Retry.RetryDelay != 0 || o.Retry.MaxRetryDelay < 2*time.Minute || o.Transport == nil {
		t.Errorf("client options %+v", o.Retry)
	}
	if clientOptions(false).Transport != nil {
		t.Error("a restore client must not sit behind the read-only guard")
	}
}

// A read still throttled after the SDK's retries is read again after a
// pause, and given up only after the last; any other failure is not
// retried here.
func TestThrottledReadsAreReadAgain(t *testing.T) {
	defer func(w []time.Duration) { patientWaits = w }(patientWaits)
	patientWaits = []time.Duration{time.Millisecond, time.Millisecond}
	serve := func(status func(n int) int) (*SDK, *int, func()) {
		var mu sync.Mutex
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n++
			s := status(n)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s)
			if s == http.StatusOK {
				w.Write([]byte(`{"name":"q"}`))
				return
			}
			w.Write([]byte(`{"error":{"code":"Throttled","message":"slow down"}}`))
		}))
		// No SDK retries here: only the layer under test retries.
		pl := runtime.NewPipeline("stackdna", "v0.1.0", runtime.PipelineOptions{}, &policy.ClientOptions{Transport: readonly.Client(), Retry: policy.RetryOptions{MaxRetries: -1}})
		return &SDK{sub: "s", pl: pl, ep: srv.URL}, &n, srv.Close
	}
	s, n, done := serve(func(n int) int {
		if n < 3 {
			return http.StatusTooManyRequests
		}
		return http.StatusOK
	})
	if _, err := s.Get(context.Background(), "/x/queues/q", "1"); err != nil || *n != 3 {
		t.Errorf("throttled twice, then answered: %v after %d reads", err, *n)
	}
	done()
	s, n, done = serve(func(int) int { return http.StatusTooManyRequests })
	_, err := s.Get(context.Background(), "/x/queues/q", "1")
	var ae *armError
	if !errors.As(err, &ae) || ae.status != http.StatusTooManyRequests || *n != 1+len(patientWaits) {
		t.Errorf("throttled every time: %v after %d reads", err, *n)
	}
	done()
	s, n, done = serve(func(int) int { return http.StatusInternalServerError })
	if _, err := s.Get(context.Background(), "/x/queues/q", "1"); err == nil || *n != 1 {
		t.Errorf("a server error is the SDK's to retry, not this layer's: %v after %d reads", err, *n)
	}
	done()
}

// A read ARM throttles past the SDK's retries waits at least the
// Retry-After ARM gave before it is sent again (review of #36).
func TestPatienceHonoursRetryAfter(t *testing.T) {
	defer func(w []time.Duration) { patientWaits = w }(patientWaits)
	patientWaits = []time.Duration{time.Millisecond}
	var mu sync.Mutex
	var at []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		at = append(at, time.Now())
		first := len(at) == 1
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if first {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":{"code":"Throttled","message":"slow down"}}`))
			return
		}
		w.Write([]byte(`{"name":"q"}`))
	}))
	defer srv.Close()
	pl := runtime.NewPipeline("stackdna", "v0.1.0", runtime.PipelineOptions{}, &policy.ClientOptions{Transport: readonly.Client(), Retry: policy.RetryOptions{MaxRetries: -1}})
	s := &SDK{sub: "s", pl: pl, ep: srv.URL}
	if _, err := s.Get(context.Background(), "/x/queues/q", "1"); err != nil {
		t.Fatal(err)
	}
	if len(at) != 2 || at[1].Sub(at[0]) < 900*time.Millisecond {
		t.Errorf("reads at %v: the second must follow the Retry-After", at)
	}
}

// A write is sent again only for a 429, which ARM answers before it
// accepts anything; a server error can come after a create has started
// (review of #36).
func TestPutRetriesOnlyThrottling(t *testing.T) {
	for status, want := range map[int]int{http.StatusInternalServerError: 1, http.StatusTooManyRequests: 2} {
		var mu sync.Mutex
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			n++
			first := n == 1 && r.Method == http.MethodPut
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if first {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(status)
				w.Write([]byte(`{"error":{"code":"X","message":"x"}}`))
				return
			}
			w.Write([]byte(`{"name":"rg","properties":{"provisioningState":"Succeeded"}}`))
		}))
		pl := runtime.NewPipeline("stackdna", "v0.1.0", runtime.PipelineOptions{}, &clientOptions(false).ClientOptions)
		s := &SDK{sub: "s", pl: pl, ep: srv.URL}
		s.Put(context.Background(), "/subscriptions/s/resourceGroups/rg", "2024-11-01", map[string]any{"location": "eastus"})
		puts := 0
		mu.Lock()
		puts = min(n, 2)
		mu.Unlock()
		srv.Close()
		if status == http.StatusInternalServerError && n != 1 {
			t.Errorf("a 500 on a PUT was sent %d times", n)
		}
		if status == http.StatusTooManyRequests && puts != want {
			t.Errorf("a 429 on a PUT: %d requests", puts)
		}
	}
}

// With StackDNA's retry policy, the SDK waits the Retry-After ARM gives.
func TestRetryAfterIsHonoured(t *testing.T) {
	var mu sync.Mutex
	var at []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		at = append(at, time.Now())
		first := len(at) == 1
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if first {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"name":"q"}`))
	}))
	defer srv.Close()
	pl := runtime.NewPipeline("stackdna", "v0.1.0", runtime.PipelineOptions{}, &clientOptions(true).ClientOptions)
	s := &SDK{sub: "s", pl: pl, ep: srv.URL}
	if _, err := s.Get(context.Background(), "/x/queues/q", "1"); err != nil {
		t.Fatal(err)
	}
	if len(at) != 2 || at[1].Sub(at[0]) < 900*time.Millisecond {
		t.Errorf("reads at %v: the second must follow the Retry-After", at)
	}
}

// The ARM pipeline behind the guard: GET reaches the server, PUT does not.
func TestReadOnlyARM(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"rg","location":"eastus"}`))
	}))
	defer srv.Close()
	pl := runtime.NewPipeline("stackdna", "v0.1.0", runtime.PipelineOptions{}, &policy.ClientOptions{Transport: readonly.Client()})
	s := &SDK{sub: "s", pl: pl, ep: srv.URL}
	id := "/subscriptions/s/resourceGroups/rg"
	if _, err := s.Get(context.Background(), id, "2024-11-01"); err != nil {
		t.Fatalf("get: %v", err)
	}
	start := time.Now()
	_, err := s.Put(context.Background(), id, "2024-11-01", map[string]any{"location": "eastus"})
	if err == nil || !strings.Contains(err.Error(), "read-only guard") {
		t.Fatalf("put not refused: %v", err)
	}
	// Refused at once: the SDK used to retry the refusal for 8 seconds,
	// taking it for a network failure (review of #36).
	if d := time.Since(start); d > time.Second {
		t.Errorf("refusal took %s", d)
	}
	if strings.Join(methods, ",") != "GET" {
		t.Fatalf("server saw %v; only the GET may arrive", methods)
	}
}
