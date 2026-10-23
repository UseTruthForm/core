package azarm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/stackdna/core/internal/readonly"
)

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
	_, err := s.Put(context.Background(), id, "2024-11-01", map[string]any{"location": "eastus"})
	if err == nil || !strings.Contains(err.Error(), "read-only guard") {
		t.Fatalf("put not refused: %v", err)
	}
	if strings.Join(methods, ",") != "GET" {
		t.Fatalf("server saw %v; only the GET may arrive", methods)
	}
}
