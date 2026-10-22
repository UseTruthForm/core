package gcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stackdna/core/internal/readonly"
)

// The GCP client behind the guard: GET reaches the server, a create does not.
func TestReadOnlyGCP(t *testing.T) {
	var mu sync.Mutex
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method)
		mu.Unlock()
		w.Write([]byte(`{"name":"projects/p/serviceAccounts/x"}`))
	}))
	defer srv.Close()
	s := &SDK{project: "p", hc: readonly.Client()}
	if _, err := s.Call(context.Background(), "GET", srv.URL+"/v1/projects/p/serviceAccounts/x", nil); err != nil {
		t.Fatalf("get: %v", err)
	}
	_, err := s.Call(context.Background(), "POST", srv.URL+"/v1/projects/p/serviceAccounts", map[string]any{"accountId": "x"})
	if err == nil || !strings.Contains(err.Error(), "read-only guard") {
		t.Fatalf("create not refused: %v", err)
	}
	if strings.Join(methods, ",") != "GET" {
		t.Fatalf("server saw %v; only the GET may arrive", methods)
	}
}
