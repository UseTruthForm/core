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
