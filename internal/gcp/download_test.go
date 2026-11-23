package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A document missing from Google's directory is read from the service's
// own endpoint (Artifact Registry's directory entry answers 404); any other
// failure stops there.
func TestDocsFallBackToTheServiceEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory":
			http.NotFound(w, r)
		case "/service":
			w.Write([]byte(`{"name":"artifactregistry","version":"v1","rootUrl":"https://artifactregistry.googleapis.com/","servicePath":"","resources":{},"schemas":{}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	old := docURLs
	defer func() { docURLs = old }()
	docURLs = func(api, ver string) []string { return []string{srv.URL + "/directory", srv.URL + "/service"} }
	d, err := FetchDocs(t.TempDir(), time.Hour).DocFor("artifactregistry", "v1")
	if err != nil || d.Name != "artifactregistry" {
		t.Fatalf("fallback: %v %v", d, err)
	}
	docURLs = func(api, ver string) []string { return []string{srv.URL + "/broken", srv.URL + "/service"} }
	if _, err := FetchDocs(t.TempDir(), time.Hour).DocFor("artifactregistry", "v1"); err == nil {
		t.Error("a server error was passed over to the next endpoint")
	}
	if got := old("artifactregistry", "v1"); len(got) != 2 || got[1] != "https://artifactregistry.googleapis.com/$discovery/rest?version=v1" {
		t.Errorf("urls: %v", got)
	}
	if got := old("evil.example.com/x", "v1"); len(got) != 1 {
		t.Errorf("a name that is not an API made a host: %v", got)
	}
}
