package readonly

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAllowed(t *testing.T) {
	req := func(method, url string, header ...string) *http.Request {
		r, _ := http.NewRequest(method, url, nil)
		for i := 0; i+1 < len(header); i += 2 {
			r.Header.Set(header[i], header[i+1])
		}
		return r
	}
	for _, c := range []struct {
		r    *http.Request
		want bool
	}{
		{req("GET", "https://management.azure.com/subscriptions/x/resources"), true},
		{req("HEAD", "https://example.com/"), true},
		{req("PUT", "https://management.azure.com/subscriptions/x/resourceGroups/rg"), false},
		{req("DELETE", "https://management.azure.com/subscriptions/x/resourceGroups/rg"), false},
		{req("PATCH", "https://kube.example/api/v1/namespaces/shop"), false},
		{req("POST", "https://iam.googleapis.com/v1/projects/p/serviceAccounts"), false},
		// Cloud Control: every call is POST /; the operation decides.
		{req("POST", "https://cloudcontrolapi.us-east-2.amazonaws.com/", "X-Amz-Target", "CloudApiService.ListResources"), true},
		{req("POST", "https://cloudcontrolapi.us-east-2.amazonaws.com/", "X-Amz-Target", "CloudApiService.GetResource"), true},
		{req("POST", "https://cloudcontrolapi.us-east-2.amazonaws.com/", "X-Amz-Target", "CloudApiService.CreateResource"), false},
		{req("POST", "https://cloudcontrolapi.us-east-2.amazonaws.com/", "X-Amz-Target", "CloudApiService.DeleteResource"), false},
		// Credential exchanges change no resource.
		{req("POST", "https://sts.us-east-1.amazonaws.com/"), true},
		{req("POST", "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"), true},
		{req("POST", "https://oauth2.googleapis.com/token"), true},
		{req("PUT", "http://169.254.169.254/latest/api/token"), true},
		{req("PUT", "http://169.254.169.254/latest/meta-data/x"), false},
	} {
		if got, why := Allowed(c.r); got != c.want {
			t.Errorf("%s %s %v: allowed=%v want %v (%s)", c.r.Method, c.r.URL, c.r.Header, got, c.want, why)
		}
	}
}

// A refused request never reaches the server, and the error says why.
func TestRefusedBeforeSending(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	c := Client()
	if _, err := c.Get(srv.URL + "/read"); err != nil {
		t.Fatal(err)
	}
	_, err := c.Post(srv.URL+"/write", "application/json", strings.NewReader("{}"))
	if !errors.Is(err, ErrWrite) || !strings.Contains(err.Error(), "read-only guard") {
		t.Fatalf("POST not refused: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("server saw %d requests, want 1 (the GET)", hits.Load())
	}
}
