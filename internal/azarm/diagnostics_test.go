package azarm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

// sdkLists answers lists through the SDK, as Azure does, and everything else
// from the fake.
type sdkLists struct {
	*Fake
	sdk *SDK
}

func (s sdkLists) List(ctx context.Context, path, version string) ([]map[string]any, error) {
	return s.sdk.List(ctx, path, version)
}

// A real capture held no resource's diagnostic settings: an AKS cluster's
// audit log to an event hub was missing, and coverage said "complete". A
// resource's settings listed at 2016-09-01 answer 404 OperationNotFound,
// which read as "none here"; it refuses the version, and the next is tried.
func TestAResourcesDiagnosticSettingsAreReadAtAVersionItServes(t *testing.T) {
	reg := fixtures(t)
	cluster := id(srcSub, "shop-rg", "Microsoft.ContainerService/managedClusters", "aks")
	path := cluster + "/providers/" + diagnosticType
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("api-version")
		asked = append(asked, v)
		w.Header().Set("Content-Type", "application/json")
		if v == "2016-09-01" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":{"code":"OperationNotFound","message":"Path: '%s' is not supported"}}`, path)
			return
		}
		fmt.Fprintf(w, `{"value":[{"id":%q,"name":"to-security","properties":{"logs":[{"category":"kube-audit-admin","enabled":true}]}}]}`, path+"/to-security")
	}))
	defer srv.Close()
	fast := policy.RetryOptions{MaxRetries: -1}
	s := &SDK{sub: srcSub, pl: runtime.NewPipeline("x", "v0", runtime.PipelineOptions{}, &policy.ClientOptions{Retry: fast}), ep: srv.URL}

	if _, err := s.List(context.Background(), path, "2016-09-01"); !errors.Is(err, ErrAPIVersion) || errors.Is(err, ErrNotFound) {
		t.Fatalf("404 OperationNotFound: got %v, want a refused version", err)
	}
	asked = nil // what listOf asks, not the call above
	api := sdkLists{NewWorld(reg).Subscription(srcSub, srcTenant), s}
	v := &versions{api: api, reg: reg, ctx: context.Background(), cache: map[string]map[string][]string{}}
	got := listOf(context.Background(), api, v, srcTenant, diagnosticType, path, nil)
	if len(got) != 1 || got[0].c == nil || !strings.HasSuffix(got[0].name, "/to-security") {
		t.Errorf("got %+v (versions asked %v), want the cluster's setting", got, asked)
	}
	if len(asked) != 2 || asked[0] != "2016-09-01" {
		t.Errorf("listOf asked %v, want 2016-09-01 refused, then the next", asked)
	}
}
