package azarm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/stackdna/core/internal/snapshot"
)

// Failures from the review of #9 and #10, 2026-10-22.

func obj(kind, ns, name, id string, spec map[string]any) snapshot.Object {
	meta := map[string]any{"name": name, "annotations": map[string]any{annID: id, annAPIVersion: "2022-01-01"}}
	if ns != "" {
		meta["namespace"] = ns
	}
	return snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": kind, "metadata": meta, "spec": spec}}
}

func position(order []snapshot.Object, kind string) int {
	for i, o := range order {
		if o.Kind() == kind {
			return i
		}
	}
	return -1
}

// A ReadOnly lock restored before the resources it covers refuses every
// later PUT in its scope; locks go last.
func TestLocksAreRestoredLast(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	order, cyclic := restoreOrder([]snapshot.Object{
		obj(groupType, "", "rg", sub+"/resourceGroups/rg", map[string]any{"location": "eastus"}),
		obj("Microsoft.Authorization/locks", "rg", "freeze", sub+"/resourceGroups/rg/providers/Microsoft.Authorization/locks/freeze", map[string]any{"properties": map[string]any{"level": "ReadOnly"}}),
		obj("Microsoft.Compute/disks", "rg", "d1", sub+"/resourceGroups/rg/providers/Microsoft.Compute/disks/d1", map[string]any{"location": "eastus"}),
		obj("Microsoft.Network/virtualNetworks", "rg", "v1", sub+"/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v1", map[string]any{"location": "eastus"}),
	})
	if len(cyclic) > 0 || position(order, "Microsoft.Authorization/locks") != len(order)-1 {
		t.Errorf("lock not last: %v", kinds(order))
	}
}

// A subscription-level role assignment names its custom role by an ID
// outside any resource group; the role still comes first.
func TestRoleDefinitionBeforeItsAssignment(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	def := sub + "/providers/Microsoft.Authorization/roleDefinitions/" + customRoleID
	order, _ := restoreOrder([]snapshot.Object{
		obj("Microsoft.Authorization/roleAssignments", "", "providers/Microsoft.Authorization/roleAssignments/"+assignmentID,
			sub+"/providers/Microsoft.Authorization/roleAssignments/"+assignmentID, map[string]any{"properties": map[string]any{"roleDefinitionId": def}}),
		obj("Microsoft.Authorization/roleDefinitions", "", "providers/Microsoft.Authorization/roleDefinitions/"+customRoleID, def, map[string]any{"properties": map[string]any{"roleName": "shop"}}),
	})
	if position(order, "Microsoft.Authorization/roleDefinitions") > position(order, "Microsoft.Authorization/roleAssignments") {
		t.Errorf("assignment before its role: %v", kinds(order))
	}
}

func kinds(os []snapshot.Object) []string {
	var out []string
	for _, o := range os {
		out = append(out, o.Kind())
	}
	return out
}

// A VM using an identity carries the identity's principal under a map key
// path no restore can resolve; the identity's own path must own it, in any
// list order.
func TestPrincipalOwnedByTheIdentity(t *testing.T) {
	const g = "11112222-3333-4444-8555-666677778888"
	mk := func(typ, name string, status, spec map[string]any) *captured {
		return &captured{rid: ResourceID{Subscription: "s", ResourceGroup: "rg", Type: typ, Name: name}, status: status, spec: spec}
	}
	for _, flip := range []bool{false, true} {
		vm := mk("Microsoft.Compute/virtualMachines", "vm1", map[string]any{"identity.userAssignedIdentities.*.principalId": g}, map[string]any{})
		id := mk("Microsoft.ManagedIdentity/userAssignedIdentities", "id1", map[string]any{"properties.principalId": g}, map[string]any{})
		ra := mk("Microsoft.Authorization/roleAssignments", "ra", map[string]any{}, map[string]any{"properties": map[string]any{"principalId": g}})
		cs := []*captured{vm, id, ra}
		if flip {
			cs = []*captured{id, vm, ra}
		}
		principalRefs(cs)
		want := refToken(id, "properties.principalId")
		if got := ra.spec["properties"].(map[string]any)["principalId"]; got != want {
			t.Errorf("flip=%v: principal %v, want %v", flip, got, want)
		}
	}
}

// Only what ARM says is "none here" is: a refused list or a wrong API
// version is a failure, not an empty result.
func TestClassifyARM(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
		want   error
	}{
		{http.StatusBadRequest, "ResourceTypeNotSupported", ErrNotApplicable},
		{http.StatusBadRequest, "FeatureDisabledOnSelectedEdition", ErrNotApplicable},
		{http.StatusBadRequest, "BMSUserErrorFeatureNotAvailable", ErrNotApplicable},
		{http.StatusBadRequest, "KindNotSpecified", nil},
		{http.StatusMethodNotAllowed, "", ErrNotApplicable},
		{http.StatusNotFound, "ResourceNotFound", ErrNotFound},
		{http.StatusNotFound, "", ErrNotFound},
		{http.StatusBadRequest, "InvalidApiVersionParameter", nil},
		{http.StatusNotFound, "InvalidResourceType", nil},
		{http.StatusBadRequest, "", nil},
	} {
		if got := classifyARM(c.status, c.code); !errors.Is(got, c.want) || (c.want == nil && got != nil) {
			t.Errorf("%d %s: got %v, want %v", c.status, c.code, got, c.want)
		}
	}
}

// A refusal is one line, with no per-request ID in it: it is written into
// coverage, and an ID made two captures of an unchanged subscription
// differ. The SDK's error stays reachable underneath.
func TestARMErrorIsOneStableLine(t *testing.T) {
	for _, c := range []struct{ msg, want string }{
		{"Must specify a valid kind filter. Operation Id: 'a93efd0df1b36819d71b12b24e5b56b4'", "Must specify a valid kind filter."},
		{"The feature is not available here. (Request ID: 0f8fad5b-d9cb-469f-a165-70867728950e)", "The feature is not available here."},
		{"Something failed. Tracking ID: 6d1f9a0e-1b2c-4d5e-8f90-123456789abc Timestamp: 2026-10-21T08:15:00Z", "Something failed."},
		{"Plain message with no ID.", "Plain message with no ID."},
	} {
		body := `{"error":{"code":"SomeCode","message":` + strconv.Quote(c.msg) + `}}`
		resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(body)), Request: httptest.NewRequest(http.MethodGet, "https://management.example/x?api-version=1", nil)}
		sdkErr := runtime.NewResponseError(resp)
		e := &armError{url: "https://management.example/x?api-version=1", status: resp.StatusCode, code: "SomeCode", msg: armMessage(resp), err: sdkErr}
		if want := "GET https://management.example/x?api-version=1: 400 SomeCode: " + c.want; e.Error() != want {
			t.Errorf("got  %q\nwant %q", e.Error(), want)
		}
		var re *azcore.ResponseError
		if !errors.As(fmt.Errorf("wrapped: %w", e), &re) || re.ErrorCode != "SomeCode" {
			t.Errorf("SDK error not reachable under %q", e)
		}
	}
}

// A resource that is both a root and another root's child has its children
// listed once: listed twice, each failure among them was reported twice.
func TestChildrenOfARootAreListedOnce(t *testing.T) {
	e := newEnv(t)
	e.src.AlsoTracked = map[string]bool{"Microsoft.Storage/storageAccounts/blobServices": true}
	e.src.RefuseVersion = func(path, _ string) bool { return strings.HasSuffix(strings.ToLower(path), "/containers") }
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range snap.Skips {
		if strings.HasSuffix(s.Resource, "/containers") && strings.HasPrefix(s.Reason, Unreadable) {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the refused container list was reported %d times, want 1: %+v", n, snap.Skips)
	}
}

// A secret inside an array counts when the array is there.
func TestSecretsInArrays(t *testing.T) {
	paths := []string{"properties.sslCertificates[].properties.password"}
	with := map[string]any{"properties": map[string]any{"sslCertificates": []any{map[string]any{"name": "c"}}}}
	if got := relevantSecrets(with, paths); len(got) != 1 {
		t.Errorf("array secret not annotated: %v", got)
	}
	if got := relevantSecrets(map[string]any{"properties": map[string]any{}}, paths); len(got) != 0 {
		t.Errorf("absent array annotated: %v", got)
	}
}

// With the identity not captured, a map-key path still never owns the
// principal: the assignment keeps the literal, not a token for
// identity.userAssignedIdentities.*.principalId that cannot be resolved.
func TestMapKeyPathNeverOwnsAPrincipal(t *testing.T) {
	const g = "11112222-3333-4444-8555-666677778888"
	vm := &captured{rid: ResourceID{Subscription: "s", ResourceGroup: "rg", Type: "Microsoft.Compute/virtualMachines", Name: "vm1"},
		status: map[string]any{"identity.userAssignedIdentities.*.principalId": g}, spec: map[string]any{}}
	ra := &captured{rid: ResourceID{Subscription: "s", ResourceGroup: "rg", Type: "Microsoft.Authorization/roleAssignments", Name: "ra"},
		status: map[string]any{}, spec: map[string]any{"properties": map[string]any{"principalId": g}}}
	principalRefs([]*captured{vm, ra})
	if got := ra.spec["properties"].(map[string]any)["principalId"]; got != g {
		t.Errorf("principal became %v", got)
	}
}

// The subscription's own diagnostic settings refuse the newest stable API
// version ("Invalid api-version query string value") and answer previews.
// That refusal read as "none here", so they were never captured; the list
// now falls back through the defined versions and records the one that
// answered, which restore then uses.
func TestListFallsBackThroughVersions(t *testing.T) {
	e := newEnv(t)
	storage := id(srcSub, "shop-rg", "Microsoft.Storage/storageAccounts", "shopassets01")
	subDiag := "/subscriptions/" + srcSub + "/providers/Microsoft.Insights/diagnosticSettings/to-storage-sub"
	if _, err := e.src.Put(context.Background(), subDiag, "2021-05-01-preview", map[string]any{
		"properties": map[string]any{"storageAccountId": storage, "logs": []any{map[string]any{"category": "Administrative", "enabled": true}}}}); err != nil {
		t.Fatal(err)
	}
	refuse := func(path, version string) bool {
		return strings.HasSuffix(strings.ToLower(path), "/subscriptions/"+srcSub+"/providers/microsoft.insights/diagnosticsettings") && version == "2016-09-01" ||
			strings.HasSuffix(strings.ToLower(path), "/subscriptions/"+dstSub+"/providers/microsoft.insights/diagnosticsettings") && version == "2016-09-01"
	}
	e.src.RefuseVersion, e.dst.RefuseVersion = refuse, refuse
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range snap.Objects {
		if strings.HasSuffix(o.Name(), "/to-storage-sub") {
			found = o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annAPIVersion] == "2021-05-01-preview"
		}
	}
	if !found {
		t.Fatal("the subscription's diagnostic setting was not captured at the version that answered")
	}
	for _, c := range snap.Coverage {
		if c.NotCaptured != "" && strings.Contains(c.NotCaptured, "api-version") {
			t.Errorf("coverage: %+v", c)
		}
	}
	for _, r := range e.adapter(e.dst).Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	got, err := e.adapter(e.dst).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snapshot.Compare(snap, got) {
		t.Errorf("target differs: %+v", c)
	}
}
