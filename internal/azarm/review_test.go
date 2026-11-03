package azarm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
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

// The all-zero GUID is ARM's "none", not a value one resource generated
// and another refers to: it stays as it is.
func TestNilGUIDIsNotAReference(t *testing.T) {
	const zero = "00000000-0000-0000-0000-000000000000"
	mk := func(typ, name string, status, spec map[string]any) *captured {
		return &captured{rid: ResourceID{Subscription: "s", ResourceGroup: "rg", Type: typ, Name: name}, status: status, spec: spec}
	}
	policy := mk("Microsoft.Authorization/policyAssignments", "p", map[string]any{"properties.instanceId": zero}, map[string]any{})
	sql := mk("Microsoft.Sql/servers", "srv", map[string]any{}, map[string]any{"properties": map[string]any{"storageAccountSubscriptionId": zero}})
	principalRefs([]*captured{policy, sql})
	if got := sql.spec["properties"].(map[string]any)["storageAccountSubscriptionId"]; got != zero {
		t.Errorf("storageAccountSubscriptionId became %v", got)
	}
}

// Only what ARM says is "none here" is: a refused list or a wrong API
// version is a failure, not an empty result.
func TestClassifyARM(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
		msg    string
		want   error
	}{
		{http.StatusBadRequest, "ResourceTypeNotSupported", "", ErrNotApplicable},
		{http.StatusBadRequest, "FeatureDisabledOnSelectedEdition", "", ErrNotApplicable},
		{http.StatusBadRequest, "BMSUserErrorFeatureNotAvailable", "", ErrNotApplicable},
		{http.StatusBadRequest, "KindNotSpecified", "", nil},
		{http.StatusNotImplemented, "DataSourceNotImplemented", "", ErrNotApplicable},
		{http.StatusNotImplemented, "", "", nil},
		{http.StatusMethodNotAllowed, "", "", ErrNotApplicable},
		{http.StatusNotFound, "ResourceNotFound", "", ErrNotFound},
		{http.StatusNotFound, "", "", ErrNotFound},
		{http.StatusBadRequest, "InvalidApiVersionParameter", "", nil},
		{http.StatusNotFound, "InvalidResourceType", "", nil},
		{http.StatusBadRequest, "", "", nil},
		// A preview child type the subscription has not registered.
		{http.StatusBadRequest, "BadRequest", "Agent fabric membership is not available in subscription s. Please register the Microsoft.ContainerService/EnableAgentFabricPreview feature.", ErrNotApplicable},
		{http.StatusBadRequest, "BadRequest", "Please register the Microsoft.ContainerService/AKS-GitOps feature.", ErrNotApplicable},
		// A bad request that only mentions a feature is still a failure, and
		// so is the same answer under another status.
		{http.StatusBadRequest, "BadRequest", "The feature flag in the request body is invalid.", nil},
		{http.StatusConflict, "Conflict", "Please register the Microsoft.ContainerService/EnableAgentFabricPreview feature.", nil},
		// An AI Services account's costControls, behind a feature the
		// subscription has not registered, answer 502 with a code that says so.
		{http.StatusBadGateway, "FeatureNotRegistered", "Subscription is not registered for feature 'Microsoft.CognitiveServices/CostControls'.", ErrNotApplicable},
		{http.StatusBadGateway, "", "", nil},
	} {
		if got := classifyARM(c.status, c.code, c.msg); !errors.Is(got, c.want) || (c.want == nil && got != nil) {
			t.Errorf("%d %s %q: got %v, want %v", c.status, c.code, c.msg, got, c.want)
		}
	}
}

// A refusal is one line, with no per-request ID in it: it is written into
// coverage, and an ID made two captures of an unchanged subscription
// differ. The SDK's error stays reachable underneath.
func TestARMErrorIsOneStableLine(t *testing.T) {
	msg := func(m string) string { return `{"error":{"code":"SomeCode","message":` + strconv.Quote(m) + `}}` }
	for _, c := range []struct{ body, code, want string }{
		{msg("Must specify a valid kind filter. Operation Id: 'a93efd0df1b36819d71b12b24e5b56b4'"), "SomeCode", "400 Bad Request SomeCode: Must specify a valid kind filter."},
		{msg("The feature is not available here. (Request ID: 0f8fad5b-d9cb-469f-a165-70867728950e)"), "SomeCode", "400 Bad Request SomeCode: The feature is not available here."},
		{msg("Something failed. Tracking ID: 6d1f9a0e-1b2c-4d5e-8f90-123456789abc Timestamp: 2026-10-21T08:15:00Z"), "SomeCode", "400 Bad Request SomeCode: Something failed."},
		// Azure also writes the time with a space, and a Trace ID (review of #32).
		{msg("Failed. Correlation ID: 6d1f9a0e-1b2c-4d5e-8f90-123456789abc Trace ID: 0f8fad5b-d9cb-469f-a165-70867728950e Timestamp: 2026-10-27 10:00:00Z"), "SomeCode", "400 Bad Request SomeCode: Failed."},
		// Words that only look like a label keep their content.
		{msg("Workload group 'request id deadbeefcafe' not supported"), "SomeCode", "400 Bad Request SomeCode: Workload group 'request id deadbeefcafe' not supported"},
		{msg("The request id abcdef12 is used."), "SomeCode", "400 Bad Request SomeCode: The request id abcdef12 is used."},
		// One line, whatever the message holds; a page that is not JSON
		// keeps its start; no code, no stray space.
		{msg("First line.\n  Second line."), "SomeCode", "400 Bad Request SomeCode: First line. Second line."},
		{"<html><body>Bad gateway</body></html>", "", "400 Bad Request: <html><body>Bad gateway</body></html>"},
	} {
		resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(c.body)), Request: httptest.NewRequest(http.MethodGet, "https://management.example/x?api-version=1", nil)}
		sdkErr := runtime.NewResponseError(resp)
		e := &armError{url: "https://management.example/x?api-version=1", status: resp.StatusCode, code: c.code, msg: armMessage(resp), err: sdkErr}
		if want := "GET https://management.example/x?api-version=1: " + c.want; e.Error() != want {
			t.Errorf("got  %q\nwant %q", e.Error(), want)
		}
		var re *azcore.ResponseError
		if !errors.As(fmt.Errorf("wrapped: %w", e), &re) {
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

// A workspace's data sources answer only a list filtered by kind. Each kind
// the definition names is listed, so they are captured, not reported as a
// failed collection.
func TestDataSourcesAreListedByKind(t *testing.T) {
	ds := schema(t, fixtures(t), "Microsoft.OperationalInsights/workspaces/dataSources")
	kinds := ds.kinds()
	if !contains(kinds, "WindowsEvent") || !contains(kinds, "LinuxSyslog") || contains(kinds, "") {
		t.Fatalf("kinds %v", kinds)
	}
	e := newEnv(t)
	e.src.ByKind = map[string]bool{"datasources": true}
	put(t, e.src, "shop-rg", "Microsoft.OperationalInsights/workspaces", "shop-logs", map[string]any{"location": "eastus", "properties": map[string]any{"retentionInDays": 30.0}})
	ws := id(srcSub, "shop-rg", "Microsoft.OperationalInsights/workspaces", "shop-logs")
	for name, body := range map[string]map[string]any{
		"app-events": {"kind": "WindowsEvent", "properties": map[string]any{"eventLogName": "Application"}},
		"syslog":     {"kind": "LinuxSyslog", "properties": map[string]any{"syslogName": "auth"}},
	} {
		if _, err := e.src.Put(context.Background(), ws+"/dataSources/"+name, stable(e.reg, "Microsoft.OperationalInsights/workspaces/dataSources"), body); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, o := range snap.Objects {
		if strings.EqualFold(o.Kind(), "Microsoft.OperationalInsights/workspaces/dataSources") {
			got = append(got, o.Name())
		}
	}
	sort.Strings(got)
	if want := []string{"shop-logs/app-events", "shop-logs/syslog"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("data sources captured %v, want %v", got, want)
	}
	for _, s := range snap.Skips {
		if strings.HasPrefix(s.Reason, Unreadable) {
			t.Errorf("failed: %s %s: %s", s.Resource, s.Name, s.Reason)
		}
	}
}

// byKindARM answers a list by kind as a real workspace does: some named
// kinds are refused, one filter returns another kind's items, and one
// kind's items get a new name on every read.
type byKindARM struct {
	ARM
	items   map[string][]map[string]any
	refuse  map[string]error
	fresh   map[string]int    // filter -> how many items it makes up per read
	freshAs map[string]string // filter -> the kind those items carry (another kind's, when aliased)
	lagged  map[string]int    // filter -> the read (1-based) that leaves its first item out
	reads   map[string]int
}

func (b byKindARM) List(_ context.Context, path, _ string) ([]map[string]any, error) {
	_, query, _ := strings.Cut(path, "?")
	q, _ := url.ParseQuery(query)
	m := kindFilterRE.FindStringSubmatch(q.Get("$filter"))
	if m == nil {
		return nil, ErrNeedsKind
	}
	k := m[1]
	if err := b.refuse[k]; err != nil {
		return nil, err
	}
	b.reads[k]++
	out := b.items[k]
	if n := b.lagged[k]; n == b.reads[k] && len(out) > 0 {
		out = out[1:]
	}
	as := k
	if b.freshAs[k] != "" {
		as = b.freshAs[k]
	}
	for i := range b.fresh[k] {
		out = append(out, item(fmt.Sprintf("/x/dataSources/DataSource_%s_%d_%d", k, b.reads[k], i), as))
	}
	return out, nil
}

func TestListByKindKeepsOnlyWhatIsThereEveryRead(t *testing.T) {
	reg := item("/x/dataSources/reg1", "ChangeTrackingDefaultRegistry")
	api := byKindARM{
		items: map[string][]map[string]any{
			"ChangeTrackingDefaultRegistry": {reg},
			"ChangeTrackingRegistry":        {reg}, // another kind's items
			"WindowsEvent":                  {item("/x/dataSources/ev1", "WindowsEvent")},
		},
		refuse: map[string]error{
			"ApplicationInsights": fmt.Errorf("x: %w", ErrNotApplicable), // 501 DataSourceNotImplemented
			"Office365":           fmt.Errorf("x: %w", ErrNeedsKind),     // the filter itself refused
		},
		// The made-up items come back under the aliased filter too, still
		// carrying their own kind: counted once, not twice (review of #34).
		fresh:   map[string]int{"ChangeTrackingDefaultRegistry": 3, "ChangeTrackingRegistry": 3},
		freshAs: map[string]string{"ChangeTrackingRegistry": "ChangeTrackingDefaultRegistry"},
		// A real item a lagging second read leaves out is kept (review of #34).
		lagged: map[string]int{"WindowsEvent": 2},
		reads:  map[string]int{},
	}
	kinds := []string{"ApplicationInsights", "ChangeTrackingDefaultRegistry", "ChangeTrackingRegistry", "Office365", "WindowsEvent"}
	got, generated, err := listByKind(context.Background(), api, "/x/dataSources", "v", kinds, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || generated != 3 {
		t.Errorf("items %v and %d generated, want reg1 and ev1 once each, and 3 generated", got, generated)
	}
	if api.reads["WindowsEvent"] != 3 || api.reads["ChangeTrackingDefaultRegistry"] != 3 {
		t.Errorf("reads %v: a kind with anything missing is read three times", api.reads)
	}
	api.reads = map[string]int{}
	api.lagged = nil
	api.refuse["WindowsEvent"] = errors.New("500 InternalServerError")
	if _, _, err := listByKind(context.Background(), api, "/x/dataSources", "v", kinds, false); err == nil || !strings.Contains(err.Error(), "kind WindowsEvent") {
		t.Errorf("a kind that fails must fail the collection, naming the kind: %v", err)
	}
	if _, _, err := listByKind(context.Background(), api, "/x/dataSources", "v", nil, false); !errors.Is(err, ErrNeedsKind) {
		t.Errorf("no kinds named: %v", err)
	}
}

func item(id, kind string) map[string]any { return map[string]any{"id": id, "kind": kind} }

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

// The part of a resource that names something the manager of a group made
// (an AKS cluster's kubelet identity, in its node group) is not sent on a
// restore, and still owns that identity's object ID: a role assignment for
// it resolves to the restored cluster's kubelet identity, not the source's
// (review of #43).
func TestManagedPartMovesToStatusAndOwnsItsPrincipal(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	kubelet := "22223333-4444-4555-8666-777788889999"
	clusterRID, _ := ParseID(sub + "/resourceGroups/shop-rg/providers/Microsoft.ContainerService/managedClusters/aks")
	cluster := &captured{rid: clusterRID, status: map[string]any{"id": clusterRID.String()}, spec: map[string]any{"properties": map[string]any{
		"dnsPrefix": "aks",
		"identityProfile": map[string]any{"kubeletidentity": map[string]any{
			"resourceId": sub + "/resourceGroups/MC_shop_aks_eastus/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-agentpool",
			"objectId":   kubelet, "clientId": "11111111-2222-3333-4444-555555555555"}},
		// A part naming a resource outside a managed group stays.
		"diagnostics": map[string]any{"resourceId": sub + "/resourceGroups/shop-rg/providers/Microsoft.Storage/storageAccounts/logs"},
	}}}
	assignRID, _ := ParseID(sub + "/resourceGroups/shop-rg/providers/Microsoft.ContainerRegistry/registries/shop/providers/Microsoft.Authorization/roleAssignments/a1")
	assign := &captured{rid: assignRID, status: map[string]any{"id": assignRID.String()}, spec: map[string]any{"properties": map[string]any{"principalId": kubelet, "principalType": "ServicePrincipal"}}}
	managed := map[string]string{"mc_shop_aks_eastus": clusterRID.String()}
	cluster.spec = withoutManaged(cluster, managed, func(string) bool { return false })
	props := cluster.spec["properties"].(map[string]any)
	if _, ok := props["identityProfile"]; ok {
		t.Errorf("the kubelet identity is still in the spec: %v", props)
	}
	if _, ok := props["diagnostics"]; !ok {
		t.Error("a part naming an ordinary resource was moved")
	}
	if cluster.status["properties.identityProfile.kubeletidentity.objectId"] != kubelet {
		t.Errorf("status %v", cluster.status)
	}
	principalRefs([]*captured{cluster, assign})
	want := refPrefix + "Microsoft.ContainerService/managedClusters|shop-rg|aks|properties.identityProfile.kubeletidentity.objectId}}"
	if got := assign.spec["properties"].(map[string]any)["principalId"]; got != want {
		t.Errorf("principalId %v\nwant %s", got, want)
	}
}

// An extension kept on a managed group is restored after the group's
// manager, which creates the group (review of #43).
func TestExtensionOnAManagedGroupWaitsForItsManager(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	o := obj("Microsoft.Authorization/roleAssignments", "MC_shop_aks_eastus", "a2", sub+"/resourceGroups/MC_shop_aks_eastus/providers/Microsoft.Authorization/roleAssignments/a2", map[string]any{})
	o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annAfter] = sub + "/resourceGroups/shop-rg/providers/Microsoft.ContainerService/managedClusters/aks"
	want := strings.ToLower(APIVersion + "|Microsoft.ContainerService/managedClusters|shop-rg|aks")
	if d := deps(o); !slices.Contains(d, want) {
		t.Errorf("deps %v: want %s", d, want)
	}
}

// Who created or changed a resource is not something a reference can
// point at. A role assignment for a person kept their object ID, where it
// was rewritten as the createdBy of another assignment someone (that same
// person) had made: restored, it would have gone to whoever ran the
// restore.
func TestAuditFieldsOwnNoPrincipal(t *testing.T) {
	reg := fixtures(t)
	s := schema(t, reg, "Microsoft.Authorization/roleAssignments")
	api := NewWorld(reg).Subscription("00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-0000000000aa")
	person := "22223333-4444-4555-8666-777788889999"
	mk := func(name, principal string) *captured {
		id := "/subscriptions/00000000-0000-0000-0000-000000000001/providers/Microsoft.Authorization/roleAssignments/" + name
		rid, _ := ParseID(id)
		return process(api, "00000000-0000-0000-0000-0000000000aa", rid, s.Version, s, map[string]any{"id": id, "name": name,
			"properties": map[string]any{"principalId": principal, "principalType": "User", "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/r",
				"createdBy": person, "updatedBy": person, "createdOn": "2026-10-21T08:15:00Z"}})
	}
	made := mk("a1", "7a2d3c4b-5e6f-4a1b-8c9d-0e1f2a3b4c5d")
	mine := mk("a2", person)
	for _, k := range []string{"properties.createdBy", "properties.updatedBy"} {
		if _, ok := made.status[k]; ok {
			t.Errorf("status kept %s", k)
		}
	}
	principalRefs([]*captured{made, mine})
	if got := mine.spec["properties"].(map[string]any)["principalId"]; got != person {
		t.Errorf("a person's principalId became %v", got)
	}
}
