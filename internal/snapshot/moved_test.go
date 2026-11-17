package snapshot

import (
	"reflect"
	"testing"
)

func kobj(apiVersion, kind, ns, name string) Object {
	md := map[string]any{"name": name}
	if ns != "" {
		md["namespace"] = ns
	}
	return Object{Body: map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}}
}

const byFlux = "applied by Flux Kustomization gitops/root; restoring it recreates this"

var kubeCoverage = []Coverage{
	{Resource: "core/v1/namespaces", Kind: "Namespace"},
	{Resource: "core/v1/configmaps", Kind: "ConfigMap"},
	{Resource: "core/v1/services", Kind: "Service"},
	{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Kind: "Kustomization"},
	{Resource: "argoproj.io/v1alpha1/applications", Kind: "Application"},
	{Resource: "app.example.com/v1/applications", Kind: "Application"},
}

func split(want, got Snapshot) ([]Change, []Moved) {
	return SplitMoved(want, got, Compare(want, got))
}

// An object one capture took and the next left out to its GitOps tool is
// said as that, and is not a difference; one that went away still is.
func TestMovedOutOfCapture(t *testing.T) {
	want := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Objects: []Object{
		kobj("v1", "Namespace", "", "shop"),
		kobj("v1", "ConfigMap", "shop", "gone"),
	}}
	got := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Skips: []Skip{
		{Resource: "core/v1/namespaces", Name: "shop", Reason: byFlux},
	}}
	real, moved := split(want, got)
	if !reflect.DeepEqual(moved, []Moved{{Key: "v1|Namespace||shop", Kind: NoLongerCaptured, Reason: byFlux}}) {
		t.Errorf("moved: %+v", moved)
	}
	if len(real) != 1 || real[0].Kind != "missing" || real[0].Key != "v1|ConfigMap|shop|gone" {
		t.Errorf("a real removal must stay one: %+v", real)
	}
	if d := moved[0].Describe(); d != "no longer captured: "+byFlux {
		t.Errorf("describe: %s", d)
	}
}

// The other way: what one capture left out and the next took.
func TestMovedIntoCapture(t *testing.T) {
	want := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Skips: []Skip{
		{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "gitops", Name: "root", Reason: byFlux},
	}}
	got := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Objects: []Object{
		kobj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root"),
		kobj("v1", "ConfigMap", "gitops", "new"),
	}}
	real, moved := split(want, got)
	if len(moved) != 1 || moved[0].Kind != NoLongerSkipped || moved[0].Reason != byFlux {
		t.Errorf("moved: %+v", moved)
	}
	if len(real) != 1 || real[0].Kind != "extra" {
		t.Errorf("a real addition must stay one: %+v", real)
	}
	if d := moved[0].Describe(); d != "no longer skipped (was: "+byFlux+"), so now captured" {
		t.Errorf("describe: %s", d)
	}
}

// A skip names an object only by its own resource, namespace and name: one
// of another kind, another group with the same kind, or another namespace
// is not it.
func TestMovedMatchesOnlyTheSameObject(t *testing.T) {
	want := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Objects: []Object{
		kobj("v1", "ConfigMap", "shop", "settings"),
		kobj("argoproj.io/v1alpha1", "Application", "argocd", "shop"),
		kobj("v1", "ConfigMap", "other", "x"),
	}}
	got := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Skips: []Skip{
		{Resource: "core/v1/secrets", Namespace: "shop", Name: "settings", Reason: byFlux},
		{Resource: "app.example.com/v1/applications", Namespace: "argocd", Name: "shop", Reason: byFlux},
		{Resource: "core/v1/configmaps", Namespace: "elsewhere", Name: "x", Reason: byFlux},
	}}
	real, moved := split(want, got)
	if len(moved) != 0 || len(real) != 3 {
		t.Errorf("nothing moved: real %+v moved %+v", real, moved)
	}
}

// A skip of "*" stands for its Names where the capture lists them (the
// Services an object owns); one without names cannot tell its objects from
// a real removal.
func TestMovedThroughNamedOwnerSkip(t *testing.T) {
	want := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Objects: []Object{
		kobj("v1", "Service", "shop", "web"),
		kobj("v1", "ConfigMap", "shop", "cache"),
	}}
	got := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Skips: []Skip{
		{Resource: "core/v1/services", Namespace: "shop", Name: "*", Reason: "owned by Gateway/front", Names: []string{"web"}},
		{Resource: "core/v1/configmaps", Namespace: "shop", Name: "*", Reason: "owned by Operator/x"},
	}}
	real, moved := split(want, got)
	if len(moved) != 1 || moved[0].Key != "v1|Service|shop|web" {
		t.Errorf("moved: %+v", moved)
	}
	if len(real) != 1 || real[0].Key != "v1|ConfigMap|shop|cache" {
		t.Errorf("real: %+v", real)
	}
}

// Azure records a skip by type and a name that holds the resource group,
// and matches names without regard to case.
func TestMovedAzure(t *testing.T) {
	cov := []Coverage{{Resource: "Microsoft.Network/networkInterfaces", Kind: "Microsoft.Network/networkInterfaces"}}
	want := Snapshot{Platform: "azure", Coverage: cov, Objects: []Object{
		kobj("azure.truthform.org/v1", "Microsoft.Network/networkInterfaces", "app-rg", "nic-1"),
		kobj("azure.truthform.org/v1", "Microsoft.Network/networkInterfaces", "app-rg", "nic-2"),
	}}
	got := Snapshot{Platform: "azure", Coverage: cov, Skips: []Skip{
		{Resource: "microsoft.network/networkInterfaces", Name: "APP-RG/nic-1", Reason: "managed by a private endpoint"},
		// No group: it may be in another one, so it does not say nic-2 moved.
		{Resource: "Microsoft.Network/networkInterfaces", Name: "nic-2", Reason: "managed by a private endpoint"},
	}}
	real, moved := split(want, got)
	if len(moved) != 1 || moved[0].Key != "azure.truthform.org/v1|Microsoft.Network/networkInterfaces|app-rg|nic-1" {
		t.Errorf("moved: %+v", moved)
	}
	if len(real) != 1 {
		t.Errorf("real: %+v", real)
	}
	// Kubernetes names are case-sensitive: the same skip in other case is
	// another object there.
	kwant := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Objects: []Object{kobj("v1", "Namespace", "", "shop")}}
	kgot := Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Skips: []Skip{{Resource: "core/v1/namespaces", Name: "Shop", Reason: byFlux}}}
	if _, moved := split(kwant, kgot); len(moved) != 0 {
		t.Errorf("kubernetes must match case: %+v", moved)
	}
}

// Changed objects and what is not working are never moved.
func TestMovedLeavesOtherChanges(t *testing.T) {
	in := []Change{{Key: "a", Kind: "changed", Fields: []string{"spec"}}, {Key: "b", Kind: "not working"}, {Key: "c", Kind: "missing"}}
	real, moved := SplitMoved(Snapshot{}, Snapshot{}, in)
	if len(moved) != 0 || !reflect.DeepEqual(real, in) {
		t.Errorf("real %+v moved %+v", real, moved)
	}
}
