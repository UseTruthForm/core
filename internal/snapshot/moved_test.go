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

var byFlux = FluxKustomizationReason("gitops", "root")

var kubeCoverage = []Coverage{
	{Resource: "core/v1/namespaces", Kind: "Namespace"},
	{Resource: "core/v1/configmaps", Kind: "ConfigMap"},
	{Resource: "core/v1/services", Kind: "Service"},
	{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Kind: "Kustomization"},
	{Resource: "argoproj.io/v1alpha1/applications", Kind: "Application"},
	{Resource: "app.example.com/v1/applications", Kind: "Application"},
}

func kube(objects []Object, skips []Skip) Snapshot {
	return Snapshot{Platform: "kubernetes", Coverage: kubeCoverage, Objects: objects, Skips: skips}
}

func split(want, got Snapshot) ([]Change, []Moved) {
	return SplitMoved(want, got, Compare(want, got))
}

// An object one capture took and the next left out to its GitOps tool is
// said as that, and is not a difference; one that went away still is.
func TestMovedOutOfCapture(t *testing.T) {
	want := kube([]Object{kobj("v1", "Namespace", "", "shop"), kobj("v1", "ConfigMap", "shop", "gone")}, nil)
	got := kube(nil, []Skip{{Resource: "core/v1/namespaces", Name: "shop", Reason: byFlux}})
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
	want := kube(nil, []Skip{{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "gitops", Name: "root", Reason: byFlux}})
	got := kube([]Object{kobj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root"), kobj("v1", "ConfigMap", "gitops", "new")}, nil)
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

// Each reason that says something else makes an object is a move.
func TestMovedForEachMaker(t *testing.T) {
	for _, why := range []string{
		OwnedReason("Gateway", "front"),
		FluxHelmReleaseReason("gitops", "web"),
		FluxKustomizationReason("gitops", "root"),
		ArgoCDReason("shop"),
		ArgoCDReason("apps_shop"),
	} {
		want := kube([]Object{kobj("v1", "ConfigMap", "shop", "cfg")}, nil)
		got := kube(nil, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: why}})
		if real, moved := split(want, got); len(moved) != 1 || len(real) != 0 {
			t.Errorf("%q: real %+v moved %+v", why, real, moved)
		}
	}
}

// No other reason is a move, in either direction: a skip for an object's
// content (identical to a baseline) or for not reading it says nothing of
// who makes it, and across it the object may have changed. Nor is a reason
// that only looks like one.
func TestMovedRefusesOtherReasons(t *testing.T) {
	for _, why := range []string{
		"identical to the distribution baseline; a new cluster provides it",
		"identical to the baseline snapshot (already there, or created by Azure)",
		"listed but could not be read: AccessDenied",
		"in system namespace kube-system",
		"composed by Crossplane composite db; restoring the composite recreates it",
		"applied by Eno",
		"owned by AWS, the same in every account: a default",
		OwnedReason("Gateway", "front") + " (edited)",
		"x" + byFlux,
		FluxKustomizationReason("", "root"),
		FluxKustomizationReason("git ops", "root"),
		"",
	} {
		want := kube([]Object{kobj("v1", "ConfigMap", "shop", "cfg")}, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "new", Reason: why}})
		got := kube([]Object{kobj("v1", "ConfigMap", "shop", "new")}, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: why}})
		real, moved := split(want, got)
		if len(moved) != 0 || len(real) != 2 {
			t.Errorf("%q: real %+v moved %+v", why, real, moved)
		}
	}
}

// Only a Kubernetes capture says something else makes an object: the same
// words from another platform's are not read as that.
func TestMovedOnlyOnKubernetes(t *testing.T) {
	for _, p := range []string{"azure", "aws", "gcp", "github", ""} {
		cov := []Coverage{{Resource: "core/v1/configmaps", Kind: "ConfigMap"}}
		want := Snapshot{Platform: p, Coverage: cov, Objects: []Object{kobj("v1", "ConfigMap", "shop", "cfg")}}
		got := Snapshot{Platform: p, Coverage: cov, Skips: []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}}}
		if _, moved := split(want, got); len(moved) != 0 {
			t.Errorf("%s: %+v", p, moved)
		}
	}
}

// Where two skips name one object, it is a move only if each says
// something else makes it, whichever comes first.
func TestMovedNeedsEverySkipToAgree(t *testing.T) {
	base := Skip{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: "identical to the distribution baseline; a new cluster provides it"}
	flux := Skip{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}
	want := kube([]Object{kobj("v1", "ConfigMap", "shop", "cfg")}, nil)
	for _, skips := range [][]Skip{{base, flux}, {flux, base}} {
		if _, moved := split(want, kube(nil, skips)); len(moved) != 0 {
			t.Errorf("%v: %+v", skips, moved)
		}
	}
	argo := Skip{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: ArgoCDReason("shop")}
	if _, moved := split(want, kube(nil, []Skip{flux, argo})); len(moved) != 1 || moved[0].Reason != byFlux {
		t.Errorf("two makers: %+v", moved)
	}
}

// A skip names an object only by its own resource, namespace and name: one
// of another kind, another group with the same kind, or another namespace
// is not it.
func TestMovedMatchesOnlyTheSameObject(t *testing.T) {
	want := kube([]Object{
		kobj("v1", "ConfigMap", "shop", "settings"),
		kobj("argoproj.io/v1alpha1", "Application", "argocd", "shop"),
		kobj("v1", "ConfigMap", "other", "x"),
		kobj("v1", "ConfigMap", "shop", "plain"),
	}, nil)
	got := kube(nil, []Skip{
		{Resource: "core/v1/secrets", Namespace: "shop", Name: "settings", Reason: byFlux},
		{Resource: "app.example.com/v1/applications", Namespace: "argocd", Name: "shop", Reason: byFlux},
		{Resource: "core/v1/configmaps", Namespace: "elsewhere", Name: "x", Reason: byFlux},
		{Resource: "core/v1/configmaps", Name: "plain", Reason: byFlux},
	})
	real, moved := split(want, got)
	if len(moved) != 0 || len(real) != 4 {
		t.Errorf("nothing moved: real %+v moved %+v", real, moved)
	}
}

// The resource is read from the coverage of the snapshot that left the
// object out, which lists every type it left anything out of.
func TestMovedReadsTheSkippingSnapshotsCoverage(t *testing.T) {
	want := Snapshot{Platform: "kubernetes", Objects: []Object{kobj("v1", "ConfigMap", "shop", "cfg")}}
	got := kube(nil, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}})
	if _, moved := split(want, got); len(moved) != 1 {
		t.Errorf("moved: %+v", moved)
	}
}

// A skip of "*" stands for its Names where the capture lists them (the
// Services an object owns); one without names cannot tell its objects from
// a real removal, and never stands for an object named "*".
func TestMovedThroughNamedOwnerSkip(t *testing.T) {
	owned := OwnedReason("Gateway", "front")
	want := kube([]Object{
		kobj("v1", "Service", "shop", "web"),
		kobj("v1", "ConfigMap", "shop", "cache"),
		kobj("v1", "Service", "shop", "*"),
	}, nil)
	got := kube(nil, []Skip{
		{Resource: "core/v1/services", Namespace: "shop", Name: "*", Reason: owned, Names: []string{"web"}},
		{Resource: "core/v1/configmaps", Namespace: "shop", Name: "*", Reason: OwnedReason("Operator", "x")},
	})
	real, moved := split(want, got)
	if len(moved) != 1 || moved[0].Key != "v1|Service|shop|web" {
		t.Errorf("moved: %+v", moved)
	}
	if len(real) != 2 {
		t.Errorf("real: %+v", real)
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
