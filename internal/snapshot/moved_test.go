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

// made marks o as carrying the marks of its maker, as madeByMark reads
// them: the stand-in here for the labels Kubernetes capture reads.
func made(o Object, why string) Object {
	o.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"test.example/made-by": why}
	return o
}

func madeByMark(o Object) string {
	a, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	s, _ := a["test.example/made-by"].(string)
	return s
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
	return SplitMoved(want, got, Compare(want, got), madeByMark)
}

// An object one capture took, already carrying its source's marks, and the
// next left out to that source is said as moved, and is not a difference;
// one that went away still is.
func TestMovedOutOfCapture(t *testing.T) {
	want := kube([]Object{made(kobj("v1", "Namespace", "", "shop"), byFlux), kobj("v1", "ConfigMap", "shop", "gone")}, nil)
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

// The other way: a self-applying root an older capture left out, which
// this one captures, carrying the same marks.
func TestMovedIntoCapture(t *testing.T) {
	want := kube(nil, []Skip{{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "gitops", Name: "root", Reason: byFlux}})
	got := kube([]Object{made(kobj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root"), byFlux), kobj("v1", "ConfigMap", "gitops", "new")}, nil)
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

// The captured copy decides. One that does not carry its maker's marks, or
// carries another's, was not left out for that reason: a label added in
// the cluster to hide an edit, or taken off one, leaves a difference.
func TestMovedOnlyWhereTheCapturedCopySaysSo(t *testing.T) {
	argo := ArgoCDReason("shop")
	for _, copyOf := range []func() Object{
		func() Object { return kobj("v1", "ConfigMap", "shop", "cfg") },
		func() Object { return made(kobj("v1", "ConfigMap", "shop", "cfg"), argo) },
		func() Object {
			return made(kobj("v1", "ConfigMap", "shop", "cfg"), FluxKustomizationReason("gitops", "other"))
		},
	} {
		skip := []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}}
		if real, moved := split(kube([]Object{copyOf()}, nil), kube(nil, skip)); len(moved) != 0 || len(real) != 1 {
			t.Errorf("out of capture, copy %v: real %+v moved %+v", copyOf().Body, real, moved)
		}
		if real, moved := split(kube(nil, skip), kube([]Object{copyOf()}, nil)); len(moved) != 0 || len(real) != 1 {
			t.Errorf("into capture, copy %v: real %+v moved %+v", copyOf().Body, real, moved)
		}
	}
}

// Each GitOps source's reason is a move, where the copy agrees.
func TestMovedForEachSource(t *testing.T) {
	for _, why := range []string{
		FluxHelmReleaseReason("gitops", "web"),
		FluxKustomizationReason("gitops", "root"),
		ArgoCDReason("shop"),
		ArgoCDReason("apps_shop"),
	} {
		want := kube([]Object{made(kobj("v1", "ConfigMap", "shop", "cfg"), why)}, nil)
		got := kube(nil, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: why}})
		if real, moved := split(want, got); len(moved) != 1 || len(real) != 0 {
			t.Errorf("%q: real %+v moved %+v", why, real, moved)
		}
	}
}

// No other reason is a move, in either direction, even where the copy
// says the same: a skip for an object's content (identical to a baseline)
// or for not reading it says nothing of who makes it; an owner reference
// is not kept in a capture, so "owned by" cannot be checked; and a reason
// that only looks like one is not one.
func TestMovedRefusesOtherReasons(t *testing.T) {
	for _, why := range []string{
		OwnedReason("Deployment", "web"),
		"identical to the distribution baseline; a new cluster provides it",
		"identical to the baseline snapshot (already there, or created by Azure)",
		"listed but could not be read: AccessDenied",
		"in system namespace kube-system",
		"composed by Crossplane composite db; restoring the composite recreates it",
		"applied by Eno",
		"owned by AWS, the same in every account: a default",
		byFlux + " (edited)",
		"x" + byFlux,
		FluxKustomizationReason("", "root"),
		FluxKustomizationReason("git ops", "root"),
		"",
	} {
		want := kube([]Object{made(kobj("v1", "ConfigMap", "shop", "cfg"), why)}, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "new", Reason: why}})
		got := kube([]Object{made(kobj("v1", "ConfigMap", "shop", "new"), why)}, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: why}})
		real, moved := split(want, got)
		if len(moved) != 0 || len(real) != 2 {
			t.Errorf("%q: real %+v moved %+v", why, real, moved)
		}
	}
}

// Only a Kubernetes capture says a GitOps source applies an object: the
// same words from another platform's are not read as that.
func TestMovedOnlyOnKubernetes(t *testing.T) {
	for _, p := range []string{"azure", "aws", "gcp", "github", ""} {
		cov := []Coverage{{Resource: "core/v1/configmaps", Kind: "ConfigMap"}}
		want := Snapshot{Platform: p, Coverage: cov, Objects: []Object{made(kobj("v1", "ConfigMap", "shop", "cfg"), byFlux)}}
		got := Snapshot{Platform: p, Coverage: cov, Skips: []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}}}
		if _, moved := split(want, got); len(moved) != 0 {
			t.Errorf("%s: %+v", p, moved)
		}
	}
}

// Without the capture's classifier nothing can be checked, so nothing moves.
func TestMovedNeedsAClassifier(t *testing.T) {
	want := kube([]Object{made(kobj("v1", "ConfigMap", "shop", "cfg"), byFlux)}, nil)
	got := kube(nil, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}})
	if real, moved := SplitMoved(want, got, Compare(want, got), nil); len(moved) != 0 || len(real) != 1 {
		t.Errorf("real %+v moved %+v", real, moved)
	}
}

// Where two skips name one object, it is a move only if each gives the
// reason its copy does, whichever comes first.
func TestMovedNeedsEverySkipToAgree(t *testing.T) {
	cfg := func(why string) Skip {
		return Skip{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: why}
	}
	base, flux, argo := cfg("identical to the distribution baseline; a new cluster provides it"), cfg(byFlux), cfg(ArgoCDReason("shop"))
	want := kube([]Object{made(kobj("v1", "ConfigMap", "shop", "cfg"), byFlux)}, nil)
	for _, skips := range [][]Skip{{base, flux}, {flux, base}, {flux, argo}, {argo, flux}} {
		if _, moved := split(want, kube(nil, skips)); len(moved) != 0 {
			t.Errorf("%v: %+v", skips, moved)
		}
	}
	if _, moved := split(want, kube(nil, []Skip{flux, flux})); len(moved) != 1 {
		t.Errorf("the same reason twice: %+v", moved)
	}
}

// A skip names an object only by its own resource, namespace and name: one
// of another kind, another group with the same kind, or another namespace
// is not it.
func TestMovedMatchesOnlyTheSameObject(t *testing.T) {
	want := kube([]Object{
		made(kobj("v1", "ConfigMap", "shop", "settings"), byFlux),
		made(kobj("argoproj.io/v1alpha1", "Application", "argocd", "shop"), byFlux),
		made(kobj("v1", "ConfigMap", "other", "x"), byFlux),
		made(kobj("v1", "ConfigMap", "shop", "plain"), byFlux),
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
	want := Snapshot{Platform: "kubernetes", Objects: []Object{made(kobj("v1", "ConfigMap", "shop", "cfg"), byFlux)}}
	got := kube(nil, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}})
	if _, moved := split(want, got); len(moved) != 1 {
		t.Errorf("moved: %+v", moved)
	}
}

// What a controller owns is never a move: a skip of "*", with names or
// without, even with a reason that could be one.
func TestMovedNotThroughOwnerSkip(t *testing.T) {
	want := kube([]Object{made(kobj("v1", "Service", "shop", "web"), byFlux), made(kobj("v1", "Service", "shop", "*"), byFlux)}, nil)
	got := kube(nil, []Skip{{Resource: "core/v1/services", Namespace: "shop", Name: "*", Reason: byFlux, Names: []string{"web"}}})
	if real, moved := split(want, got); len(moved) != 0 || len(real) != 2 {
		t.Errorf("real %+v moved %+v", real, moved)
	}
}

// Changed objects and what is not working are never moved.
func TestMovedLeavesOtherChanges(t *testing.T) {
	in := []Change{{Key: "a", Kind: "changed", Fields: []string{"spec"}}, {Key: "b", Kind: "not working"}, {Key: "c", Kind: "missing"}}
	real, moved := SplitMoved(Snapshot{}, Snapshot{}, in, madeByMark)
	if len(moved) != 0 || !reflect.DeepEqual(real, in) {
		t.Errorf("real %+v moved %+v", real, moved)
	}
}
