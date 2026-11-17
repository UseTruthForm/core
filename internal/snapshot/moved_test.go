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

func annotate(o Object, k, v string) Object {
	md := o.Body["metadata"].(map[string]any)
	a, _ := md["annotations"].(map[string]any)
	if a == nil {
		a = map[string]any{}
		md["annotations"] = a
	}
	a[k] = v
	return o
}

// made marks o as carrying its maker's marks, and kept as what a change of
// rules keeps: the stand-ins here for the labels and root status
// Kubernetes capture reads.
func made(o Object, why string) Object { return annotate(o, "test.example/made-by", why) }
func kept(o Object) Object             { return annotate(o, "test.example/kept", "yes") }

func mark(o Object, k string) string {
	a, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	s, _ := a[k].(string)
	return s
}

var testMoves = Moves{
	MadeBy: func(o Object) string { return mark(o, "test.example/made-by") },
	Kept:   func(o Object, _ Snapshot, _, _ int) bool { return mark(o, "test.example/kept") == "yes" },
}

var byFlux = FluxKustomizationReason("gitops", "root")

var kubeCoverage = []Coverage{
	{Resource: "core/v1/configmaps", Kind: "ConfigMap"},
	{Resource: "core/v1/services", Kind: "Service"},
	{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Kind: "Kustomization"},
	{Resource: "argoproj.io/v1alpha1/applications", Kind: "Application"},
	{Resource: "app.example.com/v1/applications", Kind: "Application"},
}

func kube(rules int, objects []Object, skips []Skip) Snapshot {
	return Snapshot{Platform: "kubernetes", Rules: rules, Coverage: kubeCoverage, Objects: objects, Skips: skips}
}

func split(want, got Snapshot) ([]Change, []Moved) {
	return SplitMoved(want, got, Compare(want, got), testMoves)
}

func rootObj() Object {
	return kept(made(kobj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root"), byFlux))
}

var rootSkip = []Skip{{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "gitops", Name: "root", Reason: byFlux}}

// The move a change of rules makes: the older rules left a root out, the
// newer keep it. It is moved whichever snapshot is given first, said from
// the first one's side; a real removal or addition beside it stays one.
func TestMovedFromOlderRulesToNewer(t *testing.T) {
	older := kube(0, []Object{kobj("v1", "ConfigMap", "gitops", "gone")}, rootSkip)
	newer := kube(1, []Object{rootObj()}, nil)
	real, moved := split(older, newer)
	if !reflect.DeepEqual(moved, []Moved{{Key: "kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|root", Kind: NoLongerSkipped, Reason: byFlux}}) {
		t.Errorf("older first: %+v", moved)
	}
	if len(real) != 1 || real[0].Kind != "missing" {
		t.Errorf("older first, a real removal must stay one: %+v", real)
	}
	real, moved = split(newer, older)
	if !reflect.DeepEqual(moved, []Moved{{Key: "kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|root", Kind: NoLongerCaptured, Reason: byFlux}}) {
		t.Errorf("newer first: %+v", moved)
	}
	if len(real) != 1 || real[0].Kind != "extra" {
		t.Errorf("newer first, a real addition must stay one: %+v", real)
	}
	if d := moved[0].Describe(); d != "no longer captured: "+byFlux {
		t.Errorf("describe: %s", d)
	}
}

// The other direction is never a move: what the older rules captured and
// the newer left out was not moved by any change of rules (an edit that
// took away its root status reads that way). Nor is anything under one set
// of rules, two old snapshots among them. Each in both orders.
func TestMovedOnlyOneWay(t *testing.T) {
	for _, c := range []struct {
		what                string
		capturedAt, skipped int
	}{
		{"captured under older rules", 0, 1},
		{"captured under older rules, both recorded", 1, 2},
		{"two old snapshots", 0, 0},
		{"one set of rules", 1, 1},
	} {
		captured := kube(c.capturedAt, []Object{rootObj()}, nil)
		skipped := kube(c.skipped, nil, rootSkip)
		for _, pair := range [][2]Snapshot{{captured, skipped}, {skipped, captured}} {
			if real, moved := split(pair[0], pair[1]); len(moved) != 0 || len(real) != 1 {
				t.Errorf("%s: real %+v moved %+v", c.what, real, moved)
			}
		}
	}
}

// Kept is asked of the newer snapshot, with the older one's rules and the
// newer one's, whichever argument each is.
func TestMovedAsksKeptOfTheNewer(t *testing.T) {
	older := kube(3, nil, rootSkip)
	newer := kube(5, []Object{rootObj()}, nil)
	for _, pair := range [][2]Snapshot{{older, newer}, {newer, older}} {
		var asked []int
		m := testMoves
		m.Kept = func(o Object, s Snapshot, lo, hi int) bool {
			asked = []int{s.Rules, lo, hi}
			return true
		}
		if _, moved := SplitMoved(pair[0], pair[1], Compare(pair[0], pair[1]), m); len(moved) != 1 || !reflect.DeepEqual(asked, []int{5, 3, 5}) {
			t.Errorf("asked %v, moved %+v", asked, moved)
		}
	}
}

// What a change of rules does not keep, and a copy that does not say what
// the skip says, are differences.
func TestMovedNeedsKeptAndTheCopy(t *testing.T) {
	for _, o := range []Object{
		made(kobj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root"), byFlux),
		kept(kobj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root")),
		kept(made(kobj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root"), ArgoCDReason("root"))),
	} {
		older, newer := kube(0, nil, rootSkip), kube(1, []Object{o}, nil)
		for _, pair := range [][2]Snapshot{{older, newer}, {newer, older}} {
			if real, moved := split(pair[0], pair[1]); len(moved) != 0 || len(real) != 1 {
				t.Errorf("%v: real %+v moved %+v", o.Body, real, moved)
			}
		}
	}
}

// Each GitOps source's reason can be a move.
func TestMovedForEachSource(t *testing.T) {
	for _, why := range []string{FluxHelmReleaseReason("gitops", "web"), byFlux, ArgoCDReason("shop"), ArgoCDReason("apps_shop")} {
		older := kube(0, nil, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: why}})
		newer := kube(1, []Object{kept(made(kobj("v1", "ConfigMap", "shop", "cfg"), why))}, nil)
		if real, moved := split(older, newer); len(moved) != 1 || len(real) != 0 {
			t.Errorf("%q: real %+v moved %+v", why, real, moved)
		}
	}
}

// No other reason is a move, even where the copy says the same and the
// rules kept it: a skip for an object's content (identical to a baseline)
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
		older := kube(0, nil, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: why}})
		newer := kube(1, []Object{kept(made(kobj("v1", "ConfigMap", "shop", "cfg"), why))}, nil)
		for _, pair := range [][2]Snapshot{{older, newer}, {newer, older}} {
			if real, moved := split(pair[0], pair[1]); len(moved) != 0 || len(real) != 1 {
				t.Errorf("%q: real %+v moved %+v", why, real, moved)
			}
		}
	}
}

// Only a Kubernetes capture says a GitOps source applies an object: the
// same words from another platform's are not read as that.
func TestMovedOnlyOnKubernetes(t *testing.T) {
	for _, p := range []string{"azure", "aws", "gcp", "github", ""} {
		older, newer := kube(0, nil, rootSkip), kube(1, []Object{rootObj()}, nil)
		older.Platform, newer.Platform = p, p
		if _, moved := split(older, newer); len(moved) != 0 {
			t.Errorf("%s: %+v", p, moved)
		}
	}
}

// Without the capture's classifier and its rule changes nothing can be
// checked, so nothing moves.
func TestMovedNeedsTheRules(t *testing.T) {
	older, newer := kube(0, nil, rootSkip), kube(1, []Object{rootObj()}, nil)
	for _, m := range []Moves{{}, {MadeBy: testMoves.MadeBy}, {Kept: testMoves.Kept}} {
		if real, moved := SplitMoved(older, newer, Compare(older, newer), m); len(moved) != 0 || len(real) != 1 {
			t.Errorf("real %+v moved %+v", real, moved)
		}
	}
}

// Where two skips name one object, it is a move only if each gives the
// reason its copy does, whichever comes first.
func TestMovedNeedsEverySkipToAgree(t *testing.T) {
	skip := func(why string) Skip {
		return Skip{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "gitops", Name: "root", Reason: why}
	}
	base, flux, argo := skip("identical to the distribution baseline; a new cluster provides it"), skip(byFlux), skip(ArgoCDReason("root"))
	newer := kube(1, []Object{rootObj()}, nil)
	for _, skips := range [][]Skip{{base, flux}, {flux, base}, {flux, argo}, {argo, flux}} {
		if _, moved := split(kube(0, nil, skips), newer); len(moved) != 0 {
			t.Errorf("%v: %+v", skips, moved)
		}
	}
	if _, moved := split(kube(0, nil, []Skip{flux, flux}), newer); len(moved) != 1 {
		t.Errorf("the same reason twice: %+v", moved)
	}
}

// A skip names an object only by its own resource, namespace and name: one
// of another kind, another group with the same kind, or another namespace
// is not it.
func TestMovedMatchesOnlyTheSameObject(t *testing.T) {
	newer := kube(1, []Object{
		kept(made(kobj("v1", "ConfigMap", "shop", "settings"), byFlux)),
		kept(made(kobj("argoproj.io/v1alpha1", "Application", "argocd", "shop"), byFlux)),
		kept(made(kobj("v1", "ConfigMap", "other", "x"), byFlux)),
		kept(made(kobj("v1", "ConfigMap", "shop", "plain"), byFlux)),
	}, nil)
	older := kube(0, nil, []Skip{
		{Resource: "core/v1/secrets", Namespace: "shop", Name: "settings", Reason: byFlux},
		{Resource: "app.example.com/v1/applications", Namespace: "argocd", Name: "shop", Reason: byFlux},
		{Resource: "core/v1/configmaps", Namespace: "elsewhere", Name: "x", Reason: byFlux},
		{Resource: "core/v1/configmaps", Name: "plain", Reason: byFlux},
	})
	if real, moved := split(older, newer); len(moved) != 0 || len(real) != 4 {
		t.Errorf("nothing moved: real %+v moved %+v", real, moved)
	}
}

// The resource is read from the coverage of the snapshot that left the
// object out, which lists every type it left anything out of.
func TestMovedReadsTheSkippingSnapshotsCoverage(t *testing.T) {
	newer := Snapshot{Platform: "kubernetes", Rules: 1, Objects: []Object{rootObj()}}
	if _, moved := split(kube(0, nil, rootSkip), newer); len(moved) != 1 {
		t.Errorf("moved: %+v", moved)
	}
}

// What a controller owns is never a move: a skip of "*", with names or
// without, even with a reason that could be one.
func TestMovedNotThroughOwnerSkip(t *testing.T) {
	newer := kube(1, []Object{kept(made(kobj("v1", "Service", "shop", "web"), byFlux)), kept(made(kobj("v1", "Service", "shop", "*"), byFlux))}, nil)
	older := kube(0, nil, []Skip{{Resource: "core/v1/services", Namespace: "shop", Name: "*", Reason: byFlux, Names: []string{"web"}}})
	if real, moved := split(older, newer); len(moved) != 0 || len(real) != 2 {
		t.Errorf("real %+v moved %+v", real, moved)
	}
}

// Changed objects and what is not working are never moved.
func TestMovedLeavesOtherChanges(t *testing.T) {
	in := []Change{{Key: "a", Kind: "changed", Fields: []string{"spec"}}, {Key: "b", Kind: "not working"}, {Key: "c", Kind: "missing"}}
	real, moved := SplitMoved(Snapshot{Rules: 1}, Snapshot{}, in, testMoves)
	if len(moved) != 0 || !reflect.DeepEqual(real, in) {
		t.Errorf("real %+v moved %+v", real, moved)
	}
}
