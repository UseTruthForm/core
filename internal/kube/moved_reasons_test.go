package kube

import (
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// What capture gives for an object a GitOps source applies is what compare
// reads as a move, and nothing else it gives is: the two share their
// formats, and this keeps a reason written here from parting from them.
// MadeBy, which compare runs on the captured copy, gives the same reason
// capture does.
func TestCaptureReasonsThatCanBeMoves(t *testing.T) {
	obj := func(kv ...string) snapshot.Object {
		l := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			l[kv[i]] = kv[i+1]
		}
		return snapshot.Object{Body: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "cfg", "namespace": "shop", "labels": l}}}
	}
	tracked := obj()
	tracked.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"argocd.argoproj.io/tracking-id": "shop:/ConfigMap:shop/cfg"}
	for o, want := range map[*snapshot.Object]string{
		ptr(obj("helm.toolkit.fluxcd.io/name", "web", "helm.toolkit.fluxcd.io/namespace", "gitops")):            snapshot.FluxHelmReleaseReason("gitops", "web"),
		ptr(obj("kustomize.toolkit.fluxcd.io/name", "root", "kustomize.toolkit.fluxcd.io/namespace", "gitops")): snapshot.FluxKustomizationReason("gitops", "root"),
		ptr(obj("argocd.argoproj.io/instance", "shop")):                                                         snapshot.ArgoCDReason("shop"),
		&tracked: snapshot.ArgoCDReason("shop"),
	} {
		got := MadeBy(*o)
		if got != want || got != renderedBy(o.Body["metadata"].(map[string]any)) || !snapshot.MadeElsewhere("kubernetes", got) {
			t.Errorf("%v: MadeBy %q, want %q, a move", o.Body, got, want)
		}
	}
	if got := MadeBy(obj()); got != "" {
		t.Errorf("an object with no maker's marks: %q", got)
	}
	for _, why := range []string{
		ownedReason("ReplicaSet", "web-5d9f"),
		MadeBy(obj("crossplane.io/composite", "db")),
		baselineReason,
	} {
		if snapshot.MadeElsewhere("kubernetes", why) {
			t.Errorf("a move: %q", why)
		}
	}
}

func ptr(o snapshot.Object) *snapshot.Object { return &o }

// The change of rules to 1 keeps a self-applying root, and the source a
// self-applying Kustomization in the same snapshot reads from; nothing
// else, and only across that change.
func TestRulesOneKeepsRoots(t *testing.T) {
	o := func(apiVersion, kind, name string, labels map[string]any, spec map[string]any) snapshot.Object {
		return snapshot.Object{Body: map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": name, "namespace": "gitops", "labels": labels}, "spec": spec}}
	}
	by := func(name string) map[string]any {
		return map[string]any{"kustomize.toolkit.fluxcd.io/name": name, "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
	}
	root := o("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "root", by("root"), map[string]any{"sourceRef": map[string]any{"kind": "GitRepository", "name": "repo"}})
	child := o("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "child", by("root"), map[string]any{"sourceRef": map[string]any{"kind": "GitRepository", "name": "other"}})
	repo := o("source.toolkit.fluxcd.io/v1", "GitRepository", "repo", by("root"), nil)
	other := o("source.toolkit.fluxcd.io/v1", "GitRepository", "other", by("root"), nil)
	app := o("argoproj.io/v1alpha1", "Application", "apps", map[string]any{"argocd.argoproj.io/instance": "apps"}, nil)
	cm := o("v1", "ConfigMap", "cfg", by("root"), nil)
	// A kind of the same name in another group, labelled as if it applied
	// itself, names no source Flux reads.
	lookalike := o("example.com/v1", "Kustomization", "fake", by("fake"), map[string]any{"sourceRef": map[string]any{"kind": "GitRepository", "name": "decoy"}})
	decoy := o("source.toolkit.fluxcd.io/v1", "GitRepository", "decoy", by("root"), nil)
	// An Argo CD application that applies itself reads no Flux source,
	// whatever its spec holds.
	argoRef := o("argoproj.io/v1alpha1", "Application", "self", map[string]any{"argocd.argoproj.io/instance": "self"}, map[string]any{"sourceRef": map[string]any{"kind": "GitRepository", "name": "argo-decoy"}})
	argoDecoy := o("source.toolkit.fluxcd.io/v1", "GitRepository", "argo-decoy", by("root"), nil)
	s := snapshot.Snapshot{Objects: []snapshot.Object{root, child, repo, other, app, cm, lookalike, decoy, argoRef, argoDecoy}}
	for _, c := range []struct {
		o      snapshot.Object
		lo, hi int
		want   bool
	}{
		{root, 0, 1, true},
		{app, 0, 1, true},
		{repo, 0, 1, true},
		{repo, 0, 2, true},
		{child, 0, 1, false},
		{other, 0, 1, false},
		{decoy, 0, 1, false},
		{argoDecoy, 0, 1, false},
		{cm, 0, 1, false},
		{root, 1, 2, false},
		{root, 0, 0, false},
		{root, 1, 1, false},
	} {
		if got := keptByRules(c.o, s, c.lo, c.hi); got != c.want {
			t.Errorf("%s/%s, rules %d to %d: kept %v, want %v", c.o.Kind(), c.o.Name(), c.lo, c.hi, got, c.want)
		}
	}
	// Read from the snapshot given: without the root, its repository is not one.
	if keptByRules(repo, snapshot.Snapshot{Objects: []snapshot.Object{repo}}, 0, 1) {
		t.Error("a repository no self-applying Kustomization in the snapshot reads from")
	}
}
