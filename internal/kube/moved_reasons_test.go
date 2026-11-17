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
