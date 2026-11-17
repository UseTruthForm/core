package kube

import (
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// What capture gives for an object something else makes is what compare
// reads as a move, and nothing else it gives is: the two share their
// formats, and this keeps a reason written here from parting from them.
func TestCaptureReasonsThatCanBeMoves(t *testing.T) {
	labels := func(kv ...string) map[string]any {
		l := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			l[kv[i]] = kv[i+1]
		}
		return map[string]any{"labels": l}
	}
	for _, why := range []string{
		ownedReason("ReplicaSet", "web-5d9f"),
		renderedBy(labels("helm.toolkit.fluxcd.io/name", "web", "helm.toolkit.fluxcd.io/namespace", "gitops")),
		renderedBy(labels("kustomize.toolkit.fluxcd.io/name", "root", "kustomize.toolkit.fluxcd.io/namespace", "gitops")),
		renderedBy(labels("argocd.argoproj.io/instance", "shop")),
	} {
		if !snapshot.MadeElsewhere("kubernetes", why) {
			t.Errorf("not a move: %q", why)
		}
	}
	for _, why := range []string{
		renderedBy(labels("crossplane.io/composite", "db")),
		baselineReason,
	} {
		if snapshot.MadeElsewhere("kubernetes", why) {
			t.Errorf("a move: %q", why)
		}
	}
}
