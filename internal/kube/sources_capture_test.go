package kube_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
)

// TestUnheldSourcesOfARealCapture asks, of a snapshot a capture wrote from
// a real API server, which GitOps sources a scope that holds something
// brings without holding them, and that apply into a namespace it narrows.
// Restored as it is, such a source syncs its Git path into the drill
// target and starts what the scope held back, so a restore is refused for
// it unless it is held or accepted by name. The shapes (a Kustomization
// that applies itself, what it applies, what that renders, an Argo CD
// application that manages itself) are the capture's, not written by hand.
func TestUnheldSourcesOfARealCapture(t *testing.T) {
	srv := kubetest.Start(t, "sources")
	w, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	seed(t, w, "../../testdata/k8s/gitops.yaml")
	ro, err := kube.Connect(srv.Kubeconfig, srv.Context, true)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := kube.Capture(context.Background(), ro, kube.Policy{})
	if err != nil {
		t.Fatal(err)
	}

	// What the capture wrote, which the rows below depend on: the roots
	// are objects of the snapshot, and what they apply is left to them.
	have := map[string]bool{}
	for _, o := range snap.Objects {
		have[o.Kind()+" "+o.Namespace()+"/"+o.Name()] = true
	}
	for _, k := range []string{"Kustomization gitops/root", "GitRepository gitops/root", "Kustomization gitops/edge", "Application argocd/apps", "Deployment shop/web", "ConfigMap fleet/settings"} {
		if !have[k] {
			t.Errorf("the capture did not take %s", k)
		}
	}
	reasons := map[string]string{}
	for _, sk := range snap.Skips {
		reasons[sk.Namespace+"/"+sk.Name+" "+sk.Resource[strings.LastIndex(sk.Resource, "/")+1:]] = sk.Reason
	}
	for k, want := range map[string]string{
		"gitops/payments helmreleases": "applied by Flux Kustomization gitops/root",
		"store/payments deployments":   "rendered by Flux HelmRelease gitops/payments",
		"shop/cart deployments":        "applied by Flux Kustomization gitops/root",
		"edge/proxy deployments":       "applied by Flux Kustomization gitops/edge",
		"fleet/worker deployments":     "managed by Argo CD application apps",
	} {
		if !strings.HasPrefix(reasons[k], want) {
			t.Errorf("the capture left %s as %q, want %q", k, reasons[k], want)
		}
	}

	root := kube.ScopeSource{Source: "Flux Kustomization gitops/root", Object: "Kustomization gitops/root", Namespaces: []string{"shop", "store"}, Blocks: true}
	apps := kube.ScopeSource{Source: "Argo CD application apps", Object: "Application argocd/apps", Namespaces: []string{"fleet"}, Blocks: true}
	shopHeld := []kube.ScopeEntry{
		{Namespaces: []string{"shop"}, Releases: []string{"web"}, Hold: true},
		// Nothing chosen: store is left out whole, and the root reaches it
		// through the HelmRelease it applies, which renders there.
		{Namespaces: []string{"store"}, Hold: true},
	}
	holdRoot := kube.ScopeEntry{Namespaces: []string{"gitops"}, Hold: true, Objects: []string{"Kustomization/root", "GitRepository/root"}}
	fleetHeld := []kube.ScopeEntry{{Namespaces: []string{"fleet"}, Hold: true, Objects: []string{"ConfigMap/settings"}}}
	holdApps := kube.ScopeEntry{Namespaces: []string{"argocd"}, Hold: true, Objects: []string{"Application/apps"}}
	accepted := root
	accepted.Accepted, accepted.Blocks = true, false

	for _, row := range []struct {
		name string
		sc   kube.Scope
		want []kube.ScopeSource
		held string // an object the row holds, and how
	}{
		// The root, brought not held beside a hold, applies into both
		// namespaces the scope narrows: refused. The Kustomization applied
		// by hand applies only into edge, which the scope does not narrow,
		// and is not named.
		{"root brought unheld beside a hold", kube.Scope{Narrow: shopHeld}, []kube.ScopeSource{root}, ""},
		// Held, it makes nothing: not refused.
		{"root held", kube.Scope{Narrow: append(append([]kube.ScopeEntry{}, shopHeld...), holdRoot)}, []kube.ScopeSource{}, "Kustomization gitops/root: suspended"},
		// Accepted by name: listed, and not refused.
		{"root accepted", kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/gitops/root"}}, []kube.ScopeSource{accepted}, ""},
		// An Argo CD application that manages itself.
		{"argo root brought unheld beside a hold", kube.Scope{Narrow: fleetHeld}, []kube.ScopeSource{apps}, ""},
		{"argo root held", kube.Scope{Narrow: append(append([]kube.ScopeEntry{}, fleetHeld...), holdApps)}, []kube.ScopeSource{}, "Application argocd/apps: automated sync off"},
		// A source that applies only into namespaces the scope does not
		// narrow is not refused: the root and the Kustomization of edge are
		// brought not held, and apply into shop, store and edge, none of
		// which this scope narrows.
		{"sources applying only where the scope does not narrow", kube.Scope{Narrow: []kube.ScopeEntry{{Namespaces: []string{"fleet"}, Hold: true, Objects: []string{"ConfigMap/settings"}}, holdApps}}, []kube.ScopeSource{}, ""},
		// A scope that holds nothing is not affected, though the root
		// still makes what it makes there (stillMade says so).
		{"a scope that holds nothing", kube.Scope{Narrow: []kube.ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"web"}}}}, []kube.ScopeSource{}, ""},
	} {
		_, rep, err := kube.Narrow(snap, row.sc)
		if err != nil {
			t.Errorf("%s: %v", row.name, err)
			continue
		}
		if !reflect.DeepEqual(rep.Sources, row.want) {
			t.Errorf("%s: sources not held\n got %+v\nwant %+v", row.name, rep.Sources, row.want)
		}
		if row.held != "" {
			found := false
			for _, h := range rep.Held {
				found = found || h.Object+": "+h.How == row.held
			}
			if !found {
				t.Errorf("%s: %s is not held: %+v", row.name, row.held, rep.Held)
			}
		}
		if row.name == "a scope that holds nothing" && len(rep.StillMade) == 0 {
			t.Errorf("%s: the root's note is gone too", row.name)
		}
	}

	// What sourcesRunning names is a source by its object, whole: a
	// pattern, a source that is held or not there, and one in a scope
	// that holds nothing are errors.
	for _, bad := range []struct {
		sc   kube.Scope
		want string
	}{
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/gitops/*"}}, "with no pattern"},
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/root"}}, "is not Kind/namespace/name"},
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/gitops/edge"}}, "no such source is brought not held"},
		{kube.Scope{Narrow: append(append([]kube.ScopeEntry{}, shopHeld...), holdRoot), SourcesRunning: []string{"Kustomization/gitops/root"}}, "no such source is brought not held"},
		{kube.Scope{Narrow: []kube.ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"web"}}}, SourcesRunning: []string{"Kustomization/gitops/root"}}, "the scope holds nothing"},
	} {
		if _, _, err := kube.Narrow(snap, bad.sc); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("sourcesRunning %q: %v, want %q", bad.sc.SourcesRunning, err, bad.want)
		}
	}
}
