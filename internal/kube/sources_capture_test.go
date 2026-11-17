package kube_test

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
)

// TestUnheldSourcesOfARealCapture asks, of a snapshot a capture wrote from
// a real API server, which objects a scope that holds something brings
// without holding them, and refuses a restore for: a GitOps source that
// applies into a namespace it narrows (restored as it is, it syncs its Git
// path into the drill target and starts what the scope held back), and
// Flux's objects that act outside the cluster. A restore is refused for
// one unless it is held, already stopped, or accepted by name. The shapes
// (a Kustomization that applies itself, what it applies, what that
// renders, an Argo CD application that manages itself, an ApplicationSet
// and what it generates) are the capture's, not written by hand.
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
	for _, k := range []string{"Kustomization gitops/root", "GitRepository gitops/root", "Kustomization gitops/edge", "Kustomization gitops/quiet",
		"Application argocd/apps", "Application argocd/legacy", "Application argocd/manual", "ApplicationSet argocd/set",
		"Deployment shop/web", "Deployment legacyns/legacyapp", "Deployment helmns/legacy", "ConfigMap fleet/settings",
		"ImageUpdateAutomation imaging/bump", "ImageRepository imaging/images", "Provider imaging/chat", "Alert imaging/alerts"} {
		if !have[k] {
			t.Errorf("the capture did not take %s", k)
		}
	}
	if have["Application argocd/gen"] {
		t.Errorf("the capture took the Application an ApplicationSet generates")
	}
	reasons := map[string]string{}
	for _, sk := range snap.Skips {
		r := sk.Resource[strings.LastIndex(sk.Resource, "/")+1:]
		reasons[sk.Namespace+"/"+sk.Name+" "+r] = sk.Reason
		for _, n := range sk.Names {
			reasons[sk.Namespace+"/"+n+" "+r] = sk.Reason
		}
	}
	for k, want := range map[string]string{
		"gitops/payments helmreleases": "applied by Flux Kustomization gitops/root",
		"store/payments deployments":   "rendered by Flux HelmRelease gitops/payments",
		"shop/cart deployments":        "applied by Flux Kustomization gitops/root",
		"edge/proxy deployments":       "applied by Flux Kustomization gitops/edge",
		"fleet/worker deployments":     "managed by Argo CD application apps",
		"argocd/gen applications":      "owned by ApplicationSet/set",
		"setns/genapp deployments":     "managed by Argo CD application gen",
		"quietns/q deployments":        "applied by Flux Kustomization gitops/quiet",
		"manualns/m deployments":       "managed by Argo CD application manual",
	} {
		if !strings.HasPrefix(reasons[k], want) {
			t.Errorf("the capture left %s as %q, want %q", k, reasons[k], want)
		}
	}

	src := func(source, object string, nss ...string) kube.ScopeSource {
		if nss == nil {
			nss = []string{}
		}
		return kube.ScopeSource{Source: source, Object: object, Namespaces: nss, Blocks: true}
	}
	root := src("Flux Kustomization gitops/root", "Kustomization gitops/root", "shop", "store")
	apps := src("Argo CD application argocd/apps", "Application argocd/apps", "fleet")
	set := src("Argo CD ApplicationSet argocd/set", "ApplicationSet argocd/set", "setns")
	legacy := src("Argo CD application argocd/legacy", "Application argocd/legacy", "legacyns")
	// Acting outside, they are refused under any hold, wherever they are;
	// the ImageRepository is suspended, and is not.
	outside := []kube.ScopeSource{
		{Source: "Flux notification Alert imaging/alerts", Object: "Alert imaging/alerts", Namespaces: []string{}, Reaches: "it sends the cluster's events to its Provider", Blocks: true},
		{Source: "Flux ImageUpdateAutomation imaging/bump", Object: "ImageUpdateAutomation imaging/bump", Namespaces: []string{}, Reaches: "it commits and pushes image updates to its Git repository", Blocks: true},
		{Source: "Flux notification Provider imaging/chat", Object: "Provider imaging/chat", Namespaces: []string{}, Reaches: "it sends what it is given to its chat, webhook or Git host", Blocks: true},
	}
	holdOutside := kube.ScopeEntry{Namespaces: []string{"imaging"}, Hold: true, Objects: []string{"ImageUpdateAutomation/bump", "ImageRepository/images", "Provider/chat", "Alert/alerts"}}
	with := func(l ...kube.ScopeSource) []kube.ScopeSource {
		out := append(append([]kube.ScopeSource{}, l...), outside...)
		sort.Slice(out, func(i, j int) bool { return out[i].Object < out[j].Object })
		return out
	}
	entries := func(es ...kube.ScopeEntry) []kube.ScopeEntry { return es }
	shopHeld := []kube.ScopeEntry{
		{Namespaces: []string{"shop"}, Releases: []string{"web"}, Hold: true},
		// Nothing chosen: store is left out whole, and the root reaches it
		// through the HelmRelease it applies, which renders there.
		{Namespaces: []string{"store"}, Hold: true},
	}
	holdRoot := kube.ScopeEntry{Namespaces: []string{"gitops"}, Hold: true, Objects: []string{"Kustomization/root", "GitRepository/root"}}
	fleetHeld := kube.ScopeEntry{Namespaces: []string{"fleet"}, Hold: true, Objects: []string{"ConfigMap/settings"}}
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
		{"root brought unheld beside a hold", kube.Scope{Narrow: shopHeld}, with(root), ""},
		// Held, it makes nothing: not refused.
		{"root held", kube.Scope{Narrow: append(entries(shopHeld...), holdRoot)}, with(), "Kustomization gitops/root: suspended"},
		// Left out by the scope (its namespace narrowed, and it not
		// chosen), it is not brought, and makes nothing.
		{"root left out by the scope", kube.Scope{Narrow: append(entries(shopHeld...), kube.ScopeEntry{Namespaces: []string{"gitops"}, Hold: true, Objects: []string{"GitRepository/root"}})}, with(), ""},
		// Accepted by name: listed, and not refused.
		{"root accepted", kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/gitops/root"}}, with(accepted), ""},
		// An Argo CD application that manages itself.
		{"argo root brought unheld beside a hold", kube.Scope{Narrow: entries(fleetHeld)}, with(apps), ""},
		{"argo root held", kube.Scope{Narrow: entries(fleetHeld, holdApps)}, with(), "Application argocd/apps: automated sync off"},
		// The Application an ApplicationSet generates is not in the
		// snapshot: the ApplicationSet is what is refused, and held.
		{"applicationset brought unheld beside a hold", kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"setns"}, Hold: true, Objects: []string{"Deployment/setplain"}})}, with(set), ""},
		{"applicationset held", kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"setns"}, Hold: true, Objects: []string{"Deployment/setplain"}}, kube.ScopeEntry{Namespaces: []string{"argocd"}, Hold: true, Objects: []string{"ApplicationSet/set"}})}, with(), "ApplicationSet argocd/set: automated sync off in its template"},
		// Argo CD 2's label, on what the capture took as an object.
		{"application tracked by app.kubernetes.io/instance", kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"legacyns"}, Hold: true})}, with(legacy), ""},
		// The same label on what Helm installed is Helm's.
		{"a Helm release carrying the label", kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"helmns"}, Releases: []string{"legacy"}, Hold: true})}, with(), ""},
		// Already stopped: a suspended root, an application with no
		// automated sync. Neither is refused, and neither needs a hold.
		{"already stopped", kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"quietns"}, Hold: true}, kube.ScopeEntry{Namespaces: []string{"manualns"}, Hold: true})}, with(), ""},
		// What acts outside, held: nothing is refused.
		{"outside held", kube.Scope{Narrow: append(entries(shopHeld...), holdRoot, holdOutside)}, []kube.ScopeSource{}, "ImageUpdateAutomation imaging/bump: suspended"},
		// Sources that apply only into namespaces the scope does not
		// narrow are not refused: the root and the Kustomization of edge
		// are brought not held, and apply into shop, store and edge, none
		// of which this scope narrows.
		{"sources applying only where the scope does not narrow", kube.Scope{Narrow: entries(fleetHeld, holdApps, holdOutside)}, []kube.ScopeSource{}, ""},
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

	// An ApplicationSet whose templatePatch can give what it makes a
	// sync policy cannot be held by its template: refused by name.
	if _, _, err := kube.Narrow(snap, kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"argocd"}, Hold: true, Objects: []string{"ApplicationSet/patched"}})}); err == nil || !strings.Contains(err.Error(), "ApplicationSet argocd/patched: its spec.templatePatch can give") {
		t.Errorf("holding an ApplicationSet with a templatePatch: %v", err)
	}

	// What sourcesRunning names is an object, whole: a pattern, a part of
	// a name, one that is held or not there, and one in a scope that holds
	// nothing are errors.
	for _, bad := range []struct {
		sc   kube.Scope
		want string
	}{
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/gitops/*"}}, "with no pattern"},
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/gitops/ro[o]t"}}, "with no pattern"},
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{`Kustomization/gitops/r\oot`}}, "with no pattern"},
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/root"}}, "is not Kind/namespace/name"},
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/gitops/roo"}}, "no such object is brought not held"},
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"Kustomization/gitops/edge"}}, "no such object is brought not held"},
		{kube.Scope{Narrow: append(entries(shopHeld...), holdRoot), SourcesRunning: []string{"Kustomization/gitops/root"}}, "no such object is brought not held"},
		{kube.Scope{Narrow: []kube.ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"web"}}}, SourcesRunning: []string{"Kustomization/gitops/root"}}, "the scope holds nothing"},
		{kube.Scope{SourcesRunning: []string{"Kustomization/gitops/root"}}, "has sourcesRunning and narrows nothing"},
	} {
		if _, _, err := kube.Narrow(snap, bad.sc); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("sourcesRunning %q: %v, want %q", bad.sc.SourcesRunning, err, bad.want)
		}
	}
}
