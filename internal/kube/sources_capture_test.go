package kube_test

import (
	"context"
	"reflect"
	"slices"
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
		"ImageUpdateAutomation imaging/bump", "ImageRepository imaging/images", "ImageRepository imaging/scan", "Provider imaging/chat", "Alert imaging/alerts",
		"Receiver imaging/hook", "ImagePolicy imaging/pick", "Kustomization flux2/flux2", "Kustomization gitops/decoy", "ApplicationSet argocd/rolling",
		"ApplicationSet argo2/set2", "Application apps2/svc", "Deployment legacy2ns/svcapp",
		"HelmRepository imaging/charts", "Bucket imaging/store",
		"HelmRepository charts/ocirepo", "HelmRelease apprel/app", "HelmChart charts/manual"} {
		if !have[k] {
			t.Errorf("the capture did not take %s", k)
		}
	}
	for _, k := range []string{"Application argocd/gen", "Application argo2/gen2", "ImageUpdateAutomation flux2/autobump", "Provider flux2/f2chat", "ImageUpdateAutomation botns/gitbump", "ApplicationSet argo2/decoy", "OCIRepository flux2/oci", "HelmChart charts/apprel-app"} {
		if have[k] {
			t.Errorf("the capture took %s, which it leaves to what makes it", k)
		}
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
		"gitops/payments helmreleases":          "applied by Flux Kustomization gitops/root",
		"store/payments deployments":            "rendered by Flux HelmRelease gitops/payments",
		"shop/cart deployments":                 "applied by Flux Kustomization gitops/root",
		"edge/proxy deployments":                "applied by Flux Kustomization gitops/edge",
		"fleet/worker deployments":              "managed by Argo CD application apps",
		"argocd/gen applications":               "owned by ApplicationSet/set",
		"setns/genapp deployments":              "managed by Argo CD application gen",
		"quietns/q deployments":                 "applied by Flux Kustomization gitops/quiet",
		"manualns/m deployments":                "managed by Argo CD application manual",
		"flux2/autobump imageupdateautomations": "applied by Flux Kustomization flux2/flux2",
		"flux2/f2chat providers":                "applied by Flux Kustomization flux2/flux2",
		"botns/gitbump imageupdateautomations":  "applied by Flux Kustomization flux2/flux2",
		"flux2/oci ocirepositories":             "applied by Flux Kustomization flux2/flux2",
		"charts/apprel-app helmcharts":          "rendered by Flux HelmRelease apprel/app",
		"gitops/other helmreleases":             "applied by Flux Kustomization gitops/edge",
		"argo2/gen2 applications":               "owned by ApplicationSet/set2",
		"setns2/genapp2 deployments":            "managed by Argo CD application gen2",
		"argo2/decoy applicationsets":           "applied by Flux Kustomization gitops/decoy",
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
	legacy2 := src("Argo CD application apps2/svc", "Application apps2/svc", "legacy2ns")
	decoy := src("Flux Kustomization gitops/decoy", "Kustomization gitops/decoy", "argo2")
	// Acting outside, they are refused under any hold, wherever they are:
	// brought, or applied by a source (the second root, whose Git path
	// applies image automation and a Provider, one of them in a namespace
	// of its own). The suspended ImageRepository is not, nor the
	// ImagePolicy, which only chooses a tag.
	const commits, sends = "it commits and pushes image updates to its Git repository", "it sends what it is given to its chat, webhook or Git host"
	pulls := "it pulls its chart from the chart source's repository or registry with that source's credentials"
	appRelease := kube.ScopeSource{Source: "Flux HelmRelease apprel/app", Object: "HelmRelease apprel/app", Namespaces: []string{}, Outside: []string{"HelmChart charts/apprel-app (" + pulls + ")"}, Blocks: true}
	manualChart := kube.ScopeSource{Source: "Flux HelmChart charts/manual", Object: "HelmChart charts/manual", Namespaces: []string{}, Reaches: pulls, Blocks: true}
	outside := []kube.ScopeSource{
		{Source: "Flux notification Alert imaging/alerts", Object: "Alert imaging/alerts", Namespaces: []string{}, Reaches: "it sends the cluster's events to its Provider", Blocks: true},
		{Source: "Flux ImageUpdateAutomation imaging/bump", Object: "ImageUpdateAutomation imaging/bump", Namespaces: []string{}, Reaches: commits, Blocks: true},
		{Source: "Flux ImageRepository imaging/scan", Object: "ImageRepository imaging/scan", Namespaces: []string{}, Reaches: "it scans its image registry with the registry's credentials", Blocks: true},
		{Source: "Flux Kustomization flux2/flux2", Object: "Kustomization flux2/flux2", Namespaces: []string{}, Outside: []string{
			"ImageUpdateAutomation botns/gitbump (" + commits + ")", "ImageUpdateAutomation flux2/autobump (" + commits + ")",
			"OCIRepository flux2/oci (it pulls its artifact from its OCI registry with the source's credentials)", "Provider flux2/f2chat (" + sends + ")"}, Blocks: true},
		// Flux's sources that fetch, made by hand.
		{Source: "Flux HelmRepository imaging/charts", Object: "HelmRepository imaging/charts", Namespaces: []string{}, Reaches: "it fetches its chart repository or registry with the source's credentials", Blocks: true},
		{Source: "Flux Bucket imaging/store", Object: "Bucket imaging/store", Namespaces: []string{}, Reaches: "it fetches from its storage bucket with the source's credentials", Blocks: true},
		// The HelmRelease made of a HelmRepository of type oci, for the
		// HelmChart helm-controller made for it (skipped, rendered by it),
		// and a HelmChart made by hand. The HelmRepository of type oci is
		// brought not held in every row, and is never refused:
		// source-controller makes it static and never fetches with it.
		appRelease, manualChart,
		{Source: "Flux notification Provider imaging/chat", Object: "Provider imaging/chat", Namespaces: []string{}, Reaches: sends, Blocks: true},
		{Source: "Flux notification Receiver imaging/hook", Object: "Receiver imaging/hook", Namespaces: []string{}, Reaches: "it takes webhooks from outside, which have the sources it names reconcile", Blocks: true},
	}
	holdOutside := []kube.ScopeEntry{
		{Namespaces: []string{"imaging"}, Hold: true, Objects: []string{"ImageUpdateAutomation/bump", "ImageRepository/images", "ImageRepository/scan", "Provider/chat", "Alert/alerts", "Receiver/hook", "HelmRepository/charts", "Bucket/store"}},
		{Namespaces: []string{"flux2"}, Hold: true, Objects: []string{"Kustomization/flux2"}},
		{Namespaces: []string{"charts"}, Hold: true, Objects: []string{"HelmRepository/ocirepo", "HelmChart/manual"}},
		{Namespaces: []string{"apprel"}, Hold: true, Objects: []string{"HelmRelease/app"}},
	}
	// drop is a list without the objects named, and with those given.
	drop := func(l []kube.ScopeSource, objects []string, add ...kube.ScopeSource) []kube.ScopeSource {
		out := append([]kube.ScopeSource{}, add...)
		for _, x := range l {
			if !slices.Contains(objects, x.Object) {
				out = append(out, x)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Object < out[j].Object })
		return out
	}
	holdCharts := kube.ScopeEntry{Namespaces: []string{"charts"}, Hold: true, Objects: []string{"HelmRepository/ocirepo", "HelmChart/manual"}}
	// The GitRepository the root reads fetches too: brought not held in
	// every scope that does not narrow its namespace.
	gitRoot := kube.ScopeSource{Source: "Flux GitRepository gitops/root", Object: "GitRepository gitops/root", Namespaces: []string{}, Reaches: "it fetches its Git repository with the source's credentials", Blocks: true}
	withRootHeld := func(l ...kube.ScopeSource) []kube.ScopeSource {
		out := append(append([]kube.ScopeSource{}, l...), outside...)
		sort.Slice(out, func(i, j int) bool { return out[i].Object < out[j].Object })
		return out
	}
	with := func(l ...kube.ScopeSource) []kube.ScopeSource { return withRootHeld(append(l, gitRoot)...) }
	gitRootAccepted := gitRoot
	gitRootAccepted.Accepted, gitRootAccepted.Blocks = true, false
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
		{"root held", kube.Scope{Narrow: append(entries(shopHeld...), holdRoot)}, withRootHeld(), "Kustomization gitops/root: suspended"},
		// Left out by the scope (its namespace narrowed, and it not
		// chosen), it is not brought, and makes nothing.
		{"root left out by the scope", kube.Scope{Narrow: append(entries(shopHeld...), kube.ScopeEntry{Namespaces: []string{"gitops"}, Hold: true, Objects: []string{"GitRepository/root"}})}, withRootHeld(), "GitRepository gitops/root: suspended"},
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
		// The HelmRepository of type oci held, and its HelmRelease not:
		// the release is refused for the HelmChart it makes, which pulls
		// (and for charts, now narrowed, where that chart is). The hold of
		// the repository stops nothing, and the plan says so.
		{"oci HelmRepository held, its release not", kube.Scope{Narrow: append(entries(shopHeld...), holdCharts)},
			drop(with(root), []string{"HelmChart charts/manual", "HelmRelease apprel/app"},
				kube.ScopeSource{Source: appRelease.Source, Object: appRelease.Object, Namespaces: []string{"charts"}, Outside: appRelease.Outside, Blocks: true}), "HelmRepository charts/ocirepo: suspended (a HelmRepository of type oci fetches nothing; its HelmCharts pull)"},
		{"oci HelmRepository held, the chart made by hand with it", kube.Scope{Narrow: append(entries(shopHeld...), holdCharts)},
			drop(with(root), []string{"HelmChart charts/manual", "HelmRelease apprel/app"},
				kube.ScopeSource{Source: appRelease.Source, Object: appRelease.Object, Namespaces: []string{"charts"}, Outside: appRelease.Outside, Blocks: true}), "HelmChart charts/manual: suspended"},
		// The release held: helm-controller does not reconcile a
		// suspended one, so it makes no chart, and it is not refused.
		{"helm release held", kube.Scope{Narrow: append(entries(shopHeld...), kube.ScopeEntry{Namespaces: []string{"apprel"}, Hold: true, Objects: []string{"HelmRelease/app"}})},
			drop(with(root), []string{"HelmRelease apprel/app"}), "HelmRelease apprel/app: suspended"},
		// A HelmChart in the snapshot, accepted by name.
		{"helm chart accepted", kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"HelmChart/charts/manual"}},
			drop(with(root), []string{"HelmChart charts/manual"}, kube.ScopeSource{Source: manualChart.Source, Object: manualChart.Object, Namespaces: []string{}, Reaches: pulls, Accepted: true}), ""},
		{"outside held", kube.Scope{Narrow: append(append(entries(shopHeld...), holdRoot), holdOutside...)}, []kube.ScopeSource{}, "Kustomization flux2/flux2: suspended"},
		// An Application an ApplicationSet generates, the ApplicationSet
		// left out: nothing makes what it manages. The ApplicationSet of
		// another name in its namespace is not it (the Kustomization that
		// applies that one applies into argo2, and is refused for that
		// alone).
		{"applicationset left out", kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"setns2"}, Hold: true}, kube.ScopeEntry{Namespaces: []string{"argo2"}, Hold: true})}, with(decoy), ""},
		// Argo CD 2's label for an application outside Argo CD's own
		// namespace is namespace_name.
		{"application tracked by app.kubernetes.io/instance as namespace_name", kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"legacy2ns"}, Hold: true})}, with(legacy2), ""},
		// Sources that apply only into namespaces the scope does not
		// narrow are not refused: the root and the Kustomization of edge
		// are brought not held, and apply into shop, store and edge, none
		// of which this scope narrows.
		// The root's GitRepository is brought too, and fetches: accepted
		// by name, it is listed and not refused.
		{"sources applying only where the scope does not narrow", kube.Scope{Narrow: append(entries(fleetHeld, holdApps), holdOutside...), SourcesRunning: []string{"GitRepository/gitops/root"}}, []kube.ScopeSource{gitRootAccepted}, ""},
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
	// Nor one whose RollingSync strategy has its controller sync what it
	// makes, whatever their sync policy.
	if _, _, err := kube.Narrow(snap, kube.Scope{Narrow: entries(kube.ScopeEntry{Namespaces: []string{"argocd"}, Hold: true, Objects: []string{"ApplicationSet/rolling"}})}); err == nil || !strings.Contains(err.Error(), "ApplicationSet argocd/rolling: its spec.strategy RollingSync has the ApplicationSet controller sync") {
		t.Errorf("holding an ApplicationSet with RollingSync: %v", err)
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
		// What a source applies is not brought: the error names the source.
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"ImageUpdateAutomation/flux2/autobump"}}, "is not brought: it is applied by Flux Kustomization flux2/flux2, which makes it again once it runs. Name that in sourcesRunning (Kustomization/flux2/flux2), or hold it"},
		// A HelmChart is made by its HelmRelease, not applied.
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"HelmChart/charts/apprel-app"}}, "is not brought: it is made by Flux HelmRelease apprel/app, which makes it again once it runs. Name that in sourcesRunning (HelmRelease/apprel/app), or hold it"},
		// A HelmRepository of type oci is never refused, so there is
		// nothing to accept.
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"HelmRepository/charts/ocirepo"}}, "no such object is brought not held"},
		{kube.Scope{Narrow: shopHeld, SourcesRunning: []string{"ImageUpdateAutomation/flux2/auto"}}, "no such object is brought not held"},
	} {
		if _, _, err := kube.Narrow(snap, bad.sc); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("sourcesRunning %q: %v, want %q", bad.sc.SourcesRunning, err, bad.want)
		}
	}
}
