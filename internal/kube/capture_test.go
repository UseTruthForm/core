package kube

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/openapi"
	"k8s.io/client-go/openapi/openapitest"
	clienttesting "k8s.io/client-go/testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// Helm history is listed once per release. A managed add-on moves to a new
// revision every few seconds while keeping the same number of them; listed
// by revision, the coverage of an unchanged cluster differed between two
// captures. The count stays per object, and a Secret that only has Helm's
// type is still listed by its own name (review of #33).
func TestHelmHistoryIsListedPerRelease(t *testing.T) {
	secrets := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	history := func(ns, name, release string) *unstructured.Unstructured {
		labels := map[string]any{"owner": "helm"}
		if release != "" {
			labels["name"] = release
		}
		return &unstructured.Unstructured{Object: k8sObj("Secret", ns, name, map[string]any{"labels": labels}, map[string]any{"type": "helm.sh/release.v1"})}
	}
	capture := func(revs ...int) snapshot.Snapshot {
		t.Helper()
		var objs []runtime.Object
		for _, r := range revs {
			// In a system namespace, so skipped for that reason first.
			objs = append(objs, history("kube-system", fmt.Sprintf("sh.helm.release.v1.overlay-upgrade.v%d", r), "overlay-upgrade"))
		}
		objs = append(objs,
			// The same release name in two namespaces, one without Helm's label.
			history("shop", "sh.helm.release.v1.web.v3", "web"), history("shop", "sh.helm.release.v1.web.v4", ""),
			history("other", "sh.helm.release.v1.web.v1", "web"),
			// Helm's type, but not Helm's: a label naming another release,
			// a name without the prefix or without a revision.
			history("shop", "sh.helm.release.v1.db.v1", "web"),
			history("shop", "db-creds", ""),
			history("shop", "sh.helm.release.v1.app", ""))
		dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{secrets: "SecretList"}, objs...)
		var snap snapshot.Snapshot
		cov := &snapshot.Coverage{}
		if err := captureType(context.Background(), &Clients{Dynamic: dyn}, Policy{}, secrets, "Secret", cov, &snap, newOwnership()); err != nil {
			t.Fatal(err)
		}
		sort.Slice(snap.Skips, func(i, j int) bool {
			return snap.Skips[i].Namespace+"/"+snap.Skips[i].Name < snap.Skips[j].Namespace+"/"+snap.Skips[j].Name
		})
		snap.Coverage = []snapshot.Coverage{*cov}
		return snap
	}
	first, second := capture(430432, 430433), capture(430433, 430434)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("coverage moved with the revision:\n%+v\n%+v", first, second)
	}
	var names []string
	for _, s := range first.Skips {
		names = append(names, s.Namespace+"/"+s.Name)
	}
	// A release's history as its family (.v*); a Secret of Helm's type Helm
	// did not name as its own (no revision, or labelled for another
	// release) by its own name.
	want := []string{
		"kube-system/sh.helm.release.v1.overlay-upgrade.v*",
		"other/sh.helm.release.v1.web.v*",
		"shop/db-creds",
		"shop/sh.helm.release.v1.app",
		"shop/sh.helm.release.v1.db.v1",
		"shop/sh.helm.release.v1.web.v*",
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("skips\n%v\nwant\n%v", names, want)
	}
	total := 0
	for _, n := range first.Coverage[0].Skipped {
		total += n
	}
	if total != 8 || first.Coverage[0].Skipped["in system namespace kube-system"] != 2 {
		t.Errorf("coverage counts %v, want 8 objects, 2 of them in kube-system", first.Coverage[0].Skipped)
	}
	if len(first.Objects) != 0 {
		t.Errorf("history captured: %v", first.Objects)
	}
}

// Through the capture itself: an add-on identical to the baseline except
// for a withheld credential is captured, not skipped as the
// distribution's (review of #41).
func TestWithheldIsCapturedDespiteTheBaseline(t *testing.T) {
	deps := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	mk := func(token string) map[string]any {
		return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "addon", "namespace": "addons"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "a", "image": "x",
				"env": []any{map[string]any{"name": "API_TOKEN", "value": token}}}}}}}}
	}
	base := mk("distribution-default")
	normalize("apps", "deployments", base)
	p := Policy{}.WithBaseline(snapshot.Snapshot{Objects: []snapshot.Object{{Body: base}}}, "sha256:b")
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{deps: "DeploymentList"},
		&unstructured.Unstructured{Object: mk("changed-by-someone")})
	var snap snapshot.Snapshot
	cov := &snapshot.Coverage{}
	if err := captureType(context.Background(), &Clients{Dynamic: dyn}, p, deps, "Deployment", cov, &snap, newOwnership()); err != nil {
		t.Fatal(err)
	}
	if len(snap.Objects) != 1 {
		t.Fatalf("captured %d objects, skips %+v: the add-on must be captured", len(snap.Objects), snap.Skips)
	}
}

// What controllers make is recorded once per root owner. Between two
// captures of an unchanged cluster every pod and Job was replaced under a
// new name (a node reimage, a scheduled run); the skips and coverage of the
// two are the same.
func TestOwnedObjectsAreListedPerRootOwner(t *testing.T) {
	pods := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	jobs := schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
	ownerAPI := map[string]string{"DaemonSet": "apps/v1", "Job": "batch/v1", "ScaledJob": "keda.sh/v1alpha1"}
	owned := func(apiVersion, kind, ns, name, ownerKind, ownerName string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": apiVersion, "kind": kind,
			"metadata": map[string]any{"namespace": ns, "name": name, "ownerReferences": []any{
				map[string]any{"apiVersion": ownerAPI[ownerKind], "kind": ownerKind, "name": ownerName, "controller": true},
			}},
		}}
	}
	capture := func(suffix string) snapshot.Snapshot {
		var objs []runtime.Object
		for i := 0; i < 3; i++ {
			objs = append(objs, owned("v1", "Pod", "web", fmt.Sprintf("agent-%s%d", suffix, i), "DaemonSet", "agent"),
				// In kube-system too, where most of a cluster's DaemonSets are.
				owned("v1", "Pod", "kube-system", fmt.Sprintf("proxy-%s%d", suffix, i), "DaemonSet", "proxy"))
		}
		for i := 0; i < 2; i++ {
			job := fmt.Sprintf("report-%s%d", suffix, i)
			objs = append(objs, owned("batch/v1", "Job", "web", job, "ScaledJob", "report"),
				owned("v1", "Pod", "web", job+"-x", "Job", job))
		}
		dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
			map[schema.GroupVersionResource]string{pods: "PodList", jobs: "JobList"}, objs...)
		snap := snapshot.Snapshot{}
		own := newOwnership()
		// Pods first: their owners are only known once the Jobs are listed.
		for _, r := range []struct {
			gvr  schema.GroupVersionResource
			kind string
		}{{pods, "Pod"}, {jobs, "Job"}} {
			cov := snapshot.Coverage{Resource: resourceID(r.gvr), Kind: r.kind}
			if err := captureType(context.Background(), &Clients{Dynamic: dyn}, Policy{}, r.gvr, r.kind, &cov, &snap, own); err != nil {
				t.Fatal(err)
			}
			snap.Coverage = append(snap.Coverage, cov)
		}
		own.record(&snap)
		sort.Slice(snap.Skips, func(i, j int) bool {
			return snap.Skips[i].Resource+snap.Skips[i].Namespace+snap.Skips[i].Reason < snap.Skips[j].Resource+snap.Skips[j].Namespace+snap.Skips[j].Reason
		})
		return snap
	}
	first, second := capture("a"), capture("b")
	if !reflect.DeepEqual(first.Skips, second.Skips) || !reflect.DeepEqual(first.Coverage, second.Coverage) {
		t.Errorf("an unchanged cluster captured differently:\n%+v\n%+v\n%+v\n%+v", first.Skips, second.Skips, first.Coverage, second.Coverage)
	}
	want := []snapshot.Skip{
		{Resource: "batch/v1/jobs", Namespace: "web", Name: "*", Reason: "owned by ScaledJob/report, whose controller recreates it"},
		{Resource: "core/v1/pods", Namespace: "kube-system", Name: "*", Reason: "owned by DaemonSet/proxy, whose controller recreates it"},
		{Resource: "core/v1/pods", Namespace: "web", Name: "*", Reason: "owned by DaemonSet/agent, whose controller recreates it"},
		{Resource: "core/v1/pods", Namespace: "web", Name: "*", Reason: "owned by ScaledJob/report, whose controller recreates it"},
	}
	if !reflect.DeepEqual(first.Skips, want) {
		t.Errorf("skips\n got  %+v\n want %+v", first.Skips, want)
	}
}

// An owner is found by its API group as well as its kind and name: a
// Knative Service owns a Configuration, which owns pods, next to a core
// Service of the same name (review of #46).
func TestRootOwnerTellsGroupsApart(t *testing.T) {
	own := newOwnership()
	own.owner["shop||Service|web"] = [3]string{"serving.knative.dev", "Route", "web"}
	own.owner["shop|serving.knative.dev|Route|web"] = [3]string{"serving.knative.dev", "Service", "web"}
	own.owner["shop|serving.knative.dev|Configuration|web"] = [3]string{"serving.knative.dev", "Service", "web"}
	if k, n := own.root("shop", "serving.knative.dev", "Configuration", "web"); k+"/"+n != "Service/web" {
		t.Errorf("root %s/%s, want the Knative Service/web", k, n)
	}
	if k, _ := own.root("shop", "", "Service", "web"); k != "Service" {
		t.Errorf("the core Service web resolved to %s", k)
	}
}

// The capture finds what a Kustomization that applies itself reads from,
// in its own namespace unless the reference names another, and keeps it.
func TestFluxRootSourcesAreCaptured(t *testing.T) {
	ks := schema.GroupVersionResource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}
	repos := schema.GroupVersionResource{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}
	applied := func(by string) map[string]any {
		return map[string]any{"kustomize.toolkit.fluxcd.io/name": by, "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}
	}
	obj := func(apiVersion, kind, ns, name, by string, spec map[string]any) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind,
			"metadata": map[string]any{"namespace": ns, "name": name, "labels": applied(by)}, "spec": spec}}
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{ks: "KustomizationList", repos: "GitRepositoryList"},
		obj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "flux-system", "flux-system",
			map[string]any{"path": "./clusters/one", "sourceRef": map[string]any{"kind": "GitRepository", "name": "fleet"}}),
		// Applied by the root, not by itself: what it reads from is the root's to recreate.
		obj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "apps", "flux-system",
			map[string]any{"sourceRef": map[string]any{"kind": "GitRepository", "name": "apps", "namespace": "flux-system"}}),
		obj("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "fleet", "flux-system", map[string]any{"url": "https://example.com/fleet.git"}),
		obj("source.toolkit.fluxcd.io/v1", "GitRepository", "flux-system", "apps", "flux-system", map[string]any{"url": "https://example.com/apps.git"}),
	)
	c := &Clients{Dynamic: dyn}
	verbs := metav1.Verbs{"list", "create"}
	lists := []*metav1.APIResourceList{
		{GroupVersion: "kustomize.toolkit.fluxcd.io/v1", APIResources: []metav1.APIResource{{Name: "kustomizations", Kind: "Kustomization", Verbs: verbs}, {Name: "kustomizations/status", Kind: "Kustomization", Verbs: verbs}}},
	}
	if roots := fluxRoots(context.Background(), c, lists); len(roots) != 1 || !roots["GitRepository|flux-system|fleet"] {
		t.Fatalf("roots: %v", roots)
	}
	// Through Capture itself, which looks for the roots before it reads any type.
	lists = append(lists, &metav1.APIResourceList{GroupVersion: "source.toolkit.fluxcd.io/v1", APIResources: []metav1.APIResource{{Name: "gitrepositories", Kind: "GitRepository", Verbs: verbs}}})
	c.Discovery = preferred{FakeDiscovery: &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}}, lists: lists}
	snap, err := Capture(context.Background(), c, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	var kept, skipped []string
	for _, o := range snap.Objects {
		kept = append(kept, o.Kind()+" "+o.Name())
	}
	for _, sk := range snap.Skips {
		skipped = append(skipped, sk.Name)
	}
	sort.Strings(kept)
	sort.Strings(skipped)
	if strings.Join(kept, ", ") != "GitRepository fleet, Kustomization flux-system" || strings.Join(skipped, ", ") != "apps, apps" {
		t.Errorf("kept %v, skipped %v", kept, skipped)
	}
	// A cluster without Flux has no roots, and nothing is asked of it.
	if r := fluxRoots(context.Background(), &Clients{}, []*metav1.APIResourceList{{GroupVersion: "apps/v1", APIResources: []metav1.APIResource{{Name: "deployments", Verbs: verbs}}}}); len(r) != 0 {
		t.Errorf("no Flux: roots %v", r)
	}
}

// preferred is a fake discovery that serves a list of resource types.
type preferred struct {
	*fakediscovery.FakeDiscovery
	lists []*metav1.APIResourceList
}

func (p preferred) ServerPreferredResources() ([]*metav1.APIResourceList, error) { return p.lists, nil }

// No schemas published: Capture says so for each type, after the objects.
func (p preferred) OpenAPIV3() openapi.Client { return openapitest.NewFakeClient() }

// What a label names is looked for only where the answer is known. A type
// the cluster serves and holds none of, or does not serve, has no such
// source, and what is labelled as its is captured. One whose group could
// not be discovered, whose list fails, or that cannot be listed, is not
// known: what is labelled as its is left to it, as it was before, and not
// captured whole on a failed read.
func TestSourcesAreKnownOnlyWhereTheyWereRead(t *testing.T) {
	ks := schema.GroupVersionResource{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}
	apps := schema.GroupVersionResource{Group: "argoproj.io", Version: "v1alpha1", Resource: "applications"}
	obj := func(apiVersion, kind, ns, name string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"namespace": ns, "name": name}}}
	}
	world := func() *dynamicfake.FakeDynamicClient {
		return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
			map[schema.GroupVersionResource]string{ks: "KustomizationList", apps: "ApplicationList"},
			obj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "apps"),
			obj("argoproj.io/v1alpha1", "Application", "argocd", "shop"),
			obj("argoproj.io/v1alpha1", "Application", "team-a", "web"))
	}
	verbs := metav1.Verbs{"list", "create"}
	lists := func(ksVerbs metav1.Verbs) []*metav1.APIResourceList {
		return []*metav1.APIResourceList{
			{GroupVersion: "kustomize.toolkit.fluxcd.io/v1", APIResources: []metav1.APIResource{{Name: "kustomizations", Kind: "Kustomization", Verbs: ksVerbs}}},
			{GroupVersion: "argoproj.io/v1alpha1", APIResources: []metav1.APIResource{{Name: "applications", Kind: "Application", Verbs: verbs}}},
		}
	}
	flux := func(tool, ns, name string) map[string]any {
		l := map[string]any{tool + ".toolkit.fluxcd.io/name": name}
		if ns != "" {
			l[tool+".toolkit.fluxcd.io/namespace"] = ns
		}
		return map[string]any{"labels": l}
	}
	argo := func(app string) map[string]any {
		return map[string]any{"labels": map[string]any{"argocd.argoproj.io/instance": app}}
	}
	tracked := func(app string) map[string]any {
		return map[string]any{"annotations": map[string]any{"argocd.argoproj.io/tracking-id": app + ":/ConfigMap:shop/x"}}
	}
	ctx := context.Background()

	read := gitOpsSources(ctx, &Clients{Dynamic: world()}, lists(verbs), nil)
	for name, c := range map[string]struct {
		md      map[string]any
		missing bool
	}{
		"a Kustomization that is there":            {flux("kustomize", "gitops", "apps"), false},
		"one of its name with no namespace given":  {flux("kustomize", "", "apps"), false},
		"one that is not":                          {flux("kustomize", "gitops", "anything"), true},
		"one of its name in another namespace":     {flux("kustomize", "other", "apps"), true},
		"a HelmRelease, which no type serves":      {flux("helm", "gitops", "rel"), true},
		"an application that is there":             {argo("shop"), false},
		"one outside Argo CD's namespace, by both": {argo("team-a_web"), false},
		"one tracked by annotation":                {tracked("shop"), false},
		"an application that is not":               {argo("anything"), true},
		"one tracked that is not":                  {tracked("anything"), true},
		"a Crossplane composite, not looked for":   {map[string]any{"labels": map[string]any{"crossplane.io/composite": "x"}}, false},
		"no label":                                 {map[string]any{}, false},
	} {
		if got := read.missing(c.md); got != c.missing {
			t.Errorf("%s: missing %v, want %v", name, got, c.missing)
		}
	}

	failing := world()
	failing.PrependReactor("list", "kustomizations", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})
	for name, s := range map[string]*clusterSources{
		"not looked for":            nil,
		"the list failed":           gitOpsSources(ctx, &Clients{Dynamic: failing}, lists(verbs), nil),
		"the type cannot be listed": gitOpsSources(ctx, &Clients{Dynamic: world()}, lists(metav1.Verbs{"get", "create"}), nil),
		"its group was not discovered": gitOpsSources(ctx, &Clients{Dynamic: world()}, lists(verbs)[1:],
			map[string]bool{"kustomize.toolkit.fluxcd.io": true}),
	} {
		if s.missing(flux("kustomize", "gitops", "anything")) {
			t.Errorf("%s: a Kustomization was said to be missing", name)
		}
	}
	// And through the policy: captured where it is missing, left to its
	// source where it is there or not known.
	labelled := k8sObj("ClusterRoleBinding", "", "admins", flux("kustomize", "gitops", "anything"), nil)
	if r := (Policy{sources: read}).skipReason("rbac.authorization.k8s.io", "clusterrolebindings", labelled); r != "" {
		t.Errorf("naming no source: skipped (%s)", r)
	}
	if r := (Policy{}).skipReason("rbac.authorization.k8s.io", "clusterrolebindings", labelled); !strings.Contains(r, "restoring") {
		t.Errorf("sources not known: %q, want it left to its source", r)
	}
	there := k8sObj("ClusterRoleBinding", "", "admins", flux("kustomize", "gitops", "apps"), nil)
	if r := (Policy{sources: read}).skipReason("rbac.authorization.k8s.io", "clusterrolebindings", there); !strings.Contains(r, "restoring") {
		t.Errorf("its source is there: %q, want it left to its source", r)
	}
}
