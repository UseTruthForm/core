package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// serveCRD defines a namespaced kind on a real API server and waits until
// objects of it can be listed.
func serveCRD(t *testing.T, dyn dynamic.Interface, group, kind, plural string) schema.GroupVersionResource {
	t.Helper()
	ctx := context.Background()
	open := map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}
	crd := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": map[string]any{"name": plural + "." + group},
		"spec": map[string]any{"group": group, "scope": "Namespaced",
			"names":    map[string]any{"kind": kind, "plural": plural, "singular": strings.ToLower(kind), "listKind": kind + "List"},
			"versions": []any{map[string]any{"name": "v1", "served": true, "storage": true, "schema": map[string]any{"openAPIV3Schema": open}}}},
	}}
	crds := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	if _, err := dyn.Resource(crds).Create(ctx, crd, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	gvr := schema.GroupVersionResource{Group: group, Version: "v1", Resource: plural}
	for i := 0; ; i++ {
		if _, err := dyn.Resource(gvr).Namespace("default").List(ctx, metav1.ListOptions{}); err == nil {
			return gvr
		} else if i == 60 {
			t.Fatalf("%s never served: %v", plural, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// rootFlipWorld is a real API server, a namespace, and a capture of it
// taken through the capture command after setup, with this build's rules.
type rootFlipWorld struct {
	t      *testing.T
	srv    *kubetest.Server
	dyn    dynamic.Interface
	before string
}

func newRootFlipWorld(t *testing.T, name, ns string) *rootFlipWorld {
	t.Helper()
	srv := kubetest.Start(t, name)
	settle(t, srv)
	w, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	nsr := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	if _, err := w.Dynamic.Resource(nsr).Create(context.Background(), &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	return &rootFlipWorld{t: t, srv: srv, dyn: w.Dynamic}
}

func (w *rootFlipWorld) create(gvr schema.GroupVersionResource, body map[string]any) {
	w.t.Helper()
	ns := body["metadata"].(map[string]any)["namespace"].(string)
	if _, err := w.dyn.Resource(gvr).Namespace(ns).Create(context.Background(), &unstructured.Unstructured{Object: body}, metav1.CreateOptions{}); err != nil {
		w.t.Fatal(err)
	}
}

// update reads an object, lets change edit it, and writes it back.
func (w *rootFlipWorld) update(gvr schema.GroupVersionResource, ns, name string, change func(map[string]any)) {
	w.t.Helper()
	ctx := context.Background()
	u, err := w.dyn.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		w.t.Fatal(err)
	}
	change(u.Object)
	if _, err := w.dyn.Resource(gvr).Namespace(ns).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *rootFlipWorld) capture() string {
	w.t.Helper()
	out := filepath.Join(w.t.TempDir(), "snap")
	args := []string{"--kubeconfig", w.srv.Kubeconfig, "--context", w.srv.Context, "--out", out}
	if code, stdout, stderr := output(w.t, func() int { return capture(context.Background(), args) }); code != 0 {
		w.t.Fatalf("capture: exit %d\n%s%s", code, stdout, stderr)
	}
	if s, err := snapshot.Read(out); err != nil || s.Rules != kube.CaptureRules {
		w.t.Fatalf("capture wrote rules %d, want %d (%v)", s.Rules, kube.CaptureRules, err)
	}
	return out
}

// wantDifferences runs diff against before and compare between before and
// a capture now, and wants each line as a difference, exit 2, no move.
func (w *rootFlipWorld) wantDifferences(lines ...string) {
	w.t.Helper()
	ctx := context.Background()
	diffArgs := []string{"--kubeconfig", w.srv.Kubeconfig, "--context", w.srv.Context, "--from", w.before}
	now := w.capture()
	for _, run := range []struct {
		what string
		f    func() int
	}{
		{"diff", func() int { return diff(ctx, diffArgs) }},
		{"compare", func() int { return compare([]string{w.before, now}) }},
	} {
		code, stdout, _ := output(w.t, run.f)
		for _, l := range lines {
			if !strings.Contains(stdout, l) {
				w.t.Errorf("%s: no %q in\n%s", run.what, l, stdout)
			}
		}
		if code != 2 || strings.Contains(stdout, "moved    ") {
			w.t.Errorf("%s: exit %d, want 2 and nothing moved\n%s", run.what, code, stdout)
		}
	}
	var code int
	d := asJSON(w.t, func() { code = diff(ctx, diffArgs) })
	if code != 2 || d["differences"] != float64(len(lines)) || len(d["moved"].([]any)) != 0 {
		w.t.Errorf("diff --json: exit %d, %v", code, d)
	}
}

// Third review of #24: under one set of capture rules, an edit to an
// Argo CD application hid behind a flip of its root status. Captured as a
// self-applying root (its instance label names it), it is edited and given
// a tracking-id naming another application: no longer a root, it is left
// out as managed by the application its label still names, which is what
// its captured copy says too. And the other way: a child application left
// out is edited and given a tracking-id naming itself, and is captured as a
// root. Both snapshots are under this build's rules, so neither is a move.
func TestArgoRootFlipIsADifference(t *testing.T) {
	w := newRootFlipWorld(t, "argo-flip", "argocd")
	apps := serveCRD(t, w.dyn, "argoproj.io", "Application", "applications")
	app := func(name, instance string) map[string]any {
		return map[string]any{"apiVersion": "argoproj.io/v1", "kind": "Application",
			"metadata": map[string]any{"name": name, "namespace": "argocd", "labels": map[string]any{"argocd.argoproj.io/instance": instance}},
			"spec":     map[string]any{"source": map[string]any{"repoURL": "https://git.example.com/good.git", "path": name}}}
	}
	w.create(apps, app("shop", "shop"))
	w.create(apps, app("child", "shop"))
	w.before = w.capture()
	wantSkip(t, w.before, "argoproj.io/v1|Application|argocd|shop", false)
	wantSkip(t, w.before, "argoproj.io/v1|Application|argocd|child", true)

	edit := func(name, trackingID string) {
		w.update(apps, "argocd", name, func(o map[string]any) {
			o["spec"].(map[string]any)["source"].(map[string]any)["repoURL"] = "https://git.example.com/evil.git"
			o["metadata"].(map[string]any)["annotations"] = map[string]any{"argocd.argoproj.io/tracking-id": trackingID}
		})
	}
	edit("shop", "evil:argoproj.io/Application:argocd/shop")
	edit("child", "child:argoproj.io/Application:argocd/child")
	w.wantDifferences(
		"missing  argoproj.io/v1|Application|argocd|shop",
		"extra    argoproj.io/v1|Application|argocd|child",
	)
}

// The Flux form: a GitRepository is captured because a self-applying
// Kustomization reads from it. Its url is changed, and the Kustomization's
// name label, so it no longer applies itself: the repository is left out
// as applied by the Kustomization its labels name, as its captured copy
// says. Under one set of rules, both are differences.
func TestFluxRootFlipIsADifference(t *testing.T) {
	w := newRootFlipWorld(t, "flux-flip", "gitops")
	ks := serveCRD(t, w.dyn, "kustomize.toolkit.fluxcd.io", "Kustomization", "kustomizations")
	repos := serveCRD(t, w.dyn, "source.toolkit.fluxcd.io", "GitRepository", "gitrepositories")
	by := func(name string) map[string]any {
		return map[string]any{"kustomize.toolkit.fluxcd.io/name": name, "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
	}
	w.create(ks, map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
		"metadata": map[string]any{"name": "helper", "namespace": "gitops", "labels": by("helper")},
		"spec":     map[string]any{"path": "./cluster", "sourceRef": map[string]any{"kind": "GitRepository", "name": "repo"}}})
	w.create(repos, map[string]any{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
		"metadata": map[string]any{"name": "repo", "namespace": "gitops", "labels": by("helper")},
		"spec":     map[string]any{"url": "https://git.example.com/good.git"}})
	w.before = w.capture()
	wantSkip(t, w.before, "kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|helper", false)
	wantSkip(t, w.before, "source.toolkit.fluxcd.io/v1|GitRepository|gitops|repo", false)

	w.update(repos, "gitops", "repo", func(o map[string]any) {
		o["spec"].(map[string]any)["url"] = "https://git.example.com/evil.git"
	})
	w.update(ks, "gitops", "helper", func(o map[string]any) {
		o["metadata"].(map[string]any)["labels"] = by("other")
	})
	w.wantDifferences(
		"missing  kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|helper",
		"missing  source.toolkit.fluxcd.io/v1|GitRepository|gitops|repo",
	)
}

// Across a change of rules, or from a snapshot that does not say its rules,
// the self-applying root case still moves; under one version, nothing does.
func TestMovesOnlyAcrossARulesChange(t *testing.T) {
	why := snapshot.FluxKustomizationReason("gitops", "root")
	cov := []snapshot.Coverage{{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Kind: "Kustomization"}}
	root := snapshot.Object{Body: map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
		"metadata": map[string]any{"name": "root", "namespace": "gitops", "labels": map[string]any{"kustomize.toolkit.fluxcd.io/name": "root", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}},
		"spec":     map[string]any{"path": "./cluster"}}}
	write := func(rules int, captured bool) string {
		s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Rules: rules, Coverage: cov}
		if captured {
			s.Objects = []snapshot.Object{root}
		} else {
			s.Skips = []snapshot.Skip{{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "gitops", Name: "root", Reason: why}}
		}
		d := filepath.Join(t.TempDir(), "s")
		if err := s.Write(d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	for _, c := range []struct {
		older, newer int
		moves        bool
	}{
		{0, kube.CaptureRules, true},
		{kube.CaptureRules, 0, true},
		{0, 0, true},
		{kube.CaptureRules, kube.CaptureRules + 1, true},
		{kube.CaptureRules, kube.CaptureRules, false},
	} {
		code, stdout, _ := output(t, func() int { return compare([]string{write(c.older, false), write(c.newer, true)}) })
		moved := strings.Contains(stdout, "moved    kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|root: no longer skipped")
		if c.moves != moved || (c.moves && code != 0) || (!c.moves && code != 2) {
			t.Errorf("rules %d then %d: exit %d, moved %v, want moved %v\n%s", c.older, c.newer, code, moved, c.moves, stdout)
		}
	}
}
