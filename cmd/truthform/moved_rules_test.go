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

// rootFlipWorld is a real API server, a namespace, an environment file
// naming it, and a capture of it taken through the environment capture
// after setup, with this build's rules.
type rootFlipWorld struct {
	t        *testing.T
	srv      *kubetest.Server
	dyn      dynamic.Interface
	cfg, env string
	before   string
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
	dir := t.TempDir()
	cfg := writeFile(t, dir, "env.yaml", "name: shop\ntargets:\n  - {name: cluster, platform: kubernetes, kubeconfig: '"+srv.Kubeconfig+"', context: "+srv.Context+"}\n")
	return &rootFlipWorld{t: t, srv: srv, dyn: w.Dynamic, cfg: cfg, env: filepath.Join(dir, "env")}
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

// captureBefore takes the environment capture diff --from and --config
// compare with. asMain rewrites it as the build before rules were
// recorded wrote it: the same files, no rules.
func (w *rootFlipWorld) captureBefore(asMain bool) {
	w.t.Helper()
	code, stdout, stderr := output(w.t, func() int { return captureEnvironment(context.Background(), w.cfg, w.env) })
	if code != 0 || !strings.Contains(stdout, "environment shop: 1 target into ") {
		w.t.Fatalf("capture: exit %d\n%s%s", code, stdout, stderr)
	}
	w.before = filepath.Join(w.env, "cluster")
	s, err := snapshot.Read(w.before)
	if err != nil || s.Rules != kube.CaptureRules {
		w.t.Fatalf("capture wrote rules %d, want %d (%v)", s.Rules, kube.CaptureRules, err)
	}
	if asMain {
		s.Rules = 0
		if err := s.Write(w.before); err != nil {
			w.t.Fatal(err)
		}
	}
}

func (w *rootFlipWorld) captureNow() string {
	w.t.Helper()
	out := filepath.Join(w.t.TempDir(), "snap")
	args := []string{"--kubeconfig", w.srv.Kubeconfig, "--context", w.srv.Context, "--out", out}
	if code, stdout, stderr := output(w.t, func() int { return capture(context.Background(), args) }); code != 0 {
		w.t.Fatalf("capture: exit %d\n%s%s", code, stdout, stderr)
	}
	return out
}

// wantDifferences runs diff, diff --config and compare (against a capture
// now) on before, in text and --json, and wants each of differences as one,
// exit 2, and only moved listed as moved.
func (w *rootFlipWorld) wantDifferences(differences, moved []string) {
	w.t.Helper()
	ctx := context.Background()
	diffArgs := []string{"--kubeconfig", w.srv.Kubeconfig, "--context", w.srv.Context, "--from", w.before}
	now := w.captureNow()
	for _, run := range []struct {
		what string
		f    func() int
	}{
		{"diff", func() int { return diff(ctx, diffArgs) }},
		{"diff --config", func() int { return diffEnvironment(ctx, w.cfg, w.env) }},
		{"compare", func() int { return compare([]string{w.before, now}) }},
	} {
		code, stdout, _ := output(w.t, run.f)
		for _, l := range append(append([]string{}, differences...), moved...) {
			if !strings.Contains(stdout, l) {
				w.t.Errorf("%s: no %q in\n%s", run.what, l, stdout)
			}
		}
		if code != 2 || strings.Count(stdout, "moved    ") != len(moved) {
			w.t.Errorf("%s: exit %d, want 2 and %d moved\n%s", run.what, code, len(moved), stdout)
		}
	}
	var code int
	d := asJSON(w.t, func() { code = diff(ctx, diffArgs) })
	if code != 2 || d["differences"] != float64(len(differences)) || len(d["moved"].([]any)) != len(moved) {
		w.t.Errorf("diff --json: exit %d, %v", code, d)
	}
	e := asJSON(w.t, func() { code = diffEnvironment(ctx, w.cfg, w.env) })
	tgt := e["targets"].([]any)[0].(map[string]any)
	if code != 2 || tgt["differences"] != float64(len(differences)) || len(tgt["moved"].([]any)) != len(moved) {
		w.t.Errorf("diff --config --json: exit %d, %v", code, tgt)
	}
}

// Third and fourth reviews of #24: an edit to an Argo CD application hid
// behind a flip of its root status. Captured as a self-applying root (its
// instance label names it), it is edited and given a tracking-id naming
// another application: no longer a root, it is left out as managed by the
// application its label still names, as its captured copy says too. Under
// one set of rules, or against a snapshot from before rules were recorded
// (which every baseline kept from an older build is), it is a difference:
// no change of rules leaves out what was captured.
//
// And the child: left out, edited and given a tracking-id naming itself, it
// is captured as a root. Under one set of rules it is a difference. Against
// a snapshot from before rules were recorded it reads as moved, as the
// change to rules 1 moves a root: the edit is to an object that snapshot
// did not hold, and that main, comparing, would not see while it is left
// out either (the guide says so).
func TestArgoRootFlipIsADifference(t *testing.T) {
	for _, asMain := range []bool{false, true} {
		t.Run(map[bool]string{false: "same rules", true: "baseline from before rules"}[asMain], func(t *testing.T) {
			w := newRootFlipWorld(t, "argo-flip", "argocd")
			apps := serveCRD(t, w.dyn, "argoproj.io", "Application", "applications")
			app := func(name, instance string) map[string]any {
				return map[string]any{"apiVersion": "argoproj.io/v1", "kind": "Application",
					"metadata": map[string]any{"name": name, "namespace": "argocd", "labels": map[string]any{"argocd.argoproj.io/instance": instance}},
					"spec":     map[string]any{"source": map[string]any{"repoURL": "https://git.example.com/good.git", "path": name}}}
			}
			w.create(apps, app("shop", "shop"))
			w.create(apps, app("child", "shop"))
			w.captureBefore(asMain)
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
			if asMain {
				w.wantDifferences([]string{"missing  argoproj.io/v1|Application|argocd|shop"},
					[]string{"moved    argoproj.io/v1|Application|argocd|child: no longer skipped"})
				return
			}
			w.wantDifferences([]string{"missing  argoproj.io/v1|Application|argocd|shop", "extra    argoproj.io/v1|Application|argocd|child"}, nil)
		})
	}
}

// The Flux form: a GitRepository is captured because a self-applying
// Kustomization reads from it. Its url is changed, and the Kustomization's
// name label, so it no longer applies itself: both are left out, as
// applied by the Kustomizations their labels name. Under one set of rules,
// and against a snapshot from before rules were recorded, both are
// differences and nothing is listed as moved.
func TestFluxRootFlipIsADifference(t *testing.T) {
	for _, asMain := range []bool{false, true} {
		t.Run(map[bool]string{false: "same rules", true: "baseline from before rules"}[asMain], func(t *testing.T) {
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
			w.captureBefore(asMain)
			wantSkip(t, w.before, "kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|helper", false)
			wantSkip(t, w.before, "source.toolkit.fluxcd.io/v1|GitRepository|gitops|repo", false)

			w.update(repos, "gitops", "repo", func(o map[string]any) {
				o["spec"].(map[string]any)["url"] = "https://git.example.com/evil.git"
			})
			w.update(ks, "gitops", "helper", func(o map[string]any) {
				o["metadata"].(map[string]any)["labels"] = by("other")
			})
			w.wantDifferences([]string{
				"missing  kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|helper",
				"missing  source.toolkit.fluxcd.io/v1|GitRepository|gitops|repo",
			}, nil)
		})
	}
}

// Through compare, in both orders: a root moves only from the snapshot
// under lower rules, which left it out, to the one under higher rules,
// which a change between them keeps it under.
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
		skipped, captured int
		moves             bool
	}{
		{0, 1, true},
		{0, 2, true},
		{1, 0, false},
		{0, 0, false},
		{1, 1, false},
		{1, 2, false},
	} {
		skipped, captured := write(c.skipped, false), write(c.captured, true)
		for _, args := range [][]string{{skipped, captured}, {captured, skipped}} {
			code, stdout, _ := output(t, func() int { return compare(args) })
			moved := strings.Contains(stdout, "moved    kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|root: no longer")
			if c.moves != moved || (c.moves && code != 0) || (!c.moves && code != 2) {
				t.Errorf("skipped under %d, captured under %d: exit %d, moved %v, want moved %v\n%s", c.skipped, c.captured, code, moved, c.moves, stdout)
			}
		}
	}
}
