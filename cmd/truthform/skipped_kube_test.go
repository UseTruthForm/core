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

// The note a missing or extra line carries for an object the other side
// left out, and the hint it adds where that side is from a build before
// rules were recorded and gave a GitOps source's reason.
const (
	leftOutNote = " (left out on the other side: "
	olderHint   = "; a snapshot from a build before beta.23 left out a self-applying GitOps root and the source it reads from, so this may be one)"
	// What a snapshot under Kubernetes rules before 3 adds for a GitOps
	// source's reason, and what one without rules says in all.
	noSourceHint = "; a snapshot from a build before beta.25 left out what is labelled as a GitOps source's where the cluster holds no such source, so this may be that)"
	noRulesHint  = "; a snapshot from a build before beta.23 left out a self-applying GitOps root and the source it reads from, so this may be one" + noSourceHint
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

// skipWorld is a real API server, an environment file naming it, and a
// capture of it taken through the environment capture after setup.
type skipWorld struct {
	t        *testing.T
	srv      *kubetest.Server
	dyn      dynamic.Interface
	cfg, env string
	before   string
}

func newSkipWorld(t *testing.T, name string, namespaces ...string) *skipWorld {
	t.Helper()
	srv := kubetest.Start(t, name)
	settle(t, srv)
	w, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	sw := &skipWorld{t: t, srv: srv, dyn: w.Dynamic}
	for _, ns := range namespaces {
		sw.create(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns}})
	}
	dir := t.TempDir()
	sw.cfg = writeFile(t, dir, "env.yaml", "name: shop\ntargets:\n  - {name: cluster, platform: kubernetes, kubeconfig: '"+srv.Kubeconfig+"', context: "+srv.Context+"}\n")
	sw.env = filepath.Join(dir, "env")
	return sw
}

func (w *skipWorld) create(gvr schema.GroupVersionResource, body map[string]any) {
	w.t.Helper()
	ns, _ := body["metadata"].(map[string]any)["namespace"].(string)
	if _, err := w.dyn.Resource(gvr).Namespace(ns).Create(context.Background(), &unstructured.Unstructured{Object: body}, metav1.CreateOptions{}); err != nil {
		w.t.Fatal(err)
	}
}

// update reads an object, lets change edit it, and writes it back.
func (w *skipWorld) update(gvr schema.GroupVersionResource, ns, name string, change func(map[string]any)) {
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
// compare with. asMain rewrites it as main writes it: the same files, no
// rules.
func (w *skipWorld) captureBefore(asMain bool) {
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

func (w *skipWorld) captureNow() string {
	w.t.Helper()
	out := filepath.Join(w.t.TempDir(), "snap")
	args := []string{"--kubeconfig", w.srv.Kubeconfig, "--context", w.srv.Context, "--out", out}
	if code, stdout, stderr := output(w.t, func() int { return capture(context.Background(), args) }); code != 0 {
		w.t.Fatalf("capture: exit %d\n%s%s", code, stdout, stderr)
	}
	return out
}

// wantDifferences runs diff, diff --config and compare (against a capture
// now) on before, in text and --json. Each line must be there whole, with
// its note, and each must be a difference: exit 2, and as many as given.
// notes is how many of them carry skippedOtherSide in --json.
func (w *skipWorld) wantDifferences(lines []string, notes int) {
	w.t.Helper()
	ctx := context.Background()
	diffArgs := []string{"--kubeconfig", w.srv.Kubeconfig, "--context", w.srv.Context, "--from", w.before}
	now := w.captureNow()
	for _, run := range []struct {
		what, indent string
		f            func() int
	}{
		{"diff", "", func() int { return diff(ctx, diffArgs) }},
		{"diff --config", "  ", func() int { return diffEnvironment(ctx, w.cfg, w.env) }},
		{"compare", "", func() int { return compare([]string{w.before, now}) }},
	} {
		code, stdout, _ := output(w.t, run.f)
		for _, l := range lines {
			if !strings.Contains(stdout, "\n"+run.indent+l+"\n") && !strings.HasPrefix(stdout, run.indent+l+"\n") {
				w.t.Errorf("%s: no line %q in\n%s", run.what, run.indent+l, stdout)
			}
		}
		if code != 2 {
			w.t.Errorf("%s: exit %d, want 2\n%s", run.what, code, stdout)
		}
	}
	withNotes := func(changes []any) int {
		n := 0
		for _, c := range changes {
			if s, ok := c.(map[string]any)["skippedOtherSide"].(map[string]any); ok && s["reason"] != "" && len(s) == 1 {
				n++
			}
		}
		return n
	}
	var code int
	d := asJSON(w.t, func() { code = diff(ctx, diffArgs) })
	if code != 2 || d["differences"] != float64(len(lines)) || withNotes(d["changes"].([]any)) != notes {
		w.t.Errorf("diff --json: exit %d, %v", code, d)
	}
	e := asJSON(w.t, func() { code = diffEnvironment(ctx, w.cfg, w.env) })
	tgt := e["targets"].([]any)[0].(map[string]any)
	if code != 2 || tgt["differences"] != float64(len(lines)) || withNotes(tgt["changes"].([]any)) != notes {
		w.t.Errorf("diff --config --json: exit %d, %v", code, tgt)
	}
}

var (
	configMaps = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	services   = schema.GroupVersionResource{Version: "v1", Resource: "services"}
	deploys    = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	bindings   = schema.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "clusterrolebindings"}
)

// Through diff, diff --config and compare, text and --json, against a
// baseline main wrote (no rules) and one this build wrote: an edit hidden
// behind a skip is a difference in both directions. After a capture,
// objects are edited and given the marks of a maker that is in the cluster
// and did not make them (one that is not there is captured, see
// TestALabelNamingNoSourceIsCaptured):
// Flux Kustomization labels (on a ConfigMap and on a ClusterRoleBinding
// given a new subject), Flux HelmRelease labels, an Argo CD instance label,
// an Argo CD tracking-id, and a controller reference to a real Deployment
// on a Service whose selector is changed and given an external IP. And the
// other way: a ClusterRoleBinding left out as Flux's has its labels taken
// off and its subject changed. Each is a difference, with why the other
// side left it out beside it, and the hint about an older build only on
// what a baseline without rules left out for a GitOps source.
func TestEditsBehindSkipsAreDifferences(t *testing.T) {
	for _, asMain := range []bool{true, false} {
		t.Run(map[bool]string{true: "baseline written by main", false: "baseline under this build's rules"}[asMain], func(t *testing.T) {
			w := newSkipWorld(t, "skips", "shop", "gitops")
			for _, c := range [][3]string{
				{"kustomize.toolkit.fluxcd.io", "Kustomization", "kustomizations"},
				{"helm.toolkit.fluxcd.io", "HelmRelease", "helmreleases"},
				{"argoproj.io", "Application", "applications"},
			} {
				w.create(serveCRD(t, w.dyn, c[0], c[1], c[2]), map[string]any{"apiVersion": c[0] + "/v1", "kind": c[1],
					"metadata": map[string]any{"name": "src", "namespace": "gitops"}, "spec": map[string]any{"path": "./x"}})
			}
			flux := map[string]any{"kustomize.toolkit.fluxcd.io/name": "src", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
			for _, n := range []string{"kustomized", "helmed", "instance", "tracked"} {
				w.create(configMaps, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": n, "namespace": "shop"}, "data": map[string]any{"a": "1"}})
			}
			binding := func(name string, labels map[string]any) map[string]any {
				md := map[string]any{"name": name}
				if labels != nil {
					md["labels"] = labels
				}
				return map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": md,
					"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"},
					"subjects": []any{map[string]any{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "ops"}}}
			}
			w.create(bindings, binding("ops", nil))
			w.create(bindings, binding("synced", flux))
			sel := map[string]any{"app": "web"}
			w.create(deploys, map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "web", "namespace": "shop"},
				"spec": map[string]any{"selector": map[string]any{"matchLabels": sel}, "template": map[string]any{
					"metadata": map[string]any{"labels": sel}, "spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "example.com/web:1"}}}}}})
			w.create(services, map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "front", "namespace": "shop"},
				"spec": map[string]any{"selector": sel, "ports": []any{map[string]any{"port": int64(80)}}}})
			w.captureBefore(asMain)
			wantSkip(t, w.before, "rbac.authorization.k8s.io/v1|ClusterRoleBinding||synced", true)

			edit := func(name string, labels, annotations map[string]any) {
				w.update(configMaps, "shop", name, func(o map[string]any) {
					md := o["metadata"].(map[string]any)
					o["data"].(map[string]any)["a"] = "EVIL"
					if labels != nil {
						md["labels"] = labels
					}
					if annotations != nil {
						md["annotations"] = annotations
					}
				})
			}
			edit("kustomized", flux, nil)
			edit("helmed", map[string]any{"helm.toolkit.fluxcd.io/name": "src", "helm.toolkit.fluxcd.io/namespace": "gitops"}, nil)
			edit("instance", map[string]any{"argocd.argoproj.io/instance": "src"}, nil)
			edit("tracked", nil, map[string]any{"argocd.argoproj.io/tracking-id": "src:/ConfigMap:shop/tracked"})
			mallory := map[string]any{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "mallory"}
			w.update(bindings, "", "ops", func(o map[string]any) {
				o["metadata"].(map[string]any)["labels"] = flux
				o["subjects"] = append(o["subjects"].([]any), mallory)
			})
			w.update(bindings, "", "synced", func(o map[string]any) {
				delete(o["metadata"].(map[string]any), "labels")
				o["subjects"] = []any{mallory}
			})
			dep, err := w.dyn.Resource(deploys).Namespace("shop").Get(context.Background(), "web", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			w.update(services, "shop", "front", func(o map[string]any) {
				o["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "name": "web", "uid": string(dep.GetUID()), "controller": true}}
				spec := o["spec"].(map[string]any)
				spec["selector"], spec["externalIPs"] = map[string]any{"app": "other"}, []any{"203.0.113.9"}
			})

			fluxSrc := snapshot.FluxKustomizationReason("gitops", "src")
			synced := "extra    rbac.authorization.k8s.io/v1|ClusterRoleBinding||synced" + leftOutNote + fluxSrc + ")"
			if asMain {
				synced = strings.TrimSuffix(synced, ")") + noRulesHint
			}
			w.wantDifferences([]string{
				"missing  v1|ConfigMap|shop|kustomized" + leftOutNote + fluxSrc + ")",
				"missing  v1|ConfigMap|shop|helmed" + leftOutNote + snapshot.FluxHelmReleaseReason("gitops", "src") + ")",
				"missing  v1|ConfigMap|shop|instance" + leftOutNote + snapshot.ArgoCDReason("src") + ")",
				"missing  v1|ConfigMap|shop|tracked" + leftOutNote + snapshot.ArgoCDReason("src") + ")",
				"missing  rbac.authorization.k8s.io/v1|ClusterRoleBinding||ops" + leftOutNote + fluxSrc + ")",
				"missing  v1|Service|shop|front" + leftOutNote + snapshot.OwnedReason("Deployment", "web") + ")",
				synced,
			}, 7)
		})
	}
}

// An Argo CD application captured as a self-applying root, edited and
// given a tracking-id naming another, is left out as managed by itself; a
// child left out, edited and given a tracking-id naming itself, is
// captured. Against a baseline main wrote and one this build wrote, both
// are differences, noted, the child's with the hint where the baseline has
// no rules.
func TestArgoRootFlipIsADifference(t *testing.T) {
	for _, asMain := range []bool{true, false} {
		t.Run(map[bool]string{true: "baseline written by main", false: "baseline under this build's rules"}[asMain], func(t *testing.T) {
			w := newSkipWorld(t, "argo-flip", "argocd")
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
			byShop := snapshot.ArgoCDReason("shop")
			child := "extra    argoproj.io/v1|Application|argocd|child" + leftOutNote + byShop + ")"
			if asMain {
				child = strings.TrimSuffix(child, ")") + noRulesHint
			}
			w.wantDifferences([]string{"missing  argoproj.io/v1|Application|argocd|shop" + leftOutNote + byShop + ")", child}, 2)
		})
	}
}

// A GitRepository captured because a self-applying Kustomization reads
// from it has its url changed, and the Kustomization its name label, so
// it no longer applies itself: both are left out, and both are
// differences, noted, against either baseline.
func TestFluxRootFlipIsADifference(t *testing.T) {
	for _, asMain := range []bool{true, false} {
		t.Run(map[bool]string{true: "baseline written by main", false: "baseline under this build's rules"}[asMain], func(t *testing.T) {
			w := newSkipWorld(t, "flux-flip", "gitops")
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
			// The one the edit below names: there, or the edited one would be
			// captured as naming no source.
			w.create(ks, map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
				"metadata": map[string]any{"name": "other", "namespace": "gitops"},
				"spec":     map[string]any{"path": "./other", "sourceRef": map[string]any{"kind": "GitRepository", "name": "repo"}}})
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
				"missing  kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|helper" + leftOutNote + snapshot.FluxKustomizationReason("gitops", "other") + ")",
				"missing  source.toolkit.fluxcd.io/v1|GitRepository|gitops|repo" + leftOutNote + snapshot.FluxKustomizationReason("gitops", "helper") + ")",
			}, 2)
		})
	}
}

// The case the hint is for, through compare: a self-applying root a build
// before beta.23 left out, which this build captures, is a difference, and
// its line says that may be why; under one set of rules it says only why.
func TestCompareNotesARootAnOlderBuildLeftOut(t *testing.T) {
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
	key := "kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|root"
	for _, c := range []struct {
		skippedRules int
		hint         bool
	}{{0, true}, {kube.CaptureRules, false}} {
		skipped, captured := write(c.skippedRules, false), write(kube.CaptureRules, true)
		for _, o := range []struct {
			args []string
			kind string
		}{{[]string{skipped, captured}, "extra   "}, {[]string{captured, skipped}, "missing "}} {
			code, stdout, _ := output(t, func() int { return compare(o.args) })
			line := o.kind + " " + key + leftOutNote + why + ")"
			if c.hint {
				line = strings.TrimSuffix(line, ")") + noRulesHint
			}
			if code != 2 || !strings.Contains(stdout, line+"\n") || !strings.Contains(stdout, "1 difference between") {
				t.Errorf("left out under rules %d, %s: exit %d, want 2 and %q\n%s", c.skippedRules, o.kind, code, line, stdout)
			}
		}
	}
}

// Reviews of #24, on a real API server. The first capture has Opaque
// Secrets named like Helm's: a release's history stem (foo), revisions of
// releases that the second capture lists by name (zed.v1, q.v1.v2), and
// two that the second capture really does hold as Helm's (zed, foo.v1).
// Then each is deleted, and the second capture has Helm-typed Secrets: zed
// with no revision and q.v1 whose name label says another release, each
// listed by its own name, and foo.v1, listed as foo's history.
//
// A note goes on zed and foo.v1, which the second capture left out under
// those names, and on nothing else, in either order and through diff. From
// the second capture as main wrote it (no rules, a family written as a
// bare name) no Helm history skip is a note on anything: there a family
// and a Secret's own name cannot be told apart.
func TestHelmHistoryNotesOnlyWhatItNames(t *testing.T) {
	w := newSkipWorld(t, "helm-names", "shop")
	secrets := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	p := snapshot.HelmHistoryPrefix
	secret := func(name, typ string, labels map[string]any) {
		md := map[string]any{"name": p + name, "namespace": "shop"}
		if labels != nil {
			md["labels"] = labels
		}
		w.create(secrets, map[string]any{"apiVersion": "v1", "kind": "Secret", "type": typ, "metadata": md, "data": map[string]any{"a": "MQ=="}})
	}
	opaque := []string{"foo", "zed.v1", "q.v1.v2", "zed", "foo.v1"}
	for _, n := range opaque {
		secret(n, "Opaque", nil)
	}
	w.captureBefore(false)
	for _, n := range opaque {
		if err := w.dyn.Resource(secrets).Namespace("shop").Delete(context.Background(), p+n, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	secret("zed", "helm.sh/release.v1", map[string]any{"owner": "helm"})
	secret("q.v1", "helm.sh/release.v1", map[string]any{"owner": "helm", "name": "other"})
	secret("foo.v1", "helm.sh/release.v1", map[string]any{"owner": "helm", "name": "foo"})
	now := w.captureNow()
	s, err := snapshot.Read(now)
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, sk := range s.Skips {
		if sk.Reason == snapshot.HelmHistoryReason {
			listed[sk.Name] = true
		}
	}
	for _, n := range []string{p + "zed", p + "q.v1", p + "foo" + snapshot.HelmHistoryFamily} {
		if !listed[n] {
			t.Fatalf("%s is not listed: %v", n, listed)
		}
	}
	// Listed by its own name, the note is the skip's reason; a family's
	// says it does not record which revisions.
	notes := map[string]string{
		"zed":    leftOutNote + snapshot.HelmHistoryReason + ")",
		"foo.v1": leftOutNote + snapshot.HelmFamilyNote("foo") + ")",
	}
	lines := func(kind string, noted bool) []string {
		var out []string
		for _, n := range opaque {
			l := kind + " v1|Secret|shop|" + p + n
			if noted && notes[n] != "" {
				l += notes[n]
			}
			out = append(out, l+"\n")
		}
		return out
	}
	check := func(what string, code int, stdout string, want []string) {
		t.Helper()
		for _, l := range want {
			if !strings.Contains(stdout, l) {
				t.Errorf("%s: no %q in\n%s", what, l, stdout)
			}
		}
		if code != 2 {
			t.Errorf("%s: exit %d", what, code)
		}
	}
	for _, o := range []struct {
		args []string
		kind string
	}{{[]string{w.before, now}, "missing "}, {[]string{now, w.before}, "extra   "}} {
		code, stdout, _ := output(t, func() int { return compare(o.args) })
		check("compare "+o.kind, code, stdout, lines(o.kind, true))
	}
	diffArgs := []string{"--kubeconfig", w.srv.Kubeconfig, "--context", w.srv.Context, "--from", w.before}
	code, stdout, _ := output(t, func() int { return diff(ctx(), diffArgs) })
	check("diff", code, stdout, lines("missing ", true))

	// The second capture as main wrote it.
	old := s
	old.Rules = 0
	old.Skips = nil
	for _, sk := range s.Skips {
		sk.Name = strings.TrimSuffix(sk.Name, snapshot.HelmHistoryFamily)
		old.Skips = append(old.Skips, sk)
	}
	oldDir := filepath.Join(t.TempDir(), "old")
	if err := old.Write(oldDir); err != nil {
		t.Fatal(err)
	}
	for _, o := range []struct {
		args []string
		kind string
	}{{[]string{w.before, oldDir}, "missing "}, {[]string{oldDir, w.before}, "extra   "}} {
		code, stdout, _ := output(t, func() int { return compare(o.args) })
		check("compare with main's "+o.kind, code, stdout, lines(o.kind, false))
	}
}

func ctx() context.Context { return context.Background() }

// Issue #28: a label is a claim anyone who can create an object can make. A
// ClusterRoleBinding labelled from the start as a Flux Kustomization's, a
// HelmRelease's or an Argo CD application's, where no such source is in the
// cluster, is captured: left out on its label's word, it was in no snapshot
// and no drift report. One whose source is there is left to it as before.
func TestALabelNamingNoSourceIsCaptured(t *testing.T) {
	w := newSkipWorld(t, "no-source", "gitops")
	// Flux's Kustomizations are served and one is there; its HelmReleases
	// and Argo CD's applications are not served at all.
	ks := serveCRD(t, w.dyn, "kustomize.toolkit.fluxcd.io", "Kustomization", "kustomizations")
	w.create(ks, map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
		"metadata": map[string]any{"name": "apps", "namespace": "gitops"}, "spec": map[string]any{"path": "./apps"}})
	for name, md := range map[string]map[string]any{
		"by-apps":    {"labels": map[string]any{"kustomize.toolkit.fluxcd.io/name": "apps", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}},
		"no-ks":      {"labels": map[string]any{"kustomize.toolkit.fluxcd.io/name": "anything", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}},
		"elsewhere":  {"labels": map[string]any{"kustomize.toolkit.fluxcd.io/name": "apps", "kustomize.toolkit.fluxcd.io/namespace": "other"}},
		"no-release": {"labels": map[string]any{"helm.toolkit.fluxcd.io/name": "anything", "helm.toolkit.fluxcd.io/namespace": "gitops"}},
		"no-app":     {"labels": map[string]any{"argocd.argoproj.io/instance": "anything"}},
		"no-tracked": {"annotations": map[string]any{"argocd.argoproj.io/tracking-id": "anything:rbac.authorization.k8s.io/ClusterRoleBinding:/no-tracked"}},
	} {
		md["name"] = name
		w.create(bindings, map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": md,
			"roleRef":  map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
			"subjects": []any{map[string]any{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "mallory"}}})
	}
	w.captureBefore(false)
	wantSkip(t, w.before, "rbac.authorization.k8s.io/v1|ClusterRoleBinding||by-apps", true)
	for _, name := range []string{"no-ks", "elsewhere", "no-release", "no-app", "no-tracked"} {
		wantSkip(t, w.before, "rbac.authorization.k8s.io/v1|ClusterRoleBinding||"+name, false)
	}
}
