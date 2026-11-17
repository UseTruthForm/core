package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// On a real API server, through capture, diff, compare and an environment's
// diff: a label or an owner reference added in the cluster does not hide an
// edit (second review of #24, each reproduced there with this build exiting
// 0 and main exiting 2). After a capture, objects are edited and given the
// marks of a maker that does not exist: Flux Kustomization labels (on a
// ConfigMap and on a ClusterRoleBinding given a new subject), Flux
// HelmRelease labels, an Argo CD instance label, an Argo CD tracking-id,
// and a controller reference to a real Deployment on a Service whose
// selector is changed and given an external IP. And the other way: a
// ClusterRoleBinding left out as Flux's has its labels taken off and its
// subject changed. The copies the first capture holds carry no such marks,
// so none of it was left out for that reason: each is a difference, and
// each command exits 2.
func TestMarksAddedInTheClusterDoNotHideEdits(t *testing.T) {
	srv := kubetest.Start(t, "marks")
	settle(t, srv)
	ctx := context.Background()
	w, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	cs := kubernetes.NewForConfigOrDie(w.Config)
	must := func(_ any, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	flux := map[string]string{"kustomize.toolkit.fluxcd.io/name": "nope", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
	must(cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}, metav1.CreateOptions{}))
	for _, n := range []string{"kustomized", "helmed", "instance", "tracked"} {
		must(cs.CoreV1().ConfigMaps("shop").Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "shop"}, Data: map[string]string{"a": "1"}}, metav1.CreateOptions{}))
	}
	subject := func(kind, name string) rbacv1.Subject {
		return rbacv1.Subject{Kind: kind, APIGroup: "rbac.authorization.k8s.io", Name: name}
	}
	binding := func(name string, labels map[string]string) *rbacv1.ClusterRoleBinding {
		return &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
			Subjects: []rbacv1.Subject{subject("Group", "ops")}}
	}
	must(cs.RbacV1().ClusterRoleBindings().Create(ctx, binding("ops", nil), metav1.CreateOptions{}))
	must(cs.RbacV1().ClusterRoleBindings().Create(ctx, binding("synced", flux), metav1.CreateOptions{}))
	sel := map[string]string{"app": "web"}
	dep, err := cs.AppsV1().Deployments("shop").Create(ctx, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "shop"},
		Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: sel}, Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Labels: sel}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "example.com/web:1"}}}}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	must(cs.CoreV1().Services("shop").Create(ctx, &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "front", Namespace: "shop"},
		Spec: corev1.ServiceSpec{Selector: sel, Ports: []corev1.ServicePort{{Port: 80}}}}, metav1.CreateOptions{}))

	dir := t.TempDir()
	cfg := writeFile(t, dir, "env.yaml", "name: shop\ntargets:\n  - {name: cluster, platform: kubernetes, kubeconfig: '"+srv.Kubeconfig+"', context: "+srv.Context+"}\n")
	env := filepath.Join(dir, "env")
	if code := captureEnvironment(ctx, cfg, env); code != 0 {
		t.Fatalf("capture: exit %d", code)
	}
	before := filepath.Join(env, "cluster")
	wantSkip(t, before, "rbac.authorization.k8s.io/v1|ClusterRoleBinding||synced", true)

	edit := func(name string, labels, annotations map[string]string) {
		t.Helper()
		cm, _ := cs.CoreV1().ConfigMaps("shop").Get(ctx, name, metav1.GetOptions{})
		cm.Data["a"], cm.Labels, cm.Annotations = "EVIL", labels, annotations
		must(cs.CoreV1().ConfigMaps("shop").Update(ctx, cm, metav1.UpdateOptions{}))
	}
	edit("kustomized", flux, nil)
	edit("helmed", map[string]string{"helm.toolkit.fluxcd.io/name": "nope", "helm.toolkit.fluxcd.io/namespace": "gitops"}, nil)
	edit("instance", map[string]string{"argocd.argoproj.io/instance": "nope"}, nil)
	edit("tracked", nil, map[string]string{"argocd.argoproj.io/tracking-id": "nope:/ConfigMap:shop/tracked"})
	ops, _ := cs.RbacV1().ClusterRoleBindings().Get(ctx, "ops", metav1.GetOptions{})
	ops.Labels, ops.Subjects = flux, append(ops.Subjects, subject("User", "mallory"))
	must(cs.RbacV1().ClusterRoleBindings().Update(ctx, ops, metav1.UpdateOptions{}))
	synced, _ := cs.RbacV1().ClusterRoleBindings().Get(ctx, "synced", metav1.GetOptions{})
	synced.Labels, synced.Subjects = nil, []rbacv1.Subject{subject("User", "mallory")}
	must(cs.RbacV1().ClusterRoleBindings().Update(ctx, synced, metav1.UpdateOptions{}))
	front, _ := cs.CoreV1().Services("shop").Get(ctx, "front", metav1.GetOptions{})
	yes := true
	front.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: dep.UID, Controller: &yes}}
	front.Spec.Selector, front.Spec.ExternalIPs = map[string]string{"app": "other"}, []string{"203.0.113.9"}
	must(cs.CoreV1().Services("shop").Update(ctx, front, metav1.UpdateOptions{}))

	differences := []string{
		"missing  v1|ConfigMap|shop|kustomized",
		"missing  v1|ConfigMap|shop|helmed",
		"missing  v1|ConfigMap|shop|instance",
		"missing  v1|ConfigMap|shop|tracked",
		"missing  rbac.authorization.k8s.io/v1|ClusterRoleBinding||ops",
		"missing  v1|Service|shop|front",
		"extra    rbac.authorization.k8s.io/v1|ClusterRoleBinding||synced",
	}
	check := func(what string, code int, stdout string) {
		t.Helper()
		for _, l := range differences {
			if !strings.Contains(stdout, l) {
				t.Errorf("%s: no %q in\n%s", what, l, stdout)
			}
		}
		if code != 2 || strings.Contains(stdout, "moved    ") {
			t.Errorf("%s: exit %d, want 2 and nothing moved\n%s", what, code, stdout)
		}
	}
	diffArgs := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", before}
	code, stdout, _ := output(t, func() int { return diff(ctx, diffArgs) })
	check("diff", code, stdout)
	d := asJSON(t, func() { code = diff(ctx, diffArgs) })
	if code != 2 || d["differences"] != float64(len(differences)) || len(d["moved"].([]any)) != 0 {
		t.Errorf("diff --json: exit %d, %v", code, d)
	}
	code, stdout, _ = output(t, func() int { return diffEnvironment(ctx, cfg, env) })
	check("environment diff", code, stdout)
	snap, err := kube.Capture(ctx, mustConnect(t, srv), kube.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	after := filepath.Join(dir, "after")
	if err := snap.Write(after); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = output(t, func() int { return compare([]string{before, after}) })
	check("compare", code, stdout)
}

// The genuine case, on a real API server: a ConfigMap a GitOps source
// applies, which a build that did not yet leave such objects out captured
// with the source's labels on it (made here in the same shape, from this
// capture), and which this build leaves out to that source. The copy says
// what the skip says, so it is moved, by diff and an environment's diff,
// and is not a difference; a deletion beside it still is.
func TestMovedWhereTheCapturedCopySaysSo(t *testing.T) {
	srv := kubetest.Start(t, "moved")
	settle(t, srv)
	ctx := context.Background()
	w, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	cs := kubernetes.NewForConfigOrDie(w.Config)
	flux := map[string]string{"kustomize.toolkit.fluxcd.io/name": "root", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, cm := range []*corev1.ConfigMap{
		{ObjectMeta: metav1.ObjectMeta{Name: "synced", Namespace: "shop", Labels: flux}, Data: map[string]string{"a": "1"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: "shop"}, Data: map[string]string{"b": "2"}},
	} {
		if _, err := cs.CoreV1().ConfigMaps("shop").Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	cfg := writeFile(t, dir, "env.yaml", "name: shop\ntargets:\n  - {name: cluster, platform: kubernetes, kubeconfig: '"+srv.Kubeconfig+"', context: "+srv.Context+"}\n")
	env := filepath.Join(dir, "env")
	if code := captureEnvironment(ctx, cfg, env); code != 0 {
		t.Fatalf("capture: exit %d", code)
	}
	before := filepath.Join(env, "cluster")
	wantSkip(t, before, "v1|ConfigMap|shop|synced", true)
	// As the older build captured it: the object, labels and all, and no skip.
	old, err := snapshot.Read(before)
	if err != nil {
		t.Fatal(err)
	}
	var skips []snapshot.Skip
	for _, sk := range old.Skips {
		if sk.Name != "synced" {
			skips = append(skips, sk)
		}
	}
	old.Skips = skips
	old.Objects = append(old.Objects, snapshot.Object{Body: map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]any{"name": "synced", "namespace": "shop", "labels": map[string]any{"kustomize.toolkit.fluxcd.io/name": "root", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}},
		"data":     map[string]any{"a": "1"}}})
	if err := old.Write(before); err != nil {
		t.Fatal(err)
	}
	wantSkip(t, before, "v1|ConfigMap|shop|synced", false)

	line := "moved    v1|ConfigMap|shop|synced: no longer captured: applied by Flux Kustomization gitops/root; restoring it recreates this"
	diffArgs := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", before}
	code, stdout, _ := output(t, func() int { return diff(ctx, diffArgs) })
	if code != 0 || !strings.Contains(stdout, line) || !strings.Contains(stdout, "no differences:") || !strings.Contains(stdout, "; 1 object moved between captured and left out, which is not a difference") {
		t.Errorf("diff: exit %d, want 0 and the move\n%s", code, stdout)
	}
	code, stdout, _ = output(t, func() int { return diffEnvironment(ctx, cfg, env) })
	if code != 0 || !strings.Contains(stdout, "  "+line) || !strings.Contains(stdout, "== cluster (kubernetes): 0 differences; 1 object moved") {
		t.Errorf("environment diff: exit %d, want 0 and the move\n%s", code, stdout)
	}
	envDiff := func() (int, map[string]any) {
		t.Helper()
		var code int
		d := asJSON(t, func() { code = diffEnvironment(ctx, cfg, env) })
		return code, d["targets"].([]any)[0].(map[string]any)
	}
	if code, tgt := envDiff(); code != 0 || tgt["differences"] != float64(0) || len(tgt["changes"].([]any)) != 0 || len(tgt["moved"].([]any)) != 1 {
		t.Errorf("environment diff --json: exit %d, %v", code, tgt)
	}

	if err := cs.CoreV1().ConfigMaps("shop").Delete(ctx, "plain", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = output(t, func() int { return diff(ctx, diffArgs) })
	if code != 2 || !strings.Contains(stdout, "missing  v1|ConfigMap|shop|plain") || !strings.Contains(stdout, line) || !strings.Contains(stdout, "1 differences between") {
		t.Errorf("diff after a deletion: exit %d, want 2\n%s", code, stdout)
	}
	d := asJSON(t, func() { code = diff(ctx, diffArgs) })
	if code != 2 || d["differences"] != float64(1) || len(d["changes"].([]any)) != 1 || len(d["moved"].([]any)) != 1 {
		t.Errorf("--json: exit %d, %v", code, d)
	}
	if m := d["moved"].([]any)[0].(map[string]any); m["kind"] != snapshot.NoLongerCaptured || m["key"] != "v1|ConfigMap|shop|synced" || m["reason"] != snapshot.FluxKustomizationReason("gitops", "root") {
		t.Errorf("--json moved: %v", m)
	}
	if code, tgt := envDiff(); code != 2 || tgt["differences"] != float64(1) || len(tgt["changes"].([]any)) != 1 || len(tgt["moved"].([]any)) != 1 {
		t.Errorf("environment diff --json after a deletion: exit %d, %v", code, tgt)
	}
}

// The root case through compare, in the shape a build from before roots
// were kept wrote it: a self-applying Kustomization that one snapshot left
// out and the other captured, carrying its own labels, is moved both ways;
// the same with the labels gone from the captured copy is a difference.
func TestCompareMovesASelfApplyingRoot(t *testing.T) {
	why := snapshot.FluxKustomizationReason("gitops", "root")
	cov := []snapshot.Coverage{{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Kind: "Kustomization"}}
	root := func(labelled bool) snapshot.Object {
		md := map[string]any{"name": "root", "namespace": "gitops"}
		if labelled {
			md["labels"] = map[string]any{"kustomize.toolkit.fluxcd.io/name": "root", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
		}
		return snapshot.Object{Body: map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": md, "spec": map[string]any{"path": "./cluster"}}}
	}
	skipped := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Coverage: cov, Skips: []snapshot.Skip{{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Namespace: "gitops", Name: "root", Reason: why}}}
	write := func(s snapshot.Snapshot) string {
		d := filepath.Join(t.TempDir(), "s")
		if err := s.Write(d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	old := write(skipped)
	for _, labelled := range []bool{true, false} {
		now := write(snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Coverage: cov, Objects: []snapshot.Object{root(labelled)}})
		for _, c := range []struct {
			from, to, kind string
		}{{old, now, snapshot.NoLongerSkipped}, {now, old, snapshot.NoLongerCaptured}} {
			code, stdout, _ := output(t, func() int { return compare([]string{c.from, c.to}) })
			moved := strings.Contains(stdout, "moved    kustomize.toolkit.fluxcd.io/v1|Kustomization|gitops|root: "+c.kind)
			if labelled && (code != 0 || !moved) {
				t.Errorf("labelled root, %s: exit %d, want 0 and moved\n%s", c.kind, code, stdout)
			}
			if !labelled && (code != 2 || moved) {
				t.Errorf("root without its labels, %s: exit %d, want 2 and a difference\n%s", c.kind, code, stdout)
			}
		}
	}
}

// A report says the moves its own comparison found, once: the next one in
// the same run, of a diff that looks for none, does not repeat them.
func TestReportSaysMovesOnce(t *testing.T) {
	why := snapshot.FluxKustomizationReason("gitops", "root")
	cov := []snapshot.Coverage{{Resource: "core/v1/namespaces", Kind: "Namespace"}}
	ns := elsewhereObject("v1", "Namespace", "", "shop", nil)
	ns.Body["metadata"].(map[string]any)["labels"] = map[string]any{"kustomize.toolkit.fluxcd.io/name": "root", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
	want := snapshot.Snapshot{Platform: "kubernetes", Coverage: cov, Objects: []snapshot.Object{ns}}
	got := snapshot.Snapshot{Platform: "kubernetes", Coverage: cov, Skips: []snapshot.Skip{{Resource: "core/v1/namespaces", Name: "shop", Reason: why}}}
	_, first, _ := output(t, func() int { return report(differences(want, got, snapshot.Compare(want, got)), "a", "b") })
	_, second, _ := output(t, func() int { return report(nil, "a", "c") })
	if !strings.Contains(first, "moved    v1|Namespace||shop") || strings.Contains(second, "moved") {
		t.Errorf("first:\n%s\nsecond:\n%s", first, second)
	}
}

// wantSkip checks that a snapshot captured an object or skipped it.
func wantSkip(t *testing.T, dir, key string, skipped bool) {
	t.Helper()
	s, err := snapshot.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	captured := false
	for _, o := range s.Objects {
		if o.Key() == key {
			captured = true
		}
	}
	if captured == skipped {
		t.Fatalf("%s: captured %v, want skipped %v", key, captured, skipped)
	}
}

func mustConnect(t *testing.T, srv *kubetest.Server) *kube.Clients {
	t.Helper()
	c, err := kube.Connect(srv.Kubeconfig, srv.Context, true)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
