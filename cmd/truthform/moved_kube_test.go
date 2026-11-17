package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// On a real API server: a namespace a GitOps tool begins to apply, and a
// ConfigMap it stops applying, are said as moved by compare, diff and an
// environment's diff, and none of them is a difference; a ConfigMap that
// is deleted still is one.
func TestMovedBetweenCaptures(t *testing.T) {
	srv := kubetest.Start(t, "moved")
	settle(t, srv)
	ctx := context.Background()
	c, err := kube.Connect(srv.Kubeconfig, srv.Context, true)
	if err != nil {
		t.Fatal(err)
	}
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
		{ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "shop", Labels: flux}, Data: map[string]string{"a": "1"}},
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
	wantSkip(t, before, "v1|Namespace||shop", false)
	wantSkip(t, before, "v1|ConfigMap|shop|legacy", true)

	// The tool takes the namespace on, and lets the ConfigMap go.
	ns, _ := cs.CoreV1().Namespaces().Get(ctx, "shop", metav1.GetOptions{})
	ns.Labels = flux
	if _, err := cs.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	cm, _ := cs.CoreV1().ConfigMaps("shop").Get(ctx, "legacy", metav1.GetOptions{})
	cm.Labels = nil
	if _, err := cs.CoreV1().ConfigMaps("shop").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	snap, err := kube.Capture(ctx, c, kube.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	after := filepath.Join(dir, "after")
	if err := snap.Write(after); err != nil {
		t.Fatal(err)
	}
	wantSkip(t, after, "v1|Namespace||shop", true)
	wantSkip(t, after, "v1|ConfigMap|shop|legacy", false)

	moved := []string{
		"moved    v1|ConfigMap|shop|legacy: no longer skipped (was: applied by Flux Kustomization gitops/root; restoring it recreates this), so now captured",
		"moved    v1|Namespace||shop: no longer captured: applied by Flux Kustomization gitops/root; restoring it recreates this",
	}
	check := func(what, stdout string, extra ...string) {
		t.Helper()
		for _, l := range append(moved, extra...) {
			if !strings.Contains(stdout, l) {
				t.Errorf("%s: no %q in\n%s", what, l, stdout)
			}
		}
		for _, l := range []string{"missing  v1|Namespace", "extra    v1|ConfigMap|shop|legacy"} {
			if strings.Contains(stdout, l) {
				t.Errorf("%s: a move said as a difference (%q):\n%s", what, l, stdout)
			}
		}
	}
	code, stdout, _ := output(t, func() int { return compare([]string{before, after}) })
	if code != 0 {
		t.Errorf("compare: exit %d, want 0\n%s", code, stdout)
	}
	check("compare", stdout, "no differences:", "2 objects moved between captured and left out, which is not a difference")
	diffArgs := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", before}
	code, stdout, _ = output(t, func() int { return diff(ctx, diffArgs) })
	if code != 0 {
		t.Errorf("diff: exit %d, want 0\n%s", code, stdout)
	}
	check("diff", stdout, "no differences:")
	code, stdout, _ = output(t, func() int { return diffEnvironment(ctx, cfg, env) })
	if code != 0 {
		t.Errorf("environment diff: exit %d, want 0\n%s", code, stdout)
	}
	check("environment diff", strings.ReplaceAll(stdout, "  moved", "moved"), "== cluster (kubernetes): 0 differences; 2 objects moved")

	// A real removal is still one, and the moves are still apart from it.
	if err := cs.CoreV1().ConfigMaps("shop").Delete(ctx, "plain", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = output(t, func() int { return diff(ctx, diffArgs) })
	if code != 2 {
		t.Errorf("diff after a deletion: exit %d, want 2\n%s", code, stdout)
	}
	check("diff after a deletion", stdout, "missing  v1|ConfigMap|shop|plain", "1 differences between")
	code, stdout, _ = output(t, func() int { return diffEnvironment(ctx, cfg, env) })
	if code != 2 {
		t.Errorf("environment diff after a deletion: exit %d, want 2\n%s", code, stdout)
	}
	d := asJSON(t, func() { code = diff(ctx, diffArgs) })
	if code != 2 || d["differences"] != float64(1) || len(d["changes"].([]any)) != 1 || len(d["moved"].([]any)) != 2 {
		t.Errorf("--json: exit %d, %v", code, d)
	}
	if m := d["moved"].([]any)[1].(map[string]any); m["kind"] != snapshot.NoLongerCaptured || m["key"] != "v1|Namespace||shop" || !strings.Contains(m["reason"].(string), "gitops/root") {
		t.Errorf("--json moved: %v", m)
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
