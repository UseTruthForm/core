package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// A restore with a scope that holds, and a rename that names another
// registry, writes the workload with nothing running and its image from
// the new place, on a real API server; the same files given to diff find
// it as it should be; and a restore without the hold starts it.
func TestKubernetesRestoreHoldsAndRenamesImages(t *testing.T) {
	if captureOnly {
		t.Skip("a restore, which the capture-only build refuses")
	}
	workload := func(name, image string) snapshot.Object {
		o := elsewhereObject("apps/v1", "Deployment", "shop", name, map[string]any{"spec": map[string]any{
			"replicas": float64(2),
			"selector": map[string]any{"matchLabels": map[string]any{"app": name}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"app": name}},
				"spec":     map[string]any{"containers": []any{map[string]any{"name": "c", "image": image}}},
			},
		}})
		md := o.Body["metadata"].(map[string]any)
		md["annotations"] = map[string]any{"meta.helm.sh/release-name": name, "meta.helm.sh/release-namespace": "shop"}
		md["labels"] = map[string]any{"app.kubernetes.io/managed-by": "Helm"}
		return o
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		elsewhereObject("v1", "Namespace", "", "shop", nil),
		workload("worker", "old.example.io/shop/worker:1"),
		workload("api", "old.example.io/shop/api:1"),
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	held := writeFile(t, t.TempDir(), "held.yaml", "narrow:\n  - namespaces: [shop]\n    releases: [api]\n  - namespaces: [shop]\n    releases: [worker]\n    hold: true\n")
	running := writeFile(t, t.TempDir(), "running.yaml", "narrow:\n  - namespaces: [shop]\n    releases: [api, worker]\n")
	names := writeFile(t, t.TempDir(), "names.yaml", "old.example.io/shop/: new.example.io/drill/\n")
	srv := kubetest.Start(t, "hold")
	ctx := context.Background()
	base := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", dir, "--rename", names}

	code, stdout, stderr := output(t, func() int { return restore(ctx, append(base, "--scope", held)) })
	if code != 0 || !strings.Contains(stdout, "applied 3 of 3 objects") {
		t.Fatalf("restore: exit %d, %v\n%s\n%s", code, lastErr, stdout, stderr)
	}
	for _, want := range []string{
		"1 objects are brought with nothing running",
		"Deployment shop/worker: zero replicas",
		"2 images are pulled from elsewhere",
		"Deployment shop/worker spec.template.spec.containers[].image: old.example.io/shop/worker:1 -> new.example.io/drill/worker:1",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the restore does not say %q:\n%s", want, stderr)
		}
	}
	c, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	deployments := kubernetes.NewForConfigOrDie(c.Config).AppsV1().Deployments("shop")
	replicas := func(name string) (int32, string) {
		t.Helper()
		d, err := deployments.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return *d.Spec.Replicas, d.Spec.Template.Spec.Containers[0].Image
	}
	if n, image := replicas("worker"); n != 0 || image != "new.example.io/drill/worker:1" {
		t.Errorf("worker, held: %d replicas of %s", n, image)
	}
	if n, image := replicas("api"); n != 2 || image != "new.example.io/drill/api:1" {
		t.Errorf("api, not held: %d replicas of %s", n, image)
	}

	// The same files: neither the count nor the image differs (the rest
	// of what a diff lists here is what the server fills in, which a
	// snapshot written by hand does not have). Without the hold, the held
	// one's count does.
	line := func(stdout, name string) string {
		for _, l := range strings.Split(stdout, "\n") {
			if strings.Contains(l, "Deployment|shop|"+name) {
				return l
			}
		}
		return ""
	}
	_, stdout, _ = output(t, func() int { return diff(ctx, append(base, "--scope", held)) })
	for _, name := range []string{"worker", "api"} {
		if l := line(stdout, name); strings.Contains(l, "spec.replicas") || strings.Contains(l, "].image,") || strings.HasSuffix(l, "].image") {
			t.Errorf("diff with the files the restore had: %s", l)
		}
	}
	_, stdout, _ = output(t, func() int { return diff(ctx, append(base, "--scope", running)) })
	if !strings.Contains(line(stdout, "worker"), "spec.replicas") || strings.Contains(line(stdout, "api"), "spec.replicas") {
		t.Errorf("diff without the hold:\n%s", stdout)
	}

	// The document says both.
	d := asJSON(t, func() { restore(ctx, append(base, "--scope", held)) })
	sc, _ := d["scope"].(map[string]any)
	if h, _ := sc["held"].([]any); len(h) != 1 || h[0].(map[string]any)["object"] != "Deployment shop/worker" {
		t.Errorf("scope.held: %v", sc["held"])
	}
	refs, _ := d["store_references"].(map[string]any)
	images, _ := refs["images"].(map[string]any)
	if changed, _ := images["changed"].([]any); len(changed) != 2 {
		t.Errorf("store_references.images: %v", refs["images"])
	}

	// Restored without the hold, it runs.
	if code := restore(ctx, append(base, "--scope", running)); code != 0 {
		t.Fatalf("restore without the hold: exit %d, %v", code, lastErr)
	}
	if n, _ := replicas("worker"); n != 2 {
		t.Errorf("worker, restored without the hold: %d replicas", n)
	}
}

// The rebuild plan lists where the images are pulled from, and how many
// are named by a tag alone.
func TestPlanRebuildListsRegistries(t *testing.T) {
	pod := func(image string) map[string]any {
		return map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": image}}}}}}
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		elsewhereObject("apps/v1", "Deployment", "shop", "a", pod("old.example.io/shop/a:latest")),
		elsewhereObject("apps/v1", "Deployment", "shop", "b", pod("old.example.io/shop/b@sha256:"+strings.Repeat("0", 64))),
		elsewhereObject("apps/v1", "Deployment", "shop", "c", pod("nginx:1.27")),
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := output(t, func() int { return planCmd([]string{"rebuild", "--from", dir}) })
	if code != 0 {
		t.Fatalf("exit %d, %v", code, lastErr)
	}
	for _, want := range []string{"| `old.example.io` | 2 | 1 |", "| `docker.io` | 1 | 1 |"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the plan does not say %q:\n%s", want, stdout)
		}
	}
	d := asJSON(t, func() { planCmd([]string{"rebuild", "--from", dir}) })
	p, _ := d["plan"].(map[string]any)
	if images, _ := p["images"].([]any); len(images) != 2 {
		t.Errorf("plan.images: %v (document keys %v)", p["images"], d)
	}
}
