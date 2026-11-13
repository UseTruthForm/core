package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// scopeSnapshot is a snapshot with two namespaces of Helm releases and one
// of none, written to a directory.
func scopeSnapshot(t *testing.T) string {
	t.Helper()
	rel := func(kind, ns, name, release string, rest map[string]any) snapshot.Object {
		o := elsewhereObject("v1", kind, ns, name, rest)
		o.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": release, "meta.helm.sh/release-namespace": ns}
		o.Body["metadata"].(map[string]any)["labels"] = map[string]any{"app.kubernetes.io/managed-by": "Helm"}
		return o
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		elsewhereObject("v1", "Namespace", "", "core", nil),
		elsewhereObject("v1", "Namespace", "", "team-a", nil),
		elsewhereObject("v1", "Namespace", "", "team-b", nil),
		rel("ConfigMap", "core", "api", "api", nil),
		rel("ConfigMap", "team-a", "a-search", "a-search", nil),
		rel("Secret", "team-a", "a-search", "a-search", map[string]any{"data": map[string]any{"token": ""}}),
		rel("ConfigMap", "team-a", "a-lien", "a-lien", nil),
		rel("Secret", "team-a", "a-lien", "a-lien", map[string]any{"data": map[string]any{"token": ""}}),
		elsewhereObject("v1", "ConfigMap", "team-a", "shared", nil),
		rel("ConfigMap", "team-b", "b-search", "b-search", nil),
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

const drillScope = "narrow:\n  - namespaces: [\"team-*\"]\n    releases: [a-search]\n"

// plan scope writes a file that brings everything, never over one, and
// --check says what a file brings and leaves out. The other plans, given
// the file, are of the part it brings.
func TestPlanScopeCommand(t *testing.T) {
	dir := scopeSnapshot(t)
	file := filepath.Join(t.TempDir(), "scope.yaml")
	if code := planCmd([]string{"scope", "--from", dir, "--out", file}); code != 0 {
		t.Fatalf("exit %d, %v", code, lastErr)
	}
	b, _ := os.ReadFile(file)
	for _, want := range []string{`- namespaces: ["team-a"]`, `- "a-lien" # ConfigMap, Secret`, `- "b-search" # ConfigMap`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the file lacks %q:\n%s", want, b)
		}
	}
	if code := planCmd([]string{"scope", "--from", dir, "--out", file}); code != 1 || !strings.Contains(lastErr.Error(), "is there already") {
		t.Errorf("written over a file that may be cut down: exit %d, %v", code, lastErr)
	}
	// As written, nothing is left out.
	code, stdout, _ := output(t, func() int { return planCmd([]string{"scope", "--from", dir, "--check", file}) })
	if code != 0 || strings.Contains(stdout, "left out") || !strings.Contains(stdout, "10 of 10 objects in 3 narrowed namespaces") {
		t.Errorf("the draft, checked: exit %d\n%s", code, stdout)
	}

	drill := writeFile(t, t.TempDir(), "drill.yaml", drillScope)
	code, stdout, _ = output(t, func() int { return planCmd([]string{"scope", "--from", dir, "--check", drill}) })
	for _, want := range []string{"4 of 8 objects in 2 narrowed namespaces", "team-a/a-search (2 objects)", "2 releases left out:", "team-a/a-lien (2 objects)", "team-b/b-search (1 objects)"} {
		if code != 0 || !strings.Contains(stdout, want) {
			t.Errorf("--check: exit %d, lacks %q:\n%s", code, want, stdout)
		}
	}
	d := asJSON(t, func() { planCmd([]string{"scope", "--from", dir, "--check", drill}) })
	sc, _ := d["scope"].(map[string]any)
	if left, _ := sc["leftOut"].([]any); len(left) != 2 || sc["kept"] != float64(4) {
		t.Errorf("scope as JSON: %v", d)
	}

	// The secrets to supply are those of the part brought.
	whole := filepath.Join(t.TempDir(), "all.yaml")
	part := filepath.Join(t.TempDir(), "part.yaml")
	if planCmd([]string{"secrets", "--from", dir, "--out", whole}) != 0 || planCmd([]string{"secrets", "--from", dir, "--scope", drill, "--out", part}) != 0 {
		t.Fatalf("plan secrets: %v", lastErr)
	}
	all, _ := os.ReadFile(whole)
	some, _ := os.ReadFile(part)
	if !strings.Contains(string(all), "team-a/a-lien") || strings.Contains(string(some), "team-a/a-lien") || !strings.Contains(string(some), "team-a/a-search") {
		t.Errorf("secrets of the whole:\n%s\nof the part:\n%s", all, some)
	}
	d = asJSON(t, func() { planCmd([]string{"rebuild", "--from", dir, "--scope", drill}) })
	plan, _ := d["plan"].(map[string]any)
	if byHand, _ := plan["secretsByHand"].([]any); len(byHand) != 1 || d["scope"] == nil {
		t.Errorf("plan rebuild --scope: %v", d)
	}

	azure := filepath.Join(t.TempDir(), "azure")
	if err := (snapshot.Snapshot{Platform: "azure", Policy: "default"}).Write(azure); err != nil {
		t.Fatal(err)
	}
	for why, args := range map[string][]string{
		"--from is required":         {"scope"},
		"give one of them":           {"scope", "--from", dir, "--out", file, "--check", file},
		"is a azure snapshot":        {"scope", "--from", azure},
		`no release named "a-serch"`: {"scope", "--from", dir, "--check", writeFile(t, t.TempDir(), "typo.yaml", "narrow:\n  - namespaces: [team-a]\n    releases: [a-serch]\n")},
		"unknown field":              {"scope", "--from", dir, "--check", writeFile(t, t.TempDir(), "key.yaml", "narow:\n  - namespaces: [team-a]\n")},
	} {
		lastErr = nil
		if code := planCmd(args); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), why) {
			t.Errorf("%v: exit %d, %v; want 1 and %q", args, code, lastErr, why)
		}
	}
}

// A diff given a scope expects the part and no more, and says what was
// left out: it writes nothing, so it runs in the capture-only build too.
func TestKubernetesDiffScope(t *testing.T) {
	dir := scopeSnapshot(t)
	drill := writeFile(t, t.TempDir(), "drill.yaml", drillScope)
	srv := kubetest.Start(t, "scope-diff")
	ctx := context.Background()
	base := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", dir}
	code, stdout, stderr := output(t, func() int { return diff(ctx, append(base, "--scope", drill)) })
	if code != 2 || strings.Contains(stdout, "a-lien") || strings.Contains(stdout, "team-b") || !strings.Contains(stdout, "ConfigMap|team-a|a-search") || !strings.Contains(stdout, "ConfigMap|core|api") {
		t.Errorf("diff: exit %d\n%s", code, stdout)
	}
	if !strings.Contains(stderr, "scope: 4 of 8 objects in 2 narrowed namespaces") || !strings.Contains(stderr, "team-a/a-lien (2 objects)") {
		t.Errorf("the diff does not say what the scope left out:\n%s", stderr)
	}
	d := asJSON(t, func() { diff(ctx, append(base, "--scope", drill)) })
	if sc, _ := d["scope"].(map[string]any); sc["kept"] != float64(4) {
		t.Errorf("scope in the document: %v", d["scope"])
	}
	d = asJSON(t, func() { diff(ctx, base) })
	if _, there := d["scope"]; there {
		t.Errorf("scope with no --scope: %v", d["scope"])
	}
	lastErr = nil
	if code := diff(ctx, append(base, "--scope", writeFile(t, t.TempDir(), "none.yaml", "narrow:\n  - namespaces: [team-zz]\n"))); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), `no namespace in the snapshot fits "team-zz"`) {
		t.Errorf("a scope that fits nothing: exit %d, %v", code, lastErr)
	}
}

// A restore given a scope writes the part, on a real API server.
func TestKubernetesRestoreScope(t *testing.T) {
	if captureOnly {
		t.Skip("a restore, which the capture-only build refuses")
	}
	dir := scopeSnapshot(t)
	drill := writeFile(t, t.TempDir(), "drill.yaml", drillScope)
	sources := writeFile(t, t.TempDir(), "secrets.yaml", "secrets:\n  - secret: team-a/a-search\n    from: {token: \"env:TF_SCOPE_TOKEN\"}\n")
	t.Setenv("TF_SCOPE_TOKEN", "a-value")
	srv := kubetest.Start(t, "scope")
	ctx := context.Background()
	base := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", dir}
	// The sources file names only the Secret of the part brought: the one
	// left out needs no source.
	code, stdout, stderr := output(t, func() int { return restore(ctx, append(base, "--scope", drill, "--secrets-from", sources)) })
	if code != 0 || !strings.Contains(stdout, "applied 6 of 6 objects") {
		t.Fatalf("restore: exit %d, %v\n%s\n%s", code, lastErr, stdout, stderr)
	}
	c, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	cs := kubernetes.NewForConfigOrDie(c.Config)
	for _, name := range []string{"a-search", "shared"} {
		if _, err := cs.CoreV1().ConfigMaps("team-a").Get(ctx, name, metav1.GetOptions{}); err != nil {
			t.Errorf("team-a/%s was not restored: %v", name, err)
		}
	}
	if _, err := cs.CoreV1().ConfigMaps("team-a").Get(ctx, "a-lien", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("a release left out was restored: %v", err)
	}
	if _, err := cs.CoreV1().Namespaces().Get(ctx, "team-b", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("a namespace nothing was chosen from was restored: %v", err)
	}
	d := asJSON(t, func() { restore(ctx, append(base, "--scope", drill, "--secrets-from", sources)) })
	if sc, _ := d["scope"].(map[string]any); sc["kept"] != float64(4) || d["complete"] != true {
		t.Errorf("the document: %v", d)
	}
}
