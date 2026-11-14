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

const drillScope = "narrow:\n  - namespaces: [\"team-*\"]\n    releases: [a-search]\n    objects: [ConfigMap/shared]\n"

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
	if code != 0 || strings.Contains(stdout, "left out") || !strings.Contains(stdout, "10 of the 10 objects of 3 narrowed namespaces") {
		t.Errorf("the draft, checked: exit %d\n%s", code, stdout)
	}

	drill := writeFile(t, t.TempDir(), "drill.yaml", drillScope)
	code, stdout, _ = output(t, func() int { return planCmd([]string{"scope", "--from", dir, "--check", drill}) })
	for _, want := range []string{"4 of the 8 objects of 2 narrowed namespaces", "team-a/a-search (2 objects)", "2 releases left out:", "team-a/a-lien (2 objects)", "team-b/b-search (1 objects)"} {
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
	if code != 2 || strings.Contains(stdout, "a-lien") || strings.Contains(stdout, "|team-b|") || !strings.Contains(stdout, "ConfigMap|team-a|a-search") || !strings.Contains(stdout, "ConfigMap|core|api") {
		t.Errorf("diff: exit %d\n%s", code, stdout)
	}
	if !strings.Contains(stderr, "scope: 4 of the 8 objects of 2 narrowed namespaces") || !strings.Contains(stderr, "team-a/a-lien (2 objects)") ||
		!strings.Contains(stderr, "1 objects that no release made are brought, named under objects or by label: ConfigMap team-a/shared") {
		t.Errorf("the diff does not say what the scope left out:\n%s", stderr)
	}
	// The total says it is of a part.
	if !strings.Contains(stdout, "a part only (--scope): 4 of the 8 objects of team-a, team-b were in it") {
		t.Errorf("the total reads as the whole snapshot's:\n%s", stdout)
	}
	d := asJSON(t, func() { diff(ctx, append(base, "--scope", drill)) })
	if sc, _ := d["scope"].(map[string]any); sc["kept"] != float64(4) {
		t.Errorf("scope in the document: %v", d["scope"])
	}
	d = asJSON(t, func() { diff(ctx, base) })
	if _, there := d["scope"]; there {
		t.Errorf("scope with no --scope: %v", d["scope"])
	}
	if _, err := scoped(drill, "azure", snapshot.Snapshot{Platform: "azure"}); err == nil || !strings.Contains(err.Error(), "--scope is for --platform kubernetes only") {
		t.Errorf("a scope for another platform: %v", err)
	}
	// --leave-out names objects of the snapshot as it is: one the scope
	// leaves out too is not a mistake in the file.
	leave := writeFile(t, t.TempDir(), "leave.yaml", "- ConfigMap/team-a/a-lien\n")
	code, stdout, _ = output(t, func() int { return diff(ctx, append(base, "--scope", drill, "--leave-out", leave)) })
	if code != 2 || strings.Contains(stdout, "team-a|a-lien") || !strings.Contains(stdout, "ConfigMap|team-a|a-search") {
		t.Errorf("diff with a scope and a leave-out file: exit %d, %v\n%s", code, lastErr, stdout)
	}
	for why, args := range map[string][]string{
		"--scope and --values are for a diff against one target": {"--config", drill, "--from", dir, "--scope", drill},
	} {
		lastErr = nil
		if code := diff(ctx, args); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), why) {
			t.Errorf("%v: exit %d, %v; want 1 and %q", args, code, lastErr, why)
		}
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
	// --leave-out names an object the scope leaves out too: no mistake.
	leave := writeFile(t, t.TempDir(), "leave.yaml", "- ConfigMap/team-a/a-lien\n")
	code, stdout, stderr := output(t, func() int {
		return restore(ctx, append(base, "--scope", drill, "--leave-out", leave, "--secrets-from", sources))
	})
	if code != 0 || !strings.Contains(stdout, "applied 6 of 6 objects") || !strings.Contains(stdout, "a part only (--scope): 4 of the 7 objects") {
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

// What the run says of a scope, in the words a person reads: what no
// release made and was left, what a source brought still makes, and that
// nothing checks what the part needs.
func TestScopeSaid(t *testing.T) {
	said := scopeSaid(kube.ScopeReport{
		Narrowed: []string{"shop"}, Kept: 1, Of: 3,
		ObjectsLeftOut: []string{"Deployment shop/queue-consumer"},
		ObjectsBrought: []string{"ConfigMap shop/shared"},
		SharedName:     []string{"ClusterRole x (it may be of other/x, left out)"},
		StillMade:      []kube.ScopeMade{{Source: "Flux Kustomization flux-system/root", Namespace: "shop", Objects: 2}},
	}, "scope.yaml")
	for _, want := range []string{
		"1 objects that no release made are left out (name one under objects, as Kind/name, to bring it): Deployment shop/queue-consumer",
		"1 objects that no release made are brought, named under objects or by label: ConfigMap shop/shared",
		"NOTE: Flux Kustomization flux-system/root is brought, and makes 2 objects in shop",
		"ClusterRole x (it may be of other/x, left out)",
		"nothing checks that what is brought does not need something left out",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("does not say %q:\n%s", want, said)
		}
	}
	// With everything brought there is no such warning.
	if said := scopeSaid(kube.ScopeReport{Narrowed: []string{"shop"}, Kept: 3, Of: 3}, "scope.yaml"); strings.Contains(said, "nothing checks") || strings.Contains(said, "NOTE") {
		t.Errorf("a scope that brings everything:\n%s", said)
	}
}

// A hold that passed objects it does not know says so, and does not say
// nothing is running.
func TestScopeSaidOfAHold(t *testing.T) {
	rep := kube.ScopeReport{Narrowed: []string{"shop"}, Kept: 2, Of: 2, Held: []kube.ScopeHeld{{Object: "Deployment shop/worker", How: "zero replicas (it had 3)"}}}
	if said := scopeSaid(rep, "scope.yaml"); !strings.Contains(said, "1 objects are brought with nothing running (hold: true)") || strings.Contains(said, "NOTE") {
		t.Errorf("a whole hold:\n%s", said)
	}
	rep.NotHeld = []string{"Cluster shop/db"}
	said := scopeSaid(rep, "scope.yaml")
	if strings.Contains(said, "nothing running") || !strings.Contains(said, "1 objects are brought stopped (hold: true)") ||
		!strings.Contains(said, "NOTE: 1 objects under hold: true are brought as they are") || !strings.Contains(said, "Cluster shop/db") {
		t.Errorf("a hold that passed what it does not know:\n%s", said)
	}
	// Looked at, they are still not held: the hold is not said to be whole.
	rep.NotHeld, rep.AsTheyAre = nil, []string{"Cluster shop/db"}
	if said := scopeSaid(rep, "scope.yaml"); strings.Contains(said, "nothing running") || strings.Contains(said, "NOTE") || !strings.Contains(said, "as scope.yaml asks (asTheyAre): Cluster shop/db") {
		t.Errorf("a hold with what it does not know looked at:\n%s", said)
	}
}
