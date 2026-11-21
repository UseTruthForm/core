package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
	"github.com/usetruthform/core/internal/translate"
)

// translate --gitops and --kube: the change list is printed and written,
// the variables file goes beside the report, and only a reference with no
// translation makes the run exit 3.
func TestTranslateGitOps(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	src := filepath.Join(dir, "azure")
	az := snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": "azure.truthform.org/v1", "kind": "Microsoft.ContainerRegistry/registries",
		"metadata": map[string]any{"name": "pubimages", "namespace": "rg"},
		"spec": map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Basic"},
			"properties": map[string]any{"adminUserEnabled": false, "publicNetworkAccess": "Enabled"}}}}}}
	if err := az.Write(src); err != nil {
		t.Fatal(err)
	}
	kube := filepath.Join(dir, "kube")
	k := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{{Body: map[string]any{
		"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": map[string]any{"name": "flux-system", "namespace": "flux-system"},
		"spec": map[string]any{"path": "./clusters/prod", "sourceRef": map[string]any{"kind": "GitRepository", "name": "flux-system"}}}}, {Body: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "loose", "namespace": "legacy"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "main", "image": "pubimages.azurecr.io/loose:1"}}}}}}}},
		Skips: []snapshot.Skip{{Resource: "apps/v1/deployments", Namespace: "shop", Name: "web", Reason: snapshot.FluxKustomizationReason("flux-system", "apps")}}}
	if err := k.Write(kube); err != nil {
		t.Fatal(err)
	}
	m := write("aws.yaml", "to: aws\nregion: eu-west-1\ndestinations:\n  registry: ecr\n")
	deploy := func(image string) string {
		return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: shop\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: " + image + "\n"
	}
	write("repo/apps/web.yaml", deploy("pubimages.azurecr.io/shop/web:1"))
	repo, out := filepath.Join(dir, "repo"), filepath.Join(dir, "out")
	schemas := filepath.Join("..", "..", "internal", "translate", "testdata", "aws")
	args := []string{"--from", src, "--map", m, "--out", out, "--schemas", schemas}
	vars := filepath.Join(out, translate.GitOpsVariablesFile)

	// A reference that has a translation: exit 0, and it is listed.
	code, stdout, stderr := output(t, func() int { return translateCmd(append(args, "--gitops", repo)) })
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	for _, part := range []string{
		"1 reference(s) to change, 0 to check, 0 with no translation; 0 source(s) not available to check.",
		"apps/web.yaml:11 Deployment shop/web, applied by no Flux Kustomization found in these files\n    spec.template.spec.containers[0].image names pubimages.azurecr.io/shop/web:1; on the target it is {{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/pubimages/shop/web:1",
		"variable: ${registry_pubimages}",
		"No Kubernetes snapshot was given (--kube)",
		vars,
	} {
		if !strings.Contains(stdout, part) {
			t.Errorf("not printed: %s\n%s", part, stdout)
		}
	}
	if b, err := os.ReadFile(vars); err != nil || !strings.Contains(string(b), `registry_pubimages: "{{truthform|account|self|id}}.dkr.ecr.eu-west-1.amazonaws.com/pubimages"`) {
		t.Errorf("the variables file: %v\n%s", err, b)
	}
	if b, _ := os.ReadFile(filepath.Join(out, reportFile)); !strings.Contains(string(b), "gitops:") || !strings.Contains(string(b), "file: apps/web.yaml") || !strings.Contains(string(b), "variables: "+translate.GitOpsVariablesFile) {
		t.Errorf("the report has no GitOps section:\n%s", b)
	}
	// The repository is read, never written.
	if b, _ := os.ReadFile(filepath.Join(repo, "apps", "web.yaml")); string(b) != deploy("pubimages.azurecr.io/shop/web:1") {
		t.Error("the repository was changed")
	}

	// With the cluster's snapshot: a source it names and the files do not
	// hold is counted and named, a workload in no repository is listed,
	// and neither fails the run. Which files apply is followed from the
	// Kustomization the snapshot holds: the other file is not printed.
	write("repo/clusters/prod/api.yaml", deploy("pubimages.azurecr.io/shop/api:1"))
	code, stdout, stderr = output(t, func() int { return translateCmd(append(args, "--gitops", repo, "--kube", kube)) })
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	for _, part := range []string{
		"2 reference(s) to change, 0 to check, 0 with no translation; 1 source(s) not available to check.",
		"the Kubernetes snapshot Deployment legacy/loose, applied by nothing in Git: a restore recreates it from the snapshot as it is",
		"legacy: Deployment loose",
		"Flux Kustomization flux-system/apps: not available (the capture left 1 object(s) to it)",
		"1 source(s) whose content was not available to check: Flux Kustomization flux-system/apps.",
		"clusters/prod/api.yaml:11 Deployment shop/web, applied by Flux Kustomization flux-system/flux-system",
		"1 reference(s) are in files this cluster's Flux does not apply",
	} {
		if !strings.Contains(stdout, part) {
			t.Errorf("not printed: %s\n%s", part, stdout)
		}
	}
	if strings.Contains(stdout, "apps/web.yaml:11") {
		t.Errorf("a file this cluster's Flux does not apply is printed with the rest:\n%s", stdout)
	}

	// A reference with no translation: exit 3, and why is printed.
	write("repo/apps/proxy.yaml", deploy("partner.azurecr.io/proxy:2"))
	code, stdout, stderr = output(t, func() int { return translateCmd(append(args, "--gitops", repo)) })
	if code != 3 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "2 reference(s) to change, 0 to check, 1 with no translation") ||
		!strings.Contains(stdout, "names partner.azurecr.io/proxy:2; it has no translation: registry partner is not in the Azure snapshot") {
		t.Errorf("not printed:\n%s", stdout)
	}

	// Without either flag: no section, and the earlier variables file
	// goes, as a stale snapshot does.
	code, stdout, stderr = output(t, func() int { return translateCmd(args) })
	if code != 0 || strings.Contains(stdout, "Kubernetes workloads") {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	if _, err := os.Stat(vars); !os.IsNotExist(err) {
		t.Errorf("the earlier variables file is still there: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(out, reportFile)); strings.Contains(string(b), "gitops") {
		t.Errorf("a GitOps section nobody asked for:\n%s", b)
	}

	// What is not a Kubernetes snapshot, or not a directory, is refused.
	if code, _, stderr := output(t, func() int { return translateCmd(append(args, "--kube", src)) }); code != 1 || !strings.Contains(stderr, "--kube reads a Kubernetes snapshot; this one is azure") {
		t.Errorf("an Azure snapshot as --kube: exit %d: %s", code, stderr)
	}
	if code, _, stderr := output(t, func() int { return translateCmd(append(args, "--gitops", filepath.Join(dir, "nowhere"))) }); code != 1 || !strings.Contains(stderr, "--gitops") {
		t.Errorf("a missing --gitops: exit %d: %s", code, stderr)
	}
}
