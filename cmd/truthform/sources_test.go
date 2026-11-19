package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/snapshot"
)

// A restore whose scope holds something, and brings a GitOps source that
// it does not hold and that applies into a namespace it narrows, is
// refused before anything is connected to: restored as it is, the source
// syncs its Git path and starts what the scope held back. plan scope
// --check exits 2 for it. Held, or accepted by name, it is not refused.
// The shapes are those TestUnheldSourcesOfARealCapture captures.
func TestRestoreRefusesAnUnheldSource(t *testing.T) {
	if captureOnly {
		t.Skip("a restore, which the capture-only build refuses")
	}
	obj := elsewhereObject
	labelled := func(o snapshot.Object, labels map[string]any) snapshot.Object {
		o.Body["metadata"].(map[string]any)["labels"] = labels
		return o
	}
	byRoot := map[string]any{"kustomize.toolkit.fluxcd.io/name": "root", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
	web := obj("apps/v1", "Deployment", "shop", "web", map[string]any{"spec": map[string]any{"replicas": float64(2),
		"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "x"}}}}}})
	web.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "web", "meta.helm.sh/release-namespace": "shop"}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		obj("v1", "Namespace", "", "gitops", nil),
		obj("v1", "Namespace", "", "shop", nil),
		labelled(obj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root", map[string]any{"spec": map[string]any{"path": "./one", "sourceRef": map[string]any{"kind": "GitRepository", "name": "root"}}}), byRoot),
		labelled(obj("source.toolkit.fluxcd.io/v1", "GitRepository", "gitops", "root", map[string]any{"spec": map[string]any{"url": "https://git.example.invalid/one.git"}}), byRoot),
		web,
	}, Skips: []snapshot.Skip{
		{Resource: "apps/v1/deployments", Namespace: "shop", Name: "cart", Reason: "applied by Flux Kustomization gitops/root; restoring it recreates this"},
		// And what acts outside, which its Git path applies.
		{Resource: "image.toolkit.fluxcd.io/v1beta2/imageupdateautomations", Namespace: "gitops", Name: "bump", Reason: "applied by Flux Kustomization gitops/root; restoring it recreates this"},
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	const hold = "narrow:\n  - namespaces: [shop]\n    releases: [web]\n    hold: true\n"
	files := t.TempDir()
	scope := writeFile(t, files, "scope.yaml", hold)
	accepted := writeFile(t, files, "accepted.yaml", hold+"sourcesRunning:\n  - Kustomization/gitops/root\n  - GitRepository/gitops/root\n")
	// The Kustomization accepted, and not the GitRepository it reads,
	// which fetches.
	half := writeFile(t, files, "half.yaml", hold+"sourcesRunning:\n  - Kustomization/gitops/root\n")
	held := writeFile(t, files, "held.yaml", hold+"  - namespaces: [gitops]\n    hold: true\n    objects: [Kustomization/root, GitRepository/root]\n")
	running := writeFile(t, files, "running.yaml", "narrow:\n  - namespaces: [shop]\n    releases: [web]\n")
	leave := writeFile(t, files, "leave.yaml", "- Kustomization.kustomize.toolkit.fluxcd.io/gitops/root\n- GitRepository.source.toolkit.fluxcd.io/gitops/root\n")
	// Nowhere to restore to: what is refused is refused before that.
	nowhere := []string{"--kubeconfig", filepath.Join(files, "no-such-kubeconfig"), "--context", "none", "--from", dir}
	refused := func(args ...string) bool {
		lastErr = nil
		code := restore(context.Background(), append(append([]string{}, nowhere...), args...))
		if code == 0 {
			t.Errorf("%v: a restore to nowhere ended 0", args)
		}
		return lastErr != nil && strings.Contains(lastErr.Error(), "brought, not held, by a scope that holds what it chooses")
	}

	code, stdout, _ := output(t, func() int { return planScope([]string{"--from", dir, "--check", scope}) })
	if code != 2 || !strings.Contains(stdout, "NOTE: Flux Kustomization gitops/root is brought, and not held") || !strings.Contains(stdout, "accept it by naming it under sourcesRunning in the scope file (Kustomization/gitops/root)") {
		t.Errorf("plan scope --check: exit %d\n%s", code, stdout)
	}
	d := asJSON(t, func() { code = planScope([]string{"--from", dir, "--check", scope}) })
	srcs, _ := d["scope"].(map[string]any)["sourcesNotHeld"].([]any)
	if code != 2 || len(srcs) != 2 || srcs[1].(map[string]any)["blocks"] != true || srcs[1].(map[string]any)["object"] != "Kustomization gitops/root" {
		t.Fatalf("plan scope --check --json: exit %d, %v", code, d)
	}
	if out, _ := srcs[1].(map[string]any)["appliesOutside"].([]any); len(out) != 1 || !strings.HasPrefix(out[0].(string), "ImageUpdateAutomation gitops/bump (") {
		t.Errorf("plan scope --check --json: what the source applies that acts outside: %v", srcs[1])
	}
	// The GitRepository the root reads fetches, and is refused itself.
	if g := srcs[0].(map[string]any); g["object"] != "GitRepository gitops/root" || g["blocks"] != true || g["reaches"] != "it fetches its Git repository with the source's credentials" {
		t.Errorf("plan scope --check --json: the GitRepository: %v", g)
	}
	// Told apart from the other causes of 2.
	if sc := d["scope"].(map[string]any); len(sc["broughtNotHeld"].([]any)) != 0 || len(sc["webhooksWithoutService"].([]any)) != 0 {
		t.Errorf("another cause of 2 is listed too: %v", sc)
	}
	if !refused("--scope", scope) {
		t.Fatalf("restore: %v", lastErr)
	}
	for _, want := range []string{"Flux Kustomization gitops/root applies into shop", "Flux GitRepository gitops/root (it fetches its Git repository with the source's credentials)", "starts what the scope held back", "acts for real", "sourcesRunning in " + scope, "app.kubernetes.io/instance", "also what ordinary Helm charts set", "nothing was restored"} {
		if !strings.Contains(lastErr.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, lastErr)
		}
	}
	// The document of the refusal: one, not complete, naming the source.
	was := command
	command = "restore"
	d = asJSON(t, func() {
		emitError(restore(context.Background(), append(append([]string{}, nowhere...), "--scope", scope)))
	})
	command = was
	srcs, _ = d["sourcesNotHeld"].([]any)
	if d["complete"] != false || d["exit"] != float64(1) || len(srcs) != 2 || srcs[0].(map[string]any)["source"] != "Flux GitRepository gitops/root" || srcs[1].(map[string]any)["source"] != "Flux Kustomization gitops/root" {
		t.Errorf("the document of a refusal: %v", d)
	}

	// Accepted by name: exit 0, listed as accepted, and the restore goes
	// on to its target (here nowhere, so it fails there).
	code, stdout, _ = output(t, func() int { return planScope([]string{"--from", dir, "--check", accepted}) })
	if code != 0 || !strings.Contains(stdout, "Accepted in the scope file (sourcesRunning)") {
		t.Errorf("plan scope --check, accepted: exit %d\n%s", code, stdout)
	}
	d = asJSON(t, func() { code = planScope([]string{"--from", dir, "--check", accepted}) })
	if srcs, _ := d["scope"].(map[string]any)["sourcesNotHeld"].([]any); code != 0 || len(srcs) != 2 || srcs[0].(map[string]any)["accepted"] != true || srcs[1].(map[string]any)["accepted"] != true || srcs[0].(map[string]any)["blocks"] != false {
		t.Errorf("plan scope --check --json, accepted: exit %d, %v", code, d)
	}
	// One accepted and not the other: refused for the other.
	if code, stdout, _ := output(t, func() int { return planScope([]string{"--from", dir, "--check", half}) }); code != 2 || !strings.Contains(stdout, "NOTE: Flux GitRepository gitops/root is brought, and not held") {
		t.Errorf("plan scope --check, the GitRepository not accepted: exit %d\n%s", code, stdout)
	}
	if !refused("--scope", half) || !strings.Contains(lastErr.Error(), "1 object is brought") || !strings.Contains(lastErr.Error(), "Flux GitRepository gitops/root") {
		t.Errorf("restore, the GitRepository not accepted: %v", lastErr)
	}
	if refused("--scope", accepted) || lastErr == nil || !strings.Contains(lastErr.Error(), "no-such-kubeconfig") {
		t.Errorf("restore, accepted: %v", lastErr)
	}
	// Held, left out, or in a scope that holds nothing: not refused.
	for name, args := range map[string][]string{"held": {"--scope", held}, "left out": {"--scope", scope, "--leave-out", leave}, "a scope that holds nothing": {"--scope", running}} {
		if refused(args...) {
			t.Errorf("restore, %s: %v", name, lastErr)
		}
		if code, stdout, _ := output(t, func() int { return planScope(append([]string{"--from", dir, "--check", args[1]}, args[2:]...)) }); code != 0 {
			t.Errorf("plan scope --check, %s: exit %d\n%s", name, code, stdout)
		}
	}
	// With no scope, nothing is held, and nothing is refused for it.
	if refused() {
		t.Errorf("restore with no scope: %v", lastErr)
	}
	// A file that only accepts a source says why it cannot.
	only := writeFile(t, files, "only.yaml", "sourcesRunning:\n  - Kustomization/gitops/root\n")
	if code, _, _ := output(t, func() int { return planScope([]string{"--from", dir, "--check", only}) }); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), "has sourcesRunning and narrows nothing") {
		t.Errorf("a file with only sourcesRunning: exit %d, %v", code, lastErr)
	}
	// A refusal is not carried into the document of the next run that
	// fails before the question is asked.
	command = "restore"
	_ = asJSON(t, func() {
		emitError(restore(context.Background(), append(append([]string{}, nowhere...), "--scope", scope)))
	})
	d = asJSON(t, func() {
		emitError(restore(context.Background(), append(append([]string{}, nowhere...), "--scope", filepath.Join(files, "no-such-scope.yaml"))))
	})
	command = was
	if _, there := d["sourcesNotHeld"]; there {
		t.Errorf("the document of a later failure lists the sources of an earlier refusal: %v", d)
	}
}

// A restore refused for a webhook and for a source says both, and its
// document lists both: one fixed at a time would be found one run at a
// time.
func TestRestoreRefusesForEveryCauseAtOnce(t *testing.T) {
	if captureOnly {
		t.Skip("a restore, which the capture-only build refuses")
	}
	obj := elsewhereObject
	byRoot := map[string]any{"kustomize.toolkit.fluxcd.io/name": "root", "kustomize.toolkit.fluxcd.io/namespace": "gitops"}
	root := obj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "gitops", "root", map[string]any{"spec": map[string]any{"path": "./one"}})
	root.Body["metadata"].(map[string]any)["labels"] = byRoot
	web := obj("v1", "ConfigMap", "shop", "web", nil)
	web.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "web", "meta.helm.sh/release-namespace": "shop"}
	hook := map[string]any{"webhooks": []any{map[string]any{"name": "check.policy", "failurePolicy": "Fail",
		"clientConfig": map[string]any{"service": map[string]any{"namespace": "shop", "name": "policy"}}}}}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		obj("v1", "Namespace", "", "gitops", nil), obj("v1", "Namespace", "", "shop", nil), root, web,
		obj("admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", "", "policy", hook),
	}, Skips: []snapshot.Skip{
		{Resource: "apps/v1/deployments", Namespace: "shop", Name: "cart", Reason: "applied by Flux Kustomization gitops/root; restoring it recreates this"},
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	scope := writeFile(t, files, "scope.yaml", "narrow:\n  - namespaces: [shop]\n    releases: [web]\n    hold: true\n")
	nowhere := []string{"--kubeconfig", filepath.Join(files, "no-such-kubeconfig"), "--context", "none", "--from", dir, "--scope", scope}
	lastErr = nil
	if code := restore(context.Background(), nowhere); code == 0 || lastErr == nil {
		t.Fatalf("restore: exit %d", code)
	}
	for _, want := range []string{"calls shop/policy", "Flux Kustomization gitops/root applies into shop"} {
		if !strings.Contains(lastErr.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, lastErr)
		}
	}
	if n := strings.Count(lastErr.Error(), "nothing was restored"); n != 1 {
		t.Errorf("the refusal says nothing was restored %d times: %v", n, lastErr)
	}
	was := command
	command = "restore"
	d := asJSON(t, func() { emitError(restore(context.Background(), nowhere)) })
	command = was
	hooks, _ := d["webhooksWithoutService"].([]any)
	srcs, _ := d["sourcesNotHeld"].([]any)
	if d["complete"] != false || len(hooks) != 1 || len(srcs) != 1 {
		t.Errorf("the document of a refusal for both: %v", d)
	}
}

// What acts outside is said as what it does, not as where it applies.
func TestSourceNoteOfWhatActsOutside(t *testing.T) {
	n := sourceNote(kube.ScopeSource{Source: "Flux ImageUpdateAutomation imaging/bump", Object: "ImageUpdateAutomation imaging/bump", Namespaces: []string{},
		Reaches: "it commits and pushes image updates to its Git repository", Blocks: true})
	for _, want := range []string{"it commits and pushes image updates to its Git repository", "acts for real", "(ImageUpdateAutomation/imaging/bump)"} {
		if !strings.Contains(n, want) {
			t.Errorf("the note does not say %q: %s", want, n)
		}
	}
	if strings.Contains(n, "applies into") {
		t.Errorf("the note says where it applies: %s", n)
	}
	if b := blockingSources([]kube.ScopeSource{{Source: "Flux notification Provider imaging/chat", Reaches: "it sends", Blocks: true}}); len(b) != 1 || b[0] != "Flux notification Provider imaging/chat (it sends)" {
		t.Errorf("as the refusal lists it: %q", b)
	}
	// A source whose Git path applies what acts outside is named with it,
	// and with the namespaces it applies into.
	root := kube.ScopeSource{Source: "Flux Kustomization flux2/flux2", Object: "Kustomization flux2/flux2", Namespaces: []string{"shop"},
		Outside: []string{"ImageUpdateAutomation flux2/autobump (it pushes)"}, Blocks: true}
	n = sourceNote(root)
	for _, want := range []string{"applies into shop, which the scope narrows", "applies what acts outside the cluster, ImageUpdateAutomation flux2/autobump (it pushes), which the restore does not bring and the source makes again", "(Kustomization/flux2/flux2)"} {
		if !strings.Contains(n, want) {
			t.Errorf("the note of a source that applies what acts outside does not say %q: %s", want, n)
		}
	}
	if b := blockingSources([]kube.ScopeSource{root}); len(b) != 1 || b[0] != "Flux Kustomization flux2/flux2 applies into shop and applies ImageUpdateAutomation flux2/autobump (it pushes)" {
		t.Errorf("as the refusal lists a source that applies what acts outside: %q", b)
	}
	root.Namespaces = nil
	if b := blockingSources([]kube.ScopeSource{root}); len(b) != 1 || b[0] != "Flux Kustomization flux2/flux2 applies ImageUpdateAutomation flux2/autobump (it pushes)" {
		t.Errorf("as the refusal lists a source that only applies what acts outside: %q", b)
	}
}

// A HelmRepository of type oci fetches nothing (source-controller makes
// it static), so a scope that holds something and brings one not held is
// not refused for it: check exits 0, and a restore goes on. One of the
// default type fetches its index, and is refused. Held, the plan says it
// was suspended, and that this stops nothing.
func TestAnOCIHelmRepositoryIsNotRefused(t *testing.T) {
	if captureOnly {
		t.Skip("a restore, which the capture-only build refuses")
	}
	write := func(spec map[string]any) string {
		web := elsewhereObject("apps/v1", "Deployment", "shop", "web", map[string]any{"spec": map[string]any{"replicas": float64(1),
			"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "x"}}}}}})
		web.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "web", "meta.helm.sh/release-namespace": "shop"}
		s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
			elsewhereObject("v1", "Namespace", "", "shop", nil), elsewhereObject("v1", "Namespace", "", "charts", nil), web,
			elsewhereObject("source.toolkit.fluxcd.io/v1", "HelmRepository", "charts", "ocirepo", map[string]any{"spec": spec}),
		}}
		dir := filepath.Join(t.TempDir(), "cluster")
		if err := s.Write(dir); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	files := t.TempDir()
	scope := writeFile(t, files, "scope.yaml", "narrow: [{namespaces: [shop], releases: [web], hold: true}]\n")
	held := writeFile(t, files, "held.yaml", "narrow: [{namespaces: [shop], releases: [web], hold: true}, {namespaces: [charts], hold: true, objects: [HelmRepository/ocirepo]}]\n")
	restoreOf := func(dir string) error {
		lastErr = nil
		restore(context.Background(), []string{"--kubeconfig", filepath.Join(files, "no-such-kubeconfig"), "--context", "none", "--from", dir, "--scope", scope})
		return lastErr
	}

	oci := write(map[string]any{"type": "oci", "url": "oci://example.invalid/charts"})
	if code, stdout, _ := output(t, func() int { return planScope([]string{"--from", oci, "--check", scope}) }); code != 0 || strings.Contains(stdout, "Flux HelmRepository") {
		t.Errorf("plan scope --check, an oci HelmRepository: exit %d\n%s", code, stdout)
	}
	if err := restoreOf(oci); err == nil || strings.Contains(err.Error(), "brought, not held") || !strings.Contains(err.Error(), "no-such-kubeconfig") {
		t.Errorf("restore, an oci HelmRepository: %v", err)
	}
	if code, stdout, _ := output(t, func() int { return planScope([]string{"--from", oci, "--check", held}) }); code != 0 || !strings.Contains(stdout, "HelmRepository charts/ocirepo: suspended (a HelmRepository of type oci fetches nothing; its HelmCharts pull)") {
		t.Errorf("plan scope --check, an oci HelmRepository held: exit %d\n%s", code, stdout)
	}

	// Only "oci" exactly, Flux's own value: anything else fetches.
	upper := write(map[string]any{"type": "OCI", "url": "oci://example.invalid/charts"})
	if code, stdout, _ := output(t, func() int { return planScope([]string{"--from", upper, "--check", scope}) }); code != 2 || !strings.Contains(stdout, "NOTE: Flux HelmRepository charts/ocirepo is brought, and not held") {
		t.Errorf("plan scope --check, a HelmRepository of type OCI: exit %d\n%s", code, stdout)
	}

	index := write(map[string]any{"url": "https://example.invalid/charts"})
	if code, stdout, _ := output(t, func() int { return planScope([]string{"--from", index, "--check", scope}) }); code != 2 || !strings.Contains(stdout, "NOTE: Flux HelmRepository charts/ocirepo is brought, and not held") {
		t.Errorf("plan scope --check, a HelmRepository of the default type: exit %d\n%s", code, stdout)
	}
	if err := restoreOf(index); err == nil || !strings.Contains(err.Error(), "Flux HelmRepository charts/ocirepo (it fetches") {
		t.Errorf("restore, a HelmRepository of the default type: %v", err)
	}
}

// A HelmRelease installs its chart and makes its HelmChart: said so, not
// as a Git path synced.
func TestSourceNoteOfAHelmRelease(t *testing.T) {
	rel := kube.ScopeSource{Source: "Flux HelmRelease apprel/app", Object: "HelmRelease apprel/app", Namespaces: []string{"shop"},
		Outside: []string{"HelmChart charts/apprel-app (it pulls)"}, Blocks: true}
	n := sourceNote(rel)
	for _, want := range []string{"installs into shop, which the scope narrows", "makes what acts outside the cluster, HelmChart charts/apprel-app (it pulls)", "installs its chart, whose HelmChart pulls from the chart source's repository or registry"} {
		if !strings.Contains(n, want) {
			t.Errorf("the note of a HelmRelease does not say %q: %s", want, n)
		}
	}
	if strings.Contains(n, "Git path") || strings.Contains(n, "applies") {
		t.Errorf("the note of a HelmRelease speaks of applying: %s", n)
	}
	if b := blockingSources([]kube.ScopeSource{rel}); len(b) != 1 || b[0] != "Flux HelmRelease apprel/app installs into shop and makes HelmChart charts/apprel-app (it pulls)" {
		t.Errorf("as the refusal lists a HelmRelease: %q", b)
	}
	was := scopeDone
	defer func() { scopeDone = was }()
	scopeDone = &kube.ScopeReport{Sources: []kube.ScopeSource{rel}}
	if err := refusedForSources("s.yaml"); err == nil || !strings.Contains(err.Error(), "a HelmRelease, once it runs: it installs its chart") {
		t.Errorf("the refusal of a HelmRelease: %v", err)
	}
	// One with chartRef and one with a chart source: each says its own why.
	ref := kube.ScopeSource{Source: "Flux HelmRelease gitops/rel", Object: "HelmRelease gitops/rel", Namespaces: []string{"shop"}, Blocks: true}
	scopeDone = &kube.ScopeReport{Sources: []kube.ScopeSource{rel, ref}}
	if err := refusedForSources("s.yaml"); err == nil || !strings.Contains(err.Error(), "a HelmRelease, once it runs: it installs its chart, whose HelmChart pulls") ||
		!strings.Contains(err.Error(), "; or it installs its chart, and what the chart installs runs") {
		t.Errorf("the refusal of two kinds of HelmRelease: %v", err)
	}
	// Two of one kind: said once.
	rel2 := rel
	rel2.Source, rel2.Object = "Flux HelmRelease apprel/other", "HelmRelease apprel/other"
	scopeDone = &kube.ScopeReport{Sources: []kube.ScopeSource{rel, rel2}}
	if err := refusedForSources("s.yaml"); err == nil || strings.Count(err.Error(), "whose HelmChart pulls") != 1 {
		t.Errorf("the refusal of two HelmReleases of one kind: %v", err)
	}
	// One with chartRef that makes something else outside: no HelmChart.
	refOut := ref
	refOut.Outside = []string{"ImageUpdateAutomation shop/bump (it commits and pushes image updates to its Git repository)"}
	if n := sourceNote(refOut); strings.Contains(n, "whose HelmChart") || !strings.Contains(n, "it installs its chart, and what the chart installs runs") {
		t.Errorf("the note of a chartRef HelmRelease that makes something outside: %s", n)
	}
	scopeDone = &kube.ScopeReport{Sources: []kube.ScopeSource{{Source: "Flux Kustomization gitops/root", Object: "Kustomization gitops/root", Namespaces: []string{"shop"}, Blocks: true}}}
	if err := refusedForSources("s.yaml"); err == nil || strings.Contains(err.Error(), "a HelmRelease") {
		t.Errorf("the refusal of no HelmRelease speaks of one: %v", err)
	}
}

// A HelmRelease with chartRef makes no HelmChart: helm-controller reads the
// artifact of the source it names. Its note and the refusal say it
// installs its chart, and not that a HelmChart pulls (re-review of #29).
func TestAChartRefReleaseIsNotSaidToPull(t *testing.T) {
	if captureOnly {
		t.Skip("a restore, which the capture-only build refuses")
	}
	web := elsewhereObject("apps/v1", "Deployment", "shop", "web", map[string]any{"spec": map[string]any{"replicas": float64(1),
		"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "app", "image": "x"}}}}}})
	web.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "web", "meta.helm.sh/release-namespace": "shop"}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		elsewhereObject("v1", "Namespace", "", "shop", nil), elsewhereObject("v1", "Namespace", "", "gitops", nil), web,
		elsewhereObject("helm.toolkit.fluxcd.io/v2", "HelmRelease", "gitops", "rel", map[string]any{"spec": map[string]any{
			"targetNamespace": "shop", "chartRef": map[string]any{"kind": "OCIRepository", "name": "chart"}}}),
	}, Skips: []snapshot.Skip{
		{Resource: "apps/v1/deployments", Namespace: "shop", Name: "api", Reason: "rendered by Flux HelmRelease gitops/rel; restoring the HelmRelease recreates it"},
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	scope := writeFile(t, files, "scope.yaml", "narrow: [{namespaces: [shop], releases: [web], hold: true}]\n")
	const installs = "it installs its chart, and what the chart installs runs, whatever the scope held back"
	code, stdout, _ := output(t, func() int { return planScope([]string{"--from", dir, "--check", scope}) })
	if code != 2 || !strings.Contains(stdout, "NOTE: Flux HelmRelease gitops/rel is brought, and not held") || !strings.Contains(stdout, installs) {
		t.Errorf("plan scope --check, a chartRef HelmRelease: exit %d\n%s", code, stdout)
	}
	if strings.Contains(stdout, "HelmChart") {
		t.Errorf("plan scope --check speaks of a HelmChart a chartRef HelmRelease does not make:\n%s", stdout)
	}
	lastErr = nil
	restore(context.Background(), []string{"--kubeconfig", filepath.Join(files, "no-such-kubeconfig"), "--context", "none", "--from", dir, "--scope", scope})
	if lastErr == nil || !strings.Contains(lastErr.Error(), "a HelmRelease, once it runs: "+installs) || strings.Contains(lastErr.Error(), "HelmChart") {
		t.Errorf("the refusal of a chartRef HelmRelease: %v", lastErr)
	}
}
