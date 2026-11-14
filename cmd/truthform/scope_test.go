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
	rep := kube.ScopeReport{
		Narrowed: []string{"shop"}, Kept: 1, Of: 3,
		ObjectsLeftOut: []string{"Deployment shop/queue-consumer"},
		ObjectsBrought: []string{"ConfigMap shop/shared"},
		SharedName:     []string{"ClusterRole x (it may be of other/x, left out)"},
		StillMade:      []kube.ScopeMade{{Source: "Flux Kustomization flux-system/root", Namespace: "shop", Objects: 2}},
		Webhooks: []kube.ScopeWebhook{
			{Configuration: "ValidatingWebhookConfiguration policy", Webhook: "check.policy", Service: "shop/policy", Fails: true},
			{Configuration: "ValidatingWebhookConfiguration policy", Webhook: "soft.policy", Service: "shop/soft"},
			{Configuration: "CustomResourceDefinition widgets.example.com", Webhook: "conversion", Service: "shop/policy", Fails: true},
			{Configuration: "APIService v1beta1.metrics.example.com", Webhook: "service", Service: "shop/policy", Fails: true},
			{Configuration: "MutatingWebhookConfiguration quiet", Webhook: "held.hook", Service: "shop/quiet", Why: "held", Fails: true, Blocks: true},
			{Configuration: "MutatingWebhookConfiguration quiet", Webhook: "gone.hook", Service: "shop/gone", Why: "leftOut", Fails: true, Blocks: true},
			{Configuration: "MutatingWebhookConfiguration open", Webhook: "open.hook", Service: "shop/owned", Why: "unknown", Fails: true},
			{Configuration: "MutatingWebhookConfiguration open", Webhook: "unseen.hook", Service: "shop/mixed", Why: "unseen", Fails: true},
		},
	}
	said := scopeSaid(rep, "scope.yaml")
	for _, want := range []string{
		"1 objects that no release made are left out (name one under objects, as Kind/name, to bring it): Deployment shop/queue-consumer",
		"1 objects that no release made are brought, named under objects or by label: ConfigMap shop/shared",
		"NOTE: Flux Kustomization flux-system/root is brought, and makes 2 objects in shop",
		"ClusterRole x (it may be of other/x, left out)",
		"NOTE: ValidatingWebhookConfiguration policy (check.policy) is brought, and calls the Service shop/policy, which is not brought, and nothing that is brought makes it: while nothing answers there, the API server refuses every write",
		"NOTE: ValidatingWebhookConfiguration policy (soft.policy) is brought, and calls the Service shop/soft, which is not brought, and nothing that is brought makes it: while nothing answers there, the API server goes on without it",
		"NOTE: APIService v1beta1.metrics.example.com (service) is brought, and calls the Service shop/policy, which is not brought, and nothing that is brought makes it: while nothing answers there, its API is not there",
		"NOTE: MutatingWebhookConfiguration quiet (held.hook) is brought, and calls the Service shop/quiet, which is brought with every workload behind it held (hold: true): while nothing answers there, the API server refuses every write the webhook is asked about. A restore is refused while it is so: bring what answers behind the Service without the hold, leave the webhook out",
		"NOTE: MutatingWebhookConfiguration quiet (gone.hook) is brought, and calls the Service shop/gone, which is brought with every workload behind it taken out (the scope, or --leave-out): while nothing answers",
		"NOTE: MutatingWebhookConfiguration open (unseen.hook) is brought, and calls the Service shop/mixed, which is brought with every workload of the snapshot behind it held or taken out. Whether anything answers there cannot be told: pods will run in that namespace that the snapshot does not show the labels of",
		"NOTE: MutatingWebhookConfiguration open (open.hook) is brought, and calls the Service shop/owned, which is not in the snapshot. Whether it will be there cannot be told: the snapshot lists what an object owns in that namespace without the names, as captures did before this version, and this may be one of them. A capture taken now settles it. If nothing answers there: the API server refuses every write the webhook is asked about.",
		"NOTE: CustomResourceDefinition widgets.example.com (conversion) is brought, and calls the Service shop/policy, which is not brought, and nothing that is brought makes it: while nothing answers there, objects of that kind cannot be read",
		"nothing checks that what is brought does not need something left out",
	} {
		if !strings.Contains(said, want) {
			t.Errorf("does not say %q:\n%s", want, said)
		}
	}
	// The plan is what a person keeps: it says it is of a part, and gives
	// the same notes.
	plan := planMarkdown(kube.Plan{}, nil, &rep, nil)
	for _, want := range []string{
		"**A part only.** A scope narrowed shop: 1 of their 3 objects are brought",
		"- **Note.** Flux Kustomization flux-system/root is brought, and makes 2 objects in shop",
		"- **Note.** ValidatingWebhookConfiguration policy (check.policy) is brought, and calls the Service shop/policy",
	} {
		if !strings.Contains(plan, want) {
			t.Errorf("the plan does not say %q:\n%s", want, plan)
		}
	}
	if whole := planMarkdown(kube.Plan{}, nil, nil, nil); strings.Contains(whole, "A part only") || strings.Contains(whole, "Note.") {
		t.Errorf("the plan of a whole snapshot speaks of a scope:\n%s", whole)
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

// A restore is not begun with an admission webhook that fails closed and
// has no Service to answer it: every write after it would be refused. The check
// finds it first, and the scope file or --leave-out clears it.
func TestRestoreRefusesAWebhookWithNoService(t *testing.T) {
	if captureOnly {
		t.Skip("a restore, which the capture-only build refuses")
	}
	obj := elsewhereObject
	ofRelease := func(o snapshot.Object, release string) snapshot.Object {
		md := o.Body["metadata"].(map[string]any)
		md["annotations"] = map[string]any{"meta.helm.sh/release-name": release, "meta.helm.sh/release-namespace": "shop"}
		md["labels"] = map[string]any{"app.kubernetes.io/managed-by": "Helm"}
		return o
	}
	hook := func(policy string) map[string]any {
		return map[string]any{"webhooks": []any{map[string]any{"name": "check.policy", "failurePolicy": policy,
			"clientConfig": map[string]any{"service": map[string]any{"namespace": "shop", "name": "policy"}}}}}
	}
	write := func(policy string) string {
		s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
			obj("v1", "Namespace", "", "shop", nil),
			ofRelease(obj("v1", "ConfigMap", "shop", "web", nil), "web"),
			ofRelease(obj("v1", "Service", "shop", "policy", map[string]any{"spec": map[string]any{"selector": map[string]any{"app": "policy"}}}), "policy"),
			ofRelease(obj("apps/v1", "Deployment", "shop", "policy", map[string]any{"spec": map[string]any{"replicas": float64(1),
				"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "policy"}}, "spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "x"}}}}}}), "policy"),
			obj("admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", "", "policy", hook(policy)),
		}}
		dir := filepath.Join(t.TempDir(), "cluster")
		if err := s.Write(dir); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	dir := write("Fail")
	const narrow = "narrow:\n  - namespaces: [shop]\n    releases: [web]\n"
	files := t.TempDir()
	scope := writeFile(t, files, "scope.yaml", narrow)
	accepted := writeFile(t, files, "accepted.yaml", narrow+"withoutService:\n  - ValidatingWebhookConfiguration/policy\n")
	leave := writeFile(t, files, "leave.yaml", "- ValidatingWebhookConfiguration.admissionregistration.k8s.io/policy\n")
	// Nowhere to restore to: what is refused is refused before that.
	nowhere := []string{"--kubeconfig", filepath.Join(files, "no-such-kubeconfig"), "--context", "none", "--from", dir}
	refused := func(args ...string) bool {
		lastErr = nil
		code := restore(context.Background(), append(append([]string{}, nowhere...), args...))
		if code == 0 {
			t.Errorf("%v: a restore to nowhere ended 0", args)
		}
		return lastErr != nil && strings.Contains(lastErr.Error(), "brought that fail")
	}

	code, stdout, _ := output(t, func() int { return planScope([]string{"--from", dir, "--check", scope}) })
	if code != 2 || !strings.Contains(stdout, "A restore is refused while it is so") {
		t.Errorf("plan scope --check: exit %d\n%s", code, stdout)
	}
	if !refused("--scope", scope) || !strings.Contains(lastErr.Error(), "ValidatingWebhookConfiguration policy (check.policy) calls shop/policy") || !strings.Contains(lastErr.Error(), "nothing was restored") {
		t.Errorf("restore: %v", lastErr)
	}
	// Accepted in the scope file, or left out, it is not.
	code, stdout, _ = output(t, func() int { return planScope([]string{"--from", dir, "--check", accepted}) })
	if code != 0 || !strings.Contains(stdout, "Accepted in the scope file (withoutService)") {
		t.Errorf("plan scope --check, accepted: exit %d\n%s", code, stdout)
	}
	if refused("--scope", accepted) {
		t.Errorf("restore, accepted: %v", lastErr)
	}
	if refused("--scope", scope, "--leave-out", leave) {
		t.Errorf("restore, with the webhook left out: %v", lastErr)
	}
	// One that goes on without its Service is a note only.
	soft := write("Ignore")
	code, stdout, _ = output(t, func() int { return planScope([]string{"--from", soft, "--check", scope}) })
	if code != 0 || !strings.Contains(stdout, "NOTE: ValidatingWebhookConfiguration policy") {
		t.Errorf("plan scope --check of an Ignore webhook: exit %d\n%s", code, stdout)
	}
	nowhere[len(nowhere)-1] = soft
	if refused("--scope", scope) {
		t.Errorf("restore of an Ignore webhook: %v", lastErr)
	}
	// With no scope it is the same question: the Service taken out by
	// --leave-out, the webhook refuses the restore, and a scope file that
	// does no more than accept it lets it through.
	nowhere[len(nowhere)-1] = dir
	if refused() {
		t.Errorf("restore of the whole snapshot, the Service with it: %v", lastErr)
	}
	noService := writeFile(t, files, "no-service.yaml", "- Service/shop/policy\n")
	if !refused("--leave-out", noService) || !strings.Contains(lastErr.Error(), "1 admission webhook is brought that fails closed") || !strings.Contains(lastErr.Error(), "a scope file given with --scope") {
		t.Errorf("restore with the Service left out and no scope: %v", lastErr)
	}
	onlyAccepts := writeFile(t, files, "only-accepts.yaml", "withoutService:\n  - ValidatingWebhookConfiguration/policy\n")
	if refused("--leave-out", noService, "--scope", onlyAccepts) {
		t.Errorf("restore with the Service left out, accepted: %v", lastErr)
	}
	// The workload behind the Service taken out, and the Service
	// brought: nothing answers, and the snapshot as it was read says so.
	noWorkload := writeFile(t, files, "no-workload.yaml", "- Deployment.apps/shop/policy\n")
	if !refused("--leave-out", noWorkload) || !strings.Contains(lastErr.Error(), "calls shop/policy") {
		t.Errorf("restore with the workload left out and no scope: %v", lastErr)
	}
	if !refused("--leave-out", noWorkload, "--scope", heldNothing(t, files)) {
		t.Errorf("restore with the workload left out, under a scope that brings the Service: %v", lastErr)
	}
	// A file that only accepts says it narrows nothing.
	_, _, stderr := output(t, func() int {
		return restore(context.Background(), append(append([]string{}, nowhere...), "--leave-out", noService, "--scope", onlyAccepts))
	})
	if !strings.Contains(stderr, "narrows nothing: the snapshot is brought as it is") || strings.Contains(stderr, "Jobs left out") || strings.Contains(stderr, "a part only") {
		t.Errorf("a file that only accepts:\n%s", stderr)
	}
	// The rebuild plan of the whole says it too, before any restore:
	// with no scope there is no other check to find it in.
	bare := filepath.Join(t.TempDir(), "cluster")
	{
		sn, err := snapshot.Read(dir)
		if err != nil {
			t.Fatal(err)
		}
		var kept []snapshot.Object
		for _, o := range sn.Objects {
			if o.Kind() != "Service" {
				kept = append(kept, o)
			}
		}
		sn.Objects = kept
		if err := sn.Write(bare); err != nil {
			t.Fatal(err)
		}
	}
	code, stdout, stderr = output(t, func() int { return planCmd([]string{"rebuild", "--from", bare}) })
	if code != 0 || !strings.Contains(stderr, "plan: NOTE: ValidatingWebhookConfiguration policy (check.policy) is brought") || !strings.Contains(stdout, "Webhooks with nothing to answer them") || !strings.Contains(stdout, "A restore is refused while it is so") {
		t.Errorf("plan rebuild of a snapshot whose webhook has no Service: exit %d\n%s\n%s", code, stderr, stdout)
	}
	doc := asJSON(t, func() { planCmd([]string{"rebuild", "--from", bare}) })
	if l, _ := doc["webhooksWithoutService"].([]any); len(l) != 1 {
		t.Errorf("plan rebuild --json: %v", doc["webhooksWithoutService"])
	}
	if code, stdout, stderr = output(t, func() int { return planCmd([]string{"rebuild", "--from", dir}) }); strings.Contains(stderr+stdout, "nothing to answer") || strings.Contains(stderr, "NOTE: Validating") {
		t.Errorf("plan rebuild of a whole snapshot:\n%s\n%s", stderr, stdout)
	}
	// What a restore would be given to leave out, the plan and a diff are
	// given too, and say what the restore would: neither is refused.
	code, stdout, stderr = output(t, func() int { return planCmd([]string{"rebuild", "--from", dir, "--leave-out", noWorkload}) })
	if code != 0 || !strings.Contains(stderr, "plan: NOTE: ValidatingWebhookConfiguration policy (check.policy)") || !strings.Contains(stdout, "taken out (the scope, or --leave-out)") {
		t.Errorf("plan rebuild with the workload left out: exit %d\n%s\n%s", code, stderr, stdout)
	}
	lastErr = nil
	_, _, stderr = output(t, func() int {
		return diff(context.Background(), append(append([]string{}, nowhere...), "--leave-out", noWorkload))
	})
	if !strings.Contains(stderr, "diff: NOTE: ValidatingWebhookConfiguration policy (check.policy)") || (lastErr != nil && strings.Contains(lastErr.Error(), "brought that fail")) {
		t.Errorf("diff with the workload left out:\n%s\n%v", stderr, lastErr)
	}
	_, _, stderr = output(t, func() int {
		return diff(context.Background(), append(append([]string{}, nowhere...), "--leave-out", noWorkload, "--scope", heldNothing(t, files)))
	})
	if !strings.Contains(stderr, "NOTE: ValidatingWebhookConfiguration policy (check.policy)") || !strings.Contains(stderr, "taken out (the scope, or --leave-out)") {
		t.Errorf("diff with the workload left out, under a scope:\n%s", stderr)
	}
	// The check is given what the restore would be: with the webhook
	// left out, as the refusal advises, it ends 0.
	code, _, _ = output(t, func() int { return planScope([]string{"--from", dir, "--check", scope, "--leave-out", leave}) })
	if code != 0 {
		t.Errorf("plan scope --check with the webhook left out: exit %d, %v", code, lastErr)
	}
	code, stdout, _ = output(t, func() int {
		return planScope([]string{"--from", dir, "--check", heldNothing(t, files), "--leave-out", noWorkload})
	})
	if code != 2 || !strings.Contains(stdout, "taken out (the scope, or --leave-out)") {
		t.Errorf("plan scope --check with the workload left out: exit %d\n%s", code, stdout)
	}
	if code := planScope([]string{"--from", dir, "--leave-out", leave}); code != 1 || !strings.Contains(lastErr.Error(), "--leave-out is for --check") {
		t.Errorf("plan scope --leave-out with no --check: exit %d, %v", code, lastErr)
	}
	// The document of a restore that went ahead with no scope lists the
	// webhooks it said something of, as a scope's report would.
	was0, hooks0 := scopeDone, unscopedHooks
	scopeDone, unscopedHooks = nil, []kube.ScopeWebhook{{Configuration: "ValidatingWebhookConfiguration policy", Webhook: "h", Service: "shop/owned", Why: kube.WhyUnknown, Fails: true}}
	went := asJSON(t, func() { emitRestore(nil, "target") })
	scopeDone, unscopedHooks = was0, hooks0
	if l, _ := went["webhooksWithoutService"].([]any); len(l) != 1 || l[0].(map[string]any)["why"] != "unknown" {
		t.Errorf("the document of a restore with no scope: %v", went["webhooksWithoutService"])
	}
	// And a restore that is not refused keeps them for that document.
	open := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		obj("admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", "", "policy", hook("Fail")),
		obj("example.com/v1", "Operand", "shop", "op", nil),
	}, Skips: []snapshot.Skip{{Resource: "core/v1/services", Namespace: "shop", Name: "*", Reason: "owned by Operand/op, whose controller recreates it"}}}
	scopeDone = nil
	if err := refusedForWebhooks(open, open, ""); err != nil || len(unscopedHooks) != 1 || unscopedHooks[0].Why != kube.WhyUnknown {
		t.Errorf("a restore with no scope and a webhook it cannot tell of: %v, %+v", err, unscopedHooks)
	}
	scopeDone, unscopedHooks = was0, hooks0
	// The document of a refusal says which webhooks.
	was := command
	command = "restore"
	d := asJSON(t, func() {
		emitError(restore(context.Background(), append(append([]string{}, nowhere...), "--leave-out", noService)))
	})
	command = was
	hooks, _ := d["webhooksWithoutService"].([]any)
	if len(hooks) != 1 {
		t.Fatalf("the document of a refusal: %v", d)
	}
	if h, _ := hooks[0].(map[string]any); h["blocks"] != true || h["why"] != "notBrought" || h["service"] != "shop/policy" || d["complete"] != false {
		t.Errorf("the document of a refusal: %v", d)
	}
	// Brought with what answers behind it held, the Service does not
	// answer either.
	lastErr = nil
	nowhere[len(nowhere)-1] = write("Fail")
	heldBehind := writeFile(t, files, "held.yaml", "narrow:\n  - namespaces: [shop]\n    releases: [web, policy]\n    hold: true\n")
	if !refused("--scope", heldBehind) || !strings.Contains(lastErr.Error(), "calls shop/policy") {
		t.Errorf("restore with what answers held: %v", lastErr)
	}
	// And a diff is not refused for it.
	lastErr = nil
	nowhere[len(nowhere)-1] = dir
	diff(context.Background(), append(append([]string{}, nowhere...), "--scope", scope))
	if lastErr != nil && strings.Contains(lastErr.Error(), "admission webhooks") {
		t.Errorf("diff: %v", lastErr)
	}
}

// heldNothing is a scope that brings both releases of the shop, running.
func heldNothing(t *testing.T, dir string) string {
	return writeFile(t, dir, "both.yaml", "narrow:\n  - namespaces: [shop]\n    releases: [web, policy]\n")
}

// A scope file that narrows nothing brought the whole, and a total beside
// it is not said to be of a part.
func TestScopeLineOfAFileThatNarrowsNothing(t *testing.T) {
	was := scopeDone
	defer func() { scopeDone = was }()
	scopeDone = &kube.ScopeReport{}
	if l := scopeLine(); l != "" {
		t.Errorf("a file that narrows nothing: %q", l)
	}
	scopeDone = &kube.ScopeReport{Narrowed: []string{"shop"}, Kept: 2, Of: 3}
	if l := scopeLine(); !strings.Contains(l, "2 of the 3 objects of shop") {
		t.Errorf("a file that narrows: %q", l)
	}
}
