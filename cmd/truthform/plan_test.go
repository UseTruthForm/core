package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/snapshot"
)

func planSnapshot(t *testing.T) string {
	t.Helper()
	obj := func(apiVersion, kind, ns, name string, rest map[string]any) snapshot.Object {
		body := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": map[string]any{"name": name, "namespace": ns}}
		for k, v := range rest {
			body[k] = v
		}
		return snapshot.Object{Body: body}
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Skips: []snapshot.Skip{
		{Resource: "deployments", Namespace: "ingress", Name: "proxy", Reason: "rendered by Flux HelmRelease ingress/proxy; restoring the HelmRelease recreates it"},
	}, Objects: []snapshot.Object{
		obj("onepassword.com/v1", "OnePasswordItem", "shop", "db", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/ba`se|x"}}),
		obj("v1", "Secret", "shop", "db", map[string]any{"data": map[string]any{"password": ""}}),
		obj("v1", "Secret", "shop", "token", map[string]any{"data": map[string]any{"_a_": "", "b": "", "c": "", "d": ""}}),
		obj("onepassword.com/v1", "OnePasswordItem", "shop", "bare", nil),
		// What a controller makes again, what is kept encrypted, and a key to it.
		obj("v1", "Secret", "keda", "kedaorg-certs", map[string]any{"data": map[string]any{"ca.crt": "", "ca.key": "", "tls.crt": "", "tls.key": ""}}),
		obj("v1", "Secret", "shop", "azure-storage-account-a|b-secret", map[string]any{"data": map[string]any{"azurestorageaccountkey": "", "azurestorageaccountname": ""}}),
		obj("bitnami.com/v1alpha1", "SealedSecret", "shop", "card", nil),
		obj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "kms", map[string]any{"spec": map[string]any{"decryption": map[string]any{"provider": "sops"}}}),
		obj("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "apps", map[string]any{"spec": map[string]any{"decryption": map[string]any{"secretRef": map[string]any{"name": "sops-age"}}}}),
		obj("v1", "Secret", "flux-system", "sops-age", map[string]any{"data": map[string]any{"age.agekey": ""}}),
		obj("networking.k8s.io/v1", "Ingress", "shop", "web", map[string]any{"spec": map[string]any{"rules": []any{map[string]any{"host": "shop.example.com"}}}}),
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// plan rebuild reads a snapshot and nothing else, and says in the order
// to act on it what the snapshot does not hold.
func TestPlanRebuildCommand(t *testing.T) {
	dir := planSnapshot(t)
	out := filepath.Join(t.TempDir(), "plan.md")
	if code := planCmd([]string{"rebuild", "--from", dir, "--out", out}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	last := -1
	for _, want := range []string{
		"# Rebuild plan",
		"| 4 | Make the secret store reachable | 2 items feed 2 secrets |",
		"## 1. Install first: 1 sources",
		"| Flux HelmRelease `ingress/proxy` | 1 |  |",
		"**Not in the snapshot: where the sources are read from.**",
		"## 2. APIs to have served: 3 groups",
		"| `onepassword.com` | 2 OnePasswordItem |",
		"## 3. Secrets to supply by hand: 2",
		"| `flux-system/sops-age` | `age.agekey` | Kustomization/apps | the key Flux Kustomization flux-system/apps decrypts with (SOPS) |",
		"| `shop/token` | `_a_`, `b`, `c`, and 1 more |  |  |", // a key is a code span, not emphasis
		"**Kept encrypted: SOPS, read by Flux Kustomization flux-system/apps.** The key is in `flux-system/sops-age`, of step 3. A snapshot never holds",
		"**Kept encrypted: SOPS, read by Flux Kustomization flux-system/kms.** No Secret in the snapshot is named as the key: it is outside the cluster (a cloud key service).",
		"**Kept encrypted: Sealed Secrets, 1 objects.** The capture saw no Secret that holds the controller's key.",
		"Not for you to supply: 2 that something in the cluster makes again once it runs: `keda/kedaorg-certs` (KEDA); `shop/azure-storage-account-a\\|b-secret` (the Azure Files driver).",
		"## 4. Secrets a store supplies: 2, from 2 items",
		"| 1Password | (none named) | 1 | shop/bare |",                          // an item with no path is said, not an empty code span
		`| 1Password | ` + "`vaults/apps/items/ba'se\\|x`" + ` | 1 | shop/db |`, // a "|" or a backtick in a value breaks neither table nor span
		"## 6. Names to point at the rebuilt cluster: 1",
		"- `shop.example.com`",
	} {
		i := strings.Index(text, want)
		if i < 0 {
			t.Errorf("the plan lacks %q:\n%s", want, text)
		} else if i < last {
			t.Errorf("%q is out of order", want)
		}
		last = max(last, i)
	}
	// The same snapshot gives the same plan, whatever its directory is called.
	moved := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	dir = moved
	out2 := filepath.Join(t.TempDir(), "plan.md")
	planCmd([]string{"rebuild", "--from", dir, "--out", out2})
	if b2, _ := os.ReadFile(out2); string(b2) != text {
		t.Error("two plans of one snapshot differ")
	}

	d := asJSON(t, func() {
		if code := planCmd([]string{"rebuild", "--from", dir}); code != 0 {
			t.Errorf("--json: exit %d", code)
		}
	})
	plan, _ := d["plan"].(map[string]any)
	if d["command"] != "plan" || len(plan["installFirst"].([]any)) != 1 || len(plan["secretsByHand"].([]any)) != 2 || len(plan["secretsEncrypted"].([]any)) != 3 || len(plan["hosts"].([]any)) != 1 {
		t.Errorf("document: %v", d)
	}
	// Nothing to say is an empty list, not null: "| length" reads either, ".[]" does not.
	if l, ok := plan["secretsReissued"].([]any); !ok || len(l) != 2 || l[0].(map[string]any)["by"] != "KEDA" {
		t.Errorf("secretsReissued: %v", plan["secretsReissued"])
	}
}

// A key the capture left out with kube-system is no row of step 3, and is
// still counted and said where a person looks: with nothing else to
// supply, the plan does not say there is nothing.
func TestPlanRebuildCountsAKeyTheSnapshotDoesNotHold(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Skips: []snapshot.Skip{
		{Resource: "core/v1/secrets", Namespace: "kube-system", Name: "sealed-secrets-keyab12c", Reason: "in system namespace kube-system"},
	}, Objects: []snapshot.Object{
		{Body: map[string]any{"apiVersion": "bitnami.com/v1alpha1", "kind": "SealedSecret", "metadata": map[string]any{"name": "card", "namespace": "pay"}}},
	}}
	text := planMarkdown(kube.RebuildPlan(s), nil)
	for _, want := range []string{
		"| 3 | Supply by hand the secrets no store holds | 0 secrets, and 1 keys the snapshot does not hold |",
		"No Secret in the snapshot is left for a person to supply:",
		"**Kept encrypted: Sealed Secrets, 1 objects.** **The key is in `kube-system/sealed-secrets-keyab12c`, which the capture left out with its namespace: it is not in the snapshot, and no restore brings it back.**",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the plan lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Every Secret in the snapshot is made from a store") {
		t.Error("the plan says a store makes every Secret")
	}
}

// When every source follows from one the snapshot holds, the plan still
// says where they are read from, or that the snapshot does not hold it,
// and claims no more than that the sources are held.
func TestPlanRebuildWhenEverySourceFollows(t *testing.T) {
	root := snapshot.Object{Body: map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": map[string]any{"name": "root", "namespace": "flux-system"}}}
	repo := snapshot.Object{Body: map[string]any{"apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository", "metadata": map[string]any{"name": "fleet", "namespace": "flux-system"}}}
	skips := []snapshot.Skip{{Resource: "configmaps", Namespace: "shop", Name: "c", Reason: "applied by Flux Kustomization flux-system/root; restoring it recreates this"}}
	for want, objects := range map[string][]snapshot.Object{
		"The snapshot holds these repository objects: GitRepository flux-system/fleet.": {root, repo},
		"**Not in the snapshot: where the sources are read from.**":                     {root},
	} {
		text := planMarkdown(kube.RebuildPlan(snapshot.Snapshot{Platform: "kubernetes", Skips: skips, Objects: objects}), nil)
		for _, line := range []string{"| 1 | Install what a GitOps source makes | 0 sources by hand, 1 follow |", "**Applied again by sources the snapshot holds: 1 sources, 1 objects.**", "Nothing else:", want} {
			if !strings.Contains(text, line) {
				t.Errorf("the plan lacks %q:\n%s", line, text)
			}
		}
		if strings.Contains(text, "where GitOps starts") {
			t.Errorf("claims more than that the sources are held:\n%s", text)
		}
	}
}

// What it cannot plan, it refuses, and says why: another plan, another
// platform's snapshot, no snapshot, a file asked for with --json.
func TestPlanRebuildRefuses(t *testing.T) {
	azure := filepath.Join(t.TempDir(), "azure")
	if err := (snapshot.Snapshot{Platform: "azure", Policy: "default"}).Write(azure); err != nil {
		t.Fatal(err)
	}
	for why, args := range map[string][]string{
		"it gives rebuild and secrets":  {},
		"it gives rebuild and secrets:": {"restore", "--from", planSnapshot(t)},
		"--from is required":            {"rebuild"},
		"not a TruthForm snapshot":      {"rebuild", "--from", filepath.Join(t.TempDir(), "none")},
		"is a azure snapshot":           {"rebuild", "--from", azure},
		"no positional arguments":       {"rebuild", "--from", planSnapshot(t), "extra"},
	} {
		lastErr = nil
		if code := planCmd(args); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), strings.TrimSuffix(why, ":")) {
			t.Errorf("%v: exit %d, %v; want 1 and %q", args, code, lastErr, why)
		}
	}
	// --out names the Markdown's file: with --json it would be left unwritten.
	out := filepath.Join(t.TempDir(), "plan.json")
	d := asJSON(t, func() {
		if code := planCmd([]string{"rebuild", "--from", planSnapshot(t), "--out", out}); code != 1 {
			t.Errorf("--json with --out: exit %d, want 1", code)
		}
		emitError(1)
	})
	if msg, _ := d["error"].(string); !strings.Contains(msg, "--out is for the Markdown") {
		t.Errorf("--json with --out: %v", d)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("--json with --out wrote the file")
	}
}

// A type the capture could not read may hold what a step would list: the
// plan says so first, and no step says there is nothing.
func TestPlanRebuildSaysWhatWasNotRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cluster")
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Coverage: []snapshot.Coverage{
		{Resource: "core/v1/secrets", Kind: "Secret", NotCaptured: "list failed: secrets is forbidden"},
		{Resource: "networking.k8s.io/v1/ingresses", Kind: "Ingress", NotCaptured: "list failed: timeout"},
		{Resource: "core/v1/configmaps", Kind: "ConfigMap", Captured: 3},
	}}
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "plan.md")
	code, stdout, stderr := output(t, func() int { return planCmd([]string{"rebuild", "--from", dir, "--out", out}) })
	if code != 0 || !strings.Contains(stdout, "wrote "+out) || !strings.Contains(stderr, "INCOMPLETE SNAPSHOT: its capture could not read 2 things") {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	// With --json the warning is on stderr too: the document goes to a program.
	if _, _, stderr := output(t, func() int { return planCmd([]string{"rebuild", "--from", dir}) }); !strings.Contains(stderr, "INCOMPLETE SNAPSHOT") {
		t.Errorf("no warning on stderr without --out: %q", stderr)
	}
	b, _ := os.ReadFile(out)
	text := string(b)
	for _, want := range []string{"| 0 secrets seen |", "| 0 hosts seen |", "## 3. Secrets to supply by hand: 0 seen", "## 6. Names to point at the rebuilt cluster: 0 seen",
		"**INCOMPLETE SNAPSHOT.** Its capture could not read 2 things", "- core/v1/secrets: list failed: secrets is forbidden", "None in what the capture read."} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q:\n%s", want, text)
		}
	}
	for _, allClear := range []string{"Every Secret in the snapshot", "No Secret in the snapshot", "No route in the snapshot", "The capture left nothing", "Every type in the snapshot", "has no object that reads"} {
		if strings.Contains(text, allClear) {
			t.Errorf("plan says %q of a snapshot whose capture could not read everything", allClear)
		}
	}
	d := asJSON(t, func() {
		if code := planCmd([]string{"rebuild", "--from", dir}); code != 0 {
			t.Errorf("--json: exit %d", code)
		}
	})
	if g, _ := d["gaps"].([]any); len(g) != 2 {
		t.Errorf("gaps in --json: %v", d["gaps"])
	}

	// A capture that read everything: no warning, an empty list, and the
	// steps say there is nothing.
	whole := planSnapshot(t)
	d = asJSON(t, func() { planCmd([]string{"rebuild", "--from", whole}) })
	if g, ok := d["gaps"].([]any); !ok || len(g) != 0 {
		t.Errorf("gaps of a whole snapshot: %v", d["gaps"])
	}
	if code := planCmd([]string{"rebuild", "--from", whole, "--out", out + "2"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	b, _ = os.ReadFile(out + "2")
	if strings.Contains(string(b), "INCOMPLETE") || strings.Contains(string(b), "None in what the capture read") || strings.Contains(string(b), " seen") {
		t.Errorf("a whole snapshot's plan warns:\n%s", b)
	}
}

// A repository whose address the capture withheld is named as one whose
// address the snapshot does not hold.
func TestPlanRebuildSaysAnAddressWasWithheld(t *testing.T) {
	text := planMarkdown(kube.Plan{Follows: []kube.PlanSource{{Kind: "Flux Kustomization", Name: "flux-system/root", Objects: 1}},
		Origins: []string{"GitRepository flux-system/fleet"}, OriginsWithheld: []string{"GitRepository flux-system/fleet"}}, nil)
	if !strings.Contains(text, "**Not in the snapshot: the address of GitRepository flux-system/fleet.**") {
		t.Errorf("the plan does not say the address was withheld:\n%s", text)
	}
}

// Every source follows and the capture could not read everything: the
// step still does not say there is nothing else.
func TestPlanRebuildNothingElseOfAnIncompleteSnapshot(t *testing.T) {
	p := kube.Plan{Follows: []kube.PlanSource{{Kind: "Flux Kustomization", Name: "flux-system/root", Objects: 1}}}
	if text := planMarkdown(p, []string{"core/v1/secrets: list failed"}); strings.Contains(text, "Nothing else:") || !strings.Contains(text, "None in what the capture read.") {
		t.Errorf("says there is nothing else of a snapshot not all read:\n%s", text)
	}
	if text := planMarkdown(p, nil); !strings.Contains(text, "Nothing else:") {
		t.Errorf("a whole snapshot whose sources all follow:\n%s", text)
	}
}
