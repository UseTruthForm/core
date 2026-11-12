package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		obj("onepassword.com/v1", "OnePasswordItem", "shop", "db", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/base|x"}}),
		obj("v1", "Secret", "shop", "db", map[string]any{"data": map[string]any{"password": ""}}),
		obj("v1", "Secret", "shop", "token", map[string]any{"data": map[string]any{"a": "", "b": "", "c": "", "d": ""}}),
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
		"# cluster: rebuild plan",
		"| 4 | Make the secret store reachable | 1 items feed 1 secrets |",
		"## 1. Install first: 1 sources",
		"| Flux HelmRelease `ingress/proxy` | 1 |",
		"**Not in the snapshot: where they are read from.**",
		"## 2. APIs to have served: 1 groups",
		"| `onepassword.com` | 1 OnePasswordItem |",
		"## 3. Secrets to supply by hand: 1",
		"| `shop/token` | a, b, c, and 1 more |  |",
		"## 4. Secrets a store supplies: 1, from 1 items",
		`| 1Password | ` + "`vaults/apps/items/base\\|x`" + ` | 1 | shop/db |`, // a "|" in a value does not break the table
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
	// The same snapshot gives the same plan.
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
	if d["command"] != "plan" || len(plan["installFirst"].([]any)) != 1 || len(plan["secretsByHand"].([]any)) != 1 || len(plan["hosts"].([]any)) != 1 {
		t.Errorf("document: %v", d)
	}
	// Nothing to say is an empty list, not null: "| length" reads either, ".[]" does not.
	if l, ok := plan["secretsReissued"].([]any); !ok || len(l) != 0 {
		t.Errorf("secretsReissued: %v", plan["secretsReissued"])
	}
}

// What it cannot plan, it refuses: another plan, another platform's
// snapshot, no snapshot.
func TestPlanRebuildRefuses(t *testing.T) {
	azure := filepath.Join(t.TempDir(), "azure")
	if err := (snapshot.Snapshot{Platform: "azure", Policy: "default"}).Write(azure); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no plan named":    {},
		"another plan":     {"restore", "--from", planSnapshot(t)},
		"no snapshot":      {"rebuild"},
		"a missing one":    {"rebuild", "--from", filepath.Join(t.TempDir(), "none")},
		"an azure one":     {"rebuild", "--from", azure},
		"a stray argument": {"rebuild", "--from", planSnapshot(t), "extra"},
	} {
		if code := planCmd(args); code != 1 {
			t.Errorf("%s: exit %d, want 1", name, code)
		}
	}
}
