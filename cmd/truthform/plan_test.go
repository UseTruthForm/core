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
		obj("onepassword.com/v1", "OnePasswordItem", "shop", "db", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/ba`se|x"}}),
		obj("v1", "Secret", "shop", "db", map[string]any{"data": map[string]any{"password": ""}}),
		obj("v1", "Secret", "shop", "token", map[string]any{"data": map[string]any{"_a_": "", "b": "", "c": "", "d": ""}}),
		obj("onepassword.com/v1", "OnePasswordItem", "shop", "bare", nil),
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
		"| Flux HelmRelease `ingress/proxy` | 1 |",
		"**Not in the snapshot: where they are read from.**",
		"## 2. APIs to have served: 1 groups",
		"| `onepassword.com` | 2 OnePasswordItem |",
		"## 3. Secrets to supply by hand: 1",
		"| `shop/token` | `_a_`, `b`, `c`, and 1 more |  |", // a key is a code span, not emphasis
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
	if d["command"] != "plan" || len(plan["installFirst"].([]any)) != 1 || len(plan["secretsByHand"].([]any)) != 1 || len(plan["hosts"].([]any)) != 1 {
		t.Errorf("document: %v", d)
	}
	// Nothing to say is an empty list, not null: "| length" reads either, ".[]" does not.
	if l, ok := plan["secretsReissued"].([]any); !ok || len(l) != 0 {
		t.Errorf("secretsReissued: %v", plan["secretsReissued"])
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
		"the plan it gives is rebuild":  {},
		"the plan it gives is rebuild:": {"restore", "--from", planSnapshot(t)},
		"--from is required":            {"rebuild"},
		"not a Truthform snapshot":      {"rebuild", "--from", filepath.Join(t.TempDir(), "none")},
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
