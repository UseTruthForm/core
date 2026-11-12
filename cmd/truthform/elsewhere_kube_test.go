package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// A snapshot restored into another environment, on a real API server: what
// --leave-out names does not arrive, what reads a secret store reads where
// --rename says, and a diff given the same two files finds the cluster as
// the restore left it. Without them the same diff says what differs.
func TestKubernetesRestoreElsewhere(t *testing.T) {
	obj := func(apiVersion, kind, ns, name string, rest map[string]any) snapshot.Object {
		md := map[string]any{"name": name}
		if ns != "" {
			md["namespace"] = ns
		}
		body := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}
		for k, v := range rest {
			body[k] = v
		}
		return snapshot.Object{Body: body}
	}
	open := map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		obj("apiextensions.k8s.io/v1", "CustomResourceDefinition", "", "onepassworditems.onepassword.com", map[string]any{"spec": map[string]any{
			"group": "onepassword.com", "scope": "Namespaced",
			"names":      map[string]any{"kind": "OnePasswordItem", "plural": "onepassworditems", "singular": "onepassworditem", "listKind": "OnePasswordItemList"},
			"conversion": map[string]any{"strategy": "None"},
			"versions":   []any{map[string]any{"name": "v1", "served": true, "storage": true, "schema": map[string]any{"openAPIV3Schema": open}}},
		}}),
		obj("v1", "Namespace", "", "shop", nil),
		obj("onepassword.com/v1", "OnePasswordItem", "shop", "db", map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/db"}}),
		obj("v1", "ConfigMap", "shop", "kept", map[string]any{"data": map[string]any{"path": "vaults/apps/items/db"}}),
		obj("v1", "ConfigMap", "shop", "root", map[string]any{"data": map[string]any{"sync": "the source's path"}}),
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	leave := writeFile(t, files, "leave.yaml", "- ConfigMap/shop/root\n")
	names := writeFile(t, files, "names.yaml", "vaults/apps/: vaults/apps-test/\n")

	srv := kubetest.Start(t, "elsewhere")
	ctx := context.Background()
	base := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", dir}
	code, stdout, stderr := output(t, func() int { return restore(ctx, append(base, "--leave-out", leave, "--rename", names)) })
	if code != 0 {
		t.Fatalf("restore: exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"left out 1 (--leave-out): ConfigMap/shop/root", "applied 4 of 4 objects"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the restore does not say %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stderr, "rename: 1 store references point elsewhere") || !strings.Contains(stderr, "OnePasswordItem shop/db spec.itemPath: vaults/apps/items/db -> vaults/apps-test/items/db") {
		t.Errorf("stderr:\n%s", stderr)
	}

	c, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	item, err := c.Dynamic.Resource(schema.GroupVersionResource{Group: "onepassword.com", Version: "v1", Resource: "onepassworditems"}).Namespace("shop").Get(ctx, "db", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if spec, _ := item.Object["spec"].(map[string]any); spec["itemPath"] != "vaults/apps-test/items/db" {
		t.Errorf("the item reads %v", spec["itemPath"])
	}
	cms := c.Dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}).Namespace("shop")
	if kept, err := cms.Get(ctx, "kept", metav1.GetOptions{}); err != nil {
		t.Error(err)
	} else if data, _ := kept.Object["data"].(map[string]any); data["path"] != "vaults/apps/items/db" {
		t.Errorf("a field that names no store was rewritten: %v", data["path"])
	}
	if _, err := cms.Get(ctx, "root", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("what --leave-out named was restored: %v", err)
	}

	// A fresh API server has an object of its own that no snapshot of this
	// test holds (its ServiceCIDR): of what the restore wrote, nothing differs.
	_, stdout, stderr = output(t, func() int { return diff(ctx, append(base, "--leave-out", leave, "--rename", names)) })
	if strings.Contains(stdout, "|shop|") || strings.Contains(stdout, "CustomResourceDefinition") || !strings.Contains(stdout, "leaving out 1 objects (--leave-out): ConfigMap/shop/root") {
		t.Errorf("a diff given the same files finds what the restore wrote to differ:\n%s\n%s", stdout, stderr)
	}
	code, stdout, _ = output(t, func() int { return diff(ctx, base) })
	if code != 2 || !strings.Contains(stdout, "ConfigMap|shop|root") || !strings.Contains(stdout, "OnePasswordItem|shop|db") {
		t.Errorf("a diff without them: exit %d\n%s", code, stdout)
	}

	// As JSON, what was left out is named as an entry names it.
	d := asJSON(t, func() { restore(ctx, append(base, "--leave-out", leave, "--rename", names)) })
	if l, _ := d["left_out"].([]any); len(l) != 1 || l[0] != "ConfigMap/shop/root" {
		t.Errorf("left_out: %v", d["left_out"])
	}
	wide := writeFile(t, files, "wide.yaml", "- Namespace/shop\n- \"*/shop/*\"\n- CustomResourceDefinition.apiextensions.k8s.io/onepassworditems.onepassword.com\n")
	if _, err := leftOut(wide, "kubernetes", s); err != nil || strings.Join(heldBack, " ") != "ConfigMap/shop/kept ConfigMap/shop/root CustomResourceDefinition.apiextensions.k8s.io/onepassworditems.onepassword.com Namespace/shop OnePasswordItem.onepassword.com/shop/db" {
		t.Errorf("left out, as entries: %q, %v", heldBack, err)
	}
	// Each label is an entry: given back, it leaves out the same.
	again := writeFile(t, files, "again.yaml", "- "+strings.Join(heldBack, "\n- ")+"\n")
	if out, err := leftOut(again, "kubernetes", s); err != nil || len(out.Objects) != 0 {
		t.Errorf("the labels given back as entries: %d objects left, %v", len(out.Objects), err)
	}
	empty := writeFile(t, files, "empty.yaml", "# none yet\n")
	if code := restore(ctx, append(base, "--rename", empty)); code != 1 || !strings.Contains(lastErr.Error(), "names nothing to rename") {
		t.Errorf("an empty --rename: exit %d, %v", code, lastErr)
	}

	// Refused, and nothing guessed: an entry or a start that names nothing.
	typo := writeFile(t, files, "typo.yaml", "- ConfigMap/shop/rot\n")
	if code := restore(ctx, append(base, "--leave-out", typo)); code != 1 || !strings.Contains(lastErr.Error(), "name nothing in the snapshot: ConfigMap/shop/rot") {
		t.Errorf("a mistyped --leave-out: exit %d, %v", code, lastErr)
	}
	none := writeFile(t, files, "none.yaml", "vaults/typo/: vaults/x/\n")
	if code := restore(ctx, append(base, "--rename", none)); code != 1 || !strings.Contains(lastErr.Error(), "no store reference in the snapshot starts with: vaults/typo/") {
		t.Errorf("a --rename that fits nothing: exit %d, %v", code, lastErr)
	}
}
