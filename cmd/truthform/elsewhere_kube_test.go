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

func elsewhereObject(apiVersion, kind, ns, name string, rest map[string]any) snapshot.Object {
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

// elsewhereSnapshot is a snapshot written to a directory, with a
// --leave-out and a --rename file for it.
func elsewhereSnapshot(t *testing.T) (s snapshot.Snapshot, dir, leave, names string) {
	t.Helper()
	obj := elsewhereObject
	open := map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}
	s = snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
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
	dir = filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	return s, dir, writeFile(t, files, "leave.yaml", "- ConfigMap/shop/root\n"), writeFile(t, files, "names.yaml", "vaults/apps/: vaults/apps-test/\n")
}

// A snapshot restored into another environment, on a real API server: what
// --leave-out names does not arrive, what reads a secret store reads where
// --rename says, and a diff given the same two files finds the cluster as
// the restore left it.
func TestKubernetesRestoreElsewhere(t *testing.T) {
	if captureOnly {
		t.Skip("a restore, which the capture-only build refuses")
	}
	s, dir, leave, names := elsewhereSnapshot(t)
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
	items := c.Dynamic.Resource(schema.GroupVersionResource{Group: "onepassword.com", Version: "v1", Resource: "onepassworditems"}).Namespace("shop")
	item, err := items.Get(ctx, "db", metav1.GetOptions{})
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

	// As JSON, what was left out is named as an entry names it, and what
	// the rename did is in the document.
	d := asJSON(t, func() { restore(ctx, append(base, "--leave-out", leave, "--rename", names)) })
	if l, _ := d["left_out"].([]any); len(l) != 1 || l[0] != "ConfigMap/shop/root" {
		t.Errorf("left_out: %v", d["left_out"])
	}
	refs, _ := d["store_references"].(map[string]any)
	if changed, _ := refs["changed"].([]any); len(changed) != 1 || changed[0].(map[string]any)["to"] != "vaults/apps-test/items/db" {
		t.Errorf("store_references: %v", d["store_references"])
	}

	// A store no start fits would be read as the source's: refused, with
	// nothing written, until the file or a flag says it is meant.
	s.Objects = append(s.Objects, elsewhereObject("onepassword.com/v1", "OnePasswordItem", "shop", "shared", map[string]any{"spec": map[string]any{"itemPath": "vaults/shared/items/x"}}))
	both := filepath.Join(t.TempDir(), "both")
	if err := s.Write(both); err != nil {
		t.Fatal(err)
	}
	two := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", both, "--rename", names}
	code, _, stderr = output(t, func() int { return restore(ctx, two) })
	if code != 1 || !strings.Contains(lastErr.Error(), "nothing was restored") || !strings.Contains(stderr, "OnePasswordItem shop/shared spec.itemPath: vaults/shared/items/x") {
		t.Errorf("a store no start fits: exit %d, %v\n%s", code, lastErr, stderr)
	}
	if _, err := items.Get(ctx, "shared", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("a refused restore wrote the item: %v", err)
	}
	d = asJSON(t, func() {
		if code := restore(ctx, append(two, "--keep-source-stores")); code != 0 {
			t.Errorf("--keep-source-stores: exit %d, %v", code, lastErr)
		}
	})
	refs, _ = d["store_references"].(map[string]any)
	if unnamed, _ := refs["unnamed"].([]any); len(unnamed) != 1 || unnamed[0].(map[string]any)["from"] != "vaults/shared/items/x" {
		t.Errorf("store_references of a restore that kept the source's store: %v", d["store_references"])
	}
	if _, err := items.Get(ctx, "shared", metav1.GetOptions{}); err != nil {
		t.Errorf("--keep-source-stores did not restore the item: %v", err)
	}
}

// A diff with the two files writes nothing, so it runs in the
// capture-only build too: against a cluster with none of the snapshot in
// it, what is left out is not expected, and what the rename did is said.
func TestKubernetesDiffElsewhere(t *testing.T) {
	_, dir, leave, names := elsewhereSnapshot(t)
	srv := kubetest.Start(t, "elsewhere-diff")
	ctx := context.Background()
	base := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", dir}
	// --keep-source-stores is taken, as a restore's arguments are, and changes nothing.
	code, stdout, stderr := output(t, func() int {
		return diff(ctx, append(base, "--leave-out", leave, "--rename", names, "--keep-source-stores"))
	})
	if code != 2 || strings.Contains(stdout, "ConfigMap|shop|root") || !strings.Contains(stdout, "ConfigMap|shop|kept") || !strings.Contains(stdout, "leaving out 1 objects (--leave-out): ConfigMap/shop/root") {
		t.Errorf("diff: exit %d\n%s", code, stdout)
	}
	if !strings.Contains(stderr, "OnePasswordItem shop/db spec.itemPath: vaults/apps/items/db -> vaults/apps-test/items/db") {
		t.Errorf("the diff does not say what the rename did:\n%s", stderr)
	}
	d := asJSON(t, func() { diff(ctx, append(base, "--leave-out", leave, "--rename", names)) })
	refs, _ := d["store_references"].(map[string]any)
	if changed, _ := refs["changed"].([]any); len(changed) != 1 {
		t.Errorf("store_references: %v", d["store_references"])
	}
	if l, _ := d["left_out"].([]any); len(l) != 1 {
		t.Errorf("left_out: %v", d["left_out"])
	}
	// No rename, no word of one.
	d = asJSON(t, func() { diff(ctx, base) })
	if _, there := d["store_references"]; there {
		t.Errorf("store_references with no --rename: %v", d["store_references"])
	}
}

// A file that is wrong is refused before the cluster is asked anything,
// and nothing is guessed: there is no cluster here to ask.
func TestElsewhereFilesAreRefusedBeforeTheCluster(t *testing.T) {
	s, dir, leave, names := elsewhereSnapshot(t)
	files := t.TempDir()
	ctx := context.Background()
	base := []string{"--kubeconfig", filepath.Join(files, "no-such-kubeconfig"), "--context", "none", "--from", dir}

	// The two files as they should be get as far as the cluster.
	lastErr = nil
	if code := restore(ctx, append(base, "--leave-out", leave, "--rename", names)); code != 1 || lastErr == nil || strings.Contains(lastErr.Error(), "nothing was restored") || strings.Contains(lastErr.Error(), "yaml") {
		t.Fatalf("two good files: exit %d, %v; want the failure to reach a cluster", code, lastErr)
	}

	s.Objects = append(s.Objects,
		elsewhereObject("onepassword.com/v1", "OnePasswordItem", "shop", "shared", map[string]any{"spec": map[string]any{"itemPath": "vaults/shared/items/x"}}),
		elsewhereObject("external-secrets.io/v1", "ExternalSecret", "shop", "tagged", map[string]any{"spec": map[string]any{
			"data":     []any{map[string]any{"remoteRef": map[string]any{"key": "plain-name"}}},
			"dataFrom": []any{map[string]any{"find": map[string]any{"tags": map[string]any{"env": "dev"}}}},
		}}))
	both := filepath.Join(files, "both")
	if err := s.Write(both); err != nil {
		t.Fatal(err)
	}
	wider := []string{"--kubeconfig", filepath.Join(files, "no-such-kubeconfig"), "--context", "none", "--from", both}

	for why, c := range map[string]struct {
		args []string
		file string
	}{
		"names nothing to rename":                                                   {append(base, "--rename"), "# none yet\n"},
		"name nothing in the snapshot: ConfigMap/shop/rot":                          {append(base, "--leave-out"), "- ConfigMap/shop/rot\n"},
		"no store reference and no image in the snapshot starts with: vaults/typo/": {append(base, "--rename"), "vaults/typo/: vaults/x/\n"},
		"already set in map":                                                        {append(base, "--rename"), "vaults/apps/: vaults/a/\nvaults/apps/: vaults/b/\n"},
		"want a list of":                                                            {append(base, "--leave-out"), "ConfigMap/shop/root: yes\n"},
		"2 objects would use the source's secret store":                             {append(wider, "--rename"), "vaults/apps/: vaults/apps-test/\n"},
		"1 objects would use the source's secret store":                             {append(wider, "--rename"), "vaults/apps/: vaults/apps-test/\nvaults/shared/: vaults/shared/\n"},
		"--keep-source-stores is for a kubernetes restore with --rename;":           {append(base, "--keep-source-stores", "--leave-out"), "- ConfigMap/shop/root\n"},
	} {
		file := writeFile(t, t.TempDir(), "file.yaml", c.file)
		lastErr = nil
		code, _, stderr := output(t, func() int { return restore(ctx, append(c.args, file)) })
		if code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), strings.TrimSuffix(why, ";")) {
			t.Errorf("%q: exit %d, %v; want 1 and %q", c.file, code, lastErr, why)
		}
		// What would stay the source's is listed, each by name; an item's
		// name that follows its store is listed and refuses nothing.
		if strings.Contains(why, "objects would use") {
			for _, want := range []string{"ExternalSecret shop/tagged: it finds what it reads by tags", "ExternalSecret shop/tagged spec.data[].remoteRef.key: plain-name"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("%q: stderr lacks %q:\n%s", c.file, want, stderr)
				}
			}
		}
	}

	// A restore refused says in its document what it refused for, and that
	// it is not complete; on stderr, which kinds were looked at.
	lastErr = nil
	only := writeFile(t, files, "only.yaml", "vaults/apps/: vaults/apps-test/\n")
	var refusedErr string
	was := command
	command = "restore" // as the command line sets it
	defer func() { command = was }()
	d := asJSON(t, func() {
		_, _, refusedErr = output(t, func() int { return restore(ctx, append(wider, "--rename", only)) })
		emitError(1)
	})
	refs, _ := d["store_references"].(map[string]any)
	if unnamed, _ := refs["unnamed"].([]any); len(unnamed) != 1 || d["complete"] != false || d["error"] == nil || len(refs["kinds_read"].([]any)) < 8 {
		t.Errorf("the document of a refused restore: %v", d)
	}
	if !strings.Contains(refusedErr, "was looked for in these kinds") || !strings.Contains(refusedErr, "is not seen") {
		t.Errorf("stderr does not say what was looked at:\n%s", refusedErr)
	}

	// What a PushSecret writes to, left as the source's, is said to be
	// written; and a diff takes --keep-source-stores, with no cluster to ask.
	pushing := s
	pushing.Objects = append(append([]snapshot.Object{}, s.Objects...), elsewhereObject("external-secrets.io/v1alpha1", "PushSecret", "shop", "push", map[string]any{"spec": map[string]any{
		"deletionPolicy": "Delete", "data": []any{map[string]any{"match": map[string]any{"remoteRef": map[string]any{"remoteKey": "dev/app/db"}}}}}}))
	pushDir := filepath.Join(files, "pushing")
	if err := pushing.Write(pushDir); err != nil {
		t.Fatal(err)
	}
	_, _, said := output(t, func() int {
		return restore(ctx, []string{"--kubeconfig", filepath.Join(files, "no-such-kubeconfig"), "--context", "none", "--from", pushDir, "--rename", only, "--keep-source-stores"})
	})
	if !strings.Contains(said, "what a PushSecret WRITES to") || !strings.Contains(said, "deletes them") {
		t.Errorf("does not say a PushSecret would write to the source's store:\n%s", said)
	}
	lastErr = nil
	if code := diff(ctx, append(base, "--rename", names, "--keep-source-stores")); code != 1 || lastErr == nil || strings.Contains(lastErr.Error(), "not defined") {
		t.Errorf("diff --keep-source-stores: exit %d, %v; want it to get as far as the cluster", code, lastErr)
	}

	// As JSON, each of the four is a list.
	if _, _, err := renamed(writeFile(t, files, "n.yaml", "vaults/apps/: vaults/apps-test/\n"), "kubernetes", s, false); err != nil {
		t.Fatal(err)
	}
	doc := storeRefsJSON()
	if len(doc["changed"].([]map[string]string)) != 1 || len(doc["unnamed"].([]map[string]string)) != 1 || len(doc["items_unchanged"].([]map[string]string)) != 1 ||
		len(doc["kept"].([]map[string]string)) != 0 || len(doc["unreached"].([]string)) != 1 {
		t.Errorf("store_references: %v", doc)
	}

	wide := writeFile(t, files, "wide.yaml", "- Namespace/shop\n- \"*/shop/*\"\n- CustomResourceDefinition.apiextensions.k8s.io/onepassworditems.onepassword.com\n")
	first, _, _, _ := elsewhereSnapshot(t)
	if _, err := leftOut(wide, "kubernetes", first); err != nil || strings.Join(heldBack, " ") != "ConfigMap/shop/kept ConfigMap/shop/root CustomResourceDefinition.apiextensions.k8s.io/onepassworditems.onepassword.com Namespace/shop OnePasswordItem.onepassword.com/shop/db" {
		t.Errorf("left out, as entries: %q, %v", heldBack, err)
	}
	// Each label is an entry: given back, it leaves out the same.
	again := writeFile(t, files, "again.yaml", "- "+strings.Join(heldBack, "\n- ")+"\n")
	if out, err := leftOut(again, "kubernetes", first); err != nil || len(out.Objects) != 0 {
		t.Errorf("the labels given back as entries: %d objects left, %v", len(out.Objects), err)
	}
}
