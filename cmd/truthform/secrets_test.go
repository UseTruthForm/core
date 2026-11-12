package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// sourcesSnapshot is a snapshot with a Secret a person supplies, one a
// controller makes again, one a store makes, and one with nothing withheld.
func sourcesSnapshot(t *testing.T) (snapshot.Snapshot, string) {
	t.Helper()
	secret := func(ns, name string, keys []string, labels map[string]any) snapshot.Object {
		md := map[string]any{"name": name, "namespace": ns}
		body := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": md, "type": "Opaque"}
		if labels != nil {
			md["labels"] = labels
		}
		if len(keys) > 0 {
			data := map[string]any{}
			for _, k := range keys {
				data[k] = ""
			}
			body["data"] = data
			md["annotations"] = map[string]any{kube.WithheldAnnotation: strings.Join(keys, ",")}
		}
		return snapshot.Object{Body: body}
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Objects: []snapshot.Object{
		{Body: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "shop"}}},
		secret("shop", "git", []string{"password", "username"}, nil),
		secret("shop", "odd", []string{"k"}, nil),
		secret("shop", "ca", []string{"tls.key"}, map[string]any{"app.kubernetes.io/managed-by": "cert-manager"}),
		secret("shop", "db", []string{"password"}, nil),
		secret("shop", "empty", nil, nil),
		{Body: map[string]any{"apiVersion": "onepassword.com/v1", "kind": "OnePasswordItem", "metadata": map[string]any{"name": "db", "namespace": "shop"}, "spec": map[string]any{"itemPath": "vaults/v/items/db"}}},
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	back, err := snapshot.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	return back, dir
}

// plan secrets writes a file to fill in, never over one, and --check says
// what a rebuild would lack until every Secret to supply has a source.
// --resolve reads each and prints none.
func TestPlanSecretsCommand(t *testing.T) {
	_, dir := sourcesSnapshot(t)
	file := filepath.Join(t.TempDir(), "secrets.yaml")
	if code := planCmd([]string{"secrets", "--from", dir, "--out", file}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	b, _ := os.ReadFile(file)
	text := string(b)
	// The Secrets to supply, and none of those something makes or that hold nothing.
	for _, want := range []string{`secret: "shop/git"`, `"password": ""`, `"username": ""`, `secret: "shop/odd"`} {
		if !strings.Contains(text, want) {
			t.Errorf("the file lacks %q:\n%s", want, text)
		}
	}
	for _, not := range []string{"shop/ca", "shop/db", "shop/empty"} {
		if strings.Contains(text, not) {
			t.Errorf("the file asks for %s, which is not a person's to supply:\n%s", not, text)
		}
	}
	if code := planCmd([]string{"secrets", "--from", dir, "--out", file}); code != 1 || !strings.Contains(lastErr.Error(), "is there already") {
		t.Errorf("written over a file that may be filled in: exit %d, %v", code, lastErr)
	}
	if code := planCmd([]string{"secrets", "--from", dir, "--check", file}); code != 2 {
		t.Errorf("an unfilled file passes the check: exit %d", code)
	}

	t.Setenv("TF_TEST_PASSWORD", "s3cr3t-value")
	filled := writeFile(t, t.TempDir(), "secrets.yaml", `secrets:
  - secret: shop/git
    from: {password: "env:TF_TEST_PASSWORD", username: "env:TF_TEST_USER_UNSET"}
  - secret: shop/odd
    leave: an operator this plan does not know
  - secret: shop/gone
    leave: no longer there
`)
	if code := planCmd([]string{"secrets", "--from", dir, "--check", filled}); code != 0 {
		t.Errorf("a file that covers the snapshot fails the check: exit %d", code)
	}
	d := asJSON(t, func() {
		if code := planCmd([]string{"secrets", "--from", dir, "--check", filled, "--resolve"}); code != 2 {
			t.Errorf("a source that does not answer passes --resolve: exit %d", code)
		}
	})
	doc, _ := d["secrets"].(map[string]any)
	problems, _ := doc["problems"].([]any)
	if len(problems) != 1 || !strings.Contains(problems[0].(string), "shop/git: key username: env:TF_TEST_USER_UNSET") || doc["read"] != float64(1) || len(doc["notes"].([]any)) != 1 {
		t.Errorf("document: %v", d)
	}
	if strings.Contains(strings.Join(strings.Fields(strings.ReplaceAll(strings.Trim(strings.Join([]string{problems[0].(string)}, ""), ""), "\n", " ")), " "), "s3cr3t-value") {
		t.Error("a value read is in the document")
	}
	for _, args := range [][]string{
		{"secrets", "--out", file},
		{"secrets", "--from", dir, "--out", file, "--check", filled},
		{"secrets", "--from", dir, "--resolve"},
	} {
		if code := planCmd(args); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

// Before a restore writes anything, the sources file has to cover the
// snapshot and every value has to be read. What something else makes is
// taken out of what is restored, unless the file gives it a value.
func TestWithSecretSources(t *testing.T) {
	snap, _ := sourcesSnapshot(t)
	ctx := context.Background()
	t.Setenv("TF_TEST_PASSWORD", "s3cr3t-value")
	t.Setenv("TF_TEST_USER", "git-user")
	dir := t.TempDir()
	good := writeFile(t, dir, "good.yaml", `secrets:
  - secret: shop/git
    from: {password: "env:TF_TEST_PASSWORD", username: "env:TF_TEST_USER"}
  - secret: shop/odd
    leave: an operator
`)
	out, opt, left, err := withSecretSources(ctx, snap, good, false, false)
	if err != nil {
		t.Fatal(err)
	}
	wantLeft := []string{"shop/ca (cert-manager)", "shop/db (the store (1Password))", "shop/odd (an operator)"}
	if !reflect.DeepEqual(left, wantLeft) {
		t.Errorf("left: %q, want %q", left, wantLeft)
	}
	var kept []string
	for _, o := range out.Objects {
		kept = append(kept, o.Kind()+"/"+o.Name())
	}
	if want := []string{"Namespace/shop", "OnePasswordItem/db", "Secret/empty", "Secret/git"}; !sameSet(kept, want) {
		t.Errorf("restored: %q, want %q", kept, want)
	}
	v, known, _ := opt.Values(ctx, "shop", "git", nil)
	if !known || string(v["password"]) != "s3cr3t-value" || string(v["username"]) != "git-user" {
		t.Errorf("values for shop/git: known %v, %d keys", known, len(v))
	}
	if _, known, _ := opt.Values(ctx, "shop", "empty", nil); known {
		t.Error("a Secret the file does not name is said to be known")
	}

	// A value for what a controller makes is the user's choice: it is restored.
	override := writeFile(t, dir, "override.yaml", `secrets:
  - secret: shop/git
    from: {password: "env:TF_TEST_PASSWORD", username: "env:TF_TEST_USER"}
  - secret: shop/odd
    from: {k: "env:TF_TEST_USER"}
  - secret: shop/ca
    from: {tls.key: "env:TF_TEST_PASSWORD"}
`)
	if _, _, left, err := withSecretSources(ctx, snap, override, false, false); err != nil || !reflect.DeepEqual(left, []string{"shop/db (the store (1Password))"}) {
		t.Errorf("override: left %q, %v", left, err)
	}

	// With another cluster to read from, what the file does not name is read there: nothing is left out for it.
	partial := writeFile(t, dir, "partial.yaml", "secrets:\n  - secret: shop/odd\n    leave: an operator\n")
	if _, _, _, err := withSecretSources(ctx, snap, partial, false, false); err == nil || !strings.Contains(err.Error(), "shop/git: no entry") || !strings.Contains(err.Error(), "nothing was restored") {
		t.Errorf("a file that leaves a Secret without a source: %v", err)
	}
	out, _, left, err = withSecretSources(ctx, snap, partial, false, true)
	if err != nil || !reflect.DeepEqual(left, []string{"shop/odd (an operator)"}) || len(out.Objects) != len(snap.Objects)-1 {
		t.Errorf("with a source cluster: left %q, %d objects, %v", left, len(out.Objects), err)
	}

	// A source that does not answer stops the restore before it starts, and exec: needs its flag.
	unread := writeFile(t, dir, "unread.yaml", `secrets:
  - secret: shop/git
    from: {password: "env:TF_TEST_PASSWORD", username: "exec:printf git-user"}
  - secret: shop/odd
    from: {k: "env:TF_TEST_UNSET"}
`)
	_, _, _, err = withSecretSources(ctx, snap, unread, false, false)
	if err == nil || !strings.Contains(err.Error(), "2 values could not be read; nothing was restored") || !strings.Contains(err.Error(), "--allow-exec") || strings.Contains(err.Error(), "s3cr3t-value") {
		t.Errorf("unread sources: %v", err)
	}
}

func sameSet(a, b []string) bool {
	m := map[string]int{}
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		m[v]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

// A restore with a sources file, into a real API server: the Secret a
// person supplies arrives with the values read, byte for byte; what
// something else makes is not written; and flags that have nothing to act
// on are refused.
func TestRestoreReadsSecretSources(t *testing.T) {
	_, dir := sourcesSnapshot(t)
	s := kubetest.Start(t, "sources")
	ctx := context.Background()
	// Bytes that are no text: a value is what was read, byte for byte.
	value := writeFile(t, t.TempDir(), "password.bin", "p\x00ss \n word")
	file := writeFile(t, t.TempDir(), "secrets.yaml", `secrets:
  - secret: shop/git
    from: {password: "file:`+value+`", username: "exec:printf 'git-user\n'"}
  - secret: shop/odd
    leave: an operator
`)
	base := []string{"--kubeconfig", s.Kubeconfig, "--context", s.Context, "--from", dir}
	// Without the flag an exec: reference stops the restore, and nothing is written.
	if code := restore(ctx, append(base, "--secrets-from", file)); code != 1 {
		t.Fatalf("an exec: reference ran without --allow-exec: exit %d", code)
	}
	c, err := kube.Connect(s.Kubeconfig, s.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	cs := kubernetes.NewForConfigOrDie(c.Config)
	if _, err := cs.CoreV1().Namespaces().Get(ctx, "shop", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("a refused restore wrote the namespace: %v", err)
	}
	// The OnePasswordItem has no type to be served by here: that one object fails, and the rest is applied.
	if code := restore(ctx, append(base, "--secrets-from", file, "--allow-exec")); code != 3 {
		t.Fatalf("exit %d, want 3 (one type is not served)", code)
	}
	got, err := cs.CoreV1().Secrets("shop").Get(ctx, "git", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data["password"]) != "p\x00ss \n word" || string(got.Data["username"]) != "git-user" || len(got.Data) != 2 {
		t.Errorf("the Secret does not hold what was read: %d keys, password %d bytes, username %q", len(got.Data), len(got.Data["password"]), got.Data["username"])
	}
	if got.Annotations[kube.WithheldAnnotation] != "" {
		t.Error("the restored Secret still says its values are withheld")
	}
	if _, err := cs.CoreV1().Secrets("shop").Get(ctx, "empty", metav1.GetOptions{}); err != nil {
		t.Errorf("a Secret with nothing withheld was not restored: %v", err)
	}
	for _, name := range []string{"odd", "ca", "db"} {
		if _, err := cs.CoreV1().Secrets("shop").Get(ctx, name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Errorf("shop/%s is something else's to make and was written: %v", name, err)
		}
	}
	azure := filepath.Join(t.TempDir(), "azure")
	if err := (snapshot.Snapshot{Platform: "azure", Policy: "default"}).Write(azure); err != nil {
		t.Fatal(err)
	}
	for why, args := range map[string][]string{
		"--allow-exec is for --secrets-from": append(base, "--allow-exec"),
		"are for a kubernetes restore":       {"--platform", "azure", "--subscription", "x", "--from", azure, "--secrets-from", file},
	} {
		if code := restore(ctx, args); code != 1 || !strings.Contains(lastErr.Error(), why) {
			t.Errorf("%v: exit %d, %v; want 1 and %q", args, code, lastErr, why)
		}
	}
}
