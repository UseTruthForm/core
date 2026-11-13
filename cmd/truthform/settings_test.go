package main

import (
	"context"
	"fmt"
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

const (
	envPath = "spec.template.spec.containers[api].env[DB_PASSWORD]"
	cmPath  = "data[url]"
)

// settingsSnapshot is a snapshot with credentials withheld from two
// objects that are not Secrets, as a capture leaves them: the value
// empty, and its place named.
func settingsSnapshot(t *testing.T) string {
	t.Helper()
	s := snapshot.Snapshot{Platform: "kubernetes", Policy: "default", Coverage: []snapshot.Coverage{{Resource: "core/v1/secrets", Kind: "Secret"}}, Objects: []snapshot.Object{
		{Body: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "shop"}}},
		{Body: map[string]any{"apiVersion": "apps/v1", "kind": "Deployment",
			"metadata": map[string]any{"name": "api", "namespace": "shop", "annotations": map[string]any{kube.WithheldEnvAnnotation: envPath}},
			"spec": map[string]any{
				"selector": map[string]any{"matchLabels": map[string]any{"app": "api"}},
				"template": map[string]any{"metadata": map[string]any{"labels": map[string]any{"app": "api"}},
					"spec": map[string]any{"containers": []any{map[string]any{"name": "api", "image": "example.com/api:1", "env": []any{
						map[string]any{"name": "DB_PASSWORD", "value": ""},
						map[string]any{"name": "REGION", "value": "east"},
					}}}}},
			}}},
		{Body: map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"name": "cfg", "namespace": "shop", "annotations": map[string]any{kube.WithheldEnvAnnotation: cmPath}},
			"data":     map[string]any{"url": "", "mode": "fast"}}},
	}}
	dir := filepath.Join(t.TempDir(), "cluster")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

const settingsFile = `secrets: []
settings:
  - object: "apps/v1|Deployment|shop|api"
    from:
      "` + envPath + `": "env:TF_SETTING_PASSWORD"
  - object: "v1|ConfigMap|shop|cfg"
    from:
      "` + cmPath + `": "env:TF_SETTING_URL"
`

// plan secrets lists every credential withheld from an object that is not
// a Secret, and the check wants a source for each: a person supplies them
// with no cluster to read them from.
func TestPlanSecretsListsWithheldSettings(t *testing.T) {
	dir := settingsSnapshot(t)
	file := filepath.Join(t.TempDir(), "secrets.yaml")
	if code := planCmd([]string{"secrets", "--from", dir, "--out", file}); code != 0 {
		t.Fatalf("exit %d, %v", code, lastErr)
	}
	b, _ := os.ReadFile(file)
	for _, want := range []string{"settings:", `- object: "apps/v1|Deployment|shop|api"`, `"` + envPath + `": ""`, `- object: "v1|ConfigMap|shop|cfg"`, `"` + cmPath + `": ""`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the file lacks %q:\n%s", want, b)
		}
	}
	code, stdout, _ := output(t, func() int { return planCmd([]string{"secrets", "--from", dir, "--check", file}) })
	if code != 2 || !strings.Contains(stdout, "NO SOURCE  apps/v1|Deployment|shop|api: the reference for "+envPath+" is empty") {
		t.Errorf("an unfilled file: exit %d\n%s", code, stdout)
	}
	none := writeFile(t, t.TempDir(), "none.yaml", "secrets: []\n")
	code, stdout, _ = output(t, func() int { return planCmd([]string{"secrets", "--from", dir, "--check", none}) })
	if code != 2 || !strings.Contains(stdout, "v1|ConfigMap|shop|cfg: no entry under settings") {
		t.Errorf("a file with no settings: exit %d\n%s", code, stdout)
	}

	filled := writeFile(t, t.TempDir(), "filled.yaml", settingsFile)
	code, stdout, _ = output(t, func() int { return planCmd([]string{"secrets", "--from", dir, "--check", filled}) })
	if code != 0 || !strings.Contains(stdout, "each of the 2 objects with credentials withheld from its settings has a source") {
		t.Errorf("a filled file: exit %d\n%s", code, stdout)
	}
	// --resolve reads each, and prints none.
	t.Setenv("TF_SETTING_PASSWORD", "s3cr3t-setting")
	code, stdout, stderr := output(t, func() int { return planCmd([]string{"secrets", "--from", dir, "--check", filled, "--resolve"}) })
	if code != 2 || !strings.Contains(stdout, "v1|ConfigMap|shop|cfg: "+cmPath+": env:TF_SETTING_URL") || strings.Contains(stdout+stderr, "s3cr3t-setting") {
		t.Errorf("--resolve with one source unset: exit %d\n%s\n%s", code, stdout, stderr)
	}
	d := asJSON(t, func() { planCmd([]string{"secrets", "--from", dir, "--check", filled, "--resolve"}) })
	if doc, _ := d["secrets"].(map[string]any); doc["settings"] != float64(2) || doc["read"] != float64(1) {
		t.Errorf("document: %v", d)
	}
}

// A restore given the file fills each withheld value from its source; one
// that is not covered is refused before anything is written.
func TestRestoreFillsWithheldSettings(t *testing.T) {
	dir := settingsSnapshot(t)
	ctx := context.Background()
	filled := writeFile(t, t.TempDir(), "filled.yaml", settingsFile)
	none := writeFile(t, t.TempDir(), "none.yaml", "secrets: []\n")
	srv := kubetest.Start(t, "settings")
	base := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context, "--from", dir}
	nowhere := base
	// The file is read, and every value, before anything is written.
	lastErr = nil
	if code := restore(ctx, append(nowhere, "--secrets-from", none)); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), "does not cover the snapshot") || !strings.Contains(lastErr.Error(), "no entry under settings") {
		t.Errorf("a file that names no settings: exit %d, %v", code, lastErr)
	}
	lastErr = nil
	if code := restore(ctx, append(nowhere, "--secrets-from", filled)); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), "values could not be read") {
		t.Errorf("sources that are not set: exit %d, %v", code, lastErr)
	}
	// A value that is not text is refused: a setting is text in the object.
	binary := writeFile(t, t.TempDir(), "bin", "\xff\xfe\x00k")
	notText := writeFile(t, t.TempDir(), "not-text.yaml", strings.Replace(settingsFile, "env:TF_SETTING_URL", "file:"+binary, 1))
	t.Setenv("TF_SETTING_PASSWORD", "s3cr3t-setting")
	lastErr = nil
	if code := restore(ctx, append(nowhere, "--secrets-from", notText)); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), "what was read is not text") {
		t.Errorf("a value that is not text: exit %d, %v", code, lastErr)
	}
	// Read by a command, the message does not show the command: people
	// put tokens in those.
	byCommand := writeFile(t, t.TempDir(), "by-command.yaml", strings.Replace(settingsFile, "env:TF_SETTING_URL", "exec:cat "+binary+" # token=SUPERSECRETCMD", 1))
	lastErr = nil
	if code := restore(ctx, append(nowhere, "--secrets-from", byCommand, "--allow-exec")); code != 1 || lastErr == nil || !strings.Contains(lastErr.Error(), "what was read is not text") || strings.Contains(lastErr.Error(), "SUPERSECRETCMD") || strings.Contains(lastErr.Error(), "cat ") {
		t.Errorf("a value that is not text, read by a command: exit %d, %v", code, lastErr)
	}
	// A check that reads the values refuses it as the restore does.
	lastErr = nil
	if code, stdout, stderr := output(t, func() int { return planCmd([]string{"secrets", "--from", dir, "--check", notText, "--resolve"}) }); code == 0 || !strings.Contains(stdout+stderr+fmt.Sprint(lastErr), "what was read is not text") {
		t.Errorf("plan secrets --check --resolve of a value that is not text: exit %d\n%s\n%s\n%v", code, stdout, stderr, lastErr)
	}
	os.Unsetenv("TF_SETTING_PASSWORD")

	// With another cluster to read from, an object the file does not name
	// is left to it, and one it names is still checked whole: a file that
	// misses a place is refused before anything is written, not when the
	// restore gets to that object.
	snap, err := snapshot.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	partial := writeFile(t, t.TempDir(), "partial.yaml", "secrets: []\nsettings:\n  - object: \"apps/v1|Deployment|shop|api\"\n    from: {\"spec.stale\": \"env:TF_SETTING_PASSWORD\"}\n")
	if _, _, _, err := withSecretSources(ctx, snap, partial, false, true); err == nil || !strings.Contains(err.Error(), envPath+" has no reference") {
		t.Errorf("a named object with a place missing, with another cluster: %v", err)
	}
	if _, opt, _, err := withSecretSources(ctx, snap, none, false, true); err != nil {
		t.Errorf("no settings named, with another cluster: %v", err)
	} else if _, known, _ := opt.Settings(ctx, "apps/v1|Deployment|shop|api", nil); known {
		t.Error("an object the file does not name is said to be known")
	}
	// An entry for an object nothing was withheld from is not read at all.
	unused := writeFile(t, t.TempDir(), "unused.yaml", settingsFile+"  - object: \"v1|ConfigMap|shop|other\"\n    from: {\"data[k]\": \"env:TF_NEVER_SET\"}\n")
	t.Setenv("TF_SETTING_PASSWORD", "s3cr3t-setting")
	t.Setenv("TF_SETTING_URL", "https://app:s3cr3t-url@db.example.com")
	if _, _, _, err := withSecretSources(ctx, snap, unused, false, false); err != nil {
		t.Errorf("an entry that is not used was read: %v", err)
	}
	os.Unsetenv("TF_SETTING_PASSWORD")
	os.Unsetenv("TF_SETTING_URL")

	// Nothing was written by any of the refusals above.
	c0, err := kube.Connect(srv.Kubeconfig, srv.Context, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kubernetes.NewForConfigOrDie(c0.Config).CoreV1().Namespaces().Get(ctx, "shop", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("a refused restore wrote the namespace: %v", err)
	}
	if captureOnly {
		t.Skip("the rest restores, which the capture-only build refuses")
	}
	t.Setenv("TF_SETTING_PASSWORD", "s3cr3t-setting")
	t.Setenv("TF_SETTING_URL", "https://app:s3cr3t-url@db.example.com")
	// Without a source the two objects are refused, and said to be.
	code, stdout, _ := output(t, func() int { return restore(ctx, base) })
	if strings.Contains(stdout, "s3cr3t") {
		t.Errorf("a refused object's message holds a value:\n%s", stdout)
	}
	if code != 3 || !strings.Contains(stdout, "supply them with --secrets-from or --secrets-from-context") || !strings.Contains(stdout, "applied 1 of 3 objects") {
		t.Fatalf("with no source: exit %d\n%s", code, stdout)
	}
	code, stdout, stderr := output(t, func() int { return restore(ctx, append(base, "--secrets-from", filled)) })
	if code != 0 || !strings.Contains(stdout, "applied 3 of 3 objects") || strings.Contains(stdout+stderr, "s3cr3t") {
		t.Fatalf("with the file: exit %d, %v\n%s\n%s", code, lastErr, stdout, stderr)
	}
	c, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	cs := kubernetes.NewForConfigOrDie(c.Config)
	dep, err := cs.AppsV1().Deployments("shop").Get(ctx, "api", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, e := range dep.Spec.Template.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	if env["DB_PASSWORD"] != "s3cr3t-setting" || env["REGION"] != "east" || dep.Annotations[kube.WithheldEnvAnnotation] != "" {
		t.Errorf("the Deployment: env %d entries, password set=%v, annotation %q", len(env), env["DB_PASSWORD"] != "", dep.Annotations[kube.WithheldEnvAnnotation])
	}
	cm, err := cs.CoreV1().ConfigMaps("shop").Get(ctx, "cfg", metav1.GetOptions{})
	if err != nil || cm.Data["url"] != "https://app:s3cr3t-url@db.example.com" || cm.Data["mode"] != "fast" {
		t.Errorf("the ConfigMap: %v, %d keys", err, len(cm.Data))
	}
}
