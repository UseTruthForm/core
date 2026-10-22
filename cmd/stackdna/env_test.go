package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/stackdna/core/internal/kube"
	"github.com/stackdna/core/internal/kubetest"
	"github.com/stackdna/core/internal/snapshot"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A misspelled key or a missing field fails before anything runs: a typo
// that quietly dropped a cluster would give a snapshot that looks whole.
func TestLoadEnvironmentIsStrict(t *testing.T) {
	dir := t.TempDir()
	for body, want := range map[string]string{
		"name: e\ntargets:\n  - {name: a, platform: kubernetes, contxt: x}\n":                                   "unknown field",
		"name: e\ntargets:\n  - {name: a, platform: azure}\n":                                                   "subscription is required",
		"name: e\ntargets:\n  - {name: a, platform: aws, region: r}\n  - {name: a, platform: aws, region: r}\n": "unique name",
		"name: e\ntargets:\n  - {name: a, platform: oracle, region: r}\n":                                       "platform must be",
		"name: e\ntargets: []\n": "at least one target",
	} {
		_, err := loadEnvironment(writeFile(t, dir, "env.yaml", body))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("config %q: want error containing %q, got %v", body, want, err)
		}
	}
	e, err := loadEnvironment(writeFile(t, dir, "env.yaml", "name: e\ntargets:\n  - {name: a, platform: kubernetes, context: c, baseline: base/aks}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Targets[0].Baseline; got != filepath.Join(dir, "base", "aks") {
		t.Errorf("relative baseline resolved to %s, want it next to the config", got)
	}
}

// Two real API servers and one target that cannot be reached: the two are
// captured, the third is recorded as failed without costing the others,
// and an unchanged environment captures to the same digest twice.
func TestCaptureEnvironment(t *testing.T) {
	a, b := kubetest.Start(t, "env-a"), kubetest.Start(t, "env-b")
	settle(t, a, b)
	dir := t.TempDir()
	cfg := writeFile(t, dir, "env.yaml", `name: shop
targets:
  - {name: cluster-a, platform: kubernetes, kubeconfig: '`+a.Kubeconfig+`', context: `+a.Context+`}
  - {name: cluster-b, platform: kubernetes, kubeconfig: '`+b.Kubeconfig+`', context: `+b.Context+`}
  - {name: gone, platform: kubernetes, kubeconfig: '`+a.Kubeconfig+`', context: no-such-context}
`)
	out := filepath.Join(dir, "snap")
	if code := captureEnvironment(context.Background(), cfg, out); code != 1 {
		t.Fatalf("exit %d, want 1 (one target failed)", code)
	}
	first := readEnv(t, out)
	status := map[string]string{}
	for _, r := range first.Targets {
		status[r.Name] = r.Status
	}
	if status["cluster-a"] != "complete" || status["cluster-b"] != "complete" || status["gone"] != "failed" {
		t.Fatalf("statuses %v", status)
	}
	for _, n := range []string{"cluster-a", "cluster-b"} {
		if _, err := snapshot.Read(filepath.Join(out, n)); err != nil {
			t.Errorf("%s snapshot: %v", n, err)
		}
		if _, err := os.Stat(filepath.Join(out, n, "REPORT.md")); err != nil {
			t.Errorf("%s has no REPORT.md", n)
		}
	}
	rep, _ := os.ReadFile(filepath.Join(out, "REPORT.md"))
	if !strings.Contains(string(rep), "**failed**") || strings.Index(string(rep), "gone") > strings.Index(string(rep), "cluster-a") {
		t.Errorf("environment report should list the failed target first:\n%s", rep)
	}
	captureEnvironment(context.Background(), cfg, out)
	if second := readEnv(t, out); second.Digest != first.Digest {
		t.Errorf("unchanged environment captured to %s then %s", first.Digest, second.Digest)
	}
	// Refuses to write over a directory that is not an environment capture.
	other := t.TempDir()
	writeFile(t, other, "notes.txt", "mine")
	if code := captureEnvironment(context.Background(), cfg, other); code != 1 {
		t.Errorf("wrote into a foreign directory, exit %d", code)
	}
}

type envDoc struct {
	Digest  string         `json:"digest"`
	Targets []TargetResult `json:"targets"`
}

// settle waits until each fresh API server captures to the same digest
// twice running. A server still creating its own bootstrap objects after
// /readyz differs between captures for a reason that has nothing to do
// with StackDNA: in CI (PR #14) the second of two fresh servers captured
// to one digest and then another, objects identical, and the unchanged-
// environment assertion failed. Which bootstrap object it was is not
// pinned down (six local starts never showed it), so this waits for the
// thing the assertion needs rather than for a guess.
func settle(t *testing.T, servers ...*kubetest.Server) {
	t.Helper()
	for _, s := range servers {
		c, err := kube.Connect(s.Kubeconfig, s.Context, true)
		if err != nil {
			t.Fatal(err)
		}
		prev := ""
		for i := 0; ; i++ {
			snap, err := kube.Capture(context.Background(), c, kube.Policy{})
			if err != nil {
				t.Fatal(err)
			}
			d := t.TempDir()
			if err := snap.Write(d); err != nil {
				t.Fatal(err)
			}
			dg, _ := snapshot.Digest(d)
			if dg == prev {
				break
			}
			if i == 30 {
				t.Fatalf("%s never settled: still changing after %d captures", s.Context, i)
			}
			prev = dg
			time.Sleep(time.Second)
		}
	}
}

func readEnv(t *testing.T, dir string) envDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, envManifest))
	if err != nil {
		t.Fatal(err)
	}
	var d envDoc
	if err := yaml.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// The report leads with what is missing, escapes table characters, and is
// the same bytes for the same snapshot.
func TestReport(t *testing.T) {
	s := snapshot.Snapshot{Platform: "aws", Policy: "default",
		Objects: []snapshot.Object{{Body: map[string]any{"apiVersion": "v1", "kind": "AWS::SQS::Queue", "metadata": map[string]any{"name": "q"}}}},
		Coverage: []snapshot.Coverage{
			{Resource: "AWS::SQS::Queue", Kind: "AWS::SQS::Queue", Captured: 1},
			{Resource: "AWS::FMS::Policy", Kind: "AWS::FMS::Policy", NotCaptured: "list failed: denied"},
			{Resource: "AWS::X::Y", Kind: "AWS::X::Y", NotCaptured: "not set up in this account: x"},
		},
		Skips: []snapshot.Skip{{Resource: "AWS::IAM::Role", Name: "a|b", Reason: "service-linked role"}},
	}
	dir := t.TempDir()
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(dir, s, "test"); err != nil {
		t.Fatal(err)
	}
	r1, _ := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	writeReport(dir, s, "test")
	r2, _ := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	txt := string(r1)
	if string(r1) != string(r2) {
		t.Error("report not deterministic")
	}
	inc, capd := strings.Index(txt, "## Incomplete"), strings.Index(txt, "## Captured, by type")
	if inc < 0 || capd < 0 || inc > capd {
		t.Errorf("Incomplete must come before Captured:\n%s", txt)
	}
	if !strings.Contains(txt, "AWS::FMS::Policy: list failed: denied") || !strings.Contains(txt, `a\|b`) || !strings.Contains(txt, "not set up in this account") {
		t.Errorf("report content:\n%s", txt)
	}
}
