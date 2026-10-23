package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"sigs.k8s.io/yaml"

	"github.com/stackdna/core/internal/kube"
	"github.com/stackdna/core/internal/snapshot"
)

// Environment is a config file naming every system that makes up one
// environment, so one command captures (or diffs) all of it:
//
//	name: example
//	targets:
//	  - {name: prod, platform: kubernetes, context: example, baseline: base/aks}
//	  - {name: azure, platform: azure, subscription: <id>}
//
// Restore is deliberately not driven by it: recreating a whole environment
// in one command is too easy to aim at the wrong place.
type Environment struct {
	Name    string   `json:"name"`
	Targets []Target `json:"targets"`
}

// Target is one system. Which fields apply depends on the platform.
type Target struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	// kubernetes
	Context        string `json:"context,omitempty"`
	Kubeconfig     string `json:"kubeconfig,omitempty"`
	IncludeSystem  bool   `json:"includeSystem,omitempty"`
	CaptureRender  bool   `json:"captureRendered,omitempty"`
	CaptureManaged bool   `json:"captureManaged,omitempty"`
	// aws
	Region  string `json:"region,omitempty"`
	Profile string `json:"profile,omitempty"`
	// azure
	Subscription string `json:"subscription,omitempty"`
	// gcp
	Project string `json:"project,omitempty"`
	// any cloud
	Types    []string `json:"types,omitempty"`
	Baseline string   `json:"baseline,omitempty"`
}

// loadEnvironment reads and checks a config. Unknown keys and missing
// required fields are errors before anything runs: a misspelled key that
// quietly dropped a cluster would produce a snapshot that looks complete.
func loadEnvironment(path string) (*Environment, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Environment
	if err := yaml.UnmarshalStrict(b, &e); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if e.Name == "" || len(e.Targets) == 0 {
		return nil, fmt.Errorf("%s: needs a name and at least one target", path)
	}
	seen := map[string]bool{}
	base := filepath.Dir(path)
	for i := range e.Targets {
		t := &e.Targets[i]
		if t.Name == "" || strings.ContainsAny(t.Name, `/\:`) || seen[t.Name] {
			return nil, fmt.Errorf("%s: target %d needs a unique name without / \\ or :", path, i+1)
		}
		seen[t.Name] = true
		need := map[string]string{"kubernetes": t.Context, "aws": t.Region, "azure": t.Subscription, "gcp": t.Project}
		field := map[string]string{"kubernetes": "context", "aws": "region", "azure": "subscription", "gcp": "project"}
		v, known := need[t.Platform]
		if !known {
			return nil, fmt.Errorf("%s: target %s: platform must be kubernetes, aws, azure or gcp", path, t.Name)
		}
		if v == "" {
			return nil, fmt.Errorf("%s: target %s: %s is required for platform %s", path, t.Name, field[t.Platform], t.Platform)
		}
		// Relative baselines are relative to the config file, not to
		// wherever the command happens to run.
		if t.Baseline != "" && !filepath.IsAbs(t.Baseline) {
			t.Baseline = filepath.Join(base, t.Baseline)
		}
	}
	return &e, nil
}

// TargetResult is what one target produced, recorded in environment.yaml.
type TargetResult struct {
	Name     string   `json:"name"`
	Platform string   `json:"platform"`
	Status   string   `json:"status"` // complete, incomplete, failed
	Objects  int      `json:"objects"`
	Digest   string   `json:"digest,omitempty"`
	Error    string   `json:"error,omitempty"`
	Gaps     []string `json:"gaps,omitempty"`
}

// captureTarget captures one target with the same code the single-target
// commands use, read-only.
func captureTarget(ctx context.Context, t Target) (snapshot.Snapshot, error) {
	switch t.Platform {
	case "kubernetes":
		c, err := kube.Connect(t.Kubeconfig, t.Context, true)
		if err != nil {
			return snapshot.Snapshot{}, err
		}
		pol := kube.Policy{IncludeSystem: t.IncludeSystem, CaptureRendered: t.CaptureRender}
		if t.Baseline != "" {
			if pol, err = withBaseline(pol, t.Baseline); err != nil {
				return snapshot.Snapshot{}, err
			}
		}
		return kube.Capture(ctx, c, pol)
	case "aws":
		a := awsFlags{region: t.Region, profile: t.Profile, types: strings.Join(t.Types, ","), baseline: t.Baseline, managed: t.CaptureManaged, parallel: 8}
		ad, err := a.connect(ctx, true)
		if err != nil {
			return snapshot.Snapshot{}, err
		}
		return ad.Capture(ctx)
	case "azure":
		a := azureFlags{subscription: t.Subscription, types: strings.Join(t.Types, ","), baseline: t.Baseline, managed: t.CaptureManaged, parallel: 8}
		ad, err := a.connect(true)
		if err != nil {
			return snapshot.Snapshot{}, err
		}
		return ad.Capture(ctx)
	case "gcp":
		g := gcpFlags{project: t.Project, types: strings.Join(t.Types, ","), baseline: t.Baseline, parallel: 8}
		ad, err := g.connect(ctx, true)
		if err != nil {
			return snapshot.Snapshot{}, err
		}
		return ad.Capture(ctx)
	}
	return snapshot.Snapshot{}, fmt.Errorf("unknown platform %q", t.Platform)
}

// gaps lists what makes a capture incomplete: types that failed and
// resources listed but unreadable, across every platform's wording.
func gaps(s snapshot.Snapshot) []string {
	var out []string
	_, _, failed := summarize(s)
	out = append(out, failed...)
	for _, c := range s.Coverage {
		if strings.Contains(c.NotCaptured, "no API version") {
			out = append(out, c.Resource+": "+c.NotCaptured)
		}
	}
	for _, sk := range s.Skips {
		if strings.HasPrefix(sk.Reason, "listed but could not be read") {
			out = append(out, sk.Resource+" "+sk.Name+": "+sk.Reason)
		}
	}
	sort.Strings(out)
	return out
}

// captureEnvironment captures every target, a few at a time. A target that
// fails is recorded and the others still run: one unreachable cluster
// must not cost the rest of the environment's backup.
func captureEnvironment(ctx context.Context, configPath, out string) int {
	env, err := loadEnvironment(configPath)
	if err != nil {
		return fail(err)
	}
	if err := ensureEnvDir(out); err != nil {
		return fail(err)
	}
	results := make([]TargetResult, len(env.Targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, t := range env.Targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := TargetResult{Name: t.Name, Platform: t.Platform}
			snap, err := captureTarget(ctx, t)
			if err == nil {
				err = snap.Write(filepath.Join(out, t.Name))
			}
			if err != nil {
				r.Status, r.Error = "failed", err.Error()
				results[i] = r
				return
			}
			r.Objects = len(snap.Objects)
			r.Digest, _ = snapshot.Digest(filepath.Join(out, t.Name))
			r.Gaps = gaps(snap)
			r.Status = "complete"
			if len(r.Gaps) > 0 {
				r.Status = "incomplete"
			}
			if err := writeReport(filepath.Join(out, t.Name), snap, t.Name); err != nil {
				r.Status, r.Error = "failed", "write report: "+err.Error()
			}
			results[i] = r
		}()
	}
	wg.Wait()
	if err := writeEnvironment(out, env.Name, results); err != nil {
		return fail(err)
	}
	code := 0
	for _, r := range results {
		fmt.Printf("%-10s %-11s %-10s %5d objects  %s%s\n", r.Status, r.Platform, r.Name, r.Objects, r.Digest, errSuffix(r.Error))
		for _, g := range r.Gaps {
			fmt.Println("    gap:", g)
		}
		switch {
		case r.Status == "failed":
			code = 1
		case r.Status == "incomplete" && code == 0:
			code = 3
		}
	}
	fmt.Printf("environment %s: %d targets into %s; see %s\n", env.Name, len(results), out, filepath.Join(out, "REPORT.md"))
	return code
}

func errSuffix(e string) string {
	if e == "" {
		return ""
	}
	return "  ERROR: " + e
}

const envManifest = "environment.yaml"

// ensureEnvDir refuses to write into a directory that is neither empty nor
// an environment capture, so --out cannot clobber unrelated files.
func ensureEnvDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, 0o755)
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, envManifest)); err != nil {
		return fmt.Errorf("%s is not empty and holds no %s; refusing to write an environment capture there", dir, envManifest)
	}
	return nil
}

// writeEnvironment records each target's result and one digest over them,
// so two captures of an unchanged environment compare in one line. Nothing
// time- or machine-dependent goes in.
func writeEnvironment(dir, name string, results []TargetResult) error {
	h := sha256.New()
	for _, r := range results {
		fmt.Fprintf(h, "%s|%s|%s|%s\n", r.Name, r.Status, r.Digest, r.Error)
	}
	doc := map[string]any{"name": name, "digest": "sha256:" + hex.EncodeToString(h.Sum(nil)), "targets": results}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, envManifest), b, 0o644); err != nil {
		return err
	}
	return writeEnvReport(dir, name, results)
}

// diffEnvironment compares every target with its live system.
func diffEnvironment(ctx context.Context, configPath, from string) int {
	env, err := loadEnvironment(configPath)
	if err != nil {
		return fail(err)
	}
	code := 0
	for _, t := range env.Targets {
		want, err := snapshot.Read(filepath.Join(from, t.Name))
		if err != nil {
			fmt.Printf("%s: cannot read its snapshot: %v\n", t.Name, err)
			code = 1
			continue
		}
		got, err := captureTarget(ctx, t)
		if err != nil {
			fmt.Printf("%s: capture failed: %v\n", t.Name, err)
			code = 1
			continue
		}
		if got.Policy != want.Policy {
			fmt.Printf("%s: captured with policy %q but the config now gives %q\n", t.Name, want.Policy, got.Policy)
			code = 1
			continue
		}
		ch := snapshot.Compare(want, got)
		fmt.Printf("== %s (%s): %d differences\n", t.Name, t.Platform, len(ch))
		for _, c := range ch {
			if c.Kind == "changed" {
				fmt.Printf("  changed  %s: %s\n", c.Key, strings.Join(c.Fields, ", "))
			} else {
				fmt.Printf("  %-8s %s\n", c.Kind, c.Key)
			}
		}
		if len(ch) > 0 && code == 0 {
			code = 2
		}
	}
	return code
}
