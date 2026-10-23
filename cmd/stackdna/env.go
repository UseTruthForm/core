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
	// github, cloudflare (the token comes from the environment)
	Account string `json:"account,omitempty"`
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
		// A name is a directory: unique without regard to case (Windows and
		// macOS fold it, so Prod and prod wrote into one directory at once),
		// and not "." or "..", which wrote into the environment itself.
		if t.Name == "" || strings.ContainsAny(t.Name, `/\:`) || t.Name == "." || t.Name == ".." || seen[strings.ToLower(t.Name)] {
			return nil, fmt.Errorf("%s: target %d needs a unique name (case aside) without / \\ or :, and not . or ..", path, i+1)
		}
		seen[strings.ToLower(t.Name)] = true
		need := map[string]string{"kubernetes": t.Context, "aws": t.Region, "azure": t.Subscription, "gcp": t.Project, "github": t.Account, "cloudflare": t.Account}
		field := map[string]string{"kubernetes": "context", "aws": "region", "azure": "subscription", "gcp": "project", "github": "account", "cloudflare": "account"}
		v, known := need[t.Platform]
		if !known {
			return nil, fmt.Errorf("%s: target %s: platform must be kubernetes, aws, azure, gcp, github or cloudflare", path, t.Name)
		}
		if v == "" {
			return nil, fmt.Errorf("%s: target %s: %s is required for platform %s", path, t.Name, field[t.Platform], t.Platform)
		}
		if k := inapplicable(*t); k != "" {
			return nil, fmt.Errorf("%s: target %s: %s does not apply to platform %s", path, t.Name, k, t.Platform)
		}
		// Relative baselines are relative to the config file, not to
		// wherever the command happens to run; each of a comma-separated
		// list (one per region), not only the first.
		if t.Baseline != "" {
			parts := strings.Split(t.Baseline, ",")
			for j, b := range parts {
				if b = strings.TrimSpace(b); b != "" && !filepath.IsAbs(b) {
					parts[j] = filepath.Join(base, b)
				}
			}
			t.Baseline = strings.Join(parts, ",")
		}
	}
	return &e, nil
}

// inapplicable names a key set on a target whose platform ignores it.
// UnmarshalStrict refuses unknown keys but not these, and an ignored key
// is the "misspelled key quietly does nothing" this loader exists to
// prevent: types on a GitHub target captured everything.
func inapplicable(t Target) string {
	set := map[string]bool{"context": t.Context != "", "kubeconfig": t.Kubeconfig != "", "includeSystem": t.IncludeSystem,
		"captureRendered": t.CaptureRender, "captureManaged": t.CaptureManaged, "region": t.Region != "", "profile": t.Profile != "",
		"subscription": t.Subscription != "", "project": t.Project != "", "account": t.Account != "", "types": len(t.Types) > 0,
		"baseline": t.Baseline != ""}
	applies := map[string][]string{
		"kubernetes": {"context", "kubeconfig", "includeSystem", "captureRendered", "baseline"},
		"aws":        {"region", "profile", "types", "baseline", "captureManaged"},
		"azure":      {"subscription", "types", "baseline", "captureManaged"},
		"gcp":        {"project", "types", "baseline"},
		"github":     {"account"},
		"cloudflare": {"account"},
	}
	ok := map[string]bool{}
	for _, k := range applies[t.Platform] {
		ok[k] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if set[k] && !ok[k] {
			return k
		}
	}
	return ""
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
	case "github", "cloudflare":
		sf := saasFlags{account: t.Account}
		ad, err := sf.connect(t.Platform, true)
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
			if r.Digest, err = snapshot.Digest(filepath.Join(out, t.Name)); err != nil {
				r.Status, r.Error = "failed", "written but unreadable: "+err.Error()
				results[i] = r
				return
			}
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
	if jsonOut {
		emit(map[string]any{"schema": jsonSchema, "command": "capture", "environment": env.Name, "out": out, "targets": results})
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
	// A target whose last capture failed left its previous snapshot in
	// place; diffing against it would compare with stale data and say
	// nothing about it.
	last := map[string]TargetResult{}
	b, err := os.ReadFile(filepath.Join(from, envManifest))
	if err != nil {
		return fail(fmt.Errorf("%s is not an environment capture: %w", from, err))
	}
	var doc struct {
		Targets []TargetResult `json:"targets"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fail(fmt.Errorf("%s: %w", envManifest, err))
	}
	for _, r := range doc.Targets {
		last[r.Name] = r
	}
	code := 0
	type targetDiff struct {
		Name        string       `json:"name"`
		Platform    string       `json:"platform"`
		Error       string       `json:"error,omitempty"`
		Differences int          `json:"differences"`
		Changes     []changeJSON `json:"changes"`
	}
	var diffs []targetDiff
	if jsonOut {
		defer func() {
			emit(map[string]any{"schema": jsonSchema, "command": "diff", "environment": env.Name, "from": from, "targets": diffs})
		}()
	}
	failTarget := func(t Target, msg string) {
		fmt.Printf("%s: %s\n", t.Name, msg)
		diffs = append(diffs, targetDiff{Name: t.Name, Platform: t.Platform, Error: msg, Changes: []changeJSON{}})
		code = 1
	}
	for _, t := range env.Targets {
		if r, ok := last[t.Name]; !ok || r.Status == "failed" {
			why := "it is not in the last environment capture"
			if ok {
				why = "its last capture failed (" + r.Error + ")"
			}
			failTarget(t, "not diffed: "+why+", so any snapshot there is older than the rest")
			continue
		}
		want, err := snapshot.Read(filepath.Join(from, t.Name))
		if err != nil {
			failTarget(t, "cannot read its snapshot: "+err.Error())
			continue
		}
		got, err := captureTarget(ctx, t)
		if err != nil {
			failTarget(t, "capture failed: "+err.Error())
			continue
		}
		if got.Policy != want.Policy {
			failTarget(t, fmt.Sprintf("captured with policy %q but the config now gives %q", want.Policy, got.Policy))
			continue
		}
		ch := snapshot.Compare(want, got)
		diffs = append(diffs, targetDiff{Name: t.Name, Platform: t.Platform, Differences: len(ch), Changes: changesJSON(ch)})
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
