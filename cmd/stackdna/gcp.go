package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stackdna/core/internal/gcp"
	"github.com/stackdna/core/internal/snapshot"
)

// gcpFlags are the GCP forms of capture, restore and diff. --types and
// --parallel are shared with AWS and read from there.
type gcpFlags struct {
	project, discovery string
	types, baseline    string
	parallel           int
}

func (g *gcpFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&g.project, "project", "", "GCP project ID (required for --platform gcp)")
	fs.StringVar(&g.discovery, "discovery", "", "directory of Discovery documents named api_version.json (default: Google's, cached for a day)")
}

func (g *gcpFlags) from(aws *awsFlags, baseline string) {
	g.types, g.parallel, g.baseline = aws.types, aws.parallel, baseline
}

func (g *gcpFlags) connect(ctx context.Context, readOnly bool) (*gcp.Adapter, error) {
	api, err := gcp.NewSDK(ctx, g.project, readOnly)
	if err != nil {
		return nil, err
	}
	var docs *gcp.Docs
	if g.discovery != "" {
		docs = gcp.LoadDocs(g.discovery)
	} else {
		cache, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		docs = gcp.FetchDocs(filepath.Join(cache, "stackdna", "gcp"), 24*time.Hour)
	}
	p := gcp.Policy{Parallel: g.parallel}
	for _, t := range strings.Split(g.types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			p.Types = append(p.Types, t)
		}
	}
	for _, dir := range strings.Split(g.baseline, ",") {
		if dir = strings.TrimSpace(dir); dir == "" {
			continue
		}
		b, err := snapshot.Read(dir)
		if err != nil {
			return nil, fmt.Errorf("baseline %s: %w", dir, err)
		}
		d, err := snapshot.Digest(dir)
		if err != nil {
			return nil, err
		}
		p = p.WithBaseline(b, d)
	}
	return &gcp.Adapter{API: api, Docs: docs, Policy: p}, nil
}

func captureGCP(ctx context.Context, g *gcpFlags, out string) int {
	ad, err := g.connect(ctx, true)
	if err != nil {
		return fail(err)
	}
	snap, err := ad.Capture(ctx)
	if err != nil {
		return fail(err)
	}
	if err := snap.Write(out); err != nil {
		return fail(err)
	}
	d, _ := snapshot.Digest(out)
	read, notCaptured, _ := summarize(snap)
	fmt.Printf("captured %d resources across %d types into %s (%s)\n", len(snap.Objects), read, out, d)
	var skips, unreadable []snapshot.Skip
	for _, s := range snap.Skips {
		if strings.HasPrefix(s.Reason, gcp.Unreadable) {
			unreadable = append(unreadable, s)
		} else {
			skips = append(skips, s)
		}
	}
	fmt.Printf("%d types not captured, %d skipped resources; see %s/coverage.yaml\n", notCaptured, len(skips), out)
	for _, r := range topReasons(skips, 8) {
		fmt.Println("  skipped:", r)
	}
	fmt.Println("NOTE: configuration only. Data (objects, tables, messages) and secrets are NOT in this snapshot")
	if len(unreadable) == 0 {
		return 0
	}
	fmt.Println("INCOMPLETE: these resources were listed but could not be read:")
	for _, s := range unreadable {
		fmt.Printf("   %s %s: %s\n", s.Resource, s.Name, strings.TrimPrefix(s.Reason, gcp.Unreadable))
	}
	return 3
}

func restoreGCP(ctx context.Context, g *gcpFlags, snap snapshot.Snapshot) int {
	ad, err := g.connect(ctx, captureOnly)
	if err != nil {
		return fail(err)
	}
	results := ad.Restore(ctx, snap)
	ok := 0
	for _, r := range results {
		if r.OK {
			ok++
			continue
		}
		fmt.Printf("NOT APPLIED %s: %s\n", r.Key, r.Detail)
	}
	fmt.Printf("applied %d of %d resources to project %s\n", ok, len(results), g.project)
	if ok != len(results) {
		return 3
	}
	return 0
}

func diffGCP(ctx context.Context, g *gcpFlags, want snapshot.Snapshot, from string) int {
	ad, err := g.connect(ctx, true)
	if err != nil {
		return fail(err)
	}
	if ad.Policy.Name() != want.Policy {
		return fail(fmt.Errorf("snapshot was captured with policy %q but this diff would use %q; pass the same --types and --baseline", want.Policy, ad.Policy.Name()))
	}
	got, err := ad.Capture(ctx)
	if err != nil {
		return fail(err)
	}
	return report(snapshot.Compare(want, got), from, "gcp "+g.project)
}
