package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/stackdna/core/internal/awscc"
	"github.com/stackdna/core/internal/snapshot"
)

// awsFlags are shared by the AWS forms of capture, restore and diff.
type awsFlags struct {
	region, profile, types, schemas, baseline string
	managed                                   bool
}

func (a *awsFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&a.region, "region", "", "AWS region (required for --platform aws)")
	fs.StringVar(&a.profile, "profile", "", "AWS shared-config profile (default: the standard credential chain)")
	fs.StringVar(&a.types, "types", "", "comma-separated type patterns, e.g. 'AWS::S3::*,AWS::IAM::Role' (default: every type)")
	fs.StringVar(&a.schemas, "schemas", "", "registry schema bundle (.zip) or directory (default: AWS's public bundle, cached for a day)")
	fs.BoolVar(&a.managed, "capture-managed", false, "also capture resources a CloudFormation stack or an AWS service owns")
}

func (a *awsFlags) registry() (*awscc.Registry, error) {
	switch {
	case strings.HasSuffix(a.schemas, ".zip"):
		return awscc.ReadBundle(a.schemas)
	case a.schemas != "":
		return awscc.ReadDir(a.schemas)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	return awscc.LoadBundle(a.region, filepath.Join(cache, "stackdna", "aws"), 24*time.Hour)
}

func (a *awsFlags) policy() (awscc.Policy, error) {
	p := awscc.Policy{CaptureManaged: a.managed}
	for _, t := range strings.Split(a.types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			p.Types = append(p.Types, t)
		}
	}
	// Comma-separated: one baseline per region involved, in a fixed order,
	// because the order is part of the policy name diff compares.
	for _, dir := range strings.Split(a.baseline, ",") {
		if dir = strings.TrimSpace(dir); dir == "" {
			continue
		}
		b, err := snapshot.Read(dir)
		if err != nil {
			return p, fmt.Errorf("baseline %s: %w", dir, err)
		}
		d, err := snapshot.Digest(dir)
		if err != nil {
			return p, fmt.Errorf("baseline %s: %w", dir, err)
		}
		p = p.WithBaseline(b, d)
	}
	return p, nil
}

func (a *awsFlags) connect(ctx context.Context) (*awscc.Adapter, error) {
	if a.region == "" {
		return nil, fmt.Errorf("--region is required for --platform aws (a capture is one account and region)")
	}
	reg, err := a.registry()
	if err != nil {
		return nil, err
	}
	api, err := awscc.NewSDK(ctx, a.profile, a.region)
	if err != nil {
		return nil, err
	}
	pol, err := a.policy()
	if err != nil {
		return nil, err
	}
	return &awscc.Adapter{API: api, Registry: reg, Region: a.region, Policy: pol}, nil
}

func captureAWS(ctx context.Context, a *awsFlags, out string) int {
	ad, err := a.connect(ctx)
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
	read, notCaptured, failed := summarize(snap)
	fmt.Printf("captured %d resources across %d types into %s (%s)\n", len(snap.Objects), read, out, d)
	fmt.Printf("%d types not captured by design, %d skipped resources; see %s/coverage.yaml\n", notCaptured, len(snap.Skips), out)
	for _, r := range topReasons(snap.Skips, 8) {
		fmt.Println("  skipped:", r)
	}
	// Said on every capture, because a restore that recreates a bucket or a
	// queue empty looks exactly like one that recreated its contents.
	fmt.Println("NOTE: configuration only. Data (S3 objects, queue messages, table rows) and write-only values (Lambda code, secret values) are NOT in this snapshot")
	if len(failed) > 0 {
		fmt.Println("INCOMPLETE: these types could not be read and are NOT in the snapshot:")
		for _, f := range failed {
			fmt.Println("  ", f)
		}
		return 3
	}
	return 0
}

// restoreAWS reads write-only values from a file the operator controls; they
// go to AWS and nowhere else.
func restoreAWS(ctx context.Context, a *awsFlags, snap snapshot.Snapshot, valuesFile string) int {
	ad, err := a.connect(ctx)
	if err != nil {
		return fail(err)
	}
	if valuesFile != "" {
		b, err := os.ReadFile(valuesFile)
		if err != nil {
			return fail(err)
		}
		if err := yaml.Unmarshal(b, &ad.Options.Values); err != nil {
			return fail(fmt.Errorf("%s: %w", valuesFile, err))
		}
	}
	results := ad.Restore(ctx, snap)
	ok := 0
	var partial []string
	for _, r := range results {
		if !r.OK {
			fmt.Printf("NOT APPLIED %s: %s\n", r.Key, r.Detail)
			continue
		}
		ok++
		if i := strings.Index(r.Detail, "; write-only, not supplied: "); i >= 0 {
			partial = append(partial, r.Key+": "+r.Detail[i+2:])
		}
	}
	// Created without values only the operator could have supplied: a
	// secret with no value is configured but does nothing, so it is listed
	// on every run rather than hidden in a success.
	if len(partial) > 0 {
		sort.Strings(partial)
		fmt.Printf("%d created without write-only values (pass --values to supply them):\n", len(partial))
		for _, p := range partial {
			fmt.Println("  ", p)
		}
	}
	fmt.Printf("applied %d of %d resources to aws %s\n", ok, len(results), a.region)
	if ok != len(results) {
		return 3
	}
	return 0
}

func diffAWS(ctx context.Context, a *awsFlags, want snapshot.Snapshot, from string) int {
	ad, err := a.connect(ctx)
	if err != nil {
		return fail(err)
	}
	if ad.Policy.Name() != want.Policy {
		return fail(fmt.Errorf("snapshot was captured with policy %q but this diff would use %q; pass the same --types, --baseline and --capture-managed", want.Policy, ad.Policy.Name()))
	}
	got, err := ad.Capture(ctx)
	if err != nil {
		return fail(err)
	}
	return report(snapshot.Compare(want, got), from, "aws "+a.region)
}

// awsCoverage reports, offline, what the registry lets StackDNA capture and
// restore. It reads only the public schema bundle: no account is touched.
func awsCoverage(args []string) int {
	fs := flag.NewFlagSet("aws-coverage", flag.ExitOnError)
	var a awsFlags
	fs.StringVar(&a.region, "region", "us-east-1", "region whose bundle to read")
	fs.StringVar(&a.schemas, "schemas", "", "schema bundle (.zip) or directory instead of downloading")
	_ = fs.Parse(args)
	reg, err := a.registry()
	if err != nil {
		return fail(err)
	}
	var total, legacy, noList, direct, enumerated, parented, noParent, restorable, writeOnly int
	for _, t := range reg.Types {
		total++
		switch {
		case len(t.Handlers) == 0:
			legacy++
			continue
		case !t.Capturable():
			noList++
			continue
		}
		if plan, reason := reg.Plan(t); len(t.ListRequires) == 0 {
			direct++
		} else if reason == "" && plan.ParentType == "" {
			enumerated++
		} else if reason == "" {
			parented++
		} else {
			// Capture reports these in coverage; they are not counted as
			// capturable here either, so the two never disagree.
			noParent++
			continue
		}
		if t.Handlers["create"] {
			restorable++
		}
		if len(t.WriteOnly) > 0 {
			writeOnly++
		}
	}
	pct := func(n int) string { return fmt.Sprintf("%d (%.0f%%)", n, 100*float64(n)/float64(total)) }
	fmt.Printf("AWS registry %s: %d types\n", reg.Digest, total)
	fmt.Printf("  capturable:            %s\n", pct(direct+enumerated+parented))
	fmt.Printf("    listed directly:     %d\n", direct)
	fmt.Printf("    listed per enum:     %d (values from the schema, e.g. WAFv2 Scope)\n", enumerated)
	fmt.Printf("    listed per parent:   %d (parent derived from the schemas)\n", parented)
	fmt.Printf("  not capturable:\n")
	fmt.Printf("    parent not derivable: %d\n", noParent)
	fmt.Printf("    no list/read handler: %d\n", noList)
	fmt.Printf("    legacy, no handlers:  %d\n", legacy)
	fmt.Printf("  capturable and creatable: %s\n", pct(restorable))
	fmt.Printf("  with write-only properties (restore needs --values or notes them): %d\n", writeOnly)
	return 0
}
