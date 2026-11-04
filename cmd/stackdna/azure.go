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

	"github.com/stackdna/core/internal/azarm"
	"github.com/stackdna/core/internal/snapshot"
)

// azureFlags are the Azure forms of capture, restore and diff. --types,
// --capture-managed and --parallel are shared with AWS and read from there.
type azureFlags struct {
	subscription, definitions string
	types, baseline           string
	managed                   bool
	parallel                  int
}

func (a *azureFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&a.subscription, "subscription", "", "Azure subscription ID (required for --platform azure)")
	fs.StringVar(&a.definitions, "definitions", "", "Azure type definitions directory, laid out as bicep-types-az generated/ (default: Azure's published copy, cached for a day)")
}

func (a *azureFlags) from(aws *awsFlags, baseline string) {
	a.types, a.managed, a.parallel, a.baseline = aws.types, aws.managed, aws.parallel, baseline
}

// azureAPI connects to a subscription; a test puts a fake in its place.
var azureAPI = func(subscription string, readOnly bool) (azarm.ARM, error) {
	return azarm.NewSDK(subscription, readOnly)
}

func (a *azureFlags) connect(readOnly bool) (*azarm.Adapter, error) {
	api, err := azureAPI(a.subscription, readOnly)
	if err != nil {
		return nil, err
	}
	var reg *azarm.Registry
	if a.definitions != "" {
		reg, err = azarm.LoadDefinitions(a.definitions)
	} else {
		var cache string
		if cache, err = os.UserCacheDir(); err == nil {
			reg, err = azarm.FetchDefinitions(filepath.Join(cache, "stackdna", "azure"), 24*time.Hour)
		}
	}
	if err != nil {
		return nil, err
	}
	p := azarm.Policy{CaptureManaged: a.managed, Parallel: a.parallel}
	for _, t := range strings.Split(a.types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			p.Types = append(p.Types, t)
		}
	}
	for _, dir := range strings.Split(a.baseline, ",") {
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
	return &azarm.Adapter{API: api, Registry: reg, Policy: p}, nil
}

func captureAzure(ctx context.Context, a *azureFlags, out string) int {
	ad, err := a.connect(true)
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
	emitCapture(out, snap, "azure "+a.subscription)
	if err := writeReport(out, snap, "azure "+a.subscription); err != nil {
		return fail(err)
	}
	d, _ := snapshot.Digest(out)
	read, notCaptured, _ := summarize(snap)
	fmt.Printf("captured %d resources across %d types into %s (%s)\n", len(snap.Objects), read, out, d)
	var skips, unreadable []snapshot.Skip
	for _, s := range snap.Skips {
		if strings.HasPrefix(s.Reason, azarm.Unreadable) {
			unreadable = append(unreadable, s)
		} else {
			skips = append(skips, s)
		}
	}
	fmt.Printf("%d types not captured, %d skipped resources; see %s/coverage.yaml\n", notCaptured, len(skips), out)
	if line := checkLine(skips, out); line != "" {
		fmt.Println(line)
	}
	for _, r := range topReasons(skips, 8) {
		fmt.Println("  skipped:", r)
	}
	var noVersion []string
	for _, c := range snap.Coverage {
		if strings.Contains(c.NotCaptured, "no API version") {
			noVersion = append(noVersion, c.Resource)
		}
	}
	sort.Strings(noVersion)
	fmt.Println("NOTE: configuration only. Data (blobs, databases) and secrets (passwords, keys) are NOT in this snapshot")
	if len(noVersion) == 0 && len(unreadable) == 0 {
		return 0
	}
	if len(noVersion) > 0 {
		fmt.Println("INCOMPLETE: no published definition matches an API version these types offer; their resources are NOT in the snapshot:")
		for _, t := range noVersion {
			fmt.Println("  ", t)
		}
	}
	if len(unreadable) > 0 {
		fmt.Println("INCOMPLETE: these resources were listed but could not be read:")
		for _, s := range unreadable {
			fmt.Printf("   %s %s: %s\n", s.Resource, s.Name, strings.TrimPrefix(s.Reason, azarm.Unreadable))
		}
	}
	return 3
}

func checkLine(skips []snapshot.Skip, out string) string {
	check := 0
	for _, s := range skips {
		if azarm.MayNotComeBack(s.Reason) {
			check++
		}
	}
	if check == 0 {
		return ""
	}
	return fmt.Sprintf("CHECK: %d skipped resources may not come back on a restore; see %s/REPORT.md", check, out)
}

// restoreAzure reads secrets from a file the operator controls; they go to
// Azure and nowhere else.
func restoreAzure(ctx context.Context, a *azureFlags, snap snapshot.Snapshot, valuesFile string, update bool, names map[string]string) int {
	ad, err := a.connect(captureOnly)
	if err != nil {
		return fail(err)
	}
	ad.Options.Update = update
	if bad := azarm.UnmatchedTypes(snap, ad.Policy.Types); len(bad) > 0 {
		return fail(fmt.Errorf("--types: nothing in the snapshot matches %s; nothing was restored", strings.Join(bad, ", ")))
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
	// The values file is written with the snapshot's names.
	ad.Options.Values = azarm.RenameValues(ad.Options.Values, names)
	results := ad.Restore(ctx, snap)
	if jsonOut {
		defer emitRestore(results, "azure "+a.subscription)
	}
	ok := 0
	var partial []string
	for _, r := range results {
		if !r.OK {
			fmt.Printf("NOT APPLIED %s: %s\n", r.Key, r.Detail)
			continue
		}
		ok++
		// An update changed something live; each one is said.
		if strings.HasPrefix(r.Detail, "updated") {
			fmt.Printf("UPDATED %s: %s\n", r.Key, r.Detail)
		}
		if i := strings.Index(r.Detail, "; secret, not supplied: "); i >= 0 {
			partial = append(partial, r.Key+": "+r.Detail[i+2:])
		}
	}
	// A VM restored without its password is configured but unusable: said
	// on every run, never folded into a success.
	if len(partial) > 0 {
		sort.Strings(partial)
		fmt.Printf("%d created without secrets (pass --values to supply them):\n", len(partial))
		for _, p := range partial {
			fmt.Println("  ", p)
		}
	}
	fmt.Printf("applied %d of %d resources to subscription %s\n", ok, len(results), a.subscription)
	if len(heldBack) > 0 {
		fmt.Printf("left out %d (--leave-out): %s\n", len(heldBack), strings.Join(heldBack, ", "))
	}
	if ok != len(results) {
		return 3
	}
	return 0
}

func diffAzure(ctx context.Context, a *azureFlags, want snapshot.Snapshot, from string) int {
	ad, err := a.connect(true)
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
	return report(snapshot.Compare(want, got), from, "azure "+a.subscription)
}
