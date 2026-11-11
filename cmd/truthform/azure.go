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

	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/snapshot"
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
			reg, err = azarm.FetchDefinitions(filepath.Join(cache, "truthform", "azure"), 24*time.Hour)
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
	if later, _ := azarm.KeptOnceAzureMakesIt(snap); len(later) > 0 {
		fmt.Printf("CHECK: %d resources Azure makes itself are kept only once it has (their retention, plan and custom columns); see %s/REPORT.md\n", len(later), out)
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
	vals, err := readValues(valuesFile, snap, names)
	if err != nil {
		return fail(err)
	}
	ad.Options.Values = vals
	warnSizes(ctx, ad.API, snap, ad.Options.Values)
	warnHeld(ctx, ad.API, snap)
	results := ad.Restore(ctx, snap)
	if jsonOut {
		defer emitRestore(results, "azure "+a.subscription)
	}
	ok, notSent, pending := 0, 0, 0
	var partial []string
	for _, r := range results {
		if !r.OK {
			fmt.Printf("NOT APPLIED %s: %s\n", r.Key, r.Detail)
			continue
		}
		ok++
		if strings.HasPrefix(r.Detail, azarm.NotSent) {
			fmt.Printf("NOT SENT %s: %s\n", r.Key, strings.TrimPrefix(r.Detail, azarm.NotSent))
			notSent++
			if azarm.Pending(r.Detail) {
				pending++
			}
		}
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
	// Counted as applied, since Azure makes them; said, so applied is not read
	// as sent. One whose settings wait for Azure leaves the restore unfinished.
	if notSent > 0 {
		fmt.Printf("of those, %d not sent (NOT SENT above): Azure makes them\n", notSent)
	}
	if pending > 0 {
		fmt.Printf("not finished: %d wait for Azure to make them, and their settings are not kept until then; run the restore again with --update once data has arrived\n", pending)
	}
	if len(heldBack) > 0 {
		fmt.Printf("left out %d (--leave-out): %s\n", len(heldBack), strings.Join(heldBack, ", "))
	}
	if ok != len(results) || pending > 0 {
		return 3
	}
	return 0
}

// readValues reads a --values file, written with the snapshot's names before
// --rename as --leave-out is, and gives it the names the snapshot has now. A
// key that matches nothing is refused: it was ignored, and the restore said
// "created" with the snapshot's value (re-review of #73). What --leave-out
// holds back is not in the snapshot by now, and a value for it is not a
// mistake; a held-back resource group is written Kind//name there and
// Kind/name here (third review of #73).
func readValues(file string, snap snapshot.Snapshot, names map[string]string) (map[string]map[string]any, error) {
	if file == "" {
		return nil, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var vals map[string]map[string]any
	if err := yaml.Unmarshal(b, &vals); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	held := map[string]bool{}
	for _, k := range heldBack {
		held[strings.Replace(k, "Microsoft.Resources/resourceGroups//", "Microsoft.Resources/resourceGroups/", 1)] = true
	}
	check := map[string]map[string]any{}
	for k, v := range vals {
		if !held[k] {
			check[k] = v
		}
	}
	if bad := azarm.UnmatchedValues(snap, azarm.RenameValues(check, names)); len(bad) > 0 {
		return nil, fmt.Errorf("--values: nothing in the snapshot has %s (keys are Kind/resourceGroup/name, as the snapshot spells them); nothing was restored", strings.Join(bad, ", "))
	}
	return azarm.RenameValues(vals, names), nil
}

func diffAzure(ctx context.Context, a *azureFlags, want snapshot.Snapshot, from string, vals map[string]map[string]any) int {
	ad, err := a.connect(true)
	if err != nil {
		return fail(err)
	}
	// What --values sets is what a restore sent, so it is compared too:
	// without it, every value a restore was given read as drift.
	if len(vals) > 0 {
		tenant, err := ad.API.Tenant(ctx)
		if err != nil {
			return fail(err)
		}
		want = azarm.WithValues(want, vals, ad.API.Subscription(), tenant)
	}
	if ad.Policy.Name() != want.Policy {
		return fail(fmt.Errorf("snapshot was captured with policy %q but this diff would use %q; pass the same --types, --baseline and --capture-managed", want.Policy, ad.Policy.Name()))
	}
	warnSizes(ctx, ad.API, want, vals)
	warnHeld(ctx, ad.API, want)
	got, err := ad.Capture(ctx)
	if err != nil {
		return fail(err)
	}
	return report(compareTarget("azure", want, got), from, "azure "+a.subscription)
}

// compareTarget compares a snapshot with a capture of its target now. An Azure
// snapshot is first made as this version captures: one from before a fix held
// what the fix took out, and every diff and nightly showed it as drift.
func compareTarget(platform string, want, got snapshot.Snapshot) []snapshot.Change {
	if platform == "azure" {
		want = azarm.AsCapturedNow(want)
		want, got = azarm.ForCompare(want, got)
	}
	return snapshot.Compare(want, got)
}

// warnHeld says, before a restore or with a diff, which of the snapshot's
// names a deleted resource holds in the target, and how to free each: a drill
// lost a run to two SQL servers held this way.
func warnHeld(ctx context.Context, api azarm.ARM, s snapshot.Snapshot) {
	held, unread := azarm.NamesHeld(ctx, api, s)
	namesHeld = &heldJSON{Held: append([]string{}, held...), Unread: append([]string{}, unread...)}
	if len(held) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %d names are held by deleted resources, and Azure will refuse them:\n", len(held))
		for _, x := range held {
			fmt.Fprintln(os.Stderr, "  ", x)
		}
	}
	for _, x := range unread {
		fmt.Fprintln(os.Stderr, "NOTE: could not read the deleted resources at", x)
	}
	if azarm.HeldElsewhere(s) {
		fmt.Fprintln(os.Stderr, "NOTE: names held: only deleted resources in this subscription are seen; a deleted key vault, API Management service, App Configuration store or Cognitive Services account in another subscription holds its name too")
		namesHeld.OnlyThisSubscription = true
	}
}

// warnSizes says, before a restore or with a diff, which VM sizes the target
// cannot have, with the restore's --values applied, what it could not check,
// and how much it did: silence is not read as all clear.
func warnSizes(ctx context.Context, api azarm.ARM, s snapshot.Snapshot, values map[string]map[string]any) {
	c := azarm.SizesRefused(ctx, api, s, values)
	sizeCheck = &c
	if len(c.Refused) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %d VM sizes this subscription cannot have:\n", len(c.Refused))
		for _, x := range c.Refused {
			fmt.Fprintln(os.Stderr, "  ", x)
		}
	}
	if len(c.NotChecked) > 0 {
		fmt.Fprintf(os.Stderr, "NOTE: %d VM sizes were not checked:\n", len(c.NotChecked))
		for _, x := range c.NotChecked {
			fmt.Fprintln(os.Stderr, "  ", x)
		}
	}
	fmt.Fprintf(os.Stderr, "VM sizes: checked %d in %d regions\n", c.Sizes, c.Regions)
}
