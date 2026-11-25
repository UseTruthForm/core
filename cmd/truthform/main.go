// Command truthform captures what is running into a snapshot that can recreate
// it, restores snapshots, and diffs them against live systems.
//
// Exit codes are part of the interface, so scripts and CI can tell outcomes
// apart:
//
//	0  success (capture complete, restore fully applied, no differences)
//	1  error (bad flags, cannot connect, cannot read a snapshot)
//	2  differences found (diff, compare)
//	3  incomplete: the snapshot was written but some types could not be
//	   read, or a restore applied only some objects
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/snapshot"
)

const usage = `truthform: capture what is running so it can be recreated.

Kubernetes:
  truthform capture --context <kube-context> --out <dir> [--include-system] [--baseline <dir>]
  truthform restore --context <kube-context> --from <dir> [--secrets-from <file>] [--secrets-from-context <kube-context>]
      [--leave-out <file>] [--rename <file>]   into another environment: objects to hold back, and where its secret stores are
      [--scope <file>]                         a part only (truthform plan scope writes the file)
  truthform diff    --context <kube-context> --from <dir> [--baseline <dir>] [--scope <file>] [--leave-out <file>] [--rename <file>]

AWS (Cloud Control, every type in the CloudFormation registry):
  truthform capture --platform aws --region <r> [--profile <p>] --out <dir> [--types <patterns>] [--baseline <dir>]
  truthform restore --platform aws --region <r> [--profile <p>] --from <dir> [--values <file>] [--update] [--dry-run]
  truthform diff    --platform aws --region <r> [--profile <p>] --from <dir> [--types <patterns>] [--baseline <dir>]
  truthform aws-coverage [--schemas <bundle.zip>]

Azure (ARM, every type with a published definition):
  truthform capture --platform azure --subscription <id> --out <dir> [--types <patterns>] [--baseline <dir>]
  truthform restore --platform azure --subscription <id> --from <dir> [--values <file>] [--update]
  truthform diff    --platform azure --subscription <id> --from <dir> [--types <patterns>] [--baseline <dir>]

GCP (Cloud Asset Inventory and each API's Discovery document):
  truthform capture --platform gcp --project <id> --out <dir> [--types <patterns>] [--baseline <dir>]
  truthform restore --platform gcp --project <id> --from <dir> [--update] [--dry-run]
  truthform diff    --platform gcp --project <id> --from <dir> [--types <patterns>] [--baseline <dir>]

SaaS (OpenAPI descriptions; token from GITHUB_TOKEN / CLOUDFLARE_API_TOKEN, or Cloudflare's sign-in):
  truthform login cloudflare [--no-browser]     sign in once in a browser; kept in the OS keychain
  truthform logout cloudflare
  truthform capture --platform github --account <org> --out <dir>
  truthform capture --platform cloudflare --account <account-id> --out <dir>
  truthform restore --platform github --account <org> --from <dir> [--values <file>] [--update] [--dry-run]
  truthform restore --platform cloudflare --account <account-id> --from <dir> [--update] [--dry-run]
      [--subdomain test.example.com [--address <source-ip>=<target-ip>,...] [--target <source-host>=<target-host>,...]]
      the zone's records one level down (www.example.com -> www.test.example.com), marked as TruthForm's;
      checks the zone first and stops on any conflict, before it writes
  truthform diff    --platform cloudflare --account <account-id> --from <dir> [--subdomain test.example.com [--address ...] [--target ...]]

Machine-readable: add --json to capture, diff, restore, compare, check, permissions, plan or translate; stdout is then
one JSON document (everything else goes to stderr) and the exit code is unchanged.

Access (what to grant, and what a grant can read):
  truthform permissions --platform <p> [--access capture|restore] <the platform's values> [--write <dir>]
      the template to deploy and every command to grant, verify and remove it; grants nothing itself
  truthform check --platform <p> <the target, as for capture> [--types <patterns>] [--access capture|restore]
      who TruthForm runs as, what it holds beyond what it needs, and what it can read, type by type

As a graph (resources and their relationships, for an asset inventory or a security graph):
  truthform graph --from <dir> [--types security|none|<file>] [--subscription <id>] [--tenant <id>] [--out <file>]
      Azure; JSON nodes and edges from the snapshot alone, no request made

To another cloud (offline: a snapshot and a map in, snapshots and a report out; exit 3 when anything is refused or less protected):
  truthform translate --from <azure-snapshot> --map <file> --out <dir> [--schemas <bundle.zip|dir>] [--discovery <dir>]
                      [--kube <kubernetes-snapshot>] [--gitops <checkout of the repository Flux reads>]
      writes <dir>/aws/, <dir>/gcp/ or <dir>/kubernetes/ for restore, and <dir>/translation.yaml, every object's losses
      --kube, --gitops: also lists what the cluster's workloads name that was renamed, by file and line (nothing in Git is changed)
      beta: no translated snapshot has been restored into a real account or project yet; run restore --dry-run on what it writes first

Before a rebuild (what the snapshot does not hold: what to install first, the secrets, the names):
  truthform plan rebuild --from <dir> [--scope <file>] [--leave-out <file>] [--out <file>] [--json]
  truthform plan scope --from <dir> [--out <file> | --check <file> [--json]]
  truthform plan secrets --from <dir> [--out <file> | --check <file> [--resolve] [--allow-exec] [--json]]
      Kubernetes; Markdown, or one JSON document; from the snapshot alone, no request made

For agents (MCP on stdin/stdout; every tool read-only, no restore tool):
  truthform mcp
  truthform skills [<name> | --out <dir>]
      the skills for what a translation leaves to people (data, access, machines, a TLS floor, flow logs, cost):
      lists them, prints one, or writes each as <dir>/<name>/SKILL.md; the MCP server serves the same text

A whole environment (several targets, read-only):
  truthform capture --config <env.yaml> --out <dir>
  truthform diff    --config <env.yaml> --from <dir>

Any platform:
  truthform compare <dir-a> <dir-b>
  truthform schema-diff <old-dir> <new-dir>
  truthform report <dir>        (re)write REPORT.md for a snapshot
  truthform version             which build this is (version, commit, edition)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	ctx := context.Background()
	var code int
	args, asJSON := takeJSONFlag(os.Args[2:])
	command = os.Args[1]
	if asJSON {
		jsonOut, jsonDst, os.Stdout = true, os.Stdout, os.Stderr
		// A command with no document of its own refuses --json rather than
		// run quietly: "mcp --json" served the protocol on stderr and
		// "version --json" printed nothing (review of #21).
		if !jsonCommands[command] {
			code := fail(fmt.Errorf("--json is supported by capture, diff, restore, compare, check, permissions, plan and translate, not %s", command))
			emitError(code)
			os.Exit(code)
		}
		// Every run ends with one document: an error (a missing snapshot, a
		// refused login, a bad flag) gave none, and "| jq .differences"
		// printed nothing and exited 0, which reads as all clear.
	}
	switch os.Args[1] {
	case "capture":
		code = capture(ctx, args)
	case "restore":
		if captureOnly {
			fmt.Fprintln(os.Stderr, "truthform: this is a capture-only build; restore is disabled and every request is read-only")
			code = 1
			break
		}
		code = restore(ctx, args)
	case "diff":
		code = diff(ctx, args)
	case "compare":
		code = compare(args)
	case "schema-diff":
		code = schemaDiff(args)
	case "aws-coverage":
		code = awsCoverage(args)
	case "translate":
		code = translateCmd(args)
	case "report":
		code = reportCmd(args)
	case "graph":
		code = graphCmd(args)
	case "plan":
		code = planCmd(args)
	case "mcp":
		code = mcpCmd(ctx, args)
	case "skills":
		code = skillsCmd(args)
	case "check":
		code = checkCmd(ctx, args)
	case "permissions":
		code = permissionsCmd(args)
	case "login":
		code = loginCmd(ctx, args)
	case "logout":
		code = logoutCmd(args)
	case "version", "--version", "-version":
		fmt.Println(versionString())
	default:
		fmt.Fprint(os.Stderr, usage)
		code = 1
	}
	if jsonOut && !emitted {
		emitError(code)
	}
	os.Exit(code)
}

func capture(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: standard loading rules)")
	kctx := fs.String("context", "", "kubeconfig context to capture")
	out := fs.String("out", "", "snapshot directory to write")
	includeSystem := fs.Bool("include-system", false, "also capture system namespaces and platform-created objects")
	baseline := fs.String("baseline", "", "snapshot of a fresh cluster of the same distribution; objects identical to it are skipped")
	keepPlatform := fs.Bool("capture-platform", false, "kubernetes: also capture what is only taken to be AKS's, by Eno's mark and an AKS name, group or key (skipped by default, and each listed in REPORT.md)")
	rendered := fs.Bool("capture-rendered", false, "also capture objects rendered by Flux, Argo CD or Crossplane (skipped by default: restoring their source recreates them)")
	platform := fs.String("platform", "kubernetes", "kubernetes, aws, azure, gcp, github or cloudflare")
	config := fs.String("config", "", "environment file listing several targets; captures all of them into --out/<target>")
	var aws awsFlags
	aws.register(fs)
	var az azureFlags
	az.register(fs)
	var g gcpFlags
	g.register(fs)
	var sf saasFlags
	sf.register(fs)
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if *out == "" || fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "capture: --out is required and no positional arguments are accepted")
		return 1
	}
	if *config != "" {
		return captureEnvironment(ctx, *config, *out)
	}
	switch *platform {
	case "aws":
		aws.baseline = *baseline
		return captureAWS(ctx, &aws, *out)
	case "azure":
		az.from(&aws, *baseline)
		return captureAzure(ctx, &az, *out)
	case "gcp":
		g.from(&aws, *baseline)
		return captureGCP(ctx, &g, *out)
	case "github", "cloudflare":
		return captureSaaS(ctx, *platform, &sf, *out)
	}
	c, err := kube.Connect(*kubeconfig, *kctx, true)
	if err != nil {
		return fail(err)
	}
	pol := kube.Policy{IncludeSystem: *includeSystem, CaptureRendered: *rendered, CapturePlatform: *keepPlatform}
	if *baseline != "" {
		if pol, err = withBaseline(pol, *baseline); err != nil {
			return fail(err)
		}
	}
	snap, err := kube.Capture(ctx, c, pol)
	if err != nil {
		return fail(err)
	}
	if err := snap.Write(*out); err != nil {
		return fail(err)
	}
	emitCapture(*out, snap, *kctx)
	if err := writeReport(*out, snap, *kctx); err != nil {
		return fail(err)
	}
	d, _ := snapshot.Digest(*out)
	read, notCaptured, failed := summarize(snap)
	fmt.Printf("captured %d objects across %d types into %s (%s)\n", len(snap.Objects), read, *out, d)
	fmt.Printf("%d types not captured by design, %d skipped objects; see %s/coverage.yaml\n", notCaptured, len(snap.Skips), *out)
	for _, r := range topReasons(snap.Skips, 8) {
		fmt.Println("  skipped:", r)
	}
	// Said on every capture that has claims, because a restored claim with an
	// empty volume looks exactly like a restored claim with its data.
	if n := countKind(snap, "PersistentVolumeClaim"); n > 0 {
		fmt.Printf("NOTE: %d PersistentVolumeClaims captured as configuration only; the data in their volumes is NOT in this snapshot\n", n)
	}
	if len(failed) > 0 {
		fmt.Println("INCOMPLETE: these types could not be read and are NOT in the snapshot:")
		for _, f := range failed {
			fmt.Println("  ", f)
		}
		return 3
	}
	return 0
}

func restore(ctx context.Context, args []string) int {
	sizeCheck, namesHeld, blockedBy, unscopedHooks, sourcesBlocked = nil, nil, nil, nil, nil
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig")
	kctx := fs.String("context", "", "kubeconfig context to restore into")
	from := fs.String("from", "", "snapshot directory")
	secretsFrom := fs.String("secrets-from-context", "", "live cluster to read withheld secret values from")
	secretSources := fs.String("secrets-from", "", "kubernetes: secret sources file (truthform plan secrets) saying where each withheld value is read from; read, sent to the cluster, never written")
	allowExec := fs.Bool("allow-exec", false, allowExecHelp)
	platform := fs.String("platform", "kubernetes", "kubernetes, aws, azure, gcp, github or cloudflare")
	update := fs.Bool("update", false, "aws, azure, gcp, github, cloudflare: also bring existing resources that differ in line with the snapshot (never replaces one); without it, restore only creates what is missing. Kubernetes restore always applies (server-side apply)")
	values := fs.String("values", "", "aws, azure, github, cloudflare: YAML file of values the platform never returns (Lambda code, secrets, VM passwords), keyed 'Kind/name' (AWS) or 'Kind/resourceGroup/name' (Azure); read, sent to the platform, never written. Refused elsewhere")
	rename := fs.String("rename", "", renameHelp)
	keepStores := fs.Bool("keep-source-stores", false, "kubernetes, with --rename: restore though a use of a secret store that no start fits, or that --rename does not reach, stays as the source's")
	leaveOut := fs.String("leave-out", "", leaveOutHelp)
	scope := fs.String("scope", "", scopeHelp)
	newRoleIDs := fs.Bool("new-role-assignment-ids", false, newRoleIDsHelp)
	dryRun := fs.Bool("dry-run", false, "aws, gcp, github, cloudflare: read the target and print every write the restore would make; make none")
	var aws awsFlags
	aws.register(fs)
	var az azureFlags
	az.register(fs)
	var g gcpFlags
	g.register(fs)
	var sf saasFlags
	sf.register(fs)
	sf.registerSubdomain(fs, true)
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if err := dryRunAccepted(*platform, *dryRun); err != nil {
		return fail(err)
	}
	if err := sf.subdomainAccepted(*platform); err != nil {
		return fail(err)
	}
	if *from == "" || (*kctx == "" && *platform == "kubernetes") {
		fmt.Fprintln(os.Stderr, "restore: --from and a target (--context, --platform aws --region, --platform azure --subscription, or --platform gcp --project) are required (restore never guesses its target)")
		return 1
	}
	snap, err := snapshot.Read(*from)
	if err != nil {
		return fail(err)
	}
	if err := samePlatform(snap, *platform); err != nil {
		return fail(err)
	}
	// --leave-out first: its entries name objects of the snapshot as it
	// is, whether or not the scope would have left them out too.
	whole := snap
	if snap, err = leftOut(*leaveOut, *platform, snap); err != nil {
		return fail(err)
	}
	if snap, err = scopedFrom(*scope, *platform, whole, snap); err != nil {
		return fail(err)
	}
	if *platform == "kubernetes" {
		// Every cause at once: one fixed at a time would be found one
		// run at a time.
		var why []string
		for _, err := range []error{refusedForWebhooks(whole, snap, *scope), refusedForSources(*scope)} {
			if err != nil {
				why = append(why, strings.TrimSuffix(err.Error(), "; nothing was restored"))
			}
		}
		if len(why) > 0 {
			return fail(fmt.Errorf("%s; nothing was restored", strings.Join(why, ". And ")))
		}
	}
	if *keepStores && (*rename == "" || *platform != "kubernetes") {
		return fail(fmt.Errorf("--keep-source-stores is for a kubernetes restore with --rename; nothing was restored"))
	}
	names, snap, err := renamed(*rename, *platform, snap, !*keepStores)
	if err != nil {
		return fail(err)
	}
	if snap, err = withNewRoleIDs(*newRoleIDs, *platform, az.subscription, snap); err != nil {
		return fail(err)
	}
	if err := valuesAccepted(*platform, *values); err != nil {
		return fail(err)
	}
	if *platform != "kubernetes" && (*secretSources != "" || *allowExec) {
		return fail(fmt.Errorf("--secrets-from and --allow-exec are for a kubernetes restore; nothing was restored"))
	}
	if *allowExec && *secretSources == "" {
		return fail(fmt.Errorf("--allow-exec is for --secrets-from; nothing was restored"))
	}
	// A staged --types that restored everything would create, and bill for,
	// what was held back.
	if aws.types != "" && *platform != "azure" {
		return fail(fmt.Errorf("--types is not read by restore on --platform %s; nothing was restored", *platform))
	}
	warnGaps(snap)
	warnOtherSubscriptions(snap, *platform, az.subscription)
	switch *platform {
	case "aws":
		return restoreAWS(ctx, &aws, snap, *values, *update, *dryRun)
	case "azure":
		az.from(&aws, "")
		return restoreAzure(ctx, &az, snap, *values, *update, names)
	case "gcp":
		g.from(&aws, "")
		return restoreGCP(ctx, &g, snap, *update, *dryRun)
	case "github", "cloudflare":
		return restoreSaaS(ctx, *platform, &sf, snap, *values, *update, *dryRun)
	}
	c, err := kube.Connect(*kubeconfig, *kctx, captureOnly)
	if err != nil {
		return fail(err)
	}
	var opt kube.RestoreOptions
	if *secretSources != "" {
		var left []string
		if snap, opt, left, err = withSecretSources(ctx, snap, *secretSources, *allowExec, *secretsFrom != ""); err != nil {
			return fail(err)
		}
		if len(left) > 0 {
			fmt.Printf("left %d Secrets to what makes them (--secrets-from): %s\n", len(left), strings.Join(left, ", "))
		}
	}
	if *secretsFrom != "" {
		if opt.SecretSource, err = kube.Connect(*kubeconfig, *secretsFrom, true); err != nil {
			return fail(err)
		}
	}
	results := kube.Restore(ctx, c, snap, opt)
	if jsonOut {
		defer emitRestore(results, *kctx)
	}
	ok := 0
	for _, r := range results {
		if r.OK {
			ok++
			continue
		}
		fmt.Printf("NOT APPLIED %s: %s\n", r.Key, r.Detail)
	}
	if len(heldBack) > 0 {
		fmt.Printf("left out %d (--leave-out): %s\n", len(heldBack), strings.Join(heldBack, ", "))
	}
	if l := scopeLine(); l != "" {
		fmt.Println(l)
	}
	fmt.Printf("applied %d of %d objects to %s\n", ok, len(results), *kctx)
	code := 0
	if ok != len(results) {
		code = 3
	}
	// A hold that brought what it does not know how to hold is not the
	// hold that was asked for, whatever was applied. Said beside a
	// failure too: 3 alone does not say which.
	if scopeDone != nil && len(scopeDone.NotHeld) > 0 {
		code = 3
		// Not one that was not applied: it was not brought at all.
		failed := map[string]bool{}
		for _, r := range results {
			if p := strings.Split(r.Key, "|"); !r.OK && len(p) == 4 {
				failed[p[1]+" "+p[2]+"/"+p[3]] = true
			}
		}
		var there []string
		for _, o := range scopeDone.NotHeld {
			if !failed[o] {
				there = append(there, o)
			}
		}
		if len(there) > 0 {
			fmt.Printf("%s under hold: true %s brought not held (see the NOTE above): %s\n", count(len(there), "object"), one(len(there), "was", "were"), strings.Join(there, ", "))
		}
	}
	return code
}

func diff(ctx context.Context, args []string) int {
	sizeCheck, namesHeld = nil, nil
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig")
	kctx := fs.String("context", "", "kubeconfig context to compare against")
	from := fs.String("from", "", "snapshot directory")
	baseline := fs.String("baseline", "", "the baseline the snapshot was captured with, if any")
	platform := fs.String("platform", "kubernetes", "kubernetes, aws, azure, gcp, github or cloudflare")
	config := fs.String("config", "", "environment file; diffs every target against --from/<target>")
	rename := fs.String("rename", "", renameHelp)
	leaveOut := fs.String("leave-out", "", leaveOutHelp)
	scope := fs.String("scope", "", scopeHelp)
	values := fs.String("values", "", "azure: the --values file the restore was given; what it sets is compared as it was sent, secrets aside, and a key that matches nothing is refused")
	keepStoresDiff := fs.Bool("keep-source-stores", false, "taken as restore takes it, and changes nothing: a diff lists what --rename leaves as the source's, and never refuses")
	newRoleIDs := fs.Bool("new-role-assignment-ids", false, newRoleIDsHelp)
	var aws awsFlags
	aws.register(fs)
	var az azureFlags
	az.register(fs)
	var g gcpFlags
	g.register(fs)
	var sf saasFlags
	sf.register(fs)
	sf.registerSubdomain(fs, false)
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if err := sf.subdomainAccepted(*platform); err != nil {
		return fail(err)
	}
	if *values != "" && *platform != "azure" {
		return fail(fmt.Errorf("diff: --values is for --platform azure"))
	}
	if *config != "" && *from != "" {
		if *rename != "" || *leaveOut != "" || *values != "" || *scope != "" {
			return fail(fmt.Errorf("diff: --rename, --leave-out, --scope and --values are for a diff against one target, not --config"))
		}
		return diffEnvironment(ctx, *config, *from)
	}
	if *from == "" || (*kctx == "" && *platform == "kubernetes") {
		fmt.Fprintln(os.Stderr, "diff: --from and a target (--context, --platform aws --region, --platform azure --subscription, or --platform gcp --project) are required")
		return 1
	}
	want, err := snapshot.Read(*from)
	if err != nil {
		return fail(err)
	}
	if err := samePlatform(want, *platform); err != nil {
		return fail(err)
	}
	warnGaps(want)
	whole := want
	if want, err = leftOut(*leaveOut, *platform, want); err != nil {
		return fail(err)
	}
	if want, err = scopedFrom(*scope, *platform, whole, want); err != nil {
		return fail(err)
	}
	// Said as a restore says it; a diff writes nothing, and is not
	// refused for it.
	webhookNotesWithoutScope("diff", whole, want)
	_ = *keepStoresDiff // a diff lists and never refuses: the flag is taken so that a restore's arguments can be given to it
	names, want, err := renamed(*rename, *platform, want, false)
	if err != nil {
		return fail(err)
	}
	vals, err := readValues(*values, want, names)
	if err != nil {
		return fail(err)
	}
	warnOtherSubscriptions(want, *platform, az.subscription)
	if want, err = withNewRoleIDs(*newRoleIDs, *platform, az.subscription, want); err != nil {
		return fail(err)
	}
	switch *platform {
	case "aws":
		aws.baseline = *baseline
		return diffAWS(ctx, &aws, want, *from)
	case "azure":
		az.from(&aws, *baseline)
		return diffAzure(ctx, &az, want, *from, vals)
	case "gcp":
		g.from(&aws, *baseline)
		return diffGCP(ctx, &g, want, *from)
	case "github", "cloudflare":
		return diffSaaS(ctx, *platform, &sf, want, *from)
	}
	c, err := kube.Connect(*kubeconfig, *kctx, true)
	if err != nil {
		return fail(err)
	}
	pol := kube.Policy{IncludeSystem: strings.HasPrefix(want.Policy, "include-system"), CaptureRendered: strings.Contains(want.Policy, "+rendered"), CapturePlatform: strings.Contains(want.Policy, "+platform")}
	if *baseline != "" {
		if pol, err = withBaseline(pol, *baseline); err != nil {
			return fail(err)
		}
	}
	// The live side must be filtered exactly as the snapshot was, or the
	// difference in rules shows up as drift.
	if pol.Name() != want.Policy {
		return fail(fmt.Errorf("snapshot was captured with policy %q but this diff would use %q; pass the same --baseline", want.Policy, pol.Name()))
	}
	got, err := kube.Capture(ctx, c, pol)
	if err != nil {
		return fail(err)
	}
	return report(snapshot.Compare(want, got), *from, *kctx)
}

func compare(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "compare: give exactly two snapshot directories")
		return 1
	}
	a, err := snapshot.Read(args[0])
	if err != nil {
		return fail(err)
	}
	b, err := snapshot.Read(args[1])
	if err != nil {
		return fail(err)
	}
	if a.Policy != b.Policy {
		return fail(fmt.Errorf("snapshots use different capture policies (%s vs %s); the difference would be the policy, not drift", a.Policy, b.Policy))
	}
	// Two Azure snapshots from different versions differ on what a fix took
	// out of one: each is made as this version captures.
	if a.Platform == "azure" && b.Platform == "azure" {
		b = azarm.AsCapturedNow(b)
	}
	return report(compareTarget(a.Platform, a, b), args[0], args[1])
}

// schemaDiff shows what each API added or removed between two captures,
// read from the schemas the live APIs published, not from any list in code.
func schemaDiff(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "schema-diff: give the older and the newer snapshot directory")
		return 1
	}
	a, err := snapshot.Read(args[0])
	if err != nil {
		return fail(err)
	}
	b, err := snapshot.Read(args[1])
	if err != nil {
		return fail(err)
	}
	changes := snapshot.CompareSchemas(a, b)
	if len(changes) == 0 {
		fmt.Printf("no schema changes across %d types\n", len(b.Schemas))
		return 0
	}
	for _, c := range changes {
		fmt.Printf("%-13s %s\n", c.Kind, c.Type)
		for _, f := range c.Added {
			fmt.Println("    + " + f)
		}
		for _, f := range c.Removed {
			fmt.Println("    - " + f)
		}
	}
	return 2
}

// skippedNote is what a missing or extra line says of why the other side
// left the object out, where it did. It explains the difference, which is
// still one.
func skippedNote(ch snapshot.Change) string {
	if ch.Skipped == nil {
		return ""
	}
	note := " (left out on the other side: " + ch.Skipped.Reason
	if ch.Skipped.OlderRules {
		note += "; a snapshot from a build before beta.23 left out a self-applying GitOps root and the source it reads from, so this may be one"
	}
	return note + ")"
}

// count is n things, in the singular for one.
func count(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

func report(changes []snapshot.Change, want, got string) int {
	if jsonOut {
		emitDiff(changes, want, got)
	}
	held := ""
	if len(heldBack) > 0 {
		held = fmt.Sprintf(", leaving out %d objects (--leave-out): %s", len(heldBack), strings.Join(heldBack, ", "))
	}
	if l := scopeLine(); l != "" {
		held += "; " + l
	}
	if len(changes) == 0 {
		fmt.Printf("no differences: %s matches %s%s\n", got, want, held)
		return 0
	}
	for _, ch := range changes {
		switch ch.Kind {
		case "changed":
			fmt.Printf("changed  %s: %s\n", ch.Key, strings.Join(ch.Fields, ", "))
		default:
			fmt.Printf("%-8s %s%s\n", ch.Kind, ch.Key, skippedNote(ch))
		}
	}
	fmt.Printf("%s between %s and %s%s\n", count(len(changes), "difference"), want, got, held)
	return 2
}

func summarize(s snapshot.Snapshot) (read, notCaptured int, failed []string) {
	for _, c := range s.Coverage {
		switch {
		case c.NotCaptured == "":
			read++
		case strings.HasPrefix(c.NotCaptured, "list failed") || strings.HasPrefix(c.NotCaptured, "API group discovery failed"):
			failed = append(failed, c.Resource+": "+c.NotCaptured)
		default:
			notCaptured++
		}
	}
	sort.Strings(failed)
	return
}

func topReasons(skips []snapshot.Skip, n int) []string {
	count := map[string]int{}
	for _, s := range skips {
		count[s.Reason]++
	}
	type kv struct {
		r string
		n int
	}
	var all []kv
	for r, c := range count {
		all = append(all, kv{r, c})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].r < all[j].r
	})
	var out []string
	for i, x := range all {
		if i == n {
			break
		}
		out = append(out, fmt.Sprintf("%d x %s", x.n, x.r))
	}
	return out
}

func countKind(s snapshot.Snapshot, kind string) int {
	n := 0
	for _, o := range s.Objects {
		if o.Kind() == kind {
			n++
		}
	}
	return n
}

func withBaseline(p kube.Policy, dir string) (kube.Policy, error) {
	b, err := snapshot.Read(dir)
	if err != nil {
		return p, fmt.Errorf("baseline: %w", err)
	}
	d, err := snapshot.Digest(dir)
	if err != nil {
		return p, fmt.Errorf("baseline: %w", err)
	}
	return p.WithBaseline(b, d), nil
}

// samePlatform refuses to apply a snapshot to a different kind of platform.
// SaaS snapshots record their provider as saas/<name>.
func samePlatformName(snapPlatform, flag string) bool {
	return snapPlatform == flag || snapPlatform == "saas/"+flag
}

const newRoleIDsHelp = "azure: give role assignments new names, the same each time for this subscription. For a target in the source's tenant, where a name is taken while the source exists. Pass it to the diff of that target too"

func withNewRoleIDs(on bool, platform, subscription string, s snapshot.Snapshot) (snapshot.Snapshot, error) {
	if !on {
		return s, nil
	}
	if platform != "azure" {
		return s, fmt.Errorf("--new-role-assignment-ids is for --platform azure only")
	}
	return azarm.NewRoleAssignmentIDs(s, subscription), nil
}

// warnGaps restates what the capture could not read. Only the capture said so,
// so a restore of an incomplete snapshot could report every resource applied,
// and a diff no differences, of a snapshot that does not hold the whole system.
func warnGaps(s snapshot.Snapshot) {
	if g := gaps(s); len(g) > 0 {
		fmt.Printf("INCOMPLETE SNAPSHOT: its capture could not read %d things, and neither restore nor diff can see them; see REPORT.md\n", len(g))
	}
}

// dryRunAccepted refuses --dry-run where the restore would not honour it:
// elsewhere it would apply everything it was meant to only list.
func dryRunAccepted(platform string, dryRun bool) error {
	switch platform {
	case "aws", "gcp", "github", "cloudflare":
		return nil
	}
	if dryRun {
		return fmt.Errorf("--dry-run is for --platform aws, gcp, github or cloudflare; nothing was restored")
	}
	return nil
}

// valuesAccepted refuses --values where nothing reads it. A restore that
// dropped the file would say what it applied and look as if the secrets went
// with it.
func valuesAccepted(platform, file string) error {
	if file != "" && (platform == "gcp" || platform == "kubernetes") {
		return fmt.Errorf("--values is not read on --platform %s; nothing was restored", platform)
	}
	return nil
}

// samePlatform refuses to apply a snapshot to a different kind of platform:
// a Kubernetes restore of an AWS snapshot would try to apply every resource
// as an unknown kind and fail object by object.
func samePlatform(s snapshot.Snapshot, platform string) error {
	if !samePlatformName(s.Platform, platform) {
		return fmt.Errorf("snapshot is from platform %q; pass --platform %s", s.Platform, s.Platform)
	}
	return nil
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "truthform:", err)
	lastErr = err
	return 1
}

// parseFlags parses a command's flags. A bad flag is an error (exit 1), not
// exit 2: flag.ExitOnError exits 2, which this command's exit codes reserve
// for "differences found", so a typo in a diff read as drift.
func parseFlags(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(os.Stderr)
	return fs.Parse(args)
}

const renameHelp = "kubernetes: YAML file of where Secrets are read from instead, '<start of a store reference>: <what replaces it>' (a 1Password item path, a vault's address, an ExternalSecret's key); and of where images are pulled from instead ('<start of an image reference>: <what replaces it>'); only fields that name a store, an item in it or a container's image change, and each reference is listed as changed or not, for a restore into another environment (give diff the same file). azure: YAML file of new names for resources whose names are unique across Azure (storage accounts, key vaults, registries), 'Type/name: newname'; renames each one in every group that has it, its children and every reference to it, for a restore into another subscription while the source exists (give diff the same file)"

const leaveOutHelp = "kubernetes: YAML list of objects a restore leaves out and a diff does not expect, 'Kind/namespace/name' or 'Kind/name' for one with no namespace; Kind may be Kind.group and '*' is any (quote an entry that starts with one; give diff the same file). azure: YAML list of objects a restore leaves out and a diff does not expect, keyed 'Kind/resourceGroup/name' as --values is, with the names the snapshot has (before --rename); refused if anything left in still needs one (give diff the same file)"

// leftOut applies --leave-out to a snapshot. Azure and Kubernetes have it;
// elsewhere it is refused, never ignored.
func leftOut(file, platform string, s snapshot.Snapshot) (snapshot.Snapshot, error) {
	heldBack = nil
	if file == "" {
		return s, nil
	}
	if platform != "azure" && platform != "kubernetes" {
		return s, fmt.Errorf("--leave-out is for --platform azure and kubernetes only")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return s, err
	}
	var keys []string
	if err := yaml.UnmarshalStrict(b, &keys); err != nil {
		return s, fmt.Errorf("%s: want a list of 'Kind/resourceGroup/name' (azure) or 'Kind/namespace/name' (kubernetes): %w", file, err)
	}
	var out snapshot.Snapshot
	if platform == "kubernetes" {
		out, err = kube.LeaveOut(s, keys)
	} else {
		out, err = azarm.LeaveOut(s, keys)
	}
	if err != nil {
		return s, fmt.Errorf("%s: %w", file, err)
	}
	// Each one is named, here and in what the diff or restore reports: a count
	// alone let a diff say "no differences" with no word of what it skipped.
	kept := map[string]bool{}
	for _, o := range out.Objects {
		kept[o.Key()] = true
	}
	for _, o := range s.Objects {
		if kept[o.Key()] {
			continue
		}
		if platform != "kubernetes" {
			heldBack = append(heldBack, o.Kind()+"/"+o.Namespace()+"/"+o.Name())
			continue
		}
		// As an entry names it, with the group: two APIs may share a kind,
		// and an object with no namespace has no part for one.
		group, _, versioned := strings.Cut(o.APIVersion(), "/")
		kind := o.Kind()
		if versioned {
			kind += "." + group
		}
		if o.Namespace() == "" {
			heldBack = append(heldBack, kind+"/"+o.Name())
		} else {
			heldBack = append(heldBack, kind+"/"+o.Namespace()+"/"+o.Name())
		}
	}
	sort.Strings(heldBack)
	fmt.Fprintf(os.Stderr, "leave out: %d objects, as %s asks:\n", len(heldBack), file)
	for _, k := range heldBack {
		fmt.Fprintln(os.Stderr, "  ", k)
	}
	return out, nil
}

// warnOtherSubscriptions says, before anything is sent or compared, which
// objects name another subscription: a restore sends those IDs as they are.
// It also says what access a restore needs there, which Azure checks.
func warnOtherSubscriptions(s snapshot.Snapshot, platform, target string) {
	needElsewhere = nil
	if platform != "azure" {
		return
	}
	if need := azarm.AccessElsewhere(s, target); len(need) > 0 {
		needElsewhere = need
		fmt.Fprintf(os.Stderr, "NOTE: a restore needs %d actions outside its target; grant them to the identity that restores, or --leave-out the object:\n", len(need))
		for _, x := range need {
			fmt.Fprintln(os.Stderr, "  ", x)
		}
	}
	if other := azarm.OtherSubscriptions(s); len(other) > 0 {
		fmt.Fprintf(os.Stderr, "NOTE: %d objects name another subscription; a restore sends those IDs as they are, needs access there, and what it makes reaches there (--leave-out holds one back):\n", len(other))
		for _, x := range other {
			fmt.Fprintln(os.Stderr, "  ", x)
		}
	}
}

// renamed applies --rename to a snapshot. Only Azure has it; elsewhere it
// is refused, never ignored.
//
// For Kubernetes, strict refuses a rename that leaves a store reference
// where the source's is with nobody having said so: one no start fits, or
// one a rename does not reach. A restore is strict unless told otherwise;
// a diff writes nothing, and only says.
func renamed(file, platform string, s snapshot.Snapshot, strict bool) (map[string]string, snapshot.Snapshot, error) {
	storeRefs = nil
	if file == "" {
		return nil, s, nil
	}
	if platform != "azure" && platform != "kubernetes" {
		return nil, s, fmt.Errorf("--rename is for --platform azure and kubernetes only")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, s, err
	}
	var names map[string]string
	// Strict: a start given twice is a mistake, and the last would win.
	if err := yaml.UnmarshalStrict(b, &names); err != nil {
		return nil, s, fmt.Errorf("%s: %w", file, err)
	}
	if platform == "kubernetes" {
		// Not names of objects, as Azure's are: where Secrets are read from.
		out, rep, err := kube.RenameStores(s, names)
		if err != nil {
			return nil, s, fmt.Errorf("%s: %w", file, err)
		}
		// Each one, changed or not: a restore that still read the source's
		// secrets would otherwise look like one that did not.
		fmt.Fprintf(os.Stderr, "rename: %d store references point elsewhere, as %s asks:\n", len(rep.Changed), file)
		for _, r := range rep.Changed {
			fmt.Fprintf(os.Stderr, "   %s %s: %s -> %s\n", r.Object, r.Field, r.From, r.To)
		}
		if len(rep.Kept) > 0 {
			fmt.Fprintf(os.Stderr, "rename: %d store references are as the source's, as %s asks:\n", len(rep.Kept), file)
			for _, r := range rep.Kept {
				fmt.Fprintf(os.Stderr, "   %s %s: %s\n", r.Object, r.Field, r.From)
			}
		}
		if len(rep.Within) > 0 {
			fmt.Fprintf(os.Stderr, "rename: %d references name an item in a store and no start fits them: each reads the same name, from the store its store object says:\n", len(rep.Within))
			for _, r := range rep.Within {
				fmt.Fprintf(os.Stderr, "   %s %s: %s\n", r.Object, r.Field, r.From)
			}
		}
		if len(rep.Unnamed) > 0 {
			fmt.Fprintf(os.Stderr, "rename: %d references say which store, and no start fits them: they are the source's:\n", len(rep.Unnamed))
			for _, r := range rep.Unnamed {
				fmt.Fprintf(os.Stderr, "   %s %s: %s\n", r.Object, r.Field, r.From)
			}
		}
		if len(rep.Unreached) > 0 {
			fmt.Fprintf(os.Stderr, "rename: %d objects use a store in a way --rename does not reach; they are as the source's:\n", len(rep.Unreached))
			for _, u := range rep.Unreached {
				fmt.Fprintln(os.Stderr, "  ", u)
			}
		}
		if len(rep.Images) > 0 {
			fmt.Fprintf(os.Stderr, "rename: %d images are pulled from elsewhere, as %s asks (they have to be there: built again, or copied):\n", len(rep.Images), file)
			for _, r := range rep.Images {
				fmt.Fprintf(os.Stderr, "   %s %s: %s -> %s\n", r.Object, r.Field, r.From, r.To)
			}
		}
		if len(rep.ImagesKept) > 0 {
			fmt.Fprintf(os.Stderr, "rename: %d images are pulled from where the source pulls them, as %s asks\n", len(rep.ImagesKept), file)
		}
		if len(rep.ImagesLeft) > 0 {
			var l []string
			for _, r := range rep.ImagesLeft {
				l = append(l, fmt.Sprintf("%s (%d)", r.Registry, r.References))
			}
			fmt.Fprintf(os.Stderr, "rename: images no start fits are pulled from where the source pulls them, and the new cluster has to be allowed to: %s\n", strings.Join(l, ", "))
		}
		// What a PushSecret pushes it writes, and where it is told to it
		// deletes: left as the source's, that is the source's store.
		writes := 0
		for _, r := range rep.Unnamed {
			if kube.WritesToStore(r) {
				writes++
			}
		}
		if writes > 0 {
			fmt.Fprintf(os.Stderr, "rename: %d of those are what a PushSecret WRITES to. Restored as they are, the new cluster writes the source's items, and deletes them where its deletionPolicy says Delete.\n", writes)
		}
		storeRefs = &rep
		// What was not looked at, so that nothing listed does not read as
		// nothing there.
		fmt.Fprintf(os.Stderr, "rename: a use of a secret store was looked for in these kinds, and the 1Password operator's annotation on any object: %s. One named anywhere else (a workload's own settings, another operator's objects) is not seen.\n", strings.Join(kube.StoreKinds(), ", "))
		if n := len(rep.Unnamed) + len(rep.Unreached); strict && n > 0 {
			return nil, s, fmt.Errorf("%s: %d objects would use the source's secret store (listed above: a store, or what a PushSecret writes, that no start fits, or a use --rename does not reach), and what reads or writes through them would read or write the source's; nothing was restored. Give each a start (replaced by itself, if it is the same in both), leave the object out, or pass --keep-source-stores", file, n)
		}
		return nil, out, nil
	}
	out, warnings, err := azarm.Rename(s, names)
	if err != nil {
		return nil, s, fmt.Errorf("%s: %w", file, err)
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, "rename:", w)
	}
	return names, out, nil
}
