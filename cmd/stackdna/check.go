package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/access"
	"github.com/stackdna/core/internal/snapshot"
)

// checkCmd says who StackDNA is running as and what that identity can
// read, type by type, by running a capture that is written nowhere. It is
// the step after a grant: an exit code of 0 from the grant says the
// platform accepted it, not that a capture can now read everything.
//
// A type refused for want of permission is told apart from a type that
// was read and is empty. Both are "nothing captured", and a missing
// permission must not read as an account with nothing in it.
func checkCmd(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	platform := fs.String("platform", "kubernetes", "kubernetes, aws, azure, gcp, github or cloudflare")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig")
	kctx := fs.String("context", "", "kubeconfig context")
	region := fs.String("region", "", "aws: the region")
	profile := fs.String("profile", "", "aws: the shared-config profile")
	subscription := fs.String("subscription", "", "azure: the subscription ID")
	project := fs.String("project", "", "gcp: the project ID")
	account := fs.String("account", "", "github: the organisation; cloudflare: the account ID")
	types := fs.String("types", "", "type patterns to limit the trial capture to (default: every type)")
	accessFor := fs.String("access", "capture", "what the identity is for: capture (any write is more than needed) or restore")
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if *accessFor != "capture" && *accessFor != "restore" {
		return fail(fmt.Errorf("--access is capture or restore, not %q", *accessFor))
	}
	t := Target{Name: "check", Platform: *platform, Context: *kctx, Kubeconfig: *kubeconfig, Region: *region, Profile: *profile,
		Subscription: *subscription, Project: *project, Account: *account}
	for _, p := range strings.Split(*types, ",") {
		if p = strings.TrimSpace(p); p != "" {
			t.Types = append(t.Types, p)
		}
	}
	need := map[string]string{"kubernetes": *kctx, "aws": *region, "azure": *subscription, "gcp": *project, "github": *account, "cloudflare": *account}
	flagFor := map[string]string{"kubernetes": "--context", "aws": "--region", "azure": "--subscription", "gcp": "--project", "github": "--account", "cloudflare": "--account"}
	v, known := need[*platform]
	if !known {
		return fail(fmt.Errorf("--platform must be kubernetes, aws, azure, gcp, github or cloudflare"))
	}
	if v == "" {
		return fail(fmt.Errorf("check: %s is required for --platform %s (check never guesses its target)", flagFor[*platform], *platform))
	}
	if k := inapplicable(t); k != "" {
		return fail(fmt.Errorf("check: --%s does not apply to --platform %s", k, *platform))
	}

	id, err := identify(ctx, t, *accessFor)
	if err != nil {
		return fail(err)
	}
	snap, capErr := captureTarget(ctx, t)
	rc := classify(snap)
	if jsonOut {
		defer emitCheck(id, rc, capErr)
	}
	printIdentity(id)
	if capErr != nil {
		fmt.Println("\nREADS")
		if deniedRE.MatchString(capErr.Error()) {
			fmt.Println("  DENIED: the capture could not start:", capErr)
			fmt.Println("\nRESULT: this identity cannot capture", *platform, "(see stackdna permissions)")
			return 3
		}
		return fail(capErr)
	}
	printReads(rc)
	switch {
	case len(rc.Denied) > 0 || len(rc.Failed) > 0:
		fmt.Printf("\nRESULT: incomplete: %d types refused for want of permission, %d failed otherwise. A capture now would not hold them.\n", len(rc.Denied), len(rc.Failed))
		return 3
	case len(id.Warnings) > 0:
		fmt.Printf("\nRESULT: can read every type it was asked to; %d warnings above.\n", len(id.Warnings))
	default:
		fmt.Println("\nRESULT: can read every type it was asked to.")
	}
	return 0
}

func identify(ctx context.Context, t Target, accessFor string) (access.Report, error) {
	switch t.Platform {
	case "aws":
		return access.AWS(ctx, t.Profile, t.Region, accessFor)
	case "azure":
		return access.Azure(ctx, t.Subscription, accessFor)
	case "gcp":
		return access.GCP(ctx, t.Project, accessFor)
	case "github":
		return access.GitHub(ctx, os.Getenv("GITHUB_TOKEN"), accessFor)
	case "cloudflare":
		return access.Cloudflare(ctx, os.Getenv("CLOUDFLARE_API_TOKEN"), t.Account)
	}
	return access.Kubernetes(t.Kubeconfig, t.Context)
}

// deniedRE matches the platforms' ways of saying "not allowed": AWS's
// handlers, ARM's AuthorizationFailed, Google's PERMISSION_DENIED,
// GitHub's org-admin and integration refusals, Kubernetes' forbidden.
var deniedRE = regexp.MustCompile(`(?i)not authorized to perform|accessdenied|access denied|authorizationfailed|permission_denied|permission denied|\bforbidden\b|HTTP 40[13]\b|must be an org admin|must have admin|resource not accessible|insufficient permission|does not have authorization`)

type readCheck struct {
	WithObjects int            `json:"typesWithResources"`
	Objects     int            `json:"resources"`
	Skipped     int            `json:"resourcesSkippedOnPurpose"`
	Empty       int            `json:"typesReadEmpty"`
	Denied      []string       `json:"denied"`
	Failed      []string       `json:"failed"`
	ByDesign    map[string]int `json:"notReadByDesign"`
}

func classify(s snapshot.Snapshot) readCheck {
	rc := readCheck{ByDesign: map[string]int{}, Objects: len(s.Objects), Skipped: countedSkips(s)}
	for _, sk := range s.Skips {
		if !strings.HasPrefix(sk.Reason, "listed but could not be read") {
			rc.Skipped++
		}
	}
	for _, c := range s.Coverage {
		switch {
		case c.NotCaptured == "" && (c.Captured > 0 || len(c.Skipped) > 0):
			rc.WithObjects++
		case c.NotCaptured == "":
			rc.Empty++
		// Only a failure can be a denial. A 403 the capture already
		// explained ("not available on this account's plan": GitHub refuses
		// rulesets on a private repository on Free) was counted as one, and
		// a grant would have been widened for a feature no grant can give.
		case strings.HasPrefix(c.NotCaptured, "list failed") || strings.HasPrefix(c.NotCaptured, "API group discovery failed"):
			if deniedRE.MatchString(c.NotCaptured) {
				rc.Denied = append(rc.Denied, c.Resource+": "+c.NotCaptured)
			} else {
				rc.Failed = append(rc.Failed, c.Resource+": "+c.NotCaptured)
			}
		default:
			rc.ByDesign[category(c.NotCaptured)]++
		}
	}
	// A type can be listed and some of its items refused one by one.
	for _, sk := range s.Skips {
		if !strings.HasPrefix(sk.Reason, "listed but could not be read") {
			continue
		}
		x := sk.Resource + " " + sk.Name + ": " + sk.Reason
		if deniedRE.MatchString(sk.Reason) {
			rc.Denied = append(rc.Denied, x)
		} else {
			rc.Failed = append(rc.Failed, x)
		}
	}
	sort.Strings(rc.Denied)
	sort.Strings(rc.Failed)
	return rc
}

func printIdentity(id access.Report) {
	fmt.Printf("IDENTITY  %s (%s on %s)\n", id.Who, id.Kind, id.Platform)
	for _, f := range id.Facts {
		fmt.Println("  ", f)
	}
	if len(id.Warnings) > 0 {
		fmt.Println("\nWARNINGS")
		for _, w := range id.Warnings {
			fmt.Println("  -", w)
		}
	}
	if len(id.Unchecked) > 0 {
		fmt.Println("\nNOT CHECKED (not looked at, so not known to be fine)")
		for _, u := range id.Unchecked {
			fmt.Println("  -", u)
		}
	}
}

func printReads(rc readCheck) {
	fmt.Println("\nREADS (a trial capture, written nowhere)")
	list := func(label string, xs []string) {
		fmt.Printf("  %-8s %d\n", label, len(xs))
		for i, x := range xs {
			if i == 40 {
				fmt.Printf("           ... and %d more\n", len(xs)-40)
				break
			}
			fmt.Println("          ", x)
		}
	}
	list("DENIED", rc.Denied)
	list("FAILED", rc.Failed)
	fmt.Printf("  read     %d types holding %d resources", rc.WithObjects, rc.Objects)
	if rc.Skipped > 0 {
		fmt.Printf(", and %d more read and skipped on purpose (made by the platform or a service; a capture's REPORT.md lists them)", rc.Skipped)
	}
	fmt.Println()
	fmt.Printf("  empty    %d types read and holding nothing\n", rc.Empty)
	var keys []string
	n := 0
	for k, v := range rc.ByDesign {
		keys = append(keys, k)
		n += v
	}
	sort.Strings(keys)
	fmt.Printf("  not read %d types, by design:\n", n)
	for _, k := range keys {
		fmt.Printf("           %d %s\n", rc.ByDesign[k], k)
	}
}

func emitCheck(id access.Report, rc readCheck, capErr error) {
	doc := map[string]any{"schema": jsonSchema, "command": "check",
		"identity": map[string]any{"platform": id.Platform, "who": id.Who, "kind": id.Kind, "facts": nonNil(id.Facts),
			"warnings": nonNil(id.Warnings), "unchecked": nonNil(id.Unchecked)},
		"reads": rc}
	if capErr != nil {
		doc["error"] = capErr.Error()
	}
	emit(doc)
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
