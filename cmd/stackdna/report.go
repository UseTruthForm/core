package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/azarm"
	"github.com/stackdna/core/internal/kube"
	"github.com/stackdna/core/internal/snapshot"
)

// writeReport writes REPORT.md next to a snapshot: what a person, not a
// parser, needs to know about it. What is incomplete comes first, never
// after the good news. Nothing time- or machine-dependent goes in, so an
// unchanged system gives an unchanged report.
func writeReport(dir string, s snapshot.Snapshot, title string) error {
	digest, _ := snapshot.Digest(dir)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	read, notCaptured, failed := summarize(s)
	g := gaps(s)
	w("# %s: capture report\n\n", title)
	w("| | |\n|---|---|\n")
	w("| Platform | %s |\n| Capture rules | `%s` |\n| Snapshot digest | `%s` |\n", s.Platform, md(s.Policy), digest)
	w("| Captured | **%d resources** across %d types |\n", len(s.Objects), read)
	perOwner := ""
	for _, sk := range s.Skips {
		if sk.Name == "*" {
			perOwner = "; what a controller makes counts once per owner"
			break
		}
	}
	w("| Skipped on purpose | %d resources%s |\n| Types not captured | %d |\n\n", len(s.Skips)+countedSkips(s), perOwner, notCaptured+len(failed))

	if len(g) > 0 {
		var throttled, other []string
		th := throttledGaps(s)
		for _, x := range g {
			if th[x] {
				throttled = append(throttled, x)
			} else {
				other = append(other, x)
			}
		}
		w("## Incomplete: %d gaps\n\n", len(g))
		w("These are **not in the snapshot**, and restoring it will not recreate them.\n\n")
		for _, x := range other {
			w("- %s\n", md(x))
		}
		if len(throttled) > 0 {
			if len(other) > 0 {
				w("\n")
			}
			w("**Throttled: %d.** The platform asked for fewer calls and the retries ran out. Nothing was refused: capture again later, or with a lower `--parallel`.\n\n", len(throttled))
			for _, x := range throttled {
				w("- %s\n", md(x))
			}
		}
		w("\n")
	} else {
		w("## Complete\n\nEvery type that could be read was read. Every skip below has a reason.\n\n")
	}

	w("## Not in any snapshot, by design\n\n")
	w("- **Data:** volume contents, objects in storage, database rows, queue messages. A snapshot is configuration.\n")
	w("- **Secret values:** passwords, keys, secret data. Restore needs them supplied (`--values`, `--secrets-from-context`).\n")
	if s.Platform == "azure" {
		w("- **Azure's built-in roles:** the same in every tenant, so a target has them already.\n")
	}
	if n := withAnnotation(s, "secret", "write-only", "withheld"); n > 0 {
		w("- **%d objects** in this snapshot name values that were withheld or that the platform never returns; restore will say which it was not given.\n", n)
	}
	w("\n")

	if rows := plainCredentials(s); len(rows) > 0 {
		w("## Credentials in plain configuration: %d objects\n\n", len(rows))
		w("These values are named like credentials, or are URLs with a password in them, and are set as plain configuration (a workload's environment, a ConfigMap) rather than in a Secret. ")
		w("Their values were withheld from this snapshot, but anyone who can read the workload can read them, and they are usually in its source too (Helm values, manifests). ")
		w("Move each into a Secret and reference it with `valueFrom.secretKeyRef`. A restore needs them supplied (`--secrets-from-context`).\n\n")
		w("| Object | Values (container/variable, or data/key) |\n|---|---|\n")
		for _, r := range rows {
			w("| %s | %s |\n", md(r[0]), md(r[1]))
		}
		w("\n")
	}

	if s.Platform == "azure" {
		if azarm.PredatesManagedCheck(s) {
			w("## Not checked: what a manager keeps\n\nThis snapshot's capture did not tell what comes back with its manager from what may not. Its reasons below promise more than anyone checked. Capture again with this release.\n\n")
		}
		var check []string
		for _, sk := range s.Skips {
			if azarm.MayNotComeBack(sk.Reason) {
				check = append(check, sk.Resource+" "+sk.Name)
			}
		}
		if len(check) > 0 {
			sort.Strings(check)
			w("## Check before relying on a restore: %d resources\n\n", len(check))
			w("These were left out because something else manages them, and nothing shows it will recreate them. Something a person put there, or a data disk attached to a VM, will not come back. `--capture-managed` reads them.\n\n")
			for _, x := range check {
				w("- %s\n", md(x))
			}
			w("\n")
		}
		if across := azarm.PeeringsAcrossManagedGroups(s); len(across) > 0 {
			w("## Peerings with a cluster's network: %d\n\n", len(across))
			w("A new cluster's network gets a new generated name, so a restore beside a new cluster refuses these, and each needs re-making against it. Beside the same cluster, they are restored as captured.\n\n")
			for _, x := range across {
				w("- %s\n", md(x))
			}
			w("\n")
		}
		if kept := azarm.KeptInManagedGroups(s); len(kept) > 0 {
			w("## Captured from a managed resource group: %d resources\n\n", len(kept))
			w("Nothing shows the manager made these, so they are in this snapshot and a restore applies them after it. If it did make one, a restore creates it beside the manager's own, and with `--update` sets it over one of the same name.\n\n")
			for _, x := range kept {
				w("- %s\n", md(x))
			}
			w("\n")
		}
	}

	if len(s.Objects) > 0 {
		w("## Captured, by type\n\n| Type | Resources |\n|---|---:|\n")
		counts := map[string]int{}
		for _, o := range s.Objects {
			counts[o.Kind()]++
		}
		for _, k := range sortedByCount(counts) {
			w("| %s | %d |\n", md(k), counts[k])
		}
		w("\n")
	}

	// Taken as the platform's on evidence a person's object could also carry:
	// each is named, not counted under a reason, so one that is theirs is seen.
	var taken []string
	for _, sk := range s.Skips {
		if r, ok := strings.CutPrefix(sk.Reason, kube.TakenAsPlatform); ok {
			taken = append(taken, sk.Resource+" "+qualified(sk.Namespace, sk.Name)+": "+strings.TrimSuffix(r, "; --capture-platform keeps it"))
		}
	}
	if len(taken) > 0 {
		sort.Strings(taken)
		w("## Taken as the platform's: %d resources\n\n", len(taken))
		w("Left out because they look like AKS's own, by marks a person's object could also carry. If one is yours, capture with `--capture-platform`.\n\n")
		for _, x := range taken {
			w("- %s\n", md(x))
		}
		w("\n")
	}

	if len(s.Skips) > 0 || countedSkips(s) > 0 {
		w("## Skipped on purpose\n\n| Reason | Resources | For example |\n|---|---:|---|\n")
		byReason := map[string][]string{}
		for _, sk := range s.Skips {
			if strings.HasPrefix(sk.Reason, "listed but could not be read") {
				continue // listed under Incomplete
			}
			ex := sk.Resource + " " + sk.Name
			if sk.Name == "*" {
				ex = "every " + sk.Resource // recorded per owner, not per instance
				if sk.Namespace != "" {
					ex += " in " + sk.Namespace
				}
			}
			byReason[sk.Reason] = append(byReason[sk.Reason], ex)
		}
		counts := map[string]int{}
		for r, xs := range byReason {
			counts[r] = len(xs)
		}
		for _, c := range s.Coverage {
			for r, n := range c.Skipped {
				if _, listed := byReason[r]; !listed && !strings.Contains(r, ":") {
					counts[r] += n // counted, not listed one by one (built-in roles)
				}
			}
		}
		for _, r := range sortedByCount(counts) {
			ex := ""
			if xs := byReason[r]; len(xs) > 0 {
				sort.Strings(xs)
				ex = xs[0]
			}
			w("| %s | %d | %s |\n", md(r), counts[r], md(ex))
		}
		w("\n")
	}

	notCap := map[string]int{}
	for _, c := range s.Coverage {
		if c.NotCaptured != "" && !strings.HasPrefix(c.NotCaptured, "list failed") {
			notCap[category(c.NotCaptured)]++
		}
	}
	if len(notCap) > 0 {
		w("## Types not captured, by reason\n\nFull detail per type is in `coverage.yaml`.\n\n| Reason | Types |\n|---|---:|\n")
		for _, r := range sortedByCount(notCap) {
			w("| %s | %d |\n", md(r), notCap[r])
		}
		w("\n")
	}
	return os.WriteFile(filepath.Join(dir, "REPORT.md"), []byte(b.String()), 0o644)
}

// plainCredentials lists each workload whose credential-named env values
// were withheld (kube.WithheldEnvAnnotation): kind namespace/name, names.
func plainCredentials(s snapshot.Snapshot) [][2]string {
	var rows [][2]string
	for _, o := range s.Objects {
		meta, _ := o.Body["metadata"].(map[string]any)
		ann, _ := meta["annotations"].(map[string]any)
		if v, _ := ann[kube.WithheldEnvAnnotation].(string); v != "" {
			who := o.Kind() + " " + o.Name()
			if ns := o.Namespace(); ns != "" {
				who = o.Kind() + " " + ns + "/" + o.Name()
			}
			var names []string
			for _, p := range strings.Split(v, ",") {
				names = append(names, kube.WithheldDisplay(p))
			}
			rows = append(rows, [2]string{who, strings.Join(names, ", ")})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return rows
}

// writeEnvReport writes the environment's REPORT.md: one row per target,
// failures and gaps first.
func writeEnvReport(dir, name string, results []TargetResult) error {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("# %s: environment capture\n\n", name)
	order := append([]TargetResult(nil), results...)
	rank := map[string]int{"failed": 0, "incomplete": 1, "complete": 2}
	sort.SliceStable(order, func(i, j int) bool { return rank[order[i].Status] < rank[order[j].Status] })
	w("| Target | Platform | Status | Resources | Report |\n|---|---|---|---:|---|\n")
	for _, r := range order {
		link := "—"
		if r.Status != "failed" {
			link = "[" + r.Name + "/REPORT.md](" + r.Name + "/REPORT.md)"
		}
		w("| %s | %s | **%s** | %d | %s |\n", md(r.Name), r.Platform, r.Status, r.Objects, link)
	}
	w("\n")
	for _, r := range order {
		if r.Error != "" {
			w("- **%s failed:** %s\n", md(r.Name), md(r.Error))
		}
		th := map[string]bool{}
		for _, x := range r.Throttled {
			th[x] = true
		}
		for _, x := range r.Gaps {
			if th[x] {
				w("- %s (throttled; capture again later): %s\n", md(r.Name), md(x))
			} else {
				w("- %s: %s\n", md(r.Name), md(x))
			}
		}
	}
	return os.WriteFile(filepath.Join(dir, "REPORT.md"), []byte(b.String()), 0o644)
}

// reportCmd regenerates REPORT.md for an existing snapshot.
func reportCmd(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "report: give one snapshot directory")
		return 1
	}
	s, err := snapshot.Read(args[0])
	if err != nil {
		return fail(err)
	}
	if err := writeReport(args[0], s, filepath.Base(filepath.Clean(args[0]))); err != nil {
		return fail(err)
	}
	fmt.Println("wrote", filepath.Join(args[0], "REPORT.md"))
	return 0
}

// category reduces a not-captured reason to its kind, the text before the
// first ": " ("not set up in this account").
func category(r string) string {
	if i := strings.Index(r, ": "); i > 0 {
		return r[:i]
	}
	return r
}

func countedSkips(s snapshot.Snapshot) int {
	listed := map[string]bool{}
	for _, sk := range s.Skips {
		listed[sk.Reason] = true
	}
	n := 0
	for _, c := range s.Coverage {
		for r, k := range c.Skipped {
			if !listed[r] && !strings.Contains(r, ":") {
				n += k
			}
		}
	}
	return n
}

// withAnnotation counts objects carrying an annotation whose key contains
// any of words (secrets, write-only, withheld-keys).
func withAnnotation(s snapshot.Snapshot, words ...string) int {
	n := 0
	for _, o := range s.Objects {
		ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		marked := false
		for k := range ann {
			for _, w := range words {
				marked = marked || strings.Contains(k, w)
			}
		}
		if marked {
			n++
		}
	}
	return n
}

func sortedByCount(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if m[out[i]] != m[out[j]] {
			return m[out[i]] > m[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// md keeps a value from breaking a Markdown table.
func md(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
}

func qualified(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}
