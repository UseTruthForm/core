package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/snapshot"
)

// planCmd says what rebuilding from a snapshot needs that the snapshot
// does not hold. It reads only the snapshot: no login, no request.
func planCmd(args []string) int {
	if len(args) > 0 && args[0] == "secrets" {
		return planSecrets(context.Background(), args[1:])
	}
	if len(args) > 0 && args[0] == "scope" {
		return planScope(args[1:])
	}
	if len(args) == 0 || args[0] != "rebuild" {
		return fail(fmt.Errorf("plan: it gives rebuild, secrets and scope: truthform plan rebuild --from <dir> [--scope <file>] [--out <file>] [--json], truthform plan secrets --from <dir> [--scope <file>] [--out <file> | --check <file> [--resolve]], truthform plan scope --from <dir> [--out <file> | --check <file>]"))
	}
	fs := flag.NewFlagSet("plan rebuild", flag.ContinueOnError)
	from := fs.String("from", "", "snapshot directory")
	out := fs.String("out", "", "file to write (default: stdout)")
	scope := fs.String("scope", "", scopeHelp)
	if err := parseFlags(fs, args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if *from == "" || fs.NArg() > 0 {
		return fail(fmt.Errorf("plan rebuild: --from is required and no positional arguments are accepted"))
	}
	s, err := snapshot.Read(*from)
	if err != nil {
		return fail(err)
	}
	if jsonOut && *out != "" {
		return fail(fmt.Errorf("plan rebuild: --out is for the Markdown; with --json the document is on stdout"))
	}
	if s.Platform != "kubernetes" {
		return fail(fmt.Errorf("plan rebuild: %s is a %s snapshot; the plan is for kubernetes snapshots", *from, s.Platform))
	}
	// The plan of a part: what the chosen part needs, and no more.
	if s, err = scoped(*scope, s.Platform, s); err != nil {
		return fail(err)
	}
	p := kube.RebuildPlan(s)
	// What the capture could not read, the plan cannot count: a step that
	// lists nothing is then no proof there is nothing.
	notRead := gaps(s)
	if len(notRead) > 0 {
		fmt.Fprintf(os.Stderr, "INCOMPLETE SNAPSHOT: its capture could not read %d things, and the plan cannot count what is in them; it lists them first\n", len(notRead))
	}
	if jsonOut {
		doc := map[string]any{"schema": jsonSchema, "command": "plan", "plan": p, "gaps": orEmpty(notRead)}
		if scopeDone != nil {
			doc["scope"] = scopeDone
		}
		emit(doc)
		return 0
	}
	text := planMarkdown(p, notRead)
	if *out == "" {
		_, err = os.Stdout.WriteString(text)
	} else if err = os.WriteFile(*out, []byte(text), 0o644); err == nil {
		fmt.Printf("wrote %s\n", *out)
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

// planShown is how many of a long list a row names before it counts the rest.
const planShown = 3

// planMarkdown is the plan for a person, in the order to act on it.
// Nothing time- or machine-dependent goes in, not the directory's name
// either: an unchanged snapshot gives an unchanged plan, wherever it is.
func planMarkdown(p kube.Plan, notRead []string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	// none is what a step with nothing to list says: that there is nothing,
	// or, when the capture could not read everything, only that it saw none.
	none := func(allClear string) {
		if len(notRead) > 0 {
			allClear = "None in what the capture read. It could not read everything (see the top), so there may be some."
		}
		w("%s\n\n", allClear)
	}
	fromStore := p.StoreSecrets
	w("# Rebuild plan\n\n")
	w("What rebuilding a cluster from this snapshot needs that the snapshot does not hold. Read from the snapshot alone: nothing was contacted, and no secret value is in it or here.\n\n")
	if len(notRead) > 0 {
		w("**INCOMPLETE SNAPSHOT.** Its capture could not read %d things. This plan counts only what was read: a step may be missing sources, secrets or hosts that are in these.\n\n", len(notRead))
		for _, g := range notRead {
			w("- %s\n", md(g))
		}
		w("\n")
	}
	// A count is of what was read, and says so where that is not all.
	seen := ""
	if len(notRead) > 0 {
		seen = " seen"
	}
	w("| Step | | |\n|---|---|---:|\n")
	w("| 1 | Install what a GitOps source makes | %d sources by hand, %d follow%s |\n", len(p.Sources), len(p.Follows), seen)
	w("| 2 | Have these APIs served before the restore | %d groups%s |\n", len(p.Operators), seen)
	keysOut := 0
	for _, e := range p.Encrypted {
		keysOut += len(e.KeysNotHeld)
	}
	if keysOut > 0 {
		w("| 3 | Supply by hand the secrets no store holds | %d secrets%s, and %d keys the snapshot does not hold |\n", len(p.ByHand), seen, keysOut)
	} else {
		w("| 3 | Supply by hand the secrets no store holds | %d secrets%s |\n", len(p.ByHand), seen)
	}
	w("| 4 | Make the secret store reachable | %d items feed %d secrets%s |\n", len(p.FromStore), fromStore, seen)
	w("| 5 | Restore the snapshot | |\n")
	w("| 6 | Point the names at the rebuilt cluster | %d hosts%s |\n\n", len(p.Hosts), seen)

	w("## 1. Install first: %d sources%s\n\n", len(p.Sources), seen)
	if len(p.Follows) > 0 {
		made := 0
		names := make([]string, len(p.Follows))
		for i, s := range p.Follows {
			made += s.Objects
			names[i] = s.Kind + " " + code(s.Name)
		}
		w("**Applied again by sources the snapshot holds: %d sources, %d objects.** Install the GitOps tool's own controllers and restore: the sources in the snapshot then apply these, from where they read. %s.\n\n", len(p.Follows), made, strings.Join(names, ", "))
	}
	if len(p.Sources) == 0 {
		if len(p.Follows) > 0 {
			none("Nothing else: the capture left nothing to a GitOps source that the snapshot's own sources do not apply.")
		} else {
			none("The capture left nothing to a GitOps source.")
		}
	} else {
		w("The capture left these out because their source recreates them. The snapshot holds neither the source nor what it makes.\n\n")
		w("| Source | Objects it makes | |\n|---|---:|---|\n")
		for _, s := range p.Sources {
			note := ""
			if s.SystemOnly {
				note = "only in system namespaces: the cluster's platform may install it itself"
			}
			w("| %s %s | %d | %s |\n", s.Kind, code(s.Name), s.Objects, note)
		}
		w("\n")
	}
	if len(p.Sources)+len(p.Follows) > 0 {
		if len(p.Origins) > 0 {
			w("The snapshot holds these repository objects: %s. Check that they are where the sources above are read from. The credential to read each is a Secret of step 3.\n\n", md(strings.Join(p.Origins, ", ")))
		} else {
			w("**Not in the snapshot: where the sources are read from.** The repository, branch and path the cluster was bootstrapped from, and the credential to read them, have to come from your own records.\n\n")
		}
	}

	w("## 2. APIs to have served: %d groups%s\n\n", len(p.Operators), seen)
	if len(p.Operators) == 0 {
		none("Every type in the snapshot is built in, or its definition is in the snapshot.")
	} else {
		w("The snapshot has objects of these types and not their definitions: the restore refuses them until something serves the type, usually an operator that step 1 installs.\n\n")
		w("| API group | Objects |\n|---|---|\n")
		for _, o := range p.Operators {
			kinds := make([]string, 0, len(o.Objects))
			for k := range o.Objects {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			for i, k := range kinds {
				kinds[i] = fmt.Sprintf("%d %s", o.Objects[k], k)
			}
			w("| %s | %s |\n", code(o.Group), md(strings.Join(kinds, ", ")))
		}
		w("\n")
	}

	w("## 3. Secrets to supply by hand: %d%s\n\n", len(p.ByHand), seen)
	if len(p.ByHand) == 0 {
		none("No Secret in the snapshot is left for a person to supply: each is made from a store, made again by something in the cluster, or opened with a key named below.")
	} else {
		w("No store in the snapshot supplies these, and a snapshot never holds a value. Each needs its value from where you keep it: `truthform plan secrets` writes a file to say where, which the restore reads with `--secrets-from`. One with no user here may still be read by what step 1 installs, or named from an object with no namespace.\n\n")
		w("| Secret | Keys | Used by | What it says of itself |\n|---|---|---|---|\n")
		for _, s := range p.ByHand {
			w("| %s | %s | %s | %s |\n", code(s.Namespace+"/"+s.Name), codes(s.Keys), md(some(s.UsedBy)), md(s.Note))
		}
		w("\n")
	}

	for _, e := range p.Encrypted {
		w("**Kept encrypted: %s", md(e.By))
		if e.Objects > 0 {
			w(", %d objects", e.Objects)
		}
		w(".** ")
		switch {
		case len(e.Keys) > 0:
			w("The key is in %s, of step 3. ", codes(e.Keys))
		case len(e.KeysNotHeld) == 0 && e.By == kube.SealedSecrets:
			w("The capture saw no Secret that holds the controller's key. ")
		case len(e.KeysNotHeld) == 0:
			w("No Secret in the snapshot is named as the key: it is outside the cluster (a cloud key service). ")
		}
		if len(e.KeysNotHeld) > 0 {
			w("**The key is in %s, which the capture left out with its namespace: it is not in the snapshot, and no restore brings it back.** ", codes(e.KeysNotHeld))
		}
		w("A snapshot never holds a key's value: without a copy of the key kept outside the cluster, what it encrypts cannot be read again.\n\n")
	}

	if len(p.Reissued) > 0 {
		// By what makes them, in the order of the first of each.
		var makers []string
		by := map[string][]string{}
		for _, m := range p.Reissued {
			if by[m.By] == nil {
				makers = append(makers, m.By)
			}
			by[m.By] = append(by[m.By], m.Secret)
		}
		parts := make([]string, len(makers))
		for i, m := range makers {
			parts[i] = fmt.Sprintf("%s (%s)", codes(by[m]), md(m))
		}
		w("Not for you to supply: %d that something in the cluster makes again once it runs: %s.\n\n", len(p.Reissued), strings.Join(parts, "; "))
	}

	w("## 4. Secrets a store supplies: %d, from %d items%s\n\n", fromStore, len(p.FromStore), seen)
	if len(p.FromStore) == 0 {
		none("The snapshot has no object that reads a secret store.")
	} else {
		w("The restore recreates the objects that ask for these; the store's operator then makes the Secrets. That needs the store reachable from the rebuilt cluster, and the operator's own credential, which is one of step 3's. An item holds the settings of the cluster it was written for: one that feeds many Secrets is where to look for addresses and keys that must differ in a rebuild.\n\n")
		w("| Store | Item | Secrets | |\n|---|---|---:|---|\n")
		for _, it := range p.FromStore {
			w("| %s | %s | %d | %s |\n", md(it.Store), code(it.Item), len(it.Secrets), md(some(it.Secrets)))
		}
		w("\n")
	}

	w("## 5. Restore\n\n")
	w("`truthform restore --context <kube-context> --from <this snapshot> --secrets-from <sources file>`, once steps 1 to 4 are in place. With the sources file the restore reads step 3's values from where the file says, and leaves to their makers the Secrets a store or a controller makes.\n\n")

	w("## 6. Names to point at the rebuilt cluster: %d%s\n\n", len(p.Hosts), seen)
	if len(p.Hosts) == 0 {
		none("No route in the snapshot names a host.")
	} else {
		w("The routes in the snapshot answer to these. Their DNS records point at the cluster the snapshot was taken from. A route that matches hosts by pattern names none here.\n\n")
		for _, h := range p.Hosts {
			w("- %s\n", code(h))
		}
	}
	return b.String()
}

// code is a value as a code span that a backtick, a pipe or a line break
// in it cannot end; a value that is empty says so.
func code(s string) string {
	if s == "" {
		return "(none named)"
	}
	return "`" + md(strings.ReplaceAll(s, "`", "'")) + "`"
}

// codes is some(), each value a code span: a key such as _k_ is not
// emphasis.
func codes(l []string) string {
	spans := make([]string, len(l))
	for i, v := range l {
		spans[i] = code(v)
	}
	return some(spans)
}

// some lists the first few of a sorted list and counts the rest.
func some(l []string) string {
	if len(l) <= planShown {
		return strings.Join(l, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(l[:planShown], ", "), len(l)-planShown)
}
