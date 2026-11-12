package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/snapshot"
)

// planCmd says what rebuilding from a snapshot needs that the snapshot
// does not hold. It reads only the snapshot: no login, no request.
func planCmd(args []string) int {
	if len(args) == 0 || args[0] != "rebuild" {
		fmt.Fprintln(os.Stderr, "plan: the plan to give is rebuild: truthform plan rebuild --from <dir> [--out <file>]")
		return fail(fmt.Errorf("plan: no such plan"))
	}
	fs := flag.NewFlagSet("plan rebuild", flag.ContinueOnError)
	from := fs.String("from", "", "snapshot directory")
	out := fs.String("out", "", "file to write (default: stdout)")
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
	if s.Platform != "kubernetes" {
		return fail(fmt.Errorf("plan rebuild: %s is a %s snapshot; the plan is for kubernetes snapshots", *from, s.Platform))
	}
	p := kube.RebuildPlan(s)
	if jsonOut {
		emit(map[string]any{"schema": jsonSchema, "command": "plan", "plan": p})
		return 0
	}
	text := planMarkdown(p, filepath.Base(filepath.Clean(*from)))
	if *out == "" {
		_, err = os.Stdout.WriteString(text)
	} else {
		err = os.WriteFile(*out, []byte(text), 0o644)
	}
	if err != nil {
		return fail(err)
	}
	return 0
}

// planShown is how many of a long list a row names before it counts the rest.
const planShown = 3

// planMarkdown is the plan for a person, in the order to act on it.
// Nothing time- or machine-dependent goes in: an unchanged snapshot gives
// an unchanged plan.
func planMarkdown(p kube.Plan, title string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	fromStore := 0
	for _, it := range p.FromStore {
		fromStore += len(it.Secrets)
	}
	w("# %s: rebuild plan\n\n", md(title))
	w("What rebuilding a cluster from this snapshot needs that the snapshot does not hold. Read from the snapshot alone: nothing was contacted, and no secret value is in it or here.\n\n")
	w("| Step | | |\n|---|---|---:|\n")
	w("| 1 | Install what a GitOps source makes | %d sources |\n", len(p.Sources))
	w("| 2 | Have these APIs served before the restore | %d groups |\n", len(p.Operators))
	w("| 3 | Supply by hand the secrets no store holds | %d secrets |\n", len(p.ByHand))
	w("| 4 | Make the secret store reachable | %d items feed %d secrets |\n", len(p.FromStore), fromStore)
	w("| 5 | Restore the snapshot | |\n")
	w("| 6 | Point the names at the rebuilt cluster | %d hosts |\n\n", len(p.Hosts))

	w("## 1. Install first: %d sources\n\n", len(p.Sources))
	if len(p.Sources) == 0 {
		w("The capture left nothing to a GitOps source: everything it found is in the snapshot.\n\n")
	} else {
		w("The capture left these out because their source recreates them. The snapshot holds neither the source nor what it makes.\n\n")
		w("| Source | Objects it makes |\n|---|---:|\n")
		for _, s := range p.Sources {
			w("| %s `%s` | %d |\n", s.Kind, md(s.Name), s.Objects)
		}
		if p.OriginRecorded {
			w("\nThe snapshot holds where they are read from (the repository objects).\n\n")
		} else {
			w("\n**Not in the snapshot: where they are read from.** The repository, branch and path the cluster was bootstrapped from, and the credential to read them, have to come from your own records.\n\n")
		}
	}

	w("## 2. APIs to have served: %d groups\n\n", len(p.Operators))
	if len(p.Operators) == 0 {
		w("Every type in the snapshot is built in, or its definition is in the snapshot.\n\n")
	} else {
		w("The snapshot has objects of these types and not their definitions: the restore refuses them until an operator from step 1 serves the type.\n\n")
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
			w("| `%s` | %s |\n", md(o.Group), md(strings.Join(kinds, ", ")))
		}
		w("\n")
	}

	w("## 3. Secrets to supply by hand: %d\n\n", len(p.ByHand))
	if len(p.ByHand) == 0 {
		w("Every Secret in the snapshot is made from a store.\n\n")
	} else {
		w("No store in the snapshot supplies these, and a snapshot never holds a value. Each needs its value from where you keep it. One that nothing in the snapshot uses may still be read by what step 1 installs.\n\n")
		w("| Secret | Keys | Used by |\n|---|---|---|\n")
		for _, s := range p.ByHand {
			w("| `%s/%s` | %s | %s |\n", md(s.Namespace), md(s.Name), md(some(s.Keys)), md(some(s.UsedBy)))
		}
		w("\n")
	}

	if len(p.Reissued) > 0 {
		w("Not for you to supply: %d that cert-manager issues again once it runs (%s).\n\n", len(p.Reissued), md(strings.Join(p.Reissued, ", ")))
	}

	w("## 4. Secrets a store supplies: %d, from %d items\n\n", fromStore, len(p.FromStore))
	if len(p.FromStore) == 0 {
		w("The snapshot has no object that reads a secret store.\n\n")
	} else {
		w("The restore recreates the objects that ask for these; the store's operator then makes the Secrets. That needs the store reachable from the rebuilt cluster, and the operator's own credential, which is one of step 3's. An item holds the settings of the cluster it was written for: one that feeds many Secrets is where to look for addresses and keys that must differ in a rebuild.\n\n")
		w("| Store | Item | Secrets | |\n|---|---|---:|---|\n")
		for _, it := range p.FromStore {
			w("| %s | `%s` | %d | %s |\n", md(it.Store), md(it.Item), len(it.Secrets), md(some(it.Secrets)))
		}
		w("\n")
	}

	w("## 5. Restore\n\n")
	w("`truthform restore --context <kube-context> --from <this snapshot>`, once steps 1 to 4 are in place.\n\n")

	w("## 6. Names to point at the rebuilt cluster: %d\n\n", len(p.Hosts))
	if len(p.Hosts) == 0 {
		w("No route in the snapshot names a host.\n")
	} else {
		w("The routes in the snapshot answer to these. Their DNS records point at the cluster the snapshot was taken from.\n\n")
		for _, h := range p.Hosts {
			w("- `%s`\n", md(h))
		}
	}
	return b.String()
}

// some lists the first few of a sorted list and counts the rest.
func some(l []string) string {
	if len(l) <= planShown {
		return strings.Join(l, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(l[:planShown], ", "), len(l)-planShown)
}
