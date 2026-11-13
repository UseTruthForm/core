package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/snapshot"
)

const scopeHelp = "kubernetes: scope file (truthform plan scope) saying which part of the snapshot is brought: it narrows the namespaces it names to the Helm releases and labels chosen, and leaves the rest as it is (give diff and plan the same file)"

// scopeDone is what --scope did to the snapshot, for the document; nil
// where none was given.
var scopeDone *kube.ScopeReport

// readScope reads a scope file. Strict: a key it does not know is a
// mistake, and would otherwise narrow less than was meant.
func readScope(file string) (kube.Scope, error) {
	var sc kube.Scope
	b, err := os.ReadFile(file)
	if err != nil {
		return sc, err
	}
	if err := yaml.UnmarshalStrict(b, &sc); err != nil {
		return sc, fmt.Errorf("%s: %w", file, err)
	}
	return sc, nil
}

// scoped applies --scope to a snapshot, and says on stderr what it left
// out: a restore that brought a part must not look like one that brought
// the whole.
func scoped(file, platform string, s snapshot.Snapshot) (snapshot.Snapshot, error) {
	scopeDone = nil
	if file == "" {
		return s, nil
	}
	if platform != "kubernetes" {
		return s, fmt.Errorf("--scope is for --platform kubernetes only")
	}
	sc, err := readScope(file)
	if err != nil {
		return s, err
	}
	out, rep, err := kube.Narrow(s, sc)
	if err != nil {
		return s, fmt.Errorf("%s: %w", file, err)
	}
	scopeDone = &rep
	fmt.Fprintln(os.Stderr, scopeSaid(rep, file))
	return out, nil
}

// scopeSaid is the report for a person.
func scopeSaid(rep kube.ScopeReport, file string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "scope: %d of the %d objects of %d narrowed namespaces are brought, as %s asks (%s)", rep.Kept, rep.Of, len(rep.Narrowed), file, strings.Join(rep.Narrowed, ", "))
	list := func(what string, l []kube.ScopedRelease) {
		if len(l) == 0 {
			return
		}
		fmt.Fprintf(&b, "\nscope: %d releases %s:", len(l), what)
		for _, r := range l {
			fmt.Fprintf(&b, "\n   %s (%d objects)", r.Release, r.Objects)
		}
	}
	list("brought", rep.Brought)
	list("left out", rep.LeftOut)
	if len(rep.Jobs) > 0 {
		fmt.Fprintf(&b, "\nscope: %d Jobs left out, those of a release brought among them: restored, a Job runs again (jobs: true brings them): %s", len(rep.Jobs), strings.Join(rep.Jobs, ", "))
	}
	if len(rep.Held) > 0 {
		fmt.Fprintf(&b, "\nscope: %d objects are brought with nothing running (hold: true); restoring without the hold starts them:", len(rep.Held))
		for _, h := range rep.Held {
			fmt.Fprintf(&b, "\n   %s: %s", h.Object, h.How)
		}
	}
	return b.String()
}

// planScope writes a scope file to cut down, or says what one brings and
// leaves out of a snapshot.
func planScope(args []string) int {
	fs := flag.NewFlagSet("plan scope", flag.ContinueOnError)
	from := fs.String("from", "", "snapshot directory")
	out := fs.String("out", "", "write a scope file to cut down (never over one that is there; default: stdout)")
	check := fs.String("check", "", "scope file to read against the snapshot")
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	switch {
	case *from == "" || fs.NArg() > 0:
		return fail(fmt.Errorf("plan scope: --from is required and no positional arguments are accepted"))
	case *check != "" && *out != "":
		return fail(fmt.Errorf("plan scope: --out writes a file to cut down and --check reads one; give one of them"))
	case *check == "" && jsonOut:
		return fail(fmt.Errorf("plan scope: --json is for --check; the file to cut down is YAML"))
	}
	s, err := snapshot.Read(*from)
	if err != nil {
		return fail(err)
	}
	if s.Platform != "kubernetes" {
		return fail(fmt.Errorf("plan scope: %s is a %s snapshot; a scope is for kubernetes snapshots", *from, s.Platform))
	}
	if *check == "" {
		text := kube.ScopeDraft(s)
		if *out == "" {
			_, err = os.Stdout.Write(text)
			return failIf(err)
		}
		// Never over a file: what is there may be cut down already.
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			return fail(fmt.Errorf("plan scope: %s is there already; read it against the snapshot with --check", *out))
		}
		if err != nil {
			return fail(err)
		}
		if _, err = f.Write(text); err == nil {
			err = f.Close()
		}
		if err == nil {
			fmt.Printf("wrote %s\n", *out)
		}
		return failIf(err)
	}
	sc, err := readScope(*check)
	if err != nil {
		return fail(err)
	}
	_, rep, err := kube.Narrow(s, sc)
	if err != nil {
		return fail(fmt.Errorf("%s: %w", *check, err))
	}
	if jsonOut {
		emit(map[string]any{"schema": jsonSchema, "command": "plan", "scope": rep})
		return 0
	}
	fmt.Println(scopeSaid(rep, *check))
	return 0
}
