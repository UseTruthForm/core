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

const scopeHelp = "kubernetes: scope file (truthform plan scope) saying which part of the snapshot is brought: it narrows the namespaces it names to the Helm releases, objects and labels chosen, and leaves the rest as it is (give diff and plan the same file)"

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
		what := "with nothing running"
		if len(rep.NotHeld)+len(rep.AsTheyAre) > 0 {
			what = "stopped"
		}
		fmt.Fprintf(&b, "\nscope: %d objects are brought %s (hold: true); restoring without the hold starts them:", len(rep.Held), what)
		for _, h := range rep.Held {
			fmt.Fprintf(&b, "\n   %s: %s", h.Object, h.How)
		}
	}
	if len(rep.NotHeld) > 0 {
		fmt.Fprintf(&b, "\nscope: NOTE: %d objects under hold: true are brought as they are, and not held. Nothing in one says it runs anything, but each is of an API this does not know to be idle: its controller may run something for it (an operator's database, a Spark application) or act outside the cluster (cert-manager asking for a certificate for the source's host names). Look at each, and leave out (--leave-out) what would, or name under asTheyAre in %s what may be brought as it is; until then the run does not end 0: %s", len(rep.NotHeld), file, strings.Join(rep.NotHeld, ", "))
	}
	if len(rep.AsTheyAre) > 0 {
		fmt.Fprintf(&b, "\nscope: %d objects under hold: true are brought as they are, and not held, as %s asks (asTheyAre): %s", len(rep.AsTheyAre), file, strings.Join(rep.AsTheyAre, ", "))
	}
	if len(rep.ObjectsBrought) > 0 {
		fmt.Fprintf(&b, "\nscope: %d objects that no release made are brought, named under objects or by label: %s", len(rep.ObjectsBrought), strings.Join(rep.ObjectsBrought, ", "))
	}
	if len(rep.ObjectsLeftOut) > 0 {
		fmt.Fprintf(&b, "\nscope: %d objects that no release made are left out (name one under objects, as Kind/name, to bring it): %s", len(rep.ObjectsLeftOut), strings.Join(rep.ObjectsLeftOut, ", "))
	}
	for _, n := range scopeNotes(rep) {
		b.WriteString("\nscope: NOTE: " + n)
	}
	if len(rep.SharedName) > 0 {
		fmt.Fprintf(&b, "\nscope: %d objects with no namespace are brought because a release of their name is, though another of that name is left out, and which made them they do not say (--leave-out holds one back): %s", len(rep.SharedName), strings.Join(rep.SharedName, "; "))
	}
	if rep.Kept < rep.Of {
		b.WriteString("\nscope: nothing checks that what is brought does not need something left out (a ServiceAccount, a ConfigMap, a CustomResourceDefinition)")
	}
	return b.String()
}

// scopeNotes are what a scope cannot do for the person who wrote it, and
// they have to know before a restore: each a sentence, said on stderr and
// in the rebuild plan.
func scopeNotes(rep kube.ScopeReport) []string {
	var out []string
	for _, m := range rep.StillMade {
		out = append(out, fmt.Sprintf("%s is brought, and makes %d objects in %s, which the scope narrows: once it runs they are there, whatever the scope chose. Leave the source out (--leave-out), or change what it applies.", m.Source, m.Objects, m.Namespace))
	}
	for _, w := range rep.Webhooks {
		what := "while nothing answers there, the API server goes on without it (failurePolicy Ignore), and what it would have checked or changed is not"
		if w.Fails {
			what = "while nothing answers there, the API server refuses every write the webhook is asked about"
		}
		if w.Webhook == "conversion" {
			what = "while nothing answers there, objects of that kind cannot be read or written in any version but the stored one"
		}
		if strings.HasPrefix(w.Configuration, "APIService ") {
			what = "while nothing answers there, its API is not there, and what lists every API (a namespace's deletion, for one) waits on it"
		}
		out = append(out, webhookNote(w, what))
	}
	return out
}

// notHeldCode is how a run ends when a hold brought what it does not know
// how to hold, and the scope file does not say a person looked at it: not
// 0, or a pipeline could not tell a hold that holds from one that passed
// an operator's database through. With none it is 0.
func notHeldCode(rep kube.ScopeReport, code int) int {
	if len(rep.NotHeld) > 0 || len(blocking(rep.Webhooks)) > 0 {
		return code
	}
	return 0
}

// blocking are the webhooks a restore is refused for: brought, failing
// closed, their Service not there, and not accepted in the scope file.
func blocking(hooks []kube.ScopeWebhook) []string {
	var out []string
	for _, w := range hooks {
		if w.Blocks {
			out = append(out, fmt.Sprintf("%s (%s) calls %s", w.Configuration, w.Webhook, w.Service))
		}
	}
	return out
}

// scopeLine is the scope in one line, for beside a total: "applied 5 of
// 5" would otherwise read as the whole snapshot.
func scopeLine() string {
	if scopeDone == nil {
		return ""
	}
	return fmt.Sprintf("a part only (--scope): %d of the %d objects of %s were in it", scopeDone.Kept, scopeDone.Of, strings.Join(scopeDone.Narrowed, ", "))
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
		return notHeldCode(rep, 2)
	}
	fmt.Println(scopeSaid(rep, *check))
	return notHeldCode(rep, 2)
}

// webhookNote is one webhook whose Service will not answer, for a person.
func webhookNote(w kube.ScopeWebhook, what string) string {
	which := "which is not brought, and no source that is brought makes it"
	bring := "bring what makes the Service"
	if w.Why == "held" {
		which = "which is brought with every workload behind it held (hold: true) or left out"
		bring = "bring what answers behind the Service, running"
	}
	how := "Either " + bring + ", or leave the webhook out (--leave-out)."
	switch {
	case w.Blocks:
		how = "A restore is refused while it is so: " + bring + ", leave the webhook out (--leave-out), or accept it by naming its configuration under withoutService in the scope file."
	case w.Accepted:
		how = "Accepted in the scope file (withoutService)."
	}
	return fmt.Sprintf("%s (%s) is brought, and calls the Service %s, %s: %s. %s", w.Configuration, w.Webhook, w.Service, which, what, how)
}

// refusedForWebhooks refuses a restore that brings an admission webhook
// failing closed with no Service to answer it. Webhooks are applied last,
// so the first restore would go through; from then on every write such a
// webhook is asked about is refused: a second run, a resume after a
// failure, an update, and whatever is done in the cluster next. With no
// scope the snapshot is read as it is, --leave-out applied.
func refusedForWebhooks(snap snapshot.Snapshot, scopeFile string) error {
	blockedBy = nil
	var hooks []kube.ScopeWebhook
	if scopeDone != nil {
		hooks = scopeDone.Webhooks
	} else {
		hooks = kube.WebhooksWithoutService(snap)
		for _, w := range hooks {
			if w.Blocks {
				fmt.Fprintln(os.Stderr, "restore: NOTE: "+webhookNote(w, "while nothing answers there, the API server refuses every write the webhook is asked about"))
			}
		}
	}
	b := blocking(hooks)
	if len(b) == 0 {
		return nil
	}
	blockedBy = hooks
	n, where := "admission webhooks are brought that fail closed, and the Service each calls", "a scope file given with --scope"
	if len(b) == 1 {
		n = "admission webhook is brought that fails closed, and the Service it calls"
	}
	if scopeFile != "" {
		where = scopeFile
	}
	return fmt.Errorf("%d %s will not answer: %s. The first restore would go through, since webhooks are applied last; every write such a webhook is asked about after it is refused (a second run, a resume, an update). Bring what answers at the Service, leave the webhook out (--leave-out), or accept it by naming its configuration under withoutService in %s; nothing was restored", len(b), n, strings.Join(b, "; "), where)
}

// blockedBy are the webhooks a restore was refused for, for the document.
var blockedBy []kube.ScopeWebhook
