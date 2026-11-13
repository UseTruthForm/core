package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/snapshot"
	"github.com/usetruthform/core/internal/sources"
)

// secretsNeeded are the Secrets of a snapshot that a rebuild has to be
// given (the plan's by-hand list), and every Secret the snapshot holds.
func secretsNeeded(s snapshot.Snapshot, p kube.Plan) (needed []sources.Needed, held map[string][]string) {
	for _, b := range p.ByHand {
		if len(b.Keys) == 0 {
			continue // nothing withheld: the restore applies it as it is
		}
		note := b.Note
		if note == "" && len(b.UsedBy) > 0 {
			note = "used by " + some(b.UsedBy)
		}
		needed = append(needed, sources.Needed{Secret: b.Namespace + "/" + b.Name, Keys: b.Keys, Note: note})
	}
	held = map[string][]string{}
	for _, o := range s.Objects {
		if o.Kind() == "Secret" && o.APIVersion() == "v1" {
			keys := []string{}
			for _, field := range []string{"data", "stringData"} {
				m, _ := o.Body[field].(map[string]any)
				for k := range m {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			held[o.Namespace()+"/"+o.Name()] = keys
		}
	}
	return needed, held
}

// planSecrets writes a secret sources file to fill in, or checks one
// against the snapshot: that every Secret a rebuild has to be given has
// somewhere to be read from. With --resolve each is read, and nothing
// read is printed.
func planSecrets(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("plan secrets", flag.ContinueOnError)
	from := fs.String("from", "", "snapshot directory")
	out := fs.String("out", "", "write a sources file to fill in (never over one that is there; default: stdout)")
	check := fs.String("check", "", "sources file to check against the snapshot")
	scope := fs.String("scope", "", scopeHelp)
	resolve := fs.Bool("resolve", false, "with --check: read every value from its source too, and print none")
	allowExec := fs.Bool("allow-exec", false, allowExecHelp)
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	switch {
	case *from == "" || fs.NArg() > 0:
		return fail(fmt.Errorf("plan secrets: --from is required and no positional arguments are accepted"))
	case *check != "" && *out != "":
		return fail(fmt.Errorf("plan secrets: --out writes a file to fill in and --check reads one; give one of them"))
	case *check == "" && (*resolve || *allowExec):
		return fail(fmt.Errorf("plan secrets: --resolve and --allow-exec are for --check"))
	case *allowExec && !*resolve:
		return fail(fmt.Errorf("plan secrets: --allow-exec is for --resolve; a check without it runs nothing"))
	case *check == "" && jsonOut:
		return fail(fmt.Errorf("plan secrets: --json is for --check; the file to fill in is YAML"))
	}
	s, err := snapshot.Read(*from)
	if err != nil {
		return fail(err)
	}
	if s.Platform != "kubernetes" {
		return fail(fmt.Errorf("plan secrets: %s is a %s snapshot; secret sources are for kubernetes snapshots", *from, s.Platform))
	}
	if s, err = scoped(*scope, s.Platform, s); err != nil {
		return fail(err)
	}
	needed, known := secretsNeeded(s, kube.RebuildPlan(s))
	settings := settingsNeeded(s)
	// What the capture could not read may hold Secrets to supply: neither
	// a file to fill in nor a check of one can know of them.
	notRead := gaps(s)
	if *check == "" {
		if len(notRead) > 0 {
			fmt.Fprintf(os.Stderr, "INCOMPLETE SNAPSHOT: its capture could not read %d things, and the file lists no Secret that is in them; see REPORT.md\n", len(notRead))
		}
		text := append(sources.Skeleton(needed), sources.SettingsSkeleton(settings)...)
		if *out == "" {
			_, err = os.Stdout.Write(text)
			return failIf(err)
		}
		// Never over a file: what is there may be filled in.
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			return fail(fmt.Errorf("plan secrets: %s is there already; check it against the snapshot with --check", *out))
		}
		if err != nil {
			return fail(err)
		}
		if _, err = f.Write(text); err == nil {
			err = f.Close()
		}
		return failIf(err)
	}

	file, err := sources.Read(*check)
	if err != nil {
		return fail(err)
	}
	problems, notes := sources.Check(file, needed, known)
	lacking, unused := sources.CheckSettings(file, settings)
	problems = append(problems, lacking...)
	notes = append(notes, unused...)
	unread, unsure := secretsUnread(s, notRead)
	problems = append(problems, unread...)
	notes = append(notes, unsure...)
	read := 0
	if *resolve {
		r := &sources.Resolver{AllowExec: *allowExec}
		for _, e := range file.Secrets {
			if _, held := known[e.Secret]; !held {
				continue
			}
			for _, k := range sortedKeys(e.From) {
				if e.From[k] == "" {
					continue
				}
				if _, err := r.Resolve(ctx, e.From[k]); err != nil {
					problems = append(problems, e.Secret+": key "+k+": "+err.Error())
				} else {
					read++
				}
			}
		}
	}
	if *resolve {
		r := &sources.Resolver{AllowExec: *allowExec}
		wanted := map[string]bool{}
		for _, n := range settings {
			wanted[n.Object] = true
		}
		for _, e := range file.Settings {
			if !wanted[e.Object] {
				continue
			}
			for _, at := range sortedKeys(e.From) {
				if e.From[at] == "" {
					continue
				}
				if _, err := r.Resolve(ctx, e.From[at]); err != nil {
					problems = append(problems, e.Object+": "+at+": "+err.Error())
				} else {
					read++
				}
			}
		}
	}
	if jsonOut {
		doc := map[string]any{"schema": jsonSchema, "command": "plan", "secrets": map[string]any{
			"settings": len(settings),
			"needed":   len(needed), "problems": orEmpty(problems), "notes": orEmpty(notes), "resolved": *resolve, "read": read,
		}, "gaps": orEmpty(notRead)}
		if scopeDone != nil {
			doc["scope"] = scopeDone
		}
		emit(doc)
	} else {
		for _, p := range problems {
			fmt.Println("NO SOURCE  " + p)
		}
		for _, n := range notes {
			fmt.Println("note       " + n)
		}
		switch {
		case len(problems) > 0:
			fmt.Printf("%d problems: a rebuild from %s would lack these (%d Secrets to supply, %d objects with settings withheld)\n", len(problems), *from, len(needed), len(settings))
		case *resolve:
			fmt.Printf("every one of the %d Secrets to supply has a source, and %d values were read from theirs (none printed)\n", len(needed), read)
		case len(s.Coverage) == 0:
			// Not the line of a snapshot known to be whole.
			fmt.Printf("every one of the %d Secrets to supply that the snapshot holds has a source; the snapshot does not record whether its capture read every Secret\n", len(needed))
		default:
			fmt.Printf("every one of the %d Secrets to supply has a source; --resolve reads each to prove it answers\n", len(needed))
		}
	}
	if !jsonOut && len(settings) > 0 && len(problems) == 0 {
		fmt.Printf("and each of the %d objects with credentials withheld from its settings has a source for every one\n", len(settings))
	}
	if len(problems) > 0 {
		return 2
	}
	return 0
}

// settingsNeeded are the objects of a snapshot that are not Secrets and
// had credentials withheld from them: a rebuild has to be given each.
func settingsNeeded(s snapshot.Snapshot) []sources.NeededSetting {
	var out []sources.NeededSetting
	for _, w := range kube.WithheldSettings(s) {
		out = append(out, sources.NeededSetting{Object: w.Key, Paths: w.Paths})
	}
	return out
}

// secretsUnread says what of a snapshot's capture bears on a check of its
// Secrets. Secrets it did not read are a problem: one to supply may be
// among them, and no file can be checked against what was not read.
// Another type it could not read is a note: at worst a Secret is listed
// for a person that something unread makes. A snapshot that does not say
// what its capture read is a note too.
func secretsUnread(s snapshot.Snapshot, notRead []string) (problems, notes []string) {
	const secrets = "core/v1/secrets"
	said := false
	for _, g := range notRead {
		if strings.HasPrefix(g, secrets+":") || strings.HasPrefix(g, secrets+" ") {
			problems = append(problems, "the capture could not read "+g+": a Secret to supply may be in it, and no file can be checked against what was not read")
			said = true
		} else {
			notes = append(notes, "the capture could not read "+g+": if that makes Secrets, some listed here for you to supply are made for you")
		}
	}
	if len(s.Coverage) == 0 {
		return problems, append(notes, "the snapshot does not record what its capture read: whether it read every Secret is not known")
	}
	row := false
	for _, c := range s.Coverage {
		if c.Resource != secrets {
			continue
		}
		row = true
		if c.NotCaptured != "" && !said {
			problems = append(problems, "the capture did not read Secrets ("+c.NotCaptured+"): no file can be checked against what was not read")
		}
	}
	if !row {
		problems = append(problems, "the snapshot's record of what its capture read has no row for Secrets: whether it read them is not known")
	}
	return problems, notes
}

const allowExecHelp = "let exec: references in the sources file run their commands"

func failIf(err error) int {
	if err != nil {
		return fail(err)
	}
	return 0
}

func orEmpty(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// withSecretSources prepares a Kubernetes restore to read withheld values
// as a sources file says. Before anything is written to the cluster it
// checks the file against the snapshot and reads every value, so that a
// rebuild does not stop half way for a sign-in that was missing. It
// returns the snapshot without the Secrets left to what makes them: the
// file's "leave" entries, and, unless another cluster supplies them
// (fromContext), what the plan says a store or a controller makes.
func withSecretSources(ctx context.Context, snap snapshot.Snapshot, path string, allowExec, fromContext bool) (snapshot.Snapshot, kube.RestoreOptions, []string, error) {
	var opt kube.RestoreOptions
	file, err := sources.Read(path)
	if err != nil {
		return snap, opt, nil, err
	}
	plan := kube.RebuildPlan(snap)
	needed, known := secretsNeeded(snap, plan)
	if fromContext {
		// A Secret the file does not name is read from the other cluster.
		needed = nil
	}
	settings := settingsNeeded(snap)
	if fromContext {
		// An object the file does not name is read from the other cluster.
		// One it names is still checked: named, it is filled from the file
		// alone, and a place the file misses would stop the restore at
		// that object, with others already written.
		var named []sources.NeededSetting
		for _, n := range settings {
			if _, ok := file.Setting(n.Object); ok {
				named = append(named, n)
			}
		}
		settings = named
	}
	problems, _ := sources.Check(file, needed, known)
	lacking, _ := sources.CheckSettings(file, settings)
	if problems = append(problems, lacking...); len(problems) > 0 {
		return snap, opt, nil, fmt.Errorf("--secrets-from %s does not cover the snapshot; nothing was restored:\n   %s", path, strings.Join(problems, "\n   "))
	}

	// What something else makes: by the file, then by the plan.
	leave := map[string]string{}
	if !fromContext {
		for _, m := range plan.Reissued {
			leave[m.Secret] = m.By
		}
		for _, it := range plan.FromStore {
			for _, sec := range it.Secrets {
				leave[sec] = "the store (" + it.Store + ")"
			}
		}
		for _, e := range plan.Encrypted {
			for _, sec := range e.Secrets {
				leave[sec] = e.By
			}
		}
	}
	values := map[string]map[string][]byte{}
	r := &sources.Resolver{AllowExec: allowExec}
	var failed []string
	for _, e := range file.Secrets {
		if _, held := known[e.Secret]; !held {
			continue
		}
		if e.Leave != "" {
			leave[e.Secret] = e.Leave
			continue
		}
		values[e.Secret] = map[string][]byte{}
		for _, k := range sortedKeys(e.From) {
			v, err := r.Resolve(ctx, e.From[k])
			if err != nil {
				failed = append(failed, e.Secret+": key "+k+": "+err.Error())
				continue
			}
			values[e.Secret][k] = v
		}
	}
	withheld := map[string]bool{}
	for _, w := range kube.WithheldSettings(snap) {
		withheld[w.Key] = true
	}
	given := map[string]map[string]string{}
	for _, e := range file.Settings {
		if !withheld[e.Object] {
			continue
		}
		given[e.Object] = map[string]string{}
		for _, at := range sortedKeys(e.From) {
			v, err := r.Resolve(ctx, e.From[at])
			if err == nil && !utf8.Valid(v) {
				// A setting is text in the object; a Secret's value is not.
				err = fmt.Errorf("%s: what was read is not text, and a setting is", e.From[at])
			}
			if err != nil {
				failed = append(failed, e.Object+": "+at+": "+err.Error())
				continue
			}
			given[e.Object][at] = string(v)
		}
	}
	if len(failed) > 0 {
		return snap, opt, nil, fmt.Errorf("--secrets-from %s: %d values could not be read; nothing was restored:\n   %s", path, len(failed), strings.Join(failed, "\n   "))
	}

	out := snap
	out.Objects = nil
	var left []string
	for _, o := range snap.Objects {
		if o.Kind() == "Secret" && o.APIVersion() == "v1" {
			key := o.Namespace() + "/" + o.Name()
			why, ok := leave[key]
			if !ok {
				// A ClusterExternalSecret's, in whichever namespace.
				why, ok = leave["*/"+o.Name()]
			}
			if _, given := values[key]; ok && !given {
				left = append(left, key+" ("+why+")")
				continue
			}
		}
		out.Objects = append(out.Objects, o)
	}
	sort.Strings(left)
	opt.Settings = func(_ context.Context, key string, _ []string) (map[string]string, bool, error) {
		v, ok := given[key]
		return v, ok, nil
	}
	opt.Values = func(_ context.Context, ns, name string, _ []string) (map[string][]byte, bool, error) {
		v, ok := values[ns+"/"+name]
		return v, ok, nil
	}
	return out, opt, left, nil
}
