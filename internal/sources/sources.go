// Package sources reads a secret sources file: for each Secret a rebuild
// has to be given, where its value is read from when the rebuild runs. The
// file holds references and never a value, so it can be kept in a
// repository beside the pipeline that uses it. A value is read from where
// the reference says, handed to the restore, and written nowhere.
package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	yaml "go.yaml.in/yaml/v3"
)

// File is a secret sources file.
type File struct {
	Secrets []Entry `yaml:"secrets" json:"secrets"`
}

// Entry is one Secret: where each of its keys is read from, or why the
// rebuild leaves it to something else.
type Entry struct {
	// Secret is namespace/name.
	Secret string `yaml:"secret" json:"secret"`
	// From is a reference for each key.
	From map[string]string `yaml:"from,omitempty" json:"from,omitempty"`
	// Leave says what makes the Secret, so that the rebuild does not: a
	// controller the plan could not tell makes it again.
	Leave string `yaml:"leave,omitempty" json:"leave,omitempty"`
}

// schemes are the kinds of reference, and what each reads.
var schemes = map[string]string{
	"op":      "op://<vault>/<item>/<field>: 1Password, read with the op CLI",
	"azurekv": "azurekv://<vault>/<secret>[/<version>]: Azure Key Vault, read with the az CLI",
	"env":     "env:<NAME>: an environment variable",
	"file":    "file:<path>: a file's whole content",
	"exec":    "exec:<command>: a command's output, with --allow-exec",
	"empty":   "empty: the empty value, for a key that holds nothing",
}

// Schemes are the kinds of reference, for a message.
func Schemes() []string {
	out := make([]string, 0, len(schemes))
	for _, s := range schemes {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// scheme splits a reference into its kind and the rest.
func scheme(ref string) (kind, rest string, err error) {
	if ref == "empty:" {
		return "empty", "", nil
	}
	if strings.HasPrefix(ref, "file://") {
		return "", "", fmt.Errorf("a file: reference takes a path (file:/etc/x), not a URL")
	}
	for _, sep := range []string{"://", ":"} {
		if k, r, ok := strings.Cut(ref, sep); ok && schemes[k] != "" && k != "empty" {
			if (sep == "://") != (k == "op" || k == "azurekv") {
				continue
			}
			if strings.TrimSpace(r) == "" {
				return "", "", fmt.Errorf("%q names nothing to read", ref)
			}
			return k, r, nil
		}
	}
	// Not repeated: what is no reference may be a value put in the file by
	// mistake.
	return "", "", fmt.Errorf("what is given (%d characters) is not a reference this reads (%s)", len(ref), strings.Join(Schemes(), "; "))
}

// Read reads and checks a sources file. A reference left empty is read as
// it is: Check says which those are.
func Read(path string) (File, error) {
	var f File
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		if err == io.EOF {
			return f, fmt.Errorf("%s: is empty; a sources file has a secrets list", path)
		}
		return f, fmt.Errorf("%s: %s", path, unechoed(err))
	}
	if dec.Decode(new(any)) != io.EOF {
		return f, fmt.Errorf("%s: holds more than one YAML document; only one is read, so the rest would be ignored", path)
	}
	seen := map[string]bool{}
	for i, e := range f.Secrets {
		ns, name, ok := strings.Cut(e.Secret, "/")
		switch {
		case !ok || ns == "" || name == "" || strings.ContainsAny(e.Secret, "*\n\r") || strings.Contains(name, "/"):
			// By its place: what is there may not be a name at all.
			return f, fmt.Errorf("%s: entry %d: secret is not namespace/name", path, i+1)
		case seen[e.Secret]:
			return f, fmt.Errorf("%s: %s is listed twice", path, e.Secret)
		case e.Leave != "" && len(e.From) > 0:
			return f, fmt.Errorf("%s: %s has both from and leave; a Secret is supplied or left, not both", path, e.Secret)
		case e.Leave == "" && len(e.From) == 0:
			return f, fmt.Errorf("%s: %s has neither from nor leave", path, e.Secret)
		}
		seen[e.Secret] = true
		for key, ref := range e.From {
			if key == "" {
				return f, fmt.Errorf("%s: %s has a reference for a key with no name", path, e.Secret)
			}
			if ref == "" {
				continue
			}
			kind, rest, err := scheme(ref)
			if err == nil {
				// Its shape too, here and not only when it is read: a check
				// that reads nothing still says a reference is no good.
				err = shape(kind, rest)
			}
			if err != nil {
				return f, fmt.Errorf("%s: %s, key %s: %w", path, e.Secret, key, err)
			}
		}
	}
	return f, nil
}

// lineOf finds where yaml says an error is.
var lineOf = regexp.MustCompile(`line \d+`)

// unknownField is the one kind of type error that repeats a field's name
// and never its content.
var unknownField = regexp.MustCompile(`^line \d+: field \S+ not found`)

// unechoed is a YAML error without what the file holds: yaml quotes the
// text it could not read as the type wanted, and that text may be a value
// put where a reference goes.
func unechoed(err error) string {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		if l := lineOf.FindString(err.Error()); l != "" {
			return l + ": not YAML this can read"
		}
		return "not YAML this can read"
	}
	var out []string
	for _, e := range te.Errors {
		switch {
		case unknownField.MatchString(e):
			out = append(out, unknownField.FindString(e)+" in a sources file (secret, from, leave)")
		case lineOf.MatchString(e):
			out = append(out, lineOf.FindString(e)+": not what a sources file has there (a secrets list; in each, secret, and from as key: reference, or leave)")
		default:
			out = append(out, "not what a sources file has")
		}
	}
	return strings.Join(out, "; ")
}

// Entry returns the entry for a Secret, if the file has one.
func (f File) Entry(secret string) (Entry, bool) {
	for _, e := range f.Secrets {
		if e.Secret == secret {
			return e, true
		}
	}
	return Entry{}, false
}

// Needed is a Secret a rebuild has to be given, and its keys.
type Needed struct {
	Secret string
	Keys   []string
	// Note is what the plan says of it, written beside it in a skeleton.
	Note string
}

// Skeleton is a sources file for the Secrets needed, every reference empty.
func Skeleton(needed []Needed) []byte {
	var b strings.Builder
	b.WriteString("# Where a rebuild reads each Secret's value from. References only: no value\n")
	b.WriteString("# belongs in this file. A reference is one of:\n")
	for _, s := range Schemes() {
		b.WriteString("#   " + s + "\n")
	}
	b.WriteString("# A Secret that something in the cluster makes is given no reference:\n")
	b.WriteString("# replace its \"from\" with  leave: <what makes it>.\n")
	if len(needed) == 0 {
		b.WriteString("secrets: []\n")
		return []byte(b.String())
	}
	b.WriteString("secrets:\n")
	for _, n := range needed {
		if len(n.Keys) == 0 {
			continue // nothing withheld: nothing to give a source
		}
		if n.Note != "" {
			// One line whatever it holds: a note is made of what the
			// cluster's objects say, and a line break in one would end the
			// comment and begin an entry of its author's.
			note := strings.Map(func(r rune) rune {
				if unicode.IsControl(r) || r == '\u0085' || r == '\u2028' || r == '\u2029' {
					return ' '
				}
				return r
			}, n.Note)
			b.WriteString("  # " + note + "\n")
		}
		q, _ := json.Marshal(n.Secret)
		b.WriteString("  - secret: " + string(q) + "\n    from:\n")
		for _, k := range n.Keys {
			q, _ := json.Marshal(k)
			b.WriteString("      " + string(q) + ": \"\"\n")
		}
	}
	return []byte(b.String())
}

// Check says where the file does not cover what is needed: a Secret with
// no entry, a key with no reference, a key the Secret does not have. held
// are the Secrets of the snapshot and the keys each has withheld: an entry
// may name one that is not needed (to give a value to what a controller
// would make), and then has to give every key, as a restore takes a
// Secret's values from one place. The second list is of what is not wrong
// and worth saying: an entry for a Secret the snapshot does not hold.
func Check(f File, needed []Needed, held map[string][]string) (problems, notes []string) {
	need := map[string]bool{}
	for _, n := range needed {
		need[n.Secret] = true
		if _, ok := f.Entry(n.Secret); !ok {
			problems = append(problems, n.Secret+": no entry; the rebuild has no source for it")
		}
	}
	for _, e := range f.Secrets {
		keys, ok := held[e.Secret]
		if !ok {
			notes = append(notes, e.Secret+": not a Secret in the snapshot; the entry is not used")
			continue
		}
		if e.Leave != "" {
			continue
		}
		has := map[string]bool{}
		for _, k := range keys {
			has[k] = true
			if ref, ok := e.From[k]; !ok {
				problems = append(problems, e.Secret+": key "+k+" has no reference")
			} else if ref == "" {
				problems = append(problems, e.Secret+": the reference for key "+k+" is empty")
			}
		}
		extra := []string{}
		for k := range e.From {
			if !has[k] {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		for _, k := range extra {
			problems = append(problems, e.Secret+": names key "+k+", which the Secret in the snapshot does not have")
		}
	}
	return problems, notes
}

// Resolver reads the value a reference names.
type Resolver struct {
	// AllowExec lets an exec: reference run its command.
	AllowExec bool
	// Run runs a program and returns its output; nil runs it for real.
	Run func(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)

	cache map[string][]byte
}

// timeout is how long one read may take: a CLI waiting for a sign-in that
// nobody is there to give must not hang a rebuild.
const timeout = 2 * time.Minute

func run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	return runFor(ctx, timeout, name, args...)
}

func runFor(ctx context.Context, limit time.Duration, name string, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	// With what it started: a pipeline's other commands hold its output
	// open, and killing the shell alone left the read waiting for them.
	wholeGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, nil, fmt.Errorf("%w in %s", errNoAnswer, limit)
	}
	return out.Bytes(), errb.Bytes(), err
}

var errNoAnswer = errors.New("gave no answer")

// azureName is what Azure Key Vault lets a vault, a secret or a version
// be called.
var azureName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,126}$`)

// opName is what a vault, an item, a section or a field can be called in
// a 1Password reference (anything else is given by its ID, which fits
// too), and opQuery the question that may follow (?attribute=otp).
var (
	opName   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9 ._-]{0,254}$`)
	opOption = regexp.MustCompile(` -[^ ]`)
	opQuery  = regexp.MustCompile(`^[a-z-]{1,32}=[A-Za-z0-9_-]{1,64}$`)
)

// shape checks a reference that is given to a CLI, before any is run:
// where the CLI is a script (az on Windows, op behind a wrapper), what it
// is given passes through a shell. The error shows the reference with
// what is not a name left out, which may be a command.
func shape(kind, rest string) error {
	switch kind {
	case "op":
		if shown, ok := opReference(rest); !ok {
			return fmt.Errorf("%s: a 1Password reference is op://<vault>/<item>/[<section>/]<field>, each named with letters, digits, spaces, dots, dashes and underscores (and no word that begins with a dash); give anything else by its ID", shown)
		}
	case "azurekv":
		parts := strings.Split(rest, "/")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("%s: an Azure Key Vault reference is azurekv://<vault>/<secret>[/<version>]", azureShown(parts))
		}
		for _, part := range parts {
			if part != "" && !azureName.MatchString(part) {
				return fmt.Errorf("%s: an Azure Key Vault reference names a vault, a secret and a version with letters, digits and dashes", azureShown(parts))
			}
		}
	}
	return nil
}

// opReference checks what follows op:// and gives the reference as a
// message may show it: what in it is a name, and not what is not, which
// may be a command.
func opReference(rest string) (shown string, ok bool) {
	path, query, asked := strings.Cut(rest, "?")
	parts := strings.Split(path, "/")
	ok = len(parts) == 3 || len(parts) == 4
	for i, part := range parts {
		// A word that begins with a dash would read as an option to a
		// script that splits what it is given on spaces. A dash that stands
		// alone ("AWS - prod") is a name's.
		if !opName.MatchString(part) || opOption.MatchString(part) {
			parts[i], ok = "…", false
		}
	}
	shown = "op://" + strings.Join(parts, "/")
	if asked {
		if opQuery.MatchString(query) {
			shown += "?" + query
		} else {
			shown, ok = shown+"?…", false
		}
	}
	return shown, ok
}

// azureShown is a refused reference for a message: what in it is a name,
// and not what is not, which may be a command.
func azureShown(parts []string) string {
	for i, part := range parts {
		if part != "" && !azureName.MatchString(part) {
			parts[i] = "…"
		}
	}
	return "azurekv://" + strings.Join(parts, "/")
}

// Resolve reads the value. An error names the reference and never holds
// any of what was read.
func (r *Resolver) Resolve(ctx context.Context, ref string) ([]byte, error) {
	if v, ok := r.cache[ref]; ok {
		return v, nil
	}
	kind, rest, err := scheme(ref)
	if err != nil {
		return nil, err
	}
	exe := r.Run
	if exe == nil {
		exe = run
	}
	v := []byte{}
	switch kind {
	case "env":
		s, ok := os.LookupEnv(rest)
		if !ok {
			return nil, fmt.Errorf("%s: the environment variable is not set", ref)
		}
		v = []byte(s)
	case "file":
		if v, err = os.ReadFile(rest); err != nil {
			return nil, fmt.Errorf("%s: %w", ref, err)
		}
	case "op":
		// Checked before op is run, as a Key Vault reference is: where op
		// is a script (a wrapper, a package manager's shim on Windows),
		// what it is given passes through a shell.
		if err := shape(kind, rest); err != nil {
			return nil, err
		}
		out, stderr, err := exe(ctx, "op", "read", "--no-newline", ref)
		if err != nil {
			return nil, failed(ref, "op", err, stderr)
		}
		v = out
	case "azurekv":
		if err := shape(kind, rest); err != nil {
			return nil, err
		}
		parts := strings.Split(rest, "/")
		args := []string{"keyvault", "secret", "show", "--vault-name", parts[0], "--name", parts[1], "--query", "value", "--output", "json"}
		if len(parts) == 3 && parts[2] != "" {
			args = append(args, "--version", parts[2])
		}
		out, stderr, err := exe(ctx, "az", args...)
		if err != nil {
			return nil, failed(ref, "az", err, stderr)
		}
		// As JSON, so that a value of several lines is the value and not
		// what a table of it looks like.
		var s string
		if json.Unmarshal(out, &s) != nil {
			return nil, fmt.Errorf("%s: az did not answer with the secret's value", ref)
		}
		v = []byte(s)
	case "exec":
		if !r.AllowExec {
			return nil, fmt.Errorf("%s: an exec: reference runs a command, and is read only with --allow-exec", execShown(ref))
		}
		out, _, err := exe(ctx, shell, shellFlag, rest)
		if err != nil {
			// Not its stderr: a command of the user's own may print what
			// it read.
			return nil, fmt.Errorf("%s: the command failed (%v); run it yourself to see why", execShown(ref), err)
		}
		// The line end a command prints after its answer is not the value.
		out = bytes.TrimSuffix(out, []byte("\n"))
		v = bytes.TrimSuffix(out, []byte("\r"))
	}
	if len(v) == 0 && kind != "empty" {
		return nil, fmt.Errorf("%s: read, and empty (a key that holds nothing is given  empty:)", execShown(ref))
	}
	if r.cache == nil {
		r.cache = map[string][]byte{}
	}
	r.cache[ref] = v
	return v, nil
}

// execShown is a reference for a message. A command is not shown at all:
// any part of it may be a credential of its own, and the message names
// the Secret and the key it is for.
func execShown(ref string) string {
	if strings.HasPrefix(ref, "exec:") {
		return "exec: (the command is not shown)"
	}
	return ref
}

// failed is an error for a CLI that did not answer: its own first line of
// complaint, which says a sign-in is missing or an item is not there.
func failed(ref, cli string, err error, stderr []byte) error {
	if ee, ok := err.(*exec.Error); ok && ee.Err == exec.ErrNotFound {
		return fmt.Errorf("%s: the %s CLI is not installed or not on the PATH", ref, cli)
	}
	if errors.Is(err, errNoAnswer) {
		return fmt.Errorf("%s: %s %v; is it signed in?", ref, cli, err)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(stderr)), "\n")
	if r := []rune(line); len(r) > 200 {
		line = string(r[:200]) + "…"
	}
	if line == "" {
		line = err.Error()
	}
	return fmt.Errorf("%s: %s: %s", ref, cli, line)
}
