package sources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func write(t *testing.T, text string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A sources file holds references and reasons, and is refused where it
// could be read two ways. A value put where a reference goes is refused
// without being repeated.
func TestReadRefusesWhatItCannotUse(t *testing.T) {
	f, err := Read(write(t, `secrets:
  - secret: flux-system/git
    from:
      password: op://Break Glass/git/password
      username: env:GIT_USER
      extra: "exec:az account show | jq -r .id"
      later: ""
  - secret: keda/certs
    leave: KEDA makes its own
`))
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := f.Entry("keda/certs"); !ok || e.Leave != "KEDA makes its own" || len(f.Secrets) != 2 {
		t.Errorf("read: %+v", f)
	}
	for text, want := range map[string]string{
		"secrets:\n  - secret: nonamespace\n    leave: x\n":                        "is not namespace/name",
		"secrets:\n  - secret: a/b/c\n    leave: x\n":                              "is not namespace/name",
		"secrets:\n  - secret: a/b\n    leave: x\n  - secret: a/b\n    leave: y\n": "listed twice",
		"secrets:\n  - secret: a/b\n    leave: x\n    from: {k: \"env:K\"}\n":      "both from and leave",
		"secrets:\n  - secret: a/b\n":                                              "neither from nor leave",
		"secrets:\n  - secret: a/b\n    from: {k: \"hunter2:letmein\"}\n":          "is not a reference this reads",
		"secrets:\n  - secret: a/b\n    from: {k: \"op:vault/item\"}\n":            "is not a reference this reads",
		"secrets:\n  - secret: a/b\n    from: {k: \"env:\"}\n":                     "names nothing to read",
		"secrets:\n  - secret: a/b\n    value: x\n":                                "field value not found",
		"secrets:\n  - secret: a/b\n    from: {k: \"vault://kv/x\"}\n":             "is not a reference this reads",
	} {
		_, err := Read(write(t, text))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", text, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("the error repeats what may be a value: %v", err)
		}
	}
}

// The skeleton names every Secret needed with each key empty, reads back,
// and fails the check until it is filled in.
func TestSkeletonReadsBackAndIsNotYetEnough(t *testing.T) {
	needed := []Needed{
		{Secret: "flux-system/git", Keys: []string{"password", "username"}, Note: "used by GitRepository/flux-system"},
		{Secret: "shop/odd: name", Keys: []string{"a.b", "yes"}},
	}
	p := write(t, string(Skeleton(needed)))
	f, err := Read(p)
	if err != nil {
		t.Fatalf("the skeleton does not read back: %v\n%s", err, Skeleton(needed))
	}
	if e, _ := f.Entry("shop/odd: name"); !reflect.DeepEqual(e.From, map[string]string{"a.b": "", "yes": ""}) {
		t.Errorf("keys: %+v", e)
	}
	problems, _ := Check(f, needed, nil)
	if len(problems) != 4 {
		t.Errorf("an empty skeleton passes: %v", problems)
	}
	if _, err := Read(write(t, string(Skeleton(nil)))); err != nil {
		t.Errorf("a skeleton of nothing: %v", err)
	}
}

// The check says what a rebuild would lack, and what in the file is unused.
func TestCheck(t *testing.T) {
	f := File{Secrets: []Entry{
		{Secret: "a/full", From: map[string]string{"k": "env:K", "j": "env:J"}},
		{Secret: "a/short", From: map[string]string{"k": "env:K"}},
		{Secret: "a/typo", From: map[string]string{"k": "env:K", "kk": "env:K"}},
		{Secret: "a/left", Leave: "a controller"},
		{Secret: "a/made", From: map[string]string{"k": ""}},
		{Secret: "a/gone", From: map[string]string{"k": "env:K"}},
	}}
	needed := []Needed{
		{Secret: "a/full", Keys: []string{"j", "k"}},
		{Secret: "a/short", Keys: []string{"j", "k"}},
		{Secret: "a/typo", Keys: []string{"k"}},
		{Secret: "a/left", Keys: []string{"k"}},
		{Secret: "a/absent", Keys: []string{"k"}},
	}
	problems, notes := Check(f, needed, map[string]bool{"a/made": true})
	wantProblems := []string{
		"a/short: key j has no reference",
		"a/typo: names key kk, which the Secret in the snapshot does not have",
		"a/absent: no entry; the rebuild has no source for it",
		"a/made: the reference for key k is empty",
	}
	if !reflect.DeepEqual(problems, wantProblems) {
		t.Errorf("problems:\n got %q\nwant %q", problems, wantProblems)
	}
	if !reflect.DeepEqual(notes, []string{"a/gone: not a Secret in the snapshot; the entry is not used"}) {
		t.Errorf("notes: %q", notes)
	}
}

// Each kind of reference is read as that kind is, and an error never holds
// what was read.
func TestResolve(t *testing.T) {
	ctx := context.Background()
	t.Setenv("SRC_TEST_VALUE", "from-env")
	t.Setenv("SRC_TEST_EMPTY", "")
	file := filepath.Join(t.TempDir(), "v")
	if err := os.WriteFile(file, []byte("line one\nline two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	r := &Resolver{Run: func(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
		calls = append(calls, append([]string{name}, args...))
		switch {
		case name == "op" && args[len(args)-1] == "op://v/missing/f":
			return []byte("partial-secret"), []byte("[ERROR] item not found\nmore"), errors.New("exit status 1")
		case name == "op":
			return []byte("from-op"), nil, nil
		case name == "az" && args[4] == "bad":
			return []byte("not json"), nil, nil
		case name == "az":
			return []byte("\"two\\nlines\"\n"), nil, nil
		}
		return nil, nil, errors.New("unexpected " + name)
	}}
	for ref, want := range map[string]string{
		"env:SRC_TEST_VALUE":   "from-env",
		"file:" + file:         "line one\nline two\n", // a file is its whole content
		"op://v/item/f":        "from-op",
		"azurekv://kv1/name":   "two\nlines",
		"azurekv://kv1/name/7": "two\nlines",
	} {
		got, err := r.Resolve(ctx, ref)
		if err != nil || string(got) != want {
			t.Errorf("%s: %q, %v", ref, got, err)
		}
	}
	// Read once: a second ask of the same reference runs nothing.
	n := len(calls)
	if _, err := r.Resolve(ctx, "op://v/item/f"); err != nil || len(calls) != n {
		t.Errorf("read again: %v, %d calls after %d", err, len(calls), n)
	}
	var sawVersion, sawNoNewline bool
	for _, c := range calls {
		line := strings.Join(c, " ")
		sawVersion = sawVersion || strings.Contains(line, "--vault-name kv1 --name name --query value --output json --version 7")
		sawNoNewline = sawNoNewline || line == "op read --no-newline op://v/item/f"
	}
	if !sawVersion || !sawNoNewline {
		t.Errorf("calls: %q", calls)
	}
	for ref, want := range map[string]string{
		"env:SRC_TEST_UNSET":   "is not set",
		"env:SRC_TEST_EMPTY":   "read, and empty",
		"file:/no/such/file":   "no such file",
		"op://v/missing/f":     "op: [ERROR] item not found",
		"azurekv://bad/name":   "did not answer with the secret's value",
		"azurekv://onlyvault":  "azurekv://<vault>/<secret>",
		"exec:printf x --p=zz": "only with --allow-exec",
	} {
		_, err := r.Resolve(ctx, ref)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", ref, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "partial-secret") || strings.Contains(err.Error(), "zz")) {
			t.Errorf("the error holds what was read or a command's arguments: %v", err)
		}
	}
}

// exec: runs the command for real, takes its output less the line end, and
// says nothing of what a failing command printed.
func TestResolveExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the commands here are sh's")
	}
	r := &Resolver{AllowExec: true}
	ctx := context.Background()
	if v, err := r.Resolve(ctx, "exec:printf 'a b\\n'"); err != nil || string(v) != "a b" {
		t.Errorf("exec: %q, %v", v, err)
	}
	if v, err := r.Resolve(ctx, "exec:printf 'a\\n\\n'"); err != nil || string(v) != "a\n" {
		t.Errorf("only the last line end goes: %q, %v", v, err)
	}
	_, err := r.Resolve(ctx, "exec:echo leaked-out; echo leaked-err >&2; exit 3")
	if err == nil || strings.Contains(err.Error(), "leaked") || !strings.Contains(err.Error(), "exit status 3") {
		t.Errorf("a failing command: %v", err)
	}
	if _, err := r.Resolve(ctx, "exec:true"); err == nil || !strings.Contains(err.Error(), "read, and empty") {
		t.Errorf("a command that prints nothing: %v", err)
	}
}
