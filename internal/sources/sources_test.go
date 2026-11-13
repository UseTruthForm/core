package sources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
		"secrets:\n  - secret: a/b\n    from: {k: \"file://etc/x\"}\n":             "takes a path",
		"secrets:\n  - secret: a/b\n    from: {\"\": \"env:K\"}\n":                 "a key with no name",
		"secrets:\n  - secret: \"*/b\"\n    leave: x\n":                            "entry 1: secret is not namespace/name",
		"secrets:\n  - secret: hunter2\n    leave: x\n":                            "entry 1: secret is not namespace/name",
		"secrets:\n  - secret: a/b\n    from: hunter2\n":                           "line 3: not what a sources file has there",
		"secrets: hunter2\n": "line 1: not what a sources file has there",
		"secrets:\n  - secret: a/b\n    leave: [hunter2\n": "not YAML this can read",
		"# nothing yet\n": "is empty",
		"secrets: []\n---\nsecrets:\n  - secret: a/b\n    leave: x\n": "more than one YAML document",
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
	held := map[string][]string{}
	for _, n := range needed {
		held[n.Secret] = n.Keys
	}
	problems, _ := Check(f, needed, held)
	if len(problems) != 4 {
		t.Errorf("an empty skeleton passes: %v", problems)
	}
	// A note is made of what the cluster's objects say. Whatever line break
	// one holds, it stays a comment: it adds no entry of its author's.
	for _, br := range []string{"\n", "\r", "\u0085", "\u2028", "\u2029", "\r\n"} {
		note := "x" + br + "  - secret: \"shop/planted\"" + br + "    from: {k: \"exec:touch planted\"}" + br + "  #"
		f, err := Read(write(t, string(Skeleton([]Needed{{Secret: "shop/real", Keys: []string{"k"}, Note: note}}))))
		if err != nil || len(f.Secrets) != 1 || f.Secrets[0].Secret != "shop/real" {
			t.Errorf("a note with %q in it wrote entries: %+v, %v", br, f.Secrets, err)
		}
	}
	// A Secret with nothing withheld needs no source, and gets no entry.
	if text := string(Skeleton([]Needed{{Secret: "shop/nothing"}})); strings.Contains(text, "shop/nothing") {
		t.Errorf("an entry for a Secret with no keys:\n%s", text)
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
		// Not needed, and given values all the same: every key, and no other.
		{Secret: "a/override", From: map[string]string{"tls.kee": "env:K"}},
		{Secret: "a/whole", From: map[string]string{"tls.key": "env:K"}},
		{Secret: "a/nothing", From: map[string]string{"k": "env:K"}},
	}}
	needed := []Needed{
		{Secret: "a/full", Keys: []string{"j", "k"}},
		{Secret: "a/short", Keys: []string{"j", "k"}},
		{Secret: "a/typo", Keys: []string{"k"}},
		{Secret: "a/left", Keys: []string{"k"}},
		{Secret: "a/absent", Keys: []string{"k"}},
	}
	held := map[string][]string{"a/made": {"k"}, "a/override": {"ca.crt", "tls.key"}, "a/whole": {"tls.key"}, "a/nothing": {}}
	for _, n := range needed {
		held[n.Secret] = n.Keys
	}
	problems, notes := Check(f, needed, held)
	wantProblems := []string{
		"a/absent: no entry; the rebuild has no source for it",
		"a/short: key j has no reference",
		"a/typo: names key kk, which the Secret in the snapshot does not have",
		"a/made: the reference for key k is empty",
		"a/override: key ca.crt has no reference",
		"a/override: key tls.key has no reference",
		"a/override: names key tls.kee, which the Secret in the snapshot does not have",
		"a/nothing: names key k, which the Secret in the snapshot does not have",
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
		"empty:":               "",
	} {
		got, err := r.Resolve(ctx, ref)
		if err != nil || string(got) != want || got == nil {
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
		"env:SRC_TEST_UNSET":  "is not set",
		"env:SRC_TEST_EMPTY":  "read, and empty",
		"file:/no/such/file":  "file:/no/such/file: open ", // then what the system says, which differs by system
		"op://v/missing/f":    "op: [ERROR] item not found",
		"azurekv://bad/name":  "did not answer with the secret's value",
		"azurekv://onlyvault": "azurekv://<vault>/<secret>",
		// Not names: refused before az is run, which on Windows is a
		// script whose arguments pass through a shell.
		`azurekv://kv/x"&echo zz5>marker&"`:        "azurekv://kv/…: an Azure Key Vault reference names",
		"azurekv://kv/--file=zz6":                  "azurekv://kv/…: an Azure Key Vault reference names",
		"azurekv://kv zz7/name":                    "azurekv://…/name: an Azure Key Vault reference names",
		"azurekv://kv/name/1|zz8":                  "azurekv://kv/name/…: an Azure Key Vault reference names",
		"azurekv://kv/-zz9":                        "azurekv://kv/…: an Azure Key Vault reference names",
		"azurekv://kv/_zz10":                       "azurekv://kv/…: an Azure Key Vault reference names",
		"azurekv://kv/.zz11":                       "azurekv://kv/…: an Azure Key Vault reference names",
		"azurekv://kv/%zz12%":                      "azurekv://kv/…: an Azure Key Vault reference names",
		"azurekv://kv/a%zz20%":                     "azurekv://kv/…: an Azure Key Vault reference names",
		"op://v/a%zz21%/f":                         "op://v/…/f: a 1Password reference is",
		"azurekv://kv/" + strings.Repeat("a", 128): "azurekv://kv/…: an Azure Key Vault reference names",
		"azurekv://kv/a/b/zz13&x":                  "azurekv://kv/a/b/…: an Azure Key Vault reference is azurekv://<vault>",
		// A 1Password reference likewise: op may be a script too.
		`op://v/x"&echo zz14>marker&"/f`: "op://v/…/f: a 1Password reference is op://<vault>/<item>",
		"op://v/%zz15%/f":                "op://v/…/f: a 1Password reference is",
		"op://v/item":                    "op://v/item: a 1Password reference is",
		"op://v/a/b/c/d":                 "op://v/a/b/c/d: a 1Password reference is",
		"op://v/item/f?attribute=o&zz17": "op://v/item/f?…: a 1Password reference is",
		"op://v/-zz18/f":                 "op://v/…/f: a 1Password reference is",
		"op://v/it\tem zz19/f":           "op://v/…/f: a 1Password reference is",
		"exec:printf x --p=zz":           "only with --allow-exec",
		"exec:TOKEN=zz1 printf x":        "only with --allow-exec",
		"exec:printf\tx\t--p=zz2":        "only with --allow-exec",
		"exec:printf x\n--p=zz3":         "only with --allow-exec",
		"exec:printf;echo${IFS}zz4":      "only with --allow-exec",
	} {
		_, err := r.Resolve(ctx, ref)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", ref, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "partial-secret") || strings.Contains(err.Error(), "zz")) {
			t.Errorf("the error holds what was read or a command's arguments: %v", err)
		}
	}
	for _, c := range calls {
		if strings.Contains(strings.Join(c, " "), "zz") {
			t.Errorf("ran a command with what is not a name: %q", c)
		}
	}
}

// What a 1Password reference may name is what 1Password lets a name be,
// and its IDs; nothing a shell would read.
func TestOpReference(t *testing.T) {
	for rest, want := range map[string]bool{
		"vault/item/field":                       true,
		"My Vault/an item/a section/field.name":  true,
		"hfnjvi6aymbsnfc2xeeoheizda/abc_123/f":   true,
		"v/item/one-time password?attribute=otp": true,
		"v/key/private key?ssh-format=openssh":   true,
		"v/item":                                 false,
		"v/a/b/c/d":                              false,
		"v//f":                                   false,
		"v/item/f?attribute":                     false,
		"v/item/f?attribute=a b":                 false,
		"v/ leading/f":                           false,
		"v/.hidden/f":                            false,
		"v/it;em/f":                              false,
		"v/it&em/f":                              false,
		"v/x --account other/f":                  false,
		"v/a - b/f":                              true, // a dash that stands alone is a name's
		"v/a -b/f":                               false,
		"v/a --b c/f":                            false,
		"v/it$(x)/f":                             false,
		"v/it`x`/f":                              false,
		"v/it'em/f":                              false,
		"v/it!em/f":                              false,
		"v/it^em/f":                              false,
		"v/" + strings.Repeat("a", 256) + "/f":   false,
	} {
		if _, ok := opReference(rest); ok != want {
			t.Errorf("opReference(%q) = %v, want %v", rest, ok, want)
		}
	}
}

// A reference of the wrong shape is refused when the file is read, by a
// check that reads no value too.
func TestReadRefusesAReferenceOfTheWrongShape(t *testing.T) {
	for ref, want := range map[string]string{
		"op://vault/%PATH%/f": "op://vault/…/f: a 1Password reference is",
		"op://vault/item":     "a 1Password reference is",
		"azurekv://kv/a&b":    "azurekv://kv/…: an Azure Key Vault reference names",
		"azurekv://onlyvault": "an Azure Key Vault reference is azurekv://<vault>",
	} {
		path := filepath.Join(t.TempDir(), "s.yaml")
		if err := os.WriteFile(path, []byte("secrets:\n  - secret: shop/git\n    from: {password: \""+ref+"\"}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "PATH") || strings.Contains(err.Error(), "a&b") {
			t.Errorf("%s: %v, want %q", ref, err, want)
		}
	}
}

// The settings of a sources file: the part written to fill in reads back
// and covers nothing until filled; a check says each object with no
// entry, each path with no reference, each path nothing was withheld at.
func TestSettings(t *testing.T) {
	needed := []NeededSetting{
		{Object: "apps/v1/Deployment/shop/api", Paths: []string{"spec.template.spec.containers[api].env[DB_PASSWORD]", "spec.template.spec.containers[api].env[API_TOKEN]"}},
		{Object: "source.toolkit.fluxcd.io/v1/GitRepository/flux-system/fleet\": x", Paths: []string{"spec.url"}},
	}
	text := append(Skeleton(nil), SettingsSkeleton(needed)...)
	path := filepath.Join(t.TempDir(), "s.yaml")
	if err := os.WriteFile(path, text, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Read(path)
	if err != nil || len(f.Settings) != 2 || len(f.Secrets) != 0 {
		t.Fatalf("the part to fill in does not read back: %v\n%s", err, text)
	}
	if problems, _ := CheckSettings(f, needed); len(problems) != 3 {
		t.Errorf("an unfilled file: %q", problems)
	}
	if SettingsSkeleton(nil) != nil {
		t.Error("something written for no settings")
	}

	filled := File{Settings: []Setting{
		{Object: "apps/v1/Deployment/shop/api", From: map[string]string{"spec.template.spec.containers[api].env[DB_PASSWORD]": "env:X", "spec.template.spec.containers[api].env[OLD]": "env:Y"}},
		{Object: "apps/v1/Deployment/shop/gone", From: map[string]string{"a": "env:Z"}},
	}}
	problems, notes := CheckSettings(filled, needed)
	want := []string{
		`source.toolkit.fluxcd.io/v1/GitRepository/flux-system/fleet": x: no entry under settings; the rebuild has no source for what was withheld from it`,
		"apps/v1/Deployment/shop/api: spec.template.spec.containers[api].env[API_TOKEN] has no reference",
		"apps/v1/Deployment/shop/api: names spec.template.spec.containers[api].env[OLD], at which nothing was withheld",
	}
	if !reflect.DeepEqual(problems, want) || len(notes) != 1 || !strings.Contains(notes[0], "shop/gone") {
		t.Errorf("problems:\n %q\nwant\n %q\nnotes %q", problems, want, notes)
	}

	for body, want := range map[string]string{
		"settings:\n  - object: a\n    from: {p: \"env:X\"}\n  - object: a\n    from: {p: \"env:X\"}\n": "a is listed twice under settings",
		"settings:\n  - object: a\n":                                     "a has no from under settings",
		"settings:\n  - from: {p: \"env:X\"}\n":                          "settings entry 1: object is not an object's key",
		"settings:\n  - object: a\n    from: {p: \"op://v/%PATH%/f\"}\n": "a, p: op://v/…/f: a 1Password reference is",
		"settings:\n  - object: a\n    from: {p: \"ftp://x\"}\n":         "a, p:",
		"settings:\n  - object: a\n    form: {p: \"env:X\"}\n":           "form",
	} {
		if err := os.WriteFile(path, []byte("secrets: []\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
}
