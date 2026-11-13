package bootstrap_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/sources"
)

// fakeOp stands in for the 1Password CLI. It keeps what it is told in
// $OP_STATE, writes every argument it is given to $OP_STATE/calls, and
// fails the step named in $OP_FAIL.
const fakeOp = `#!/usr/bin/env bash
set -euo pipefail
S=$OP_STATE
printf '%s\n' "$*" >>"$S/calls"
F=${OP_FAIL:-}
fail() { [ "$F" != "$1" ] || { echo "op: $1 failed" >&2; exit 1; }; }
vault_named() { jq -e --arg v "$1" 'any(.[]; .name == $v or .id == $v)' "$S/vaults.json" >/dev/null || { echo "op: no vault $1" >&2; exit 1; }; }
case "$1 ${2:-} ${3:-}" in
  "whoami  ") echo "op: account is not signed in" >&2; exit 1 ;; # what it says when signed in through the app
  "connect server list")
    fail list
    case "$F" in
      list-shape) echo '{"servers":[]}' ;;
      list-empty) if [ -f "$S/made-in" ]; then cat "$S/servers.json"; fi ;;
      *) cat "$S/servers.json" ;;
    esac ;;
  "connect server create")
    fail server-create
    pwd >"$S/made-in"
    printf '%s' "$CREDS" >1password-credentials.json
    add='[{id: "new-server-id", name: $n}]'
    [ "$F" != two-new ] || add='[{id: "new-server-id", name: $n}, {id: "another-new-id", name: $n}]'
    jq --arg n "$4" ". + $add" "$S/servers.json" >"$S/servers.tmp"
    mv "$S/servers.tmp" "$S/servers.json" ;;
  "connect server delete")
    jq --arg i "$4" 'map(select(.id != $i))' "$S/servers.json" >"$S/servers.tmp"
    mv "$S/servers.tmp" "$S/servers.json" ;;
  "connect token create") fail token-create; fail two-new; [ "$F" = token-empty ] || echo "$TOKEN" ;;
  "vault list "*) fail vault-list; cat "$S/vaults.json" ;;
  "vault create "*)
    jq --arg n "$3" '. + [{id: ("id-of-" + $n), name: $n}]' "$S/vaults.json" >"$S/vaults.tmp"
    mv "$S/vaults.tmp" "$S/vaults.json" ;;
  "item list "*)
    fail item-list
    vault_named "$4"
    for f in "$S"/items/*.json; do if [ -e "$f" ]; then jq '{id: "an-item", title: .title}' "$f"; fi; done | jq -s . ;;
  "item create "*)
    vault_named "$4"
    # As op does: the template is a file named with --template, and with
    # --category its fields are dropped.
    case " $* " in *" --category "*) echo "op: fields dropped" >&2; exit 1 ;; esac
    [ "$5" = "--template" ] || { echo "op: provide the item category with --category flag" >&2; exit 1; }
    cp "$6" "$S/item.tmp"
    jq -e '.title and .category == "SECURE_NOTE" and (.fields | length > 0)' "$S/item.tmp" >/dev/null
    case " $* " in *" --dry-run "*)
      fail item-dry-run
      if [ "$F" = item-dry-run-shape ]; then echo "{}"; else cat "$S/item.tmp"; fi
      rm "$S/item.tmp"; exit 0 ;;
    esac
    fail item-create
    mv "$S/item.tmp" "$S/items/$(jq -r .title "$S/item.tmp").json"
    fail item-create-but-saved ;;
  "read "*)
    fail read-fails
    ref=${3#op://}; vault=${ref%%/*}; rest=${ref#*/}; title=${rest%/*}; field=${rest##*/}
    vault_named "$vault"
    if [ "$F" = "read-differs" ]; then printf 'something else'; exit 0; fi
    jq -j --arg f "$field" '.fields[] | select(.label == $f) | .value' "$S/items/$title.json" ;;
  *) echo "fake op: unexpected: $*" >&2; exit 64 ;;
esac
`

const (
	creds = `{"verifier":{"salt":"c2FsdA"},"encCredentials":{"data":"Q1JFRFNFQ1JFVA"},"uniqueKey":{"k":"S0VZU0VDUkVU"}}` + "\n"
	token = "eyJhbGciOiJFUzI1NiJ9.TOKENSECRET.c2ln"
)

type run struct {
	t     *testing.T
	state string
	env   []string
}

func setup(t *testing.T) *run {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a bash script")
	}
	for _, tool := range []string{"bash", "jq", "cmp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{state, bin, filepath.Join(state, "items")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(bin, "op"), fakeOp, 0o755)
	write(t, filepath.Join(state, "servers.json"), `[{"id":"old-id","name":"dev-cluster"}]`, 0o644)
	write(t, filepath.Join(state, "vaults.json"), `[{"id":"keepid","name":"Break Glass"},{"id":"readid","name":"App Config"}]`, 0o644)
	write(t, filepath.Join(state, "calls"), "", 0o644)
	return &run{t: t, state: state, env: append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"OP_STATE="+state, "CREDS="+creds, "TOKEN="+token, "TMPDIR="+dir)}
}

func write(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
}

// script runs the bootstrap script and gives what it printed (both
// streams) and whether it succeeded.
func (r *run) script(fail string, args ...string) (string, bool) {
	r.t.Helper()
	cmd := exec.Command("bash", append([]string{"1password-connect.sh"}, args...)...)
	cmd.Env = append(r.env, "OP_FAIL="+fail)
	out, err := cmd.CombinedOutput()
	if _, exited := err.(*exec.ExitError); err != nil && !exited {
		r.t.Fatal(err)
	}
	return string(out), err == nil
}

// calls are the arguments op was run with, a line a run, less the runs
// that only ask whether an item would be taken.
func (r *run) calls() string {
	b, err := os.ReadFile(filepath.Join(r.state, "calls"))
	if err != nil {
		r.t.Fatal(err)
	}
	var kept []string
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if !strings.Contains(l, " --dry-run ") {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "")
}

func (r *run) servers() string {
	b, _ := os.ReadFile(filepath.Join(r.state, "servers.json"))
	return string(b)
}

// noSecret fails if text shows any of what was made.
func noSecret(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range []string{"CREDSECRET", "Q1JFRFNFQ1JFVA", "KEYSECRET", "TOKENSECRET", base64.StdEncoding.EncodeToString([]byte(creds))[:40]} {
		if strings.Contains(text, s) {
			t.Errorf("%s shows a secret (%s):\n%s", what, s, text)
		}
	}
}

var usual = []string{"--server", "test-cluster", "--reads", "App Config", "--keep-in", "Break Glass"}

func TestMakesKeepsAndPrintsOnlyReferences(t *testing.T) {
	r := setup(t)
	out, ok := r.script("", append(usual, "--credentials-secret", "onepassword/op-credentials", "--token-secret", "onepassword/op-token:value")...)
	if !ok {
		t.Fatalf("failed:\n%s", out)
	}
	noSecret(t, "the output", out)
	noSecret(t, "the arguments given to op", r.calls())

	// What was kept is what was made, in each form.
	b, err := os.ReadFile(filepath.Join(r.state, "items", "test-cluster Connect credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	var item struct {
		Category string
		Fields   []struct{ Label, Type, Value string }
	}
	if err := json.Unmarshal(b, &item); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range item.Fields {
		got[f.Label] = f.Value
		if strings.HasPrefix(f.Label, "credentials") || f.Label == "token" {
			if f.Type != "CONCEALED" {
				t.Errorf("field %s is %s, not concealed", f.Label, f.Type)
			}
		}
	}
	if got["credentials-json"] != strings.TrimSuffix(creds, "\n") || got["token"] != token || got["credentials-base64"] != base64.StdEncoding.EncodeToString([]byte(creds)) {
		t.Errorf("kept item does not hold what was made: %v", got)
	}

	// The token reads, and cannot write.
	if !strings.Contains(r.calls(), "connect token create test-cluster cluster token --server new-server-id --vault App Config,r\n") {
		t.Errorf("token not made read-only on the vault:\n%s", r.calls())
	}
	// Nothing is left where op wrote the credentials file.
	dir, _ := os.ReadFile(filepath.Join(r.state, "made-in"))
	if _, err := os.Stat(strings.TrimSpace(string(dir))); !os.IsNotExist(err) {
		t.Errorf("the directory the credentials file was written in is still there: %v", err)
	}

	// The entries printed are a sources file as they stand.
	_, entries, found := strings.Cut(out, "entries for it:\n")
	if !found {
		t.Fatalf("no entries printed:\n%s", out)
	}
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	write(t, path, "secrets:\n"+entries, 0o644)
	f, err := sources.Read(path)
	if err != nil {
		t.Fatalf("printed entries are not a sources file: %v\n%s", err, entries)
	}
	want := map[string]string{
		"onepassword/op-credentials|1password-credentials.json": "op://Break Glass/test-cluster Connect credentials/credentials-base64",
		"onepassword/op-token|value":                            "op://Break Glass/test-cluster Connect credentials/token",
	}
	for _, e := range f.Secrets {
		for k, ref := range e.From {
			if want[e.Secret+"|"+k] != ref {
				t.Errorf("entry %s key %s reads %q", e.Secret, k, ref)
			}
			delete(want, e.Secret+"|"+k)
		}
	}
	if len(want) > 0 {
		t.Errorf("entries missing: %v", want)
	}
}

func TestRefusesBeforeMakingAnything(t *testing.T) {
	for name, c := range map[string]struct {
		args []string
		fail string
		want string
	}{
		"a server of the name":           {[]string{"--server", "dev-cluster", "--reads", "App Config", "--keep-in", "Break Glass"}, "", "is there already"},
		"kept where the server reads":    {[]string{"--server", "x", "--reads", "App Config", "--keep-in", "App Config"}, "", "own credentials"},
		"the same vault spelt by id":     {[]string{"--server", "x", "--reads", "keepid", "--keep-in", "break glass"}, "", "own credentials"},
		"a server of the name, cased":    {[]string{"--server", "Dev-Cluster", "--reads", "App Config", "--keep-in", "Break Glass"}, "", "is there already"},
		"a list that is not a list":      {usual, "list-shape", "does not read as a list"},
		"vaults cannot be listed":        {usual, "vault-list", "could not list vaults"},
		"items cannot be listed":         {usual, "item-list", "could not list the items"},
		"op would not take the item":     {usual, "item-dry-run", "op would not save the item"},
		"op would save something else":   {usual, "item-dry-run-shape", "not under its title with the fields"},
		"a name a reference cannot hold": {[]string{"--server", "x", "--reads", "App Config", "--keep-in", "Break Glass (Prod)"}, "", "a name holds letters"},
		"a quote in a title":             {append(usual, "--item", `a"b`), "", "a name holds letters"},
		"a name that is a flag":          {[]string{"--server", "x", "--reads", "App Config", "--keep-in", "--help"}, "", "a name holds letters"},
		"a comma in a vault":             {[]string{"--server", "x", "--reads", "a,b", "--keep-in", "Break Glass"}, "", "a name holds letters"},
		"a length of time that is not":   {append(usual, "--expires-in", "soon"), "", "not a length of time"},
		"no vault to keep in":            {[]string{"--server", "x", "--reads", "App Config", "--keep-in", "Nowhere"}, "", "not made for you"},
		"no vault to read":               {[]string{"--server", "x", "--reads", "App Config Test", "--keep-in", "Break Glass"}, "", "--create-vaults makes them"},
		"may not list servers":           {usual, "list", "Sign in first (op signin"},
		"a slash in a name":              {[]string{"--server", "a/b", "--reads", "App Config", "--keep-in", "Break Glass"}, "", "a name holds letters"},
		"a secret without a namespace":   {append(usual, "--token-secret", "op-token"), "", "<namespace>/<name>"},
		"a key that would break yaml":    {append(usual, "--token-secret", "ns/name:a: b"), "", "Secret's key"},
		"dry run":                        {append(usual, "--dry-run"), "", "nothing was made (--dry-run)"},
	} {
		t.Run(name, func(t *testing.T) {
			r := setup(t)
			out, ok := r.script(c.fail, c.args...)
			if ok != (name == "dry run") || !strings.Contains(out, c.want) {
				t.Errorf("ok=%v, output:\n%s", ok, out)
			}
			for _, made := range []string{"server create", "token create", "item create", "vault create", "server delete"} {
				if strings.Contains(r.calls(), made) {
					t.Errorf("ran %q:\n%s", made, r.calls())
				}
			}
		})
	}
}

func TestRefusesAnItemOfTheTitle(t *testing.T) {
	r := setup(t)
	write(t, filepath.Join(r.state, "items", "Mine.json"), `{"title":"Mine"}`, 0o644)
	out, ok := r.script("", append(usual, "--item", "mine")...)
	if ok || !strings.Contains(out, "nothing is written over") || strings.Contains(r.calls(), "create") {
		t.Errorf("ok=%v\n%s\n%s", ok, out, r.calls())
	}
}

// An account with no Connect server yet may list nothing at all.
func TestTakesAnEmptyListAsNoServers(t *testing.T) {
	r := setup(t)
	if out, ok := r.script("list-empty", append(usual, "--expires-in", "90d")...); !ok {
		t.Fatalf("failed:\n%s", out)
	}
	if !strings.Contains(r.calls(), "--vault App Config,r --expires-in 90d\n") {
		t.Errorf("token not made to expire:\n%s", r.calls())
	}
}

func TestMakesAMissingVaultOnlyWhenAsked(t *testing.T) {
	r := setup(t)
	many := []string{"--server", "test-cluster", "--reads", "App Config", "--reads", "App Config Test", "--keep-in", "Break Glass", "--create-vaults"}
	if out, ok := r.script("", append(many, "--dry-run")...); !ok || !strings.Contains(out, `would make vault "App Config Test"`) || strings.Contains(r.calls(), "vault create") {
		t.Fatalf("dry run: ok=%v\n%s\n%s", ok, out, r.calls())
	}
	out, ok := r.script("", many...)
	if !ok {
		t.Fatalf("failed:\n%s", out)
	}
	calls := r.calls()
	if !strings.Contains(calls, "vault create App Config Test\n") || strings.Contains(calls, "vault create App Config\n") {
		t.Errorf("vaults made:\n%s", calls)
	}
	if !strings.Contains(calls, "--vaults App Config,App Config Test\n") || !strings.Contains(calls, "--vault App Config,r --vault App Config Test,r\n") {
		t.Errorf("server or token not on both vaults:\n%s", calls)
	}
}

// A server whose credentials were not kept is of no use, and would stop
// the same command being run again: it is removed, and only it.
func TestRemovesTheServerItMadeWhenKeepingFails(t *testing.T) {
	for _, step := range []string{"token-create", "token-empty", "item-create"} {
		t.Run(step, func(t *testing.T) {
			r := setup(t)
			out, ok := r.script(step, usual...)
			if ok || !strings.Contains(out, "was removed again") {
				t.Errorf("ok=%v\n%s", ok, out)
			}
			noSecret(t, "the output", out)
			if !strings.Contains(r.calls(), "connect server delete new-server-id\n") {
				t.Errorf("did not remove the server it made, by its id:\n%s", r.calls())
			}
			if s := r.servers(); !strings.Contains(s, "old-id") || strings.Contains(s, "new-server-id") {
				t.Errorf("servers left: %s", s)
			}
			// And it can be run again.
			if out, ok := r.script("", usual...); !ok {
				t.Errorf("second run failed:\n%s", out)
			}
		})
	}
}

func TestSaysSoWhenWhatReadsBackDiffers(t *testing.T) {
	r := setup(t)
	out, ok := r.script("read-differs", usual...)
	if ok || !strings.Contains(out, "not what was saved") {
		t.Errorf("ok=%v\n%s", ok, out)
	}
	// The item holds the credentials: the server is not removed.
	if strings.Contains(r.calls(), "server delete") || strings.Contains(out, "references for") {
		t.Errorf("removed the server, or printed references:\n%s\n%s", out, r.calls())
	}
}

// What is said and done when a step fails is from what 1Password lists
// then, and never more than the one server this run made.
func TestRemovesNothingItCannotTellIsItsOwn(t *testing.T) {
	for name, c := range map[string]struct {
		fail, want string
		args       []string
	}{
		"the server was not made":           {"server-create", "none was removed", usual},
		"two new servers have the name":     {"two-new", "none was removed", usual},
		"the item was saved all the same":   {"item-create-but-saved", "may hold an item", usual},
		"a vault was made before it failed": {"server-create", `vault "App Config Test" was made and is left`, append([]string{"--create-vaults", "--reads", "App Config Test"}, usual...)},
	} {
		t.Run(name, func(t *testing.T) {
			r := setup(t)
			out, ok := r.script(c.fail, c.args...)
			if ok || !strings.Contains(out, c.want) || strings.Contains(out, "was removed again") {
				t.Errorf("ok=%v\n%s", ok, out)
			}
			noSecret(t, "the output", out)
			if strings.Contains(r.calls(), "server delete") {
				t.Errorf("removed a server:\n%s", r.calls())
			}
			dir, _ := os.ReadFile(filepath.Join(r.state, "made-in"))
			if d := strings.TrimSpace(string(dir)); d != "" {
				if _, err := os.Stat(d); !os.IsNotExist(err) {
					t.Errorf("the directory the credentials file was written in is still there: %v", err)
				}
			}
		})
	}
}

func TestSaysSoWhenNothingReadsBack(t *testing.T) {
	r := setup(t)
	out, ok := r.script("read-fails", usual...)
	if ok || !strings.Contains(out, "not what was saved") || strings.Contains(out, "references for") {
		t.Errorf("ok=%v\n%s", ok, out)
	}
}
