package bootstrap_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

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
      names-odd) echo '[{"name":7},{"id":"x","name":"test-cluster"}]' ;;
      names-broken) echo '[7]' ;;
      list-empty) if [ -f "$S/made-in" ]; then cat "$S/servers.json"; fi ;;
      *) cat "$S/servers.json" ;;
    esac ;;
  "connect server create")
    fail server-create
    pwd >"$S/made-in"
    stat -c %a . >"$S/made-in-mode" 2>/dev/null || stat -f %Lp . >"$S/made-in-mode"
    if [ "$F" = other-appears-at-create ]; then
      # Someone else makes a server of the name in the same moment, and
      # this run's is refused for it.
      jq --arg n "$4" '. + [{id: "someone-elses-id", name: $n}]' "$S/servers.json" >"$S/servers.tmp"
      mv "$S/servers.tmp" "$S/servers.json"
      echo "op: a server has that name" >&2; exit 1
    fi
    echo "FAKE OP OUTPUT $CREDS" # what op prints is not the script's to show
    [ "$F" = create-says-no-id ] || echo "UUID: new-server-id"
    if [ "$F" = creds-bad ]; then printf 'not json' >1password-credentials.json; else printf '%s' "$CREDS" >1password-credentials.json; fi
    add='[{id: "new-server-id", name: $n}]'
    [ "$F" != two-new ] || add='[{id: "new-server-id", name: $n}, {id: "another-new-id", name: $n}]'
    jq --arg n "$4" ". + $add" "$S/servers.json" >"$S/servers.tmp"
    mv "$S/servers.tmp" "$S/servers.json" ;;
  "connect server delete")
    fail delete
    [ "$F" != slow-token ] || sleep 2 # long enough for a second signal to land
    jq --arg i "$4" 'map(select(.id != $i))' "$S/servers.json" >"$S/servers.tmp"
    mv "$S/servers.tmp" "$S/servers.json" ;;
  "connect token create")
    fail token-create; fail two-new
    [ "$F" != slow-token ] || sleep 5
    # As op does: the server and each vault have to be there.
    shift 4
    while [ $# -gt 0 ]; do
      case "$1" in
        --server) jq -e --arg v "$2" 'any(.[]; .name == $v or .id == $v)' "$S/servers.json" >/dev/null || { echo "op: no server $2" >&2; exit 1; }; shift 2 ;;
        --vault) vault_named "${2%,r}"; shift 2 ;;
        --expires-in) shift 2 ;;
        *) echo "op: unknown flag $1" >&2; exit 1 ;;
      esac
    done
    # No token comes back, so that what follows a failure can be tried.
    case "$F" in token-empty|delete|item-list-late) ;; *) echo "$TOKEN" ;; esac ;;
  "vault list "*) fail vault-list; cat "$S/vaults.json" ;;
  "vault create "*)
    [ "$F" != slow-vault ] || sleep 2
    if [ "$F" = vault-create-other-appears ]; then
      # Someone else makes a server of the name just now, and this fails.
      jq '. + [{id: "someone-elses-id", name: "test-cluster"}]' "$S/servers.json" >"$S/servers.tmp"
      mv "$S/servers.tmp" "$S/servers.json"
      echo "op: vault create failed" >&2; exit 1
    fi
    jq --arg n "$3" '. + [{id: ("id-of-" + $n), name: $n}]' "$S/vaults.json" >"$S/vaults.tmp"
    mv "$S/vaults.tmp" "$S/vaults.json"
    if [ "$F" = other-appears ]; then
      jq '. + [{id: "someone-elses-id", name: "test-cluster"}]' "$S/servers.json" >"$S/servers.tmp"
      mv "$S/servers.tmp" "$S/servers.json"
    fi
    jq -n --arg n "$3" '{id: ("id-of-" + $n), name: $n}' ;;
  "item list "*)
    fail item-list
    if [ "$F" = item-list-late ] && [ -f "$S/made-in" ]; then echo "op: item list failed" >&2; exit 1; fi
    vault_named "$4"
    for f in "$S"/items/*.json; do if [ -e "$f" ]; then jq '{id: "an-item", title: .title}' "$f"; fi; done | jq -s . ;;
  "item create "*)
    vault_named "$4"
    # As op does: the template is a file named with --template, and with
    # --category its fields are dropped.
    case " $* " in *" --category "*) echo "op: fields dropped" >&2; exit 1 ;; esac
    [ "$5" = "--template" ] || { echo "op: provide the item category with --category flag" >&2; exit 1; }
    stat -c %a "$6" >"$S/template-mode" 2>/dev/null || stat -f %Lp "$6" >"$S/template-mode"
    cp "$6" "$S/item.tmp"
    jq -e '.title and .category == "SECURE_NOTE" and (.fields | length > 0)' "$S/item.tmp" >/dev/null
    case " $* " in *" --dry-run "*)
      fail item-dry-run
      if [ "$F" = item-dry-run-shape ]; then echo "{}"; else cat "$S/item.tmp"; fi
      rm "$S/item.tmp"; exit 0 ;;
    esac
    fail item-create
    echo "FAKE OP OUTPUT $TOKEN" # op may print the item it made
    mv "$S/item.tmp" "$S/items/$(jq -r .title "$S/item.tmp").json"
    fail item-create-but-saved ;;
  "read "*)
    fail read-fails
    [ "$F" != slow-read ] || sleep 2
    ref=${3#op://}; vault=${ref%%/*}; rest=${ref#*/}; title=${rest%/*}; field=${rest##*/}
    vault_named "$vault"
    if [ "$F" = "read-differs" ]; then echo "op: warning about $TOKEN" >&2; printf 'something else'; exit 0; fi
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
	dir   string // TMPDIR: where the script makes its private directory
	env   []string
}

// left fails if the script's private directory, which held the
// credentials, is still there after a run, however the run ended.
func (r *run) left() {
	r.t.Helper()
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "state" && e.Name() != "bin" {
			r.t.Errorf("the script left %s behind", filepath.Join(r.dir, e.Name()))
		}
	}
}

func setup(t *testing.T) *run {
	t.Helper()
	// Where the tools are missing the test cannot run. In CI that is a
	// failure and not a skip: a run that tested nothing must not read as a
	// pass (TRUTHFORM_REQUIRE_BOOTSTRAP_TOOLS, as the API-server tests have
	// TRUTHFORM_REQUIRE_KUBE_ASSETS).
	cannot := func(why string) {
		t.Helper()
		if os.Getenv("TRUTHFORM_REQUIRE_BOOTSTRAP_TOOLS") != "" {
			t.Fatalf("%s, and TRUTHFORM_REQUIRE_BOOTSTRAP_TOOLS is set", why)
		}
		t.Skip(why)
	}
	if runtime.GOOS == "windows" {
		cannot("a bash script, not run on Windows")
	}
	for _, tool := range []string{"bash", "jq", "cmp"} {
		if _, err := exec.LookPath(tool); err != nil {
			cannot(tool + " is not installed")
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
	return &run{t: t, state: state, dir: dir, env: append(os.Environ(),
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
	r.left()
	if strings.Contains(string(out), "FAKE OP OUTPUT") {
		r.t.Errorf("the script showed what op printed:\n%s", out)
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
	if !strings.Contains(r.calls(), "connect token create test-cluster cluster token --server new-server-id --vault readid,r\n") {
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
		"names that are not text":        {usual, "names-odd", "is there already"},
		"a list of what are not entries": {usual, "names-broken", "could not be read for names"},
		"a time with no number":          {append(usual, "--expires-in", "d"), "", "not a length of time"},
		"a time of letters":              {append(usual, "--expires-in", "sss"), "", "not a length of time"},
		"a time with no unit":            {append(usual, "--expires-in", "9"), "", "not a length of time"},
		"a time that trails off":         {append(usual, "--expires-in", "1d2"), "", "not a length of time"},
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
	if !strings.Contains(r.calls(), "--vault readid,r --expires-in 90d\n") {
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
	if !strings.Contains(calls, "vault create App Config Test --format json\n") || strings.Contains(calls, "vault create App Config --format json\n") {
		t.Errorf("vaults made:\n%s", calls)
	}
	if !strings.Contains(calls, "--vaults readid,id-of-App Config Test\n") || !strings.Contains(calls, "--vault readid,r --vault id-of-App Config Test,r\n") {
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
	noSecret(t, "the output when what reads back differs", out)
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
		"the server was not made":                      {"server-create", "none was removed", usual},
		"op did not say which server it made":          {"create-says-no-id", "did not say which", usual},
		"another's server took the name as this asked": {"other-appears-at-create", "none was removed", usual},
		"the item was saved all the same":              {"item-create-but-saved", "may hold an item", usual},
		"a vault was made before it failed":            {"server-create", `vault "App Config Test" was made and is left`, append([]string{"--create-vaults", "--reads", "App Config Test"}, usual...)},
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

// Before this run has asked for a server, a new server of the name is
// someone else's: a failure then removes none.
func TestRemovesNoServerBeforeItAskedForOne(t *testing.T) {
	r := setup(t)
	args := []string{"--server", "test-cluster", "--reads", "App Config Test", "--keep-in", "Break Glass", "--create-vaults"}
	out, ok := r.script("vault-create-other-appears", args...)
	if ok || strings.Contains(r.calls(), "server delete") || strings.Contains(out, "removed again") || !strings.Contains(r.servers(), "someone-elses-id") {
		t.Errorf("ok=%v\n%s\n%s", ok, out, r.calls())
	}
	// And one that appears while the vaults are made stops the run, with no
	// server made and none removed.
	r = setup(t)
	out, ok = r.script("other-appears", args...)
	if ok || !strings.Contains(out, "was made by someone else while this ran") || strings.Contains(r.calls(), "server create") || strings.Contains(r.calls(), "server delete") {
		t.Errorf("ok=%v\n%s\n%s", ok, out, r.calls())
	}
	if !strings.Contains(out, `vault "App Config Test" was made and is left as it is`) {
		t.Errorf("does not say a vault was left:\n%s", out)
	}
}

// One vault given three ways is one vault; a name two vaults share is
// refused; a time as op takes it passes the checks.
func TestVaultsGivenTwiceAndTimes(t *testing.T) {
	r := setup(t)
	out, ok := r.script("", "--server", "test-cluster", "--reads", "App Config", "--reads", "app config", "--reads", "readid", "--keep-in", "Break Glass", "--expires-in", "1d12h")
	if !ok || !strings.Contains(r.calls(), "--vaults readid\n") || !strings.Contains(r.calls(), "--vault readid,r --expires-in 1d12h\n") || !strings.Contains(out, `both read: "App Config" `+"\n") {
		t.Errorf("ok=%v\n%s\n%s", ok, out, r.calls())
	}
	for _, args := range [][]string{
		{"--server", "x", "--reads", "Twice", "--keep-in", "Break Glass"},
		{"--server", "x", "--reads", "App Config", "--keep-in", "Twice"},
	} {
		r := setup(t)
		write(t, filepath.Join(r.state, "vaults.json"), `[{"id":"keepid","name":"Break Glass"},{"id":"readid","name":"App Config"},{"id":"t1","name":"Twice"},{"id":"t2","name":"twice"}]`, 0o644)
		out, ok := r.script("", args...)
		if ok || !strings.Contains(out, `more than one vault is named "Twice"`) || strings.Contains(r.calls(), "create") {
			t.Errorf("%v: ok=%v\n%s", args, ok, out)
		}
	}
}

// What the cleaning up does when it cannot be sure, or cannot do it.
func TestCleanupWhenItCannotBeSure(t *testing.T) {
	for name, c := range map[string]struct {
		fail, want string
		deleted    bool
	}{
		"the credentials file is not JSON": {"creds-bad", "was removed again", true},
		"the items cannot be listed then":  {"item-list-late", "may hold an item", false},
		"the server cannot be removed":     {"delete", "could not be removed", false},
	} {
		t.Run(name, func(t *testing.T) {
			r := setup(t)
			out, ok := r.script(c.fail, usual...)
			if ok || !strings.Contains(out, c.want) {
				t.Errorf("ok=%v, want %q:\n%s", ok, c.want, out)
			}
			noSecret(t, "the output", out)
			if gone := !strings.Contains(r.servers(), "new-server-id"); gone != c.deleted {
				t.Errorf("server removed=%v, want %v: %s\n%s", gone, c.deleted, r.servers(), r.calls())
			}
		})
	}
}

// The directory the credentials are in is the user's alone.
func TestPrivateDirectory(t *testing.T) {
	r := setup(t)
	if out, ok := r.script("", usual...); !ok {
		t.Fatalf("failed:\n%s", out)
	}
	mode, _ := os.ReadFile(filepath.Join(r.state, "made-in-mode"))
	if strings.TrimSpace(string(mode)) != "700" {
		t.Errorf("the directory the credentials file was written in has mode %q, want 700", mode)
	}
	if mode, _ := os.ReadFile(filepath.Join(r.state, "template-mode")); strings.TrimSpace(string(mode)) != "600" {
		t.Errorf("the file the item was given to op in has mode %q, want 600", mode)
	}
}

// A second signal while it cleans up does not stop the cleaning up: the
// server is removed, the directory is gone, and it says so.
func TestTwoSignalsStillCleanUp(t *testing.T) {
	r := setup(t)
	cmd := exec.Command("bash", append([]string{"1password-connect.sh"}, usual...)...)
	cmd.Env = append(r.env, "OP_FAIL=slow-token")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait until the server is made and the script is waiting for the token.
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(r.calls(), "connect token create") {
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("the script never asked for a token:\n%s", r.calls())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	// The second lands while it is removing the server.
	for !strings.Contains(r.calls(), "connect server delete") {
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("the script never began to clean up:\n%s", r.calls())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Process.Signal(syscall.SIGHUP)
	cmd.Process.Signal(syscall.SIGINT)
	err := cmd.Wait()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 143 {
		t.Errorf("exit: %v, want 143", err)
	}
	if !strings.Contains(out.String(), "was removed again") || strings.Contains(r.servers(), "new-server-id") {
		t.Errorf("the server was not removed after two signals:\n%s\n%s", out.String(), r.servers())
	}
	noSecret(t, "the output", out.String())
	r.left()
}

// Two new servers have the name, one of them another person's made in the
// same moment: the one op said this run made is the one removed, and the
// other is left.
func TestRemovesOnlyTheServerOpSaidItMade(t *testing.T) {
	r := setup(t)
	out, ok := r.script("two-new", usual...)
	if ok || !strings.Contains(out, "was removed again") {
		t.Errorf("ok=%v\n%s", ok, out)
	}
	if !strings.Contains(r.calls(), "connect server delete new-server-id\n") || strings.Count(r.calls(), "server delete") != 1 {
		t.Errorf("removed:\n%s", r.calls())
	}
	if !strings.Contains(r.servers(), "another-new-id") || strings.Contains(r.servers(), "new-server-id") {
		t.Errorf("servers left: %s", r.servers())
	}
	// The token was asked for by that id, not by the name two have.
	if !strings.Contains(r.calls(), "--server new-server-id") {
		t.Errorf("the token was not asked for by id:\n%s", r.calls())
	}
	// Another's server that took the name as this asked is left, and so
	// is one op made without saying which: no token is asked for by name.
	for _, fail := range []string{"other-appears-at-create", "create-says-no-id"} {
		r = setup(t)
		r.script(fail, usual...)
		if strings.Contains(r.calls(), "server delete") || strings.Contains(r.calls(), "token create") {
			t.Errorf("%s:\n%s", fail, r.calls())
		}
	}
	if !strings.Contains(r.servers(), "new-server-id") {
		t.Errorf("a server this could not tell was its own was removed: %s", r.servers())
	}
}

// signalled runs the script, sends it a signal once op has been asked
// for what is named, and gives what it printed and its exit code.
func signalled(t *testing.T, r *run, fail, when string, sig syscall.Signal, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"1password-connect.sh"}, args...)...)
	cmd.Env = append(r.env, "OP_FAIL="+fail)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, _ := os.ReadFile(filepath.Join(r.state, "calls"))
		if strings.Contains(string(b), when) {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("the script never ran op %s:\n%s", when, b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cmd.Process.Signal(sig)
	err := cmd.Wait()
	ee, _ := err.(*exec.ExitError)
	if ee == nil {
		t.Fatalf("it went on after the signal:\n%s", out.String())
	}
	noSecret(t, "the output", out.String())
	r.left()
	return out.String(), ee.ExitCode()
}

// Stopped after the item is saved and before it is read back, it says
// that the server and the item are there, and removes neither.
func TestASignalWhileReadingBackSaysWhatIsLeft(t *testing.T) {
	for sig, code := range map[syscall.Signal]int{syscall.SIGTERM: 143, syscall.SIGINT: 130} {
		r := setup(t)
		out, got := signalled(t, r, "slow-read", "read --no-newline", sig, usual...)
		if got != code {
			t.Errorf("exit %d, want %d", got, code)
		}
		for _, want := range []string{`Connect server "test-cluster" was made`, `item "test-cluster Connect credentials" was saved in vault "Break Glass"`, "before the item was read back"} {
			if !strings.Contains(out, want) {
				t.Errorf("does not say %q:\n%s", want, out)
			}
		}
		if strings.Contains(r.calls(), "server delete") || !strings.Contains(r.servers(), "new-server-id") || strings.Contains(out, "references for") {
			t.Errorf("after the signal:\n%s\n%s", out, r.calls())
		}
	}
	// What a finished run says is not that.
	r := setup(t)
	if out, ok := r.script("", usual...); !ok || strings.Contains(out, "before the item was read back") {
		t.Errorf("a finished run:\n%s", out)
	}
	// And one whose item reads back wrong says so once.
	r = setup(t)
	if out, _ := r.script("read-differs", usual...); strings.Contains(out, "before the item was read back") {
		t.Errorf("said twice:\n%s", out)
	}
}

// Stopped while a vault is being made, it says the vault may be there.
func TestASignalWhileMakingAVaultSaysSo(t *testing.T) {
	r := setup(t)
	out, code := signalled(t, r, "slow-vault", "vault create", syscall.SIGTERM, "--server", "test-cluster", "--reads", "App Config Test", "--keep-in", "Break Glass", "--create-vaults")
	if code != 143 || (!strings.Contains(out, `vault "App Config Test" was being made`) && !strings.Contains(out, `vault "App Config Test" was made and is left`)) {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if strings.Contains(r.calls(), "server create") {
		t.Errorf("went on to make a server:\n%s", r.calls())
	}
}
