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
fail() { [ "${OP_FAIL:-}" != "$1" ] || { echo "op: $1 failed" >&2; exit 1; }; }
case "$1 ${2:-} ${3:-}" in
  "whoami  ") fail whoami ;;
  "connect server list") fail list; cat "$S/servers.json" ;;
  "connect server create")
    fail server-create
    pwd >"$S/made-in"
    printf '%s' "$CREDS" >1password-credentials.json
    jq --arg n "$4" '. + [{id: "new-server-id", name: $n}]' "$S/servers.json" >"$S/servers.tmp"
    mv "$S/servers.tmp" "$S/servers.json" ;;
  "connect server delete")
    jq --arg i "$4" 'map(select(.id != $i))' "$S/servers.json" >"$S/servers.tmp"
    mv "$S/servers.tmp" "$S/servers.json" ;;
  "connect token create") fail token-create; echo "$TOKEN" ;;
  "vault get "*) grep -qxF "$3" "$S/vaults" || { echo "op: no vault $3" >&2; exit 1; } ;;
  "vault create "*) echo "$3" >>"$S/vaults" ;;
  "item get "*) test -f "$S/item-$3.json" ;;
  "item create "*)
    fail item-create
    cat >"$S/item.tmp"
    mv "$S/item.tmp" "$S/item-$(jq -r .title "$S/item.tmp").json" ;;
  "read "*)
    ref=${3#op://}; rest=${ref#*/}; title=${rest%/*}; field=${rest##*/}
    if [ "${OP_FAIL:-}" = "read-differs" ]; then printf 'something else'; exit 0; fi
    jq -j --arg f "$field" '.fields[] | select(.label == $f) | .value' "$S/item-$title.json" ;;
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
	for _, tool := range []string{"bash", "jq", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{state, bin} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(bin, "op"), fakeOp, 0o755)
	write(t, filepath.Join(state, "servers.json"), `[{"id":"old-id","name":"dev-cluster"}]`, 0o644)
	write(t, filepath.Join(state, "vaults"), "Break Glass\nApp Config\n", 0o644)
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

func (r *run) calls() string {
	b, err := os.ReadFile(filepath.Join(r.state, "calls"))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
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
	b, err := os.ReadFile(filepath.Join(r.state, "item-test-cluster Connect credentials.json"))
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
	if got["credentials-json"] != creds || got["token"] != token || got["credentials-base64"] != base64.StdEncoding.EncodeToString([]byte(creds)) {
		t.Errorf("kept item does not hold what was made: %v", got)
	}

	// The token reads, and cannot write.
	if !strings.Contains(r.calls(), "connect token create test-cluster cluster token --server test-cluster --vault App Config,r\n") {
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
		"a server of the name":         {[]string{"--server", "dev-cluster", "--reads", "App Config", "--keep-in", "Break Glass"}, "", "is there already"},
		"kept where the server reads":  {[]string{"--server", "x", "--reads", "App Config", "--keep-in", "App Config"}, "", "own credentials"},
		"no vault to keep in":          {[]string{"--server", "x", "--reads", "App Config", "--keep-in", "Nowhere"}, "", "not made for you"},
		"no vault to read":             {[]string{"--server", "x", "--reads", "App Config Test", "--keep-in", "Break Glass"}, "", "--create-vaults makes them"},
		"not signed in":                {usual, "whoami", "op signin"},
		"may not list servers":         {usual, "list", "a service account or a Connect token cannot"},
		"a slash in a name":            {[]string{"--server", "a/b", "--reads", "App Config", "--keep-in", "Break Glass"}, "", "cannot be empty or hold a slash"},
		"a secret without a namespace": {append(usual, "--token-secret", "op-token"), "", "<namespace>/<name>"},
		"a key that would break yaml":  {append(usual, "--token-secret", "ns/name:a: b"), "", "Secret's key"},
		"dry run":                      {append(usual, "--dry-run"), "", "nothing was made (--dry-run)"},
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
	write(t, filepath.Join(r.state, "item-mine.json"), `{}`, 0o644)
	out, ok := r.script("", append(usual, "--item", "mine")...)
	if ok || !strings.Contains(out, "nothing is written over") || strings.Contains(r.calls(), "create") {
		t.Errorf("ok=%v\n%s\n%s", ok, out, r.calls())
	}
}

func TestMakesAMissingVaultOnlyWhenAsked(t *testing.T) {
	r := setup(t)
	out, ok := r.script("", "--server", "test-cluster", "--reads", "App Config", "--reads", "App Config Test", "--keep-in", "Break Glass", "--create-vaults")
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
	for _, step := range []string{"token-create", "item-create"} {
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
