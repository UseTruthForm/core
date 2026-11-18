package snapshot

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func lineEndingsSnapshot() Snapshot {
	return Snapshot{Platform: "kubernetes", Policy: "default",
		Objects: []Object{{Body: map[string]any{"apiVersion": "v1", "kind": "ConfigMap",
			"metadata": map[string]any{"namespace": "shop", "name": "cfg"},
			"data":     map[string]any{"script": "line one\nline two\n", "windows": "a\r\nb"}}}},
		Coverage: []Coverage{{Resource: "core/v1/configmaps", Kind: "ConfigMap", Captured: 1}},
		Schemas:  []TypeSchema{{APIVersion: "v1", Kind: "ConfigMap", Digest: "sha256:x", Fields: []string{"data"}}}}
}

// eachFile rewrites every file under dir with f.
func eachFile(t *testing.T, dir string, f func([]byte) []byte) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(p, f(b), 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Git for Windows checks text files out with CRLF line endings by default
// (core.autocrlf=true). A snapshot cloned there matched no digest, and every
// command refused it as changed after capture. TruthForm never writes a
// carriage return, so CRLF is read back as the LF it was.
func TestASnapshotWithWindowsLineEndingsIsRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	want := lineEndingsSnapshot()
	if err := want.Write(dir); err != nil {
		t.Fatal(err)
	}
	eachFile(t, dir, func(b []byte) []byte {
		if bytes.Contains(b, []byte("\r")) {
			t.Fatalf("TruthForm wrote a carriage return: %q", b)
		}
		return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
	})
	got, err := Read(dir)
	if err != nil {
		t.Fatalf("CRLF: %v", err)
	}
	if !reflect.DeepEqual(got.Objects, want.Objects) {
		t.Errorf("read back as %v", got.Objects)
	}
	if d, err := Digest(dir); err != nil || !strings.HasPrefix(d, "sha256:") || strings.ContainsRune(d, '\r') {
		t.Errorf("Digest: %q %v", d, err)
	}
	// A carriage return on its own is not a line ending: still a change.
	eachFile(t, filepath.Join(dir, "objects"), func(b []byte) []byte { return bytes.Replace(b, []byte("line one"), []byte("line\rone"), 1) })
	if _, err := Read(dir); err == nil {
		t.Error("a carriage return added was read")
	}
}

// A snapshot says, in a .gitattributes of its own, that git is to leave its
// files as they are. It is not part of the digest: one without it is read.
func TestASnapshotTellsGitToKeepItsLineEndings(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	if err := lineEndingsSnapshot().Write(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".gitattributes"))
	if err != nil || !strings.Contains(string(b), "\n* -text\n") {
		t.Fatalf(".gitattributes: %q %v", b, err)
	}
	if err := os.Remove(filepath.Join(dir, ".gitattributes")); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err != nil {
		t.Errorf("without .gitattributes: %v", err)
	}
	// Written again over it, as a capture into the same directory is.
	if err := lineEndingsSnapshot().Write(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitattributes")); err != nil {
		t.Error(err)
	}
}

// Through git itself, with Git for Windows' default: a snapshot from this
// build comes back from a clone byte for byte, and one from an earlier build
// (no .gitattributes) comes back with CRLF and is read.
func TestASnapshotClonedWithAutocrlfIsRead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "core.autocrlf=true", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	for _, withAttributes := range []bool{true, false} {
		repo := t.TempDir()
		run(repo, "init", "-q")
		snap := filepath.Join(repo, "snap")
		if err := lineEndingsSnapshot().Write(snap); err != nil {
			t.Fatal(err)
		}
		if !withAttributes {
			_ = os.Remove(filepath.Join(snap, ".gitattributes"))
		}
		run(repo, "add", "-A")
		run(repo, "commit", "-q", "-m", "capture")
		clone := filepath.Join(t.TempDir(), "clone")
		run(filepath.Dir(clone), "clone", "-q", repo, clone)
		cfg, err := os.ReadFile(filepath.Join(clone, "snap", "objects", "core", "v1", "ConfigMap", "shop", "cfg.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if crlf := bytes.Contains(cfg, []byte("\r\n")); crlf == withAttributes {
			t.Errorf(".gitattributes %v: the clone has CRLF %v", withAttributes, crlf)
		}
		if _, err := Read(filepath.Join(clone, "snap")); err != nil {
			t.Errorf(".gitattributes %v: %v", withAttributes, err)
		}
	}
}
