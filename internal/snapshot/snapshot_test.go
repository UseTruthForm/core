package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func obj(apiVersion, kind, ns, name string, extra map[string]any) Object {
	md := map[string]any{"name": name}
	if ns != "" {
		md["namespace"] = ns
	}
	b := map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}
	for k, v := range extra {
		b[k] = v
	}
	return Object{Body: b}
}

func sample() Snapshot {
	return Snapshot{
		Platform: "kubernetes", ServerVersion: "v1.36.1", Policy: "default",
		Objects: []Object{
			obj("v1", "ConfigMap", "shop", "shop-config", map[string]any{"data": map[string]any{"B": "2", "A": "1"}}),
			obj("rbac.authorization.k8s.io/v1", "ClusterRole", "", "system:auth-delegator", nil),
		},
		Coverage: []Coverage{{Resource: "core/v1/configmaps", Kind: "ConfigMap", Captured: 1}},
	}
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := sample().Write(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Objects) != 2 || got.Policy != "default" || got.ServerVersion != "v1.36.1" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if ch := Compare(sample(), got); len(ch) != 0 {
		t.Fatalf("read-back differs from what was written: %+v", ch)
	}
}

// Regression for the property CI relies on: an unchanged system must capture
// to byte-identical files, or every scheduled capture opens a noisy PR.
func TestWriteIsDeterministic(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	s := sample()
	if err := s.Write(a); err != nil {
		t.Fatal(err)
	}
	// Same objects in a different order must not change the output.
	s.Objects[0], s.Objects[1] = s.Objects[1], s.Objects[0]
	if err := s.Write(b); err != nil {
		t.Fatal(err)
	}
	da, _ := Digest(a)
	db, _ := Digest(b)
	if da != db {
		t.Fatalf("digests differ: %s vs %s", da, db)
	}
}

// A hand-edited or half-copied snapshot must be refused, not restored as if whole.
func TestReadRejectsTamperedSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := sample().Write(dir); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "objects", "core", "v1", "ConfigMap", "shop", "shop-config.yaml")
	if err := os.WriteFile(p, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: shop-config, namespace: shop}\ndata: {A: changed}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("want digest mismatch error, got %v", err)
	}
}

// Regression: reusing the objects directory would keep files for objects
// that were deleted since, and restore would bring them back.
func TestRewriteDropsDeletedObjects(t *testing.T) {
	dir := t.TempDir()
	s := sample()
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	s.Objects = s.Objects[:1]
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Objects) != 1 {
		t.Fatalf("want 1 object after the other was deleted, got %d", len(got.Objects))
	}
}

func TestWriteRefusesForeignDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sample().Write(dir); err == nil {
		t.Fatal("Write replaced a directory that is not a snapshot")
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal("the user's file is gone")
	}
}

func TestSegIsPathSafe(t *testing.T) {
	cases := map[string]string{
		"shop-config":           "shop-config",
		"system:auth-delegator": "system%3Aauth-delegator", // ':' is invalid on Windows
		"a/b":                   "a%2Fb",
		"..":                    "%2e2e",
		"":                      "%",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			if got := seg(in); got != want {
				t.Fatalf("seg(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	base := func() Snapshot { return sample() }
	cases := []struct {
		name   string
		mutate func(*Snapshot)
		want   []Change
	}{
		{"identical", func(*Snapshot) {}, nil},
		{"missing", func(s *Snapshot) { s.Objects = s.Objects[1:] }, []Change{{Key: "v1|ConfigMap|shop|shop-config", Kind: "missing"}}},
		{"extra", func(s *Snapshot) { s.Objects = append(s.Objects, obj("v1", "ConfigMap", "shop", "stray", nil)) }, []Change{{Key: "v1|ConfigMap|shop|stray", Kind: "extra"}}},
		{"changed field", func(s *Snapshot) {
			s.Objects[0].Body["data"] = map[string]any{"A": "1", "B": "changed"}
		}, []Change{{Key: "v1|ConfigMap|shop|shop-config", Kind: "changed", Fields: []string{"data.B"}}}},
		{"int vs float is not drift", func(s *Snapshot) { s.Objects[0].Body["replicas"] = 2 }, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := base()
			got := base()
			if c.name == "int vs float is not drift" {
				want.Objects[0].Body["replicas"] = float64(2)
			}
			c.mutate(&got)
			ch := Compare(want, got)
			if len(ch) != len(c.want) {
				t.Fatalf("got %+v, want %+v", ch, c.want)
			}
			for i := range ch {
				if ch[i].Key != c.want[i].Key || ch[i].Kind != c.want[i].Kind || strings.Join(ch[i].Fields, ",") != strings.Join(c.want[i].Fields, ",") {
					t.Fatalf("got %+v, want %+v", ch[i], c.want[i])
				}
			}
		})
	}
}

// Regression: a CRD enum containing "=" (alertmanagerconfigs.monitoring.coreos.com)
// was written unquoted, and YAML 1.1 readers such as PyYAML rejected the whole
// snapshot ("could not determine a constructor for tag:yaml.org,2002:value").
func TestYAML11SpecialScalarsAreQuoted(t *testing.T) {
	b, err := encodeYAML(map[string]any{"enum": []any{"=", "<<", "plain", "yes", "on", "12:30", "2001-12-14", "v1.2.3"}, "text": "line one\nline two\n"})
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{`- "="`, `- "<<"`, "- plain", `- "yes"`, `- "on"`, `- "12:30"`, `- "2001-12-14"`, "- v1.2.3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in:\n%s", want, out)
		}
	}
	var back map[string]any
	if err := yaml.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back["text"] != "line one\nline two\n" || back["enum"].([]any)[0] != "=" {
		t.Fatalf("round trip changed values: %#v", back)
	}
}
