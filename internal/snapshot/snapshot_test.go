package snapshot

import (
	"fmt"
	"io/fs"
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
	// Skips that differ only by reason, as skips recorded per owner do.
	s.Skips = []Skip{
		{Resource: "core/v1/pods", Namespace: "shop", Name: "*", Reason: "owned by Deployment/api, whose controller recreates it"},
		{Resource: "core/v1/pods", Namespace: "shop", Name: "*", Reason: "owned by Deployment/web, whose controller recreates it"},
	}
	if err := s.Write(a); err != nil {
		t.Fatal(err)
	}
	// Same objects and skips in a different order must not change the output.
	s.Objects[0], s.Objects[1] = s.Objects[1], s.Objects[0]
	s.Skips[0], s.Skips[1] = s.Skips[1], s.Skips[0]
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

// The point of schema fingerprints: an API adding a field must show up as
// that field, with no field list maintained anywhere in TruthForm.
func TestCompareSchemasShowsAddedAndRemovedFields(t *testing.T) {
	ts := func(kind, digest string, fields ...string) TypeSchema {
		return TypeSchema{APIVersion: "example.truthform.org/v1", Kind: kind, Digest: digest, Fields: fields}
	}
	old := Snapshot{Schemas: []TypeSchema{ts("Widget", "a", "spec.size", "spec.colour"), ts("Gone", "g", "x"), ts("NoSchema", "")}}
	new := Snapshot{Schemas: []TypeSchema{ts("Widget", "b", "spec.size", "spec.shape"), ts("New", "n", "y"), ts("NoSchema", "")}}
	got := CompareSchemas(old, new)
	want := []string{
		"example.truthform.org/v1 Gone|removed type||",
		"example.truthform.org/v1 New|added type||",
		"example.truthform.org/v1 Widget|changed|spec.shape|spec.colour",
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, c := range got {
		line := c.Type + "|" + c.Kind + "|" + strings.Join(c.Added, ",") + "|" + strings.Join(c.Removed, ",")
		if line != want[i] {
			t.Fatalf("got %s, want %s", line, want[i])
		}
	}
}

// A full AWS capture failed after 32 minutes, writing nothing, because one
// SSM document held a character JSON leaves raw and YAML refuses. Every
// such character must be written and read back exactly.
func TestUnusualCharactersRoundTrip(t *testing.T) {
	values := map[string]any{}
	for i, r := range []rune{0x7f, 0x80, 0x85, 0x9b, 0x9f, 0xa0, 0xfeff, 0xfffe, 0xffff, 0x1f600} {
		values[fmt.Sprintf("v%d", i)] = "before" + string(r) + "after"
	}
	values["mixed"] = "tab\there\nnewline\x00nul\x1besc line-sep"
	s := Snapshot{Platform: "aws", Policy: "default", Objects: []Object{obj("v1", "ConfigMap", "", "odd", map[string]any{"data": values})}}
	dir := t.TempDir()
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ch := Compare(s, got); len(ch) != 0 {
		t.Fatalf("read-back differs: %+v", ch)
	}
}

// The names a skip stands for are written and read back, and a skip with
// none is written as it always was: a snapshot of a cluster where nothing
// owns a Service has the digest it had.
func TestSkipNamesRoundTrip(t *testing.T) {
	plain := Snapshot{Platform: "kubernetes", Skips: []Skip{{Resource: "core/v1/pods", Namespace: "shop", Name: "*", Reason: "owned by Deployment/api, whose controller recreates it"}}}
	named := plain
	named.Skips = append([]Skip{}, plain.Skips...)
	named.Skips = append(named.Skips, Skip{Resource: "core/v1/services", Namespace: "shop", Name: "*", Reason: "owned by Operand/op, whose controller recreates it", Names: []string{"hook", "metrics"}, Selectors: map[string]map[string]string{"hook": {"app": "hook"}}})

	dir := t.TempDir()
	for name, s := range map[string]Snapshot{"plain": plain, "named": named} {
		if err := s.Write(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	cov, _ := os.ReadFile(filepath.Join(dir, "plain", "coverage.yaml"))
	if strings.Contains(string(cov), "names:") {
		t.Errorf("a skip with no names is written with the key:\n%s", cov)
	}
	got, err := Read(filepath.Join(dir, "named"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sk := range got.Skips {
		names = append(names, sk.Names...)
	}
	if strings.Join(names, " ") != "hook metrics" {
		t.Errorf("names read back: %q", names)
	}
	for _, sk := range got.Skips {
		if len(sk.Names) > 0 && sk.Selectors["hook"]["app"] != "hook" {
			t.Errorf("selectors read back: %v", sk.Selectors)
		}
	}
	if strings.Contains(string(cov), "selectors:") {
		t.Errorf("a skip with no selectors is written with the key:\n%s", cov)
	}
}

// The capture rules are in the manifest, outside the digest: the same
// files under another version have the same digest, a snapshot from before
// they were recorded reads as 0, and one with them reads them back.
func TestRulesAreOutsideTheDigest(t *testing.T) {
	s := Snapshot{Platform: "kubernetes", Policy: "default", Coverage: []Coverage{{Resource: "core/v1/configmaps", Kind: "ConfigMap", Captured: 1}},
		Objects: []Object{{Body: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "cfg", "namespace": "shop"}}}}}
	none, with := t.TempDir(), t.TempDir()
	if err := s.Write(none); err != nil {
		t.Fatal(err)
	}
	s.Rules = 7
	if err := s.Write(with); err != nil {
		t.Fatal(err)
	}
	a, _ := Digest(none)
	b, _ := Digest(with)
	if a != b || a == "" {
		t.Errorf("digest %s without rules, %s with", a, b)
	}
	m, _ := os.ReadFile(filepath.Join(none, "snapshot.yaml"))
	if strings.Contains(string(m), "rules") {
		t.Errorf("a manifest without rules says some:\n%s", m)
	}
	for dir, want := range map[string]int{none: 0, with: 7} {
		got, err := Read(dir)
		if err != nil || got.Rules != want {
			t.Errorf("%s: rules %d, want %d (%v)", dir, got.Rules, want, err)
		}
	}
}

// Where a platform's names ignore case, an object's file does not depend on
// the case its name was returned in, and two spellings of one name are one
// object. Elsewhere they are two.
func TestAzureFilesDoNotDependOnCase(t *testing.T) {
	obj := func(name string) Object {
		return Object{Body: map[string]any{"apiVersion": "azure.truthform.org/v1", "kind": "Microsoft.OperationalInsights/workspaces/tables",
			"metadata": map[string]any{"namespace": "Logs", "name": name}}}
	}
	files := func(s Snapshot) []string {
		dir := filepath.Join(t.TempDir(), "s")
		if err := s.Write(dir); err != nil {
			t.Fatal(err)
		}
		var out []string
		_ = filepath.WalkDir(filepath.Join(dir, "objects"), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				rel, _ := filepath.Rel(dir, p)
				out = append(out, filepath.ToSlash(rel))
			}
			return err
		})
		return out
	}
	a := files(Snapshot{Platform: "azure", Objects: []Object{obj("law/ACSUsage")}})
	b := files(Snapshot{Platform: "azure", Objects: []Object{obj("law/AcsUsage")}})
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Errorf("one table in two cases is in two files: %v %v", a, b)
	}
	if want := "objects/azure.truthform.org/v1/microsoft.operationalinsights%2Fworkspaces%2Ftables/logs/law%2Facsusage.yaml"; len(a) == 1 && a[0] != want {
		t.Errorf("file %s, want %s", a[0], want)
	}
	err := Snapshot{Platform: "azure", Objects: []Object{obj("law/ACSUsage"), obj("law/AcsUsage")}}.Write(filepath.Join(t.TempDir(), "s"))
	if err == nil || !strings.Contains(err.Error(), "ignore case") {
		t.Errorf("two spellings of one Azure object were written: %v", err)
	}
	// Asked of the path, not the filesystem: on Windows and macOS cfg and
	// Cfg are one file whatever TruthForm names them.
	k := func(name string) Object {
		return Object{Body: map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"namespace": "Shop", "name": name}}}
	}
	if got := objectPath(k("Cfg"), FoldsCase("kubernetes")); got != "objects/core/v1/ConfigMap/Shop/Cfg.yaml" {
		t.Errorf("Kubernetes names are case-sensitive: %s", got)
	}
	// Schemas too.
	sch := TypeSchema{APIVersion: "azure.truthform.org/v1", Kind: "Microsoft.Insights/diagnosticSettings"}
	if got := schemaPath(sch, FoldsCase("azure")); got != "schemas/azure.truthform.org/v1/microsoft.insights%2Fdiagnosticsettings.yaml" {
		t.Errorf("schema file %s", got)
	}
	dir := filepath.Join(t.TempDir(), "s")
	if err := (Snapshot{Platform: "azure", Objects: []Object{obj("law/ACSUsage")}, Schemas: []TypeSchema{sch}}).Write(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "schemas", "azure.truthform.org", "v1", "microsoft.insights%2Fdiagnosticsettings.yaml")); err != nil {
		t.Errorf("the schema is not under its lower-case path: %v", err)
	}
}

// On Windows and macOS git keeps the case a path was first committed in, so a
// clone of an Azure snapshot committed before paths were in lower case, and
// then replaced by this build's, has the old paths and the new contents. It is
// read; a file whose contents changed is still refused.
func TestAzurePathsInAnotherCaseAreRead(t *testing.T) {
	o := Object{Body: map[string]any{"apiVersion": "azure.truthform.org/v1", "kind": "Microsoft.OperationalInsights/workspaces/tables",
		"metadata": map[string]any{"namespace": "Logs", "name": "law/ACSUsage"}, "spec": map[string]any{"properties": map[string]any{"plan": "Analytics"}}}}
	sch := TypeSchema{APIVersion: "azure.truthform.org/v1", Kind: "Microsoft.OperationalInsights/workspaces/tables"}
	write := func(platform string) string {
		dir := filepath.Join(t.TempDir(), "s")
		if err := (Snapshot{Platform: platform, Objects: []Object{o}, Schemas: []TypeSchema{sch}}).Write(dir); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// Each file moved to the path an earlier build gave it.
	asBefore := func(dir string) {
		for _, f := range []string{objectPath(o, true), schemaPath(sch, true)} {
			old := filepath.Join(dir, filepath.FromSlash(objectPathOrSchema(f, o, sch)))
			if err := os.MkdirAll(filepath.Dir(old), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, filepath.FromSlash(f)), old); err != nil {
				t.Fatal(err)
			}
		}
	}
	dir := write("azure")
	asBefore(dir)
	if _, err := Read(dir); err != nil {
		t.Errorf("paths in the case an earlier build wrote: %v", err)
	}
	p := filepath.Join(dir, filepath.FromSlash(objectPath(o, false)))
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), "Analytics", "Basic", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil || !strings.Contains(err.Error(), "does not match its manifest digest") {
		t.Errorf("a changed file under such a path was read: %v", err)
	}
	// Only where the path differs in case: a file moved elsewhere is refused.
	dir = write("azure")
	elsewhere := filepath.Join(dir, "objects", "azure.truthform.org", "v1", "elsewhere.yaml")
	if err := os.Rename(filepath.Join(dir, filepath.FromSlash(objectPath(o, true))), elsewhere); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil {
		t.Error("an Azure file moved to another path was read")
	}
	// Only where names ignore case. A path all in lower case, moved to
	// another case: on a filesystem that ignores case (NTFS, APFS) the file
	// is still found at its own path, and nothing was moved to test.
	if !caseSensitiveFS(t) {
		return
	}
	o.Body["apiVersion"], o.Body["kind"] = "example.com/v1", "widget"
	o.Body["metadata"] = map[string]any{"namespace": "shop", "name": "w"}
	sch = TypeSchema{APIVersion: "example.com/v1", Kind: "widget"}
	dir = write("kubernetes")
	moved := filepath.Join(dir, "objects", "example.com", "v1", "Widget", "shop", "w.yaml")
	if err := os.MkdirAll(filepath.Dir(moved), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, filepath.FromSlash(objectPath(o, false))), moved); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil {
		t.Error("a Kubernetes file under a path in another case was read")
	}
}

// objectPathOrSchema is f as an earlier build named it: in the case given.
func objectPathOrSchema(f string, o Object, sch TypeSchema) string {
	if strings.HasPrefix(f, "schemas/") {
		return schemaPath(sch, false)
	}
	return objectPath(o, false)
}

// caseSensitiveFS reports whether the temporary directory's filesystem tells
// two names apart by case.
func caseSensitiveFS(t *testing.T) bool {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := os.Stat(filepath.Join(dir, "A"))
	return err != nil
}
