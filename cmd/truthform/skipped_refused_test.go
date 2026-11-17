package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/kube"
	"github.com/usetruthform/core/internal/kubetest"
	"github.com/usetruthform/core/internal/snapshot"
)

// On a real API server, through capture and diff: an object left out as
// identical to the baseline and then edited is a difference, and so is one
// captured edited and then put back to the baseline, each with why the
// other side left it out beside it, and no hint about an older build: the
// baseline skip is decided by the object's content.
func TestBaselineSkipIsADifference(t *testing.T) {
	srv := kubetest.Start(t, "baseline-skip")
	settle(t, srv)
	ctx := context.Background()
	w, err := kube.Connect(srv.Kubeconfig, srv.Context, false)
	if err != nil {
		t.Fatal(err)
	}
	cs := kubernetes.NewForConfigOrDie(w.Config)
	if _, err := cs.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().ConfigMaps("shop").Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "shop"}, Data: map[string]string{"a": "1"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "ops"},
		RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
		Subjects: []rbacv1.Subject{{Kind: "Group", APIGroup: "rbac.authorization.k8s.io", Name: "ops"}}}
	if _, err := cs.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	conn := []string{"--kubeconfig", srv.Kubeconfig, "--context", srv.Context}
	snap := func(name string, extra ...string) string {
		t.Helper()
		out := filepath.Join(dir, name)
		if code, stdout, stderr := output(t, func() int { return capture(ctx, append(append(append([]string{}, conn...), "--out", out), extra...)) }); code != 0 {
			t.Fatalf("capture %s: exit %d\n%s%s", name, code, stdout, stderr)
		}
		return out
	}
	base := snap("base")
	a := snap("a", "--baseline", base)
	for _, key := range []string{"v1|ConfigMap|shop|cfg", "rbac.authorization.k8s.io/v1|ClusterRoleBinding||ops"} {
		wantSkip(t, a, key, true)
	}
	edit := func(value string, subjects []rbacv1.Subject) {
		t.Helper()
		cm, _ := cs.CoreV1().ConfigMaps("shop").Get(ctx, "cfg", metav1.GetOptions{})
		cm.Data["a"] = value
		if _, err := cs.CoreV1().ConfigMaps("shop").Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		b, _ := cs.RbacV1().ClusterRoleBindings().Get(ctx, "ops", metav1.GetOptions{})
		b.Subjects = subjects
		if _, err := cs.RbacV1().ClusterRoleBindings().Update(ctx, b, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	const baseline = "identical to the distribution baseline; a new cluster provides it"
	wantDifferences := func(what, from, kind string) {
		t.Helper()
		args := append(append([]string{}, conn...), "--from", from, "--baseline", base)
		code, stdout, _ := output(t, func() int { return diff(ctx, args) })
		for _, l := range []string{kind + " v1|ConfigMap|shop|cfg" + leftOutNote + baseline + ")\n", kind + " rbac.authorization.k8s.io/v1|ClusterRoleBinding||ops" + leftOutNote + baseline + ")\n", "2 differences between"} {
			if !strings.Contains(stdout, l) {
				t.Errorf("%s: no %q\n%s", what, l, stdout)
			}
		}
		if code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", what, code, stdout)
		}
		d := asJSON(t, func() { code = diff(ctx, args) })
		if code != 2 || d["differences"] != float64(2) {
			t.Errorf("%s --json: exit %d, %v", what, code, d)
		}
		for _, c := range d["changes"].([]any) {
			if s, _ := c.(map[string]any)["skippedOtherSide"].(map[string]any); s["reason"] != baseline {
				t.Errorf("%s --json: %v", what, c)
			}
		}
	}
	// Edited after a capture that left it out as the baseline's.
	edit("EVIL", append(crb.Subjects, rbacv1.Subject{Kind: "User", APIGroup: "rbac.authorization.k8s.io", Name: "mallory"}))
	wantDifferences("edited away from the baseline", a, "extra   ")
	// Captured edited, then put back.
	c := snap("c", "--baseline", base)
	wantSkip(t, c, "v1|ConfigMap|shop|cfg", false)
	edit("1", crb.Subjects)
	wantDifferences("put back to the baseline", c, "missing ")
}

// What the target could not be read is missing, the diff exits 2, and the
// line says the target could not read it. Through diff against a fake
// Azure target whose GET fails for one zone.
func TestUnreadableOnTheTargetIsNoted(t *testing.T) {
	reg, err := azarm.LoadDefinitions(leaveDefs)
	if err != nil {
		t.Fatal(err)
	}
	world := azarm.NewWorld(reg)
	src := world.Subscription(leaveDst, "tenant")
	ctx := context.Background()
	rg := "/subscriptions/" + leaveDst + "/resourceGroups/rg"
	zone := rg + "/providers/Microsoft.Network/privateDnsZones/corp.example"
	record := zone + "/A/www"
	for _, p := range []struct {
		id, typ string
		body    map[string]any
	}{
		{rg, "Microsoft.Resources/resourceGroups", map[string]any{"location": "eastus"}},
		{zone, "Microsoft.Network/privateDnsZones", map[string]any{"location": "global"}},
		{record, "Microsoft.Network/privateDnsZones/A", map[string]any{"properties": map[string]any{"ttl": 300, "aRecords": []any{map[string]any{"ipv4Address": "10.0.0.4"}}}}},
	} {
		v := reg.Versions(p.typ)
		if _, err := src.Put(ctx, p.id, v[len(v)-1], p.body); err != nil {
			t.Fatalf("seed %s: %v", p.id, err)
		}
	}
	s, err := (&azarm.Adapter{API: src, Registry: reg}).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "snap")
	if err := s.Write(dir); err != nil {
		t.Fatal(err)
	}
	old := azureAPI
	azureAPI = func(sub string, _ bool) (azarm.ARM, error) {
		if sub != leaveDst {
			return nil, errors.New("only the fake target")
		}
		return failingGet{readOnlyFake{src}, zone}, nil
	}
	t.Cleanup(func() { azureAPI = old })
	target := []string{"--platform", "azure", "--subscription", leaveDst, "--definitions", leaveDefs, "--from", dir}
	code, stdout, stderr := output(t, func() int { return diff(ctx, target) })
	if code != 2 || !strings.Contains(stdout, "missing  azure.truthform.org/v1|Microsoft.Network/privateDnsZones|rg|corp.example"+leftOutNote+azarm.Unreadable+"AuthorizationFailed: ") {
		t.Errorf("diff of a target that could not be read: exit %d, want 2 and the record missing\n%s%s", code, stdout, stderr)
	}
}

// failingGet answers every GET but one, as ARM does to a caller denied one
// resource.
type failingGet struct {
	readOnlyFake
	id string
}

func (f failingGet) Get(ctx context.Context, id, version string) (map[string]any, error) {
	if strings.EqualFold(id, f.id) {
		return nil, fmt.Errorf("AuthorizationFailed: %s", id)
	}
	return f.readOnlyFake.Get(ctx, id, version)
}

// Through compare, for each platform's own words for what it left out for
// its content or could not read: a difference in either direction, noted
// without the hint where the platform's skips name objects (Azure only
// under its rules 1), and with no note where they do not (AWS; Azure
// before rules 1).
func TestCompareNotesContentAndReadSkips(t *testing.T) {
	for _, c := range []struct {
		platform, resource, kind, apiVersion, ns, name, skipName, reason string
		rules                                                            int
		note                                                             bool
	}{
		{"aws", "AWS::S3::Bucket", "AWS::S3::Bucket", "aws.truthform.org/v1", "", "assets", "assets", awscc.Unreadable + "AccessDenied", 0, false},
		{"aws", "AWS::EC2::VPC", "AWS::EC2::VPC", "aws.truthform.org/v1", "", "main", "main", "identical to the baseline snapshot (already there, or created by AWS)", 0, false},
		{"azure", "Microsoft.Network/privateDnsZones", "Microsoft.Network/privateDnsZones", "azure.truthform.org/v1", "rg", "corp.example", "rg/corp.example", azarm.Unreadable + "AuthorizationFailed", snapshot.AzureCaptureRules, true},
		{"azure", "Microsoft.Network/privateDnsZones", "Microsoft.Network/privateDnsZones", "azure.truthform.org/v1", "rg", "corp.example", "rg/corp.example", "identical to the baseline snapshot (already there, or created by Azure)", snapshot.AzureCaptureRules, true},
		{"azure", "Microsoft.Network/privateDnsZones", "Microsoft.Network/privateDnsZones", "azure.truthform.org/v1", "rg", "corp.example", "rg/corp.example", "identical to the baseline snapshot (already there, or created by Azure)", 0, false},
		{"gcp", "storage.googleapis.com/Bucket", "storage.googleapis.com/Bucket", "gcp.truthform.org/v1", "", "assets", "assets", gcp.Unreadable + "403", 0, true},
		{"gcp", "storage.googleapis.com/Bucket", "storage.googleapis.com/Bucket", "gcp.truthform.org/v1", "", "assets", "assets", "identical to the baseline snapshot (already there, or created by Google)", 0, true},
		{"kubernetes", "core/v1/configmaps", "ConfigMap", "v1", "shop", "cfg", "cfg", "identical to the distribution baseline; a new cluster provides it", 0, true},
	} {
		obj := snapshot.Object{Body: map[string]any{"apiVersion": c.apiVersion, "kind": c.kind, "metadata": map[string]any{"name": c.name}, "spec": map[string]any{"a": "1"}}}
		if c.ns != "" {
			obj.Body["metadata"].(map[string]any)["namespace"] = c.ns
		}
		cov := []snapshot.Coverage{{Resource: c.resource, Kind: c.kind}}
		skipNs := ""
		if c.platform == "kubernetes" {
			skipNs = c.ns
		}
		took := snapshot.Snapshot{Platform: c.platform, Policy: "default", Rules: c.rules, Coverage: cov, Objects: []snapshot.Object{obj}}
		left := snapshot.Snapshot{Platform: c.platform, Policy: "default", Rules: c.rules, Coverage: cov, Skips: []snapshot.Skip{{Resource: c.resource, Namespace: skipNs, Name: c.skipName, Reason: c.reason}}}
		a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
		if err := took.Write(a); err != nil {
			t.Fatal(err)
		}
		if err := left.Write(b); err != nil {
			t.Fatal(err)
		}
		for _, dirs := range [][2]string{{a, b}, {b, a}} {
			code, stdout, stderr := output(t, func() int { return compare([]string{dirs[0], dirs[1]}) })
			noted := strings.Contains(stdout, leftOutNote+c.reason+")\n")
			if code != 2 || noted != c.note || strings.Contains(stdout, leftOutNote) != c.note || strings.Contains(stdout, olderHint) {
				t.Errorf("%s rules %d %q: exit %d, want 2 and a note %v\n%s%s", c.platform, c.rules, c.reason, code, c.note, stdout, stderr)
			}
		}
	}
}

// wantSkip checks that a snapshot captured an object or skipped it.
func wantSkip(t *testing.T, dir, key string, skipped bool) {
	t.Helper()
	s, err := snapshot.Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	captured := false
	for _, o := range s.Objects {
		if o.Key() == key {
			captured = true
		}
	}
	if captured == skipped {
		t.Fatalf("%s: captured %v, want skipped %v", key, captured, skipped)
	}
}

// A report says the note beside the line it explains, and in --json only on
// that change, as {reason}; a change with no note has no field; the count
// and the exit code are those of every change.
func TestReportNotesOnlyWhatWasLeftOut(t *testing.T) {
	changes := []snapshot.Change{
		{Key: "v1|ConfigMap|shop|cfg", Kind: "missing", Skipped: &snapshot.SkippedOtherSide{Reason: "why", OlderRules: true}},
		{Key: "v1|ConfigMap|shop|gone", Kind: "missing"},
	}
	code, stdout, _ := output(t, func() int { return report(changes, "a", "b") })
	for _, l := range []string{
		"missing  v1|ConfigMap|shop|cfg" + leftOutNote + "why" + olderHint + "\n",
		"missing  v1|ConfigMap|shop|gone\n",
		"2 differences between a and b\n",
	} {
		if !strings.Contains(stdout, l) {
			t.Errorf("no %q in\n%s", l, stdout)
		}
	}
	if code != 2 {
		t.Errorf("exit %d", code)
	}
	if _, one, _ := output(t, func() int { return report(changes[1:], "a", "b") }); !strings.Contains(one, "1 difference between a and b\n") {
		t.Errorf("one difference:\n%s", one)
	}
	d := asJSON(t, func() { code = report(changes, "a", "b") })
	cs := d["changes"].([]any)
	if code != 2 || d["differences"] != float64(2) || len(cs) != 2 {
		t.Fatalf("exit %d, %v", code, d)
	}
	if s, _ := cs[0].(map[string]any)["skippedOtherSide"].(map[string]any); len(s) != 1 || s["reason"] != "why" {
		t.Errorf("noted change: %v", cs[0])
	}
	if _, has := cs[1].(map[string]any)["skippedOtherSide"]; has {
		t.Errorf("a change with no note: %v", cs[1])
	}
}
