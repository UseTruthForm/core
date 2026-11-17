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
// identical to the baseline and then edited is a difference, not a move,
// and so is one captured edited and then put back to the baseline. The
// baseline skip is decided by the object's content, so a move across it
// is always a change (review of #24: a ConfigMap edited and a subject
// added to a ClusterRoleBinding read as moved, and the diff exited 0).
func TestBaselineSkipIsNeverAMove(t *testing.T) {
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
	wantDifferences := func(what, from, kind string) {
		t.Helper()
		args := append(append([]string{}, conn...), "--from", from, "--baseline", base)
		code, stdout, _ := output(t, func() int { return diff(ctx, args) })
		for _, l := range []string{kind + " v1|ConfigMap|shop|cfg", kind + " rbac.authorization.k8s.io/v1|ClusterRoleBinding||ops", "2 differences between"} {
			if !strings.Contains(stdout, l) {
				t.Errorf("%s: no %q\n%s", what, l, stdout)
			}
		}
		if code != 2 || strings.Contains(stdout, "\nmoved ") {
			t.Errorf("%s: exit %d, want 2 and nothing moved\n%s", what, code, stdout)
		}
		d := asJSON(t, func() { code = diff(ctx, args) })
		if code != 2 || d["differences"] != float64(2) || len(d["moved"].([]any)) != 0 {
			t.Errorf("%s --json: exit %d, %v", what, code, d)
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

// What the target could not be read is never a move: an object the
// snapshot has and a diff could not read on the target is missing, and the
// diff exits 2 (review of #24: Azure's and AWS's "listed but could not be
// read" read as moved, and nothing said the read had failed). Through diff
// against a fake Azure target whose GET fails for one zone.
func TestUnreadableOnTheTargetIsNotAMove(t *testing.T) {
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
	if code != 2 || !strings.Contains(stdout, "missing  azure.truthform.org/v1|Microsoft.Network/privateDnsZones|rg|corp.example\n") || strings.Contains(stdout, "\nmoved ") {
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
// its content or could not read: never a move, in either direction.
func TestCompareRefusesContentAndReadSkips(t *testing.T) {
	for _, c := range []struct {
		platform, resource, kind, apiVersion, ns, name, skipName, reason string
	}{
		{"aws", "AWS::S3::Bucket", "AWS::S3::Bucket", "aws.truthform.org/v1", "", "assets", "assets", awscc.Unreadable + "AccessDenied"},
		{"aws", "AWS::EC2::VPC", "AWS::EC2::VPC", "aws.truthform.org/v1", "", "main", "main", "identical to the baseline snapshot (already there, or created by AWS)"},
		{"azure", "Microsoft.Network/privateDnsZones", "Microsoft.Network/privateDnsZones", "azure.truthform.org/v1", "rg", "corp.example", "rg/corp.example", azarm.Unreadable + "AuthorizationFailed"},
		{"azure", "Microsoft.Network/privateDnsZones", "Microsoft.Network/privateDnsZones", "azure.truthform.org/v1", "rg", "corp.example", "rg/corp.example", "identical to the baseline snapshot (already there, or created by Azure)"},
		{"gcp", "storage.googleapis.com/Bucket", "storage.googleapis.com/Bucket", "gcp.truthform.org/v1", "", "assets", "assets", gcp.Unreadable + "403"},
		{"gcp", "storage.googleapis.com/Bucket", "storage.googleapis.com/Bucket", "gcp.truthform.org/v1", "", "assets", "assets", "identical to the baseline snapshot (already there, or created by Google)"},
		{"kubernetes", "core/v1/configmaps", "ConfigMap", "v1", "shop", "cfg", "cfg", "identical to the distribution baseline; a new cluster provides it"},
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
		took := snapshot.Snapshot{Platform: c.platform, Policy: "default", Coverage: cov, Objects: []snapshot.Object{obj}}
		left := snapshot.Snapshot{Platform: c.platform, Policy: "default", Coverage: cov, Skips: []snapshot.Skip{{Resource: c.resource, Namespace: skipNs, Name: c.skipName, Reason: c.reason}}}
		a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
		if err := took.Write(a); err != nil {
			t.Fatal(err)
		}
		if err := left.Write(b); err != nil {
			t.Fatal(err)
		}
		for _, dirs := range [][2]string{{a, b}, {b, a}} {
			code, stdout, stderr := output(t, func() int { return compare([]string{dirs[0], dirs[1]}) })
			if code != 2 || strings.HasPrefix(stdout, "moved ") || strings.Contains(stdout, "\nmoved ") {
				t.Errorf("%s %q: exit %d, want 2 and nothing moved\n%s%s", c.platform, c.reason, code, stdout, stderr)
			}
		}
	}
}
