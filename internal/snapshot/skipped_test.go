package snapshot

import (
	"reflect"
	"strings"
	"testing"
)

func kobj(apiVersion, kind, ns, name string) Object {
	md := map[string]any{"name": name}
	if ns != "" {
		md["namespace"] = ns
	}
	return Object{Body: map[string]any{"apiVersion": apiVersion, "kind": kind, "metadata": md}}
}

var byFlux = FluxKustomizationReason("gitops", "root")

var kubeCoverage = []Coverage{
	{Resource: "core/v1/namespaces", Kind: "Namespace"},
	{Resource: "core/v1/configmaps", Kind: "ConfigMap"},
	{Resource: "core/v1/services", Kind: "Service"},
	{Resource: "kustomize.toolkit.fluxcd.io/v1/kustomizations", Kind: "Kustomization"},
	{Resource: "argoproj.io/v1alpha1/applications", Kind: "Application"},
	{Resource: "app.example.com/v1/applications", Kind: "Application"},
	{Resource: "apps/v1beta1/deployments", Kind: "Deployment"},
	{Resource: "Widget", Kind: "Widget"},
	{Resource: "core/v1/secrets", Kind: "Secret"},
}

func kube(rules int, objects []Object, skips []Skip) Snapshot {
	return Snapshot{Platform: "kubernetes", Rules: rules, Coverage: kubeCoverage, Objects: objects, Skips: skips}
}

// noted is the note Compare gives the one change between want and got,
// which must be the kind given: a note never takes a difference away.
func noted(t *testing.T, want, got Snapshot, kind string) *SkippedOtherSide {
	t.Helper()
	ch := Compare(want, got)
	if len(ch) != 1 || ch[0].Kind != kind {
		t.Fatalf("want one %s, got %+v", kind, ch)
	}
	return ch[0].Skipped
}

// A missing object the other side left out, and an extra one the first
// side left out, are each still a difference, with the reason beside it.
func TestSkippedOtherSideIsNotedOnBothSides(t *testing.T) {
	cfg := kobj("v1", "ConfigMap", "shop", "cfg")
	skip := []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}}
	if n := noted(t, kube(1, []Object{cfg}, nil), kube(1, nil, skip), "missing"); !reflect.DeepEqual(n, &SkippedOtherSide{Reason: byFlux}) {
		t.Errorf("missing: %+v", n)
	}
	if n := noted(t, kube(1, nil, skip), kube(1, []Object{cfg}, nil), "extra"); !reflect.DeepEqual(n, &SkippedOtherSide{Reason: byFlux}) {
		t.Errorf("extra: %+v", n)
	}
	if n := noted(t, kube(1, []Object{cfg}, nil), kube(1, nil, nil), "missing"); n != nil {
		t.Errorf("nothing left it out: %+v", n)
	}
}

// The hint about a build before beta.23 is given only where the side that
// left the object out does not say its rules, and every reason it gives is
// a GitOps source's, on Kubernetes.
func TestSkippedOtherSideOlderRules(t *testing.T) {
	cfg := kobj("v1", "ConfigMap", "shop", "cfg")
	for _, c := range []struct {
		what    string
		rules   int
		reasons []string
		older   bool
	}{
		{"Flux Kustomization, no rules", 0, []string{byFlux}, true},
		{"Flux HelmRelease, no rules", 0, []string{FluxHelmReleaseReason("gitops", "web")}, true},
		{"Argo CD, no rules", 0, []string{ArgoCDReason("shop")}, true},
		{"two GitOps reasons, no rules", 0, []string{byFlux, ArgoCDReason("shop")}, true},
		{"under rules", 1, []string{byFlux}, false},
		{"owned by a controller", 0, []string{OwnedReason("Deployment", "web")}, false},
		{"baseline", 0, []string{"identical to the distribution baseline; a new cluster provides it"}, false},
		{"GitOps and baseline", 0, []string{byFlux, "identical to the distribution baseline; a new cluster provides it"}, false},
		// Sorted, the GitOps reason is last: every reason must be one.
		{"Crossplane and GitOps", 0, []string{"composed by Crossplane composite db; restoring the composite recreates it", ArgoCDReason("shop")}, false},
		{"GitOps and owned", 0, []string{byFlux, OwnedReason("Deployment", "web")}, false},
		{"near miss after", 0, []string{byFlux + " (edited)"}, false},
		{"near miss before", 0, []string{"x" + byFlux}, false},
		{"no namespace in the label", 0, []string{FluxKustomizationReason("", "root")}, false},
		{"a space in a name", 0, []string{FluxKustomizationReason("git ops", "root")}, false},
		{"a slash in a name", 0, []string{FluxKustomizationReason("git/ops", "root")}, false},
		{"a semicolon in a name", 0, []string{ArgoCDReason("shop;x")}, false},
	} {
		var skips []Skip
		for _, r := range c.reasons {
			skips = append(skips, Skip{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: r})
		}
		for _, pair := range [][2]Snapshot{{kube(1, []Object{cfg}, nil), kube(c.rules, nil, skips)}, {kube(c.rules, nil, skips), kube(1, []Object{cfg}, nil)}} {
			kind := "missing"
			if len(pair[0].Objects) == 0 {
				kind = "extra"
			}
			n := noted(t, pair[0], pair[1], kind)
			if n == nil || n.OlderRules != c.older {
				t.Errorf("%s, %s: %+v, want older %v", c.what, kind, n, c.older)
			}
		}
	}
	// Only a Kubernetes capture gives a GitOps source's reason.
	gcp := Object{Body: map[string]any{"apiVersion": "gcp.truthform.org/v1", "kind": "storage.googleapis.com/Bucket", "metadata": map[string]any{"name": "assets"}}}
	cov := []Coverage{{Resource: "storage.googleapis.com/Bucket", Kind: "storage.googleapis.com/Bucket"}}
	want := Snapshot{Platform: "gcp", Coverage: cov, Objects: []Object{gcp}}
	got := Snapshot{Platform: "gcp", Coverage: cov, Skips: []Skip{{Resource: "storage.googleapis.com/Bucket", Name: "assets", Reason: byFlux}}}
	if n := noted(t, want, got, "missing"); n == nil || n.OlderRules {
		t.Errorf("gcp: %+v", n)
	}
	// Off Kubernetes the resource is the kind itself: another resource the
	// coverage gives the same kind is another type.
	cov = append(cov, Coverage{Resource: "other.googleapis.com/Bucket", Kind: "storage.googleapis.com/Bucket"})
	want.Coverage = cov
	got = Snapshot{Platform: "gcp", Coverage: cov, Skips: []Skip{{Resource: "other.googleapis.com/Bucket", Name: "assets", Reason: "r"}}}
	if n := noted(t, want, got, "missing"); n != nil {
		t.Errorf("gcp, another type: %+v", n)
	}
}

// A skip names an object only where the platform's skips name objects as
// its snapshots key them: AWS and SaaS skips name a resource by its
// identifier, which another's logical name may be, so they give no note.
func TestSkippedOtherSideOnlyWhereNamesMatch(t *testing.T) {
	for _, p := range []string{"aws", "github", "cloudflare", ""} {
		o := Object{Body: map[string]any{"apiVersion": p + ".truthform.org/v1", "kind": "Thing", "metadata": map[string]any{"name": "web"}}}
		cov := []Coverage{{Resource: "Thing", Kind: "Thing"}}
		want := Snapshot{Platform: p, Coverage: cov, Objects: []Object{o}}
		got := Snapshot{Platform: p, Coverage: cov, Skips: []Skip{{Resource: "Thing", Name: "web", Reason: "listed but could not be read: AccessDenied"}}}
		if n := noted(t, want, got, "missing"); n != nil {
			t.Errorf("%q: %+v", p, n)
		}
	}
}

// Every reason the other side gives is said, once each, in order.
func TestSkippedOtherSideGivesEveryReason(t *testing.T) {
	argo := ArgoCDReason("shop")
	skips := []Skip{
		{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux},
		{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: argo},
		{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux},
	}
	n := noted(t, kube(1, []Object{kobj("v1", "ConfigMap", "shop", "cfg")}, nil), kube(1, nil, skips), "missing")
	if n == nil || n.Reason != byFlux+"; "+argo {
		t.Errorf("%+v", n)
	}
}

// A skip names an object only by its own resource, namespace and name:
// one of another kind, another group with the same kind, another namespace,
// or a skip with no namespace for a namespaced object, is another object.
func TestSkippedOtherSideMatchesOnlyTheSameObject(t *testing.T) {
	for _, c := range []struct {
		o    Object
		skip Skip
	}{
		{kobj("v1", "ConfigMap", "shop", "settings"), Skip{Resource: "core/v1/secrets", Namespace: "shop", Name: "settings", Reason: byFlux}},
		{kobj("argoproj.io/v1alpha1", "Application", "argocd", "shop"), Skip{Resource: "app.example.com/v1/applications", Namespace: "argocd", Name: "shop", Reason: byFlux}},
		{kobj("v1", "ConfigMap", "other", "x"), Skip{Resource: "core/v1/configmaps", Namespace: "elsewhere", Name: "x", Reason: byFlux}},
		{kobj("v1", "ConfigMap", "shop", "plain"), Skip{Resource: "core/v1/configmaps", Name: "plain", Reason: byFlux}},
		{kobj("v1", "ConfigMap", "shop", "Cfg"), Skip{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}},
		// apps/v1 is not apps/v1beta1.
		{kobj("apps/v1", "Deployment", "shop", "web"), Skip{Resource: "apps/v1beta1/deployments", Namespace: "shop", Name: "web", Reason: byFlux}},
		// On Kubernetes a resource is group/version/plural, never the kind.
		{kobj("v1", "Widget", "shop", "w"), Skip{Resource: "Widget", Namespace: "shop", Name: "w", Reason: byFlux}},
	} {
		if n := noted(t, kube(1, []Object{c.o}, nil), kube(1, nil, []Skip{c.skip}), "missing"); n != nil {
			t.Errorf("%v / %v: %+v", c.o.Body, c.skip, n)
		}
	}
	// A cluster-scoped object is named by its name alone.
	if n := noted(t, kube(1, []Object{kobj("v1", "Namespace", "", "shop")}, nil), kube(1, nil, []Skip{{Resource: "core/v1/namespaces", Name: "shop", Reason: byFlux}}), "missing"); n == nil {
		t.Error("a namespace left out has no note")
	}
}

// The resource is read from the coverage of the snapshot that left the
// object out, which lists every type it left anything out of.
func TestSkippedOtherSideReadsTheSkippingSnapshotsCoverage(t *testing.T) {
	want := Snapshot{Platform: "kubernetes", Objects: []Object{kobj("v1", "ConfigMap", "shop", "cfg")}}
	if n := noted(t, want, kube(1, nil, []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}}), "missing"); n == nil {
		t.Error("no note")
	}
	got := Snapshot{Platform: "kubernetes", Skips: []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}}}
	if n := noted(t, kube(1, []Object{kobj("v1", "ConfigMap", "shop", "cfg")}, nil), got, "missing"); n != nil {
		t.Errorf("a skip whose type its own snapshot does not cover: %+v", n)
	}
}

// A skip of "*" stands for its Names where the capture lists them (the
// Services an object owns); one without names names nothing.
func TestSkippedOtherSideThroughOwnerSkip(t *testing.T) {
	owned := OwnedReason("Gateway", "front")
	want := kube(1, []Object{kobj("v1", "Service", "shop", "web")}, nil)
	n := noted(t, want, kube(1, nil, []Skip{{Resource: "core/v1/services", Namespace: "shop", Name: "*", Reason: owned, Names: []string{"web"}}}), "missing")
	if n == nil || n.Reason != owned {
		t.Errorf("named: %+v", n)
	}
	if n := noted(t, want, kube(1, nil, []Skip{{Resource: "core/v1/services", Namespace: "shop", Name: "*", Reason: owned}}), "missing"); n != nil {
		t.Errorf("unnamed: %+v", n)
	}
}

// Azure from rules 1 names a skip by group and name as the snapshot keys
// it, without regard to case: an extension by its path below the group, a
// group as itself twice, one with no group by its path below the
// subscription.
func TestSkippedOtherSideAzure(t *testing.T) {
	const lock = "Microsoft.Authorization/locks"
	cov := []Coverage{{Resource: "Microsoft.Network/networkInterfaces", Kind: "Microsoft.Network/networkInterfaces"}, {Resource: lock, Kind: lock}, {Resource: "Microsoft.Resources/resourceGroups", Kind: "Microsoft.Resources/resourceGroups"}}
	az := func(kind, ns, name string) Object { return kobj("azure.truthform.org/v1", kind, ns, name) }
	saLock := "providers/Microsoft.Storage/storageAccounts/sa/providers/Microsoft.Authorization/locks/l1"
	for _, c := range []struct {
		what string
		o    Object
		skip Skip
		note bool
	}{
		{"resource", az("Microsoft.Network/networkInterfaces", "app-rg", "nic-1"), Skip{Resource: "microsoft.network/networkInterfaces", Name: "APP-RG/nic-1", Reason: "r"}, true},
		{"group", az("Microsoft.Resources/resourceGroups", "", "app-rg"), Skip{Resource: "Microsoft.Resources/resourceGroups", Name: "app-rg/app-rg", Reason: "r"}, true},
		{"extension", az(lock, "app-rg", saLock), Skip{Resource: lock, Name: "app-rg/" + saLock, Reason: "r"}, true},
		{"no group", az(lock, "", "providers/Microsoft.Authorization/locks/l1"), Skip{Resource: lock, Name: "/providers/Microsoft.Authorization/locks/l1", Reason: "r"}, true},
		// Review of #24: a lock on the group is not one of its name on a
		// resource in it, nor the other way.
		{"group's lock, resource's skipped", az(lock, "app-rg", "l1"), Skip{Resource: lock, Name: "app-rg/" + saLock, Reason: "r"}, false},
		{"resource's lock, group's skipped", az(lock, "app-rg", saLock), Skip{Resource: lock, Name: "app-rg/l1", Reason: "r"}, false},
		{"name without its group", az("Microsoft.Network/networkInterfaces", "app-rg", "nic-1"), Skip{Resource: "Microsoft.Network/networkInterfaces", Name: "nic-1", Reason: "r"}, false},
		{"group without its own name", az("Microsoft.Resources/resourceGroups", "", "app-rg"), Skip{Resource: "Microsoft.Resources/resourceGroups", Name: "app-rg", Reason: "r"}, false},
	} {
		want := Snapshot{Platform: "azure", Rules: AzureCaptureRules, Coverage: cov, Objects: []Object{c.o}}
		got := Snapshot{Platform: "azure", Rules: AzureCaptureRules, Coverage: cov, Skips: []Skip{c.skip}}
		if n := noted(t, want, got, "missing"); (n != nil) != c.note || (n != nil && (n.Reason != "r" || n.OlderRules)) {
			t.Errorf("%s: %+v, want a note %v", c.what, n, c.note)
		}
		// A snapshot under Azure rules 0 named an extension by its group and
		// last name: no skip from one is a note on any object.
		got.Rules = 0
		if n := noted(t, want, got, "missing"); n != nil {
			t.Errorf("%s, rules 0: %+v", c.what, n)
		}
	}
}

// Helm history is listed once per release, as a family: that stands for
// the release's .v<N> Secrets, never for a Secret of the bare name. A
// Secret of Helm's type Helm did not name as its own is listed by its own
// name, and that notes only itself (reviews of #24). Before Kubernetes
// rules 2 the two were written alike, so such a snapshot gives no note.
func TestSkippedOtherSideHelmHistory(t *testing.T) {
	family := Skip{Resource: "core/v1/secrets", Namespace: "shop", Name: HelmHistoryPrefix + "foo" + HelmHistoryFamily, Reason: HelmHistoryReason}
	exact := func(name string) Skip {
		return Skip{Resource: "core/v1/secrets", Namespace: "shop", Name: HelmHistoryPrefix + name, Reason: HelmHistoryReason}
	}
	for _, c := range []struct {
		object string
		skip   Skip
		note   bool
	}{
		{"foo.v1", family, true},
		{"foo.v12", family, true},
		{"foo", family, false},
		{"foo.v", family, false},
		{"foo.vx", family, false},
		{"foo.v1x", family, false},
		{"foobar.v1", family, false},
		{"fo.v1", family, false},
		// Listed by its own name: a Helm-typed Secret with no revision, and
		// one whose name label says another release.
		{"zed", exact("zed"), true},
		{"zed.v1", exact("zed"), false},
		{"q.v1", exact("q.v1"), true},
		{"q.v1.v2", exact("q.v1"), false},
	} {
		obj := kobj("v1", "Secret", "shop", HelmHistoryPrefix+c.object)
		n := noted(t, kube(KubernetesCaptureRules, []Object{obj}, nil), kube(KubernetesCaptureRules, nil, []Skip{c.skip}), "missing")
		if (n != nil) != c.note || (n != nil && n.Reason != HelmHistoryReason) {
			t.Errorf("%s by %s: %+v, want a note %v", c.object, c.skip.Name, n, c.note)
		}
		// Before rules 2 a family read as a bare name and the other way
		// round: no Helm history note at all.
		old := c.skip
		old.Name = strings.TrimSuffix(old.Name, HelmHistoryFamily)
		for _, rules := range []int{0, 1} {
			if n := noted(t, kube(rules, []Object{obj}, nil), kube(rules, nil, []Skip{old}), "missing"); n != nil {
				t.Errorf("%s by %s, rules %d: %+v", c.object, old.Name, rules, n)
			}
		}
	}
	// In another namespace it is another release.
	if n := noted(t, kube(KubernetesCaptureRules, []Object{kobj("v1", "Secret", "other", HelmHistoryPrefix+"foo.v1")}, nil), kube(KubernetesCaptureRules, nil, []Skip{family}), "missing"); n != nil {
		t.Errorf("another namespace: %+v", n)
	}
	// A Secret of a Helm-like name skipped for another reason is named by
	// it, whatever the rules.
	other := Skip{Resource: "core/v1/secrets", Namespace: "shop", Name: HelmHistoryPrefix + "foo", Reason: "identical to the distribution baseline; a new cluster provides it"}
	if n := noted(t, kube(0, []Object{kobj("v1", "Secret", "shop", HelmHistoryPrefix+"foo")}, nil), kube(0, nil, []Skip{other}), "missing"); n == nil {
		t.Error("an exact name skipped for another reason has no note")
	}
}

// Changed objects and what is not working are never noted.
func TestSkippedOtherSideOnlyMissingAndExtra(t *testing.T) {
	a := kobj("v1", "ConfigMap", "shop", "cfg")
	b := kobj("v1", "ConfigMap", "shop", "cfg")
	b.Body["data"] = map[string]any{"a": "1"}
	skip := []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}}
	want, got := kube(1, []Object{a}, skip), kube(1, []Object{b}, skip)
	got.Unwell = []string{"x: broken"}
	for _, c := range Compare(want, got) {
		if c.Skipped != nil {
			t.Errorf("%+v", c)
		}
	}
}
