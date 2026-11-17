package snapshot

import (
	"reflect"
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
		{"near miss after", 0, []string{byFlux + " (edited)"}, false},
		{"near miss before", 0, []string{"x" + byFlux}, false},
		{"no namespace in the label", 0, []string{FluxKustomizationReason("", "root")}, false},
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
	cov := []Coverage{{Resource: "core/v1/configmaps", Kind: "ConfigMap"}}
	want := Snapshot{Platform: "aws", Coverage: cov, Objects: []Object{cfg}}
	got := Snapshot{Platform: "aws", Coverage: cov, Skips: []Skip{{Resource: "core/v1/configmaps", Namespace: "shop", Name: "cfg", Reason: byFlux}}}
	if n := noted(t, want, got, "missing"); n == nil || n.OlderRules {
		t.Errorf("aws: %+v", n)
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

// Azure records a skip by type and a name that holds the resource group,
// and names match without regard to case.
func TestSkippedOtherSideAzure(t *testing.T) {
	cov := []Coverage{{Resource: "Microsoft.Network/networkInterfaces", Kind: "Microsoft.Network/networkInterfaces"}}
	nic := kobj("azure.truthform.org/v1", "Microsoft.Network/networkInterfaces", "app-rg", "nic-1")
	want := Snapshot{Platform: "azure", Coverage: cov, Objects: []Object{nic}}
	for _, sk := range []Skip{
		{Resource: "microsoft.network/networkInterfaces", Name: "APP-RG/nic-1", Reason: "listed but could not be read: AuthorizationFailed"},
		{Resource: "Microsoft.Network/networkInterfaces", Name: "app-rg/nic-1", Reason: "listed but could not be read: AuthorizationFailed"},
	} {
		got := Snapshot{Platform: "azure", Coverage: cov, Skips: []Skip{sk}}
		if n := noted(t, want, got, "missing"); n == nil || n.Reason != sk.Reason || n.OlderRules {
			t.Errorf("%v: %+v", sk, n)
		}
	}
	got := Snapshot{Platform: "azure", Coverage: cov, Skips: []Skip{{Resource: "Microsoft.Network/networkInterfaces", Name: "nic-1", Reason: "x"}}}
	if n := noted(t, want, got, "missing"); n != nil {
		t.Errorf("no group in the name: %+v", n)
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
