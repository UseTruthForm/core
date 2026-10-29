package kube

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/stackdna/core/internal/snapshot"
)

// Helm history is listed once per release. A managed add-on moves to a new
// revision every few seconds while keeping the same number of them; listed
// by revision, the coverage of an unchanged cluster differed between two
// captures. The count stays per object, and a Secret that only has Helm's
// type is still listed by its own name (review of #33).
func TestHelmHistoryIsListedPerRelease(t *testing.T) {
	secrets := schema.GroupVersionResource{Version: "v1", Resource: "secrets"}
	history := func(ns, name, release string) *unstructured.Unstructured {
		labels := map[string]any{"owner": "helm"}
		if release != "" {
			labels["name"] = release
		}
		return &unstructured.Unstructured{Object: k8sObj("Secret", ns, name, map[string]any{"labels": labels}, map[string]any{"type": "helm.sh/release.v1"})}
	}
	capture := func(revs ...int) snapshot.Snapshot {
		t.Helper()
		var objs []runtime.Object
		for _, r := range revs {
			// In a system namespace, so skipped for that reason first.
			objs = append(objs, history("kube-system", fmt.Sprintf("sh.helm.release.v1.overlay-upgrade.v%d", r), "overlay-upgrade"))
		}
		objs = append(objs,
			// The same release name in two namespaces, one without Helm's label.
			history("shop", "sh.helm.release.v1.web.v3", "web"), history("shop", "sh.helm.release.v1.web.v4", ""),
			history("other", "sh.helm.release.v1.web.v1", "web"),
			// Helm's type, but not Helm's: a label naming another release,
			// a name without the prefix or without a revision.
			history("shop", "sh.helm.release.v1.db.v1", "web"),
			history("shop", "db-creds", ""),
			history("shop", "sh.helm.release.v1.app", ""))
		dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{secrets: "SecretList"}, objs...)
		var snap snapshot.Snapshot
		cov := &snapshot.Coverage{}
		if err := captureType(context.Background(), &Clients{Dynamic: dyn}, Policy{}, secrets, "Secret", cov, &snap, newOwnership()); err != nil {
			t.Fatal(err)
		}
		sort.Slice(snap.Skips, func(i, j int) bool {
			return snap.Skips[i].Namespace+"/"+snap.Skips[i].Name < snap.Skips[j].Namespace+"/"+snap.Skips[j].Name
		})
		snap.Coverage = []snapshot.Coverage{*cov}
		return snap
	}
	first, second := capture(430432, 430433), capture(430433, 430434)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("coverage moved with the revision:\n%+v\n%+v", first, second)
	}
	var names []string
	for _, s := range first.Skips {
		names = append(names, s.Namespace+"/"+s.Name)
	}
	want := []string{
		"kube-system/sh.helm.release.v1.overlay-upgrade",
		"other/sh.helm.release.v1.web",
		"shop/db-creds",
		"shop/sh.helm.release.v1.app",
		"shop/sh.helm.release.v1.db.v1",
		"shop/sh.helm.release.v1.web",
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("skips\n%v\nwant\n%v", names, want)
	}
	total := 0
	for _, n := range first.Coverage[0].Skipped {
		total += n
	}
	if total != 8 || first.Coverage[0].Skipped["in system namespace kube-system"] != 2 {
		t.Errorf("coverage counts %v, want 8 objects, 2 of them in kube-system", first.Coverage[0].Skipped)
	}
	if len(first.Objects) != 0 {
		t.Errorf("history captured: %v", first.Objects)
	}
}

// Through the capture itself: an add-on identical to the baseline except
// for a withheld credential is captured, not skipped as the
// distribution's (review of #41).
func TestWithheldIsCapturedDespiteTheBaseline(t *testing.T) {
	deps := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	mk := func(token string) map[string]any {
		return map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": map[string]any{"name": "addon", "namespace": "addons"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "a", "image": "x",
				"env": []any{map[string]any{"name": "API_TOKEN", "value": token}}}}}}}}
	}
	base := mk("distribution-default")
	normalize("apps", "deployments", base)
	p := Policy{}.WithBaseline(snapshot.Snapshot{Objects: []snapshot.Object{{Body: base}}}, "sha256:b")
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{deps: "DeploymentList"},
		&unstructured.Unstructured{Object: mk("changed-by-someone")})
	var snap snapshot.Snapshot
	cov := &snapshot.Coverage{}
	if err := captureType(context.Background(), &Clients{Dynamic: dyn}, p, deps, "Deployment", cov, &snap, newOwnership()); err != nil {
		t.Fatal(err)
	}
	if len(snap.Objects) != 1 {
		t.Fatalf("captured %d objects, skips %+v: the add-on must be captured", len(snap.Objects), snap.Skips)
	}
}

// What controllers make is recorded once per root owner. Between two
// captures of an unchanged cluster every pod and Job was replaced under a
// new name (a node reimage, a scheduled run); the skips and coverage of the
// two are the same.
func TestOwnedObjectsAreListedPerRootOwner(t *testing.T) {
	pods := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	jobs := schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}
	ownerAPI := map[string]string{"DaemonSet": "apps/v1", "Job": "batch/v1", "ScaledJob": "keda.sh/v1alpha1"}
	owned := func(apiVersion, kind, ns, name, ownerKind, ownerName string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": apiVersion, "kind": kind,
			"metadata": map[string]any{"namespace": ns, "name": name, "ownerReferences": []any{
				map[string]any{"apiVersion": ownerAPI[ownerKind], "kind": ownerKind, "name": ownerName, "controller": true},
			}},
		}}
	}
	capture := func(suffix string) snapshot.Snapshot {
		var objs []runtime.Object
		for i := 0; i < 3; i++ {
			objs = append(objs, owned("v1", "Pod", "web", fmt.Sprintf("agent-%s%d", suffix, i), "DaemonSet", "agent"),
				// In kube-system too, where most of a cluster's DaemonSets are.
				owned("v1", "Pod", "kube-system", fmt.Sprintf("proxy-%s%d", suffix, i), "DaemonSet", "proxy"))
		}
		for i := 0; i < 2; i++ {
			job := fmt.Sprintf("report-%s%d", suffix, i)
			objs = append(objs, owned("batch/v1", "Job", "web", job, "ScaledJob", "report"),
				owned("v1", "Pod", "web", job+"-x", "Job", job))
		}
		dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
			map[schema.GroupVersionResource]string{pods: "PodList", jobs: "JobList"}, objs...)
		snap := snapshot.Snapshot{}
		own := newOwnership()
		// Pods first: their owners are only known once the Jobs are listed.
		for _, r := range []struct {
			gvr  schema.GroupVersionResource
			kind string
		}{{pods, "Pod"}, {jobs, "Job"}} {
			cov := snapshot.Coverage{Resource: resourceID(r.gvr), Kind: r.kind}
			if err := captureType(context.Background(), &Clients{Dynamic: dyn}, Policy{}, r.gvr, r.kind, &cov, &snap, own); err != nil {
				t.Fatal(err)
			}
			snap.Coverage = append(snap.Coverage, cov)
		}
		own.record(&snap)
		sort.Slice(snap.Skips, func(i, j int) bool {
			return snap.Skips[i].Resource+snap.Skips[i].Namespace+snap.Skips[i].Reason < snap.Skips[j].Resource+snap.Skips[j].Namespace+snap.Skips[j].Reason
		})
		return snap
	}
	first, second := capture("a"), capture("b")
	if !reflect.DeepEqual(first.Skips, second.Skips) || !reflect.DeepEqual(first.Coverage, second.Coverage) {
		t.Errorf("an unchanged cluster captured differently:\n%+v\n%+v\n%+v\n%+v", first.Skips, second.Skips, first.Coverage, second.Coverage)
	}
	want := []snapshot.Skip{
		{Resource: "batch/v1/jobs", Namespace: "web", Name: "*", Reason: "owned by ScaledJob/report, whose controller recreates it"},
		{Resource: "core/v1/pods", Namespace: "kube-system", Name: "*", Reason: "owned by DaemonSet/proxy, whose controller recreates it"},
		{Resource: "core/v1/pods", Namespace: "web", Name: "*", Reason: "owned by DaemonSet/agent, whose controller recreates it"},
		{Resource: "core/v1/pods", Namespace: "web", Name: "*", Reason: "owned by ScaledJob/report, whose controller recreates it"},
	}
	if !reflect.DeepEqual(first.Skips, want) {
		t.Errorf("skips\n got  %+v\n want %+v", first.Skips, want)
	}
}

// An owner is found by its API group as well as its kind and name: a
// Knative Service owns a Configuration, which owns pods, next to a core
// Service of the same name (review of #46).
func TestRootOwnerTellsGroupsApart(t *testing.T) {
	own := newOwnership()
	own.owner["shop||Service|web"] = [3]string{"serving.knative.dev", "Route", "web"}
	own.owner["shop|serving.knative.dev|Route|web"] = [3]string{"serving.knative.dev", "Service", "web"}
	own.owner["shop|serving.knative.dev|Configuration|web"] = [3]string{"serving.knative.dev", "Service", "web"}
	if k, n := own.root("shop", "serving.knative.dev", "Configuration", "web"); k+"/"+n != "Service/web" {
		t.Errorf("root %s/%s, want the Knative Service/web", k, n)
	}
	if k, _ := own.root("shop", "", "Service", "web"); k != "Service" {
		t.Errorf("the core Service web resolved to %s", k)
	}
}
