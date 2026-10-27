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
		if err := captureType(context.Background(), &Clients{Dynamic: dyn}, Policy{}, secrets, "Secret", cov, &snap); err != nil {
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
