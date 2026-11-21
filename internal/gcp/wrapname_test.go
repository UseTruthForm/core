package gcp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// A create whose request wraps the resource and has no ID field of its own
// (GKE's CreateClusterRequest: cluster, parent, and a deprecated projectId)
// sends the resource with its short name in the body. The deprecated
// projectId is not the ID: taken for one, it got the cluster's name and the
// cluster went without one. A second restore finds it.
func TestRestoreCreatesWhatNamesItself(t *testing.T) {
	docs := LoadDocs(filepath.Join("..", "translate", "testdata", "gcp"))
	parent := "projects/" + tokProject + "/locations/europe-west1"
	cluster := snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "container.googleapis.com/Cluster",
		"metadata": map[string]any{"name": parent + "/clusters/shop", "annotations": map[string]any{
			annDiscovery: "container/v1", annSchema: "Cluster", annCollection: "projects.locations.clusters", annParent: parent}},
		"spec": map[string]any{"name": "shop", "initialClusterVersion": "1.31"}}}
	doc, err := docs.DocFor("container", "v1")
	if err != nil {
		t.Fatal(err)
	}
	body, _, err := wrap(doc, "Cluster", doc.collectionMethods("projects.locations.clusters")["create"], map[string]any{"name": "shop"}, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if _, set := body["projectId"]; set || body["cluster"].(map[string]any)["name"] != "shop" {
		t.Fatalf("request: %v", body)
	}
	f := NewWorld(docs).Project("p1", "1")
	s := snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{cluster}}
	r := Restore(context.Background(), f, docs, s, RestoreOptions{})
	if len(r) != 1 || !r[0].OK || !strings.HasPrefix(r[0].Detail, "created projects/p1/locations/europe-west1/clusters/shop") {
		t.Fatalf("restore: %+v", r)
	}
	if r := Restore(context.Background(), f, docs, s, RestoreOptions{}); !r[0].OK || r[0].Detail != "already present and identical" {
		t.Errorf("again: %+v", r)
	}
}
