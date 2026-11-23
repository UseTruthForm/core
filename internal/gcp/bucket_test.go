package gcp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// A Cloud Storage bucket has no parent in its name: it is created by a
// POST to b with the project as a query parameter, Cloud Asset Inventory
// names it by its ID, and its get is b/{bucket}. A second restore finds it,
// and the fields the server sets, which the document flags nowhere, are not
// configuration.
func TestRestoreCreatesABucket(t *testing.T) {
	docs := LoadDocs(filepath.Join("..", "translate", "testdata", "gcp"))
	bucket := snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "storage.googleapis.com/Bucket",
		"metadata": map[string]any{"name": "shop-assets", "annotations": map[string]any{
			annDiscovery: "storage/v1", annSchema: "Bucket", annCollection: "buckets", annParent: ""}},
		"spec": map[string]any{"name": "shop-assets", "location": "EUROPE-WEST1", "versioning": map[string]any{"enabled": true}}}}
	f := NewWorld(docs).Project("p1", "1")
	s := snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{bucket}}
	r := Restore(context.Background(), f, docs, s, RestoreOptions{})
	if len(r) != 1 || !r[0].OK || r[0].Detail != "created shop-assets" {
		t.Fatalf("restore: %+v", r)
	}
	if r := Restore(context.Background(), f, docs, s, RestoreOptions{}); !r[0].OK || r[0].Detail != "already present and identical" {
		t.Errorf("again: %+v", r)
	}
	got, err := Capture(context.Background(), f, docs, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Objects) != 1 || got.Objects[0].Name() != "shop-assets" {
		t.Fatalf("capture: %+v", got.Objects)
	}
	if sp := got.Objects[0].Body["spec"].(map[string]any); sp["selfLink"] != nil {
		t.Errorf("selfLink is kept as configuration: %v", sp)
	}
	// Without the project, Google refuses the create.
	if _, err := f.Call(context.Background(), "POST", "https://storage.googleapis.com/storage/v1/b", map[string]any{"name": "other"}); err == nil || !strings.Contains(err.Error(), "project") {
		t.Errorf("a bucket created with no project: %v", err)
	}
	d, _ := docs.DocFor("storage", "v1")
	if err := d.CheckSpec("Bucket", map[string]any{"name": "x", "timeCreated": "now"}); err == nil {
		t.Error("timeCreated is accepted as configuration")
	}
}
