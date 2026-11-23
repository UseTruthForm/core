package gcp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// A create that names the resource in its path (Pub/Sub's PUT v1/{+name})
// is sent as a PUT of the resource at its own name, not a POST under its
// parent; a second restore finds it.
func TestRestoreCreatesWithAPut(t *testing.T) {
	docs := LoadDocs(filepath.Join("..", "translate", "testdata", "gcp"))
	topic := snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "pubsub.googleapis.com/Topic",
		"metadata": map[string]any{"name": "projects/" + tokProject + "/topics/orders", "annotations": map[string]any{
			annDiscovery: "pubsub/v1", annSchema: "Topic", annCollection: "projects.topics", annParent: "projects/" + tokProject}},
		"spec": map[string]any{"name": "projects/" + tokProject + "/topics/orders", "messageRetentionDuration": "600s"}}}
	f := NewWorld(docs).Project("p1", "1")
	s := snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{topic}}
	r := Restore(context.Background(), f, docs, s, RestoreOptions{})
	if len(r) != 1 || !r[0].OK || !strings.HasPrefix(r[0].Detail, "created projects/p1/topics/orders") {
		t.Fatalf("restore: %+v", r)
	}
	if r := Restore(context.Background(), f, docs, s, RestoreOptions{}); !r[0].OK || r[0].Detail != "already present and identical" {
		t.Errorf("again: %+v", r)
	}
	// The body's name must be the one in the path, as Google requires.
	if _, err := f.Call(context.Background(), "PUT", "https://pubsub.googleapis.com/v1/projects/p1/topics/other", map[string]any{"name": "projects/p1/topics/x"}); err == nil {
		t.Error("a PUT whose body names another topic was accepted")
	}
}
