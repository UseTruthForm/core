package gcp

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/usetruthform/core/internal/drilltest"
)

// Cloud SQL's document puts the version in every method path
// (v1/projects/{project}/instances/{instance}) under an empty servicePath.
// Its instances are read and created by name like Compute's, a drill
// passes, and Cloud Asset Inventory's name for the type is the one used.
func TestCloudSQLInstances(t *testing.T) {
	docs := LoadDocs(filepath.Join("..", "translate", "testdata", "gcp"))
	d, err := docs.Doc(docURL("sqladmin", "v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	k, err := d.Kind("DatabaseInstance", "projects/p1/instances/shop-pg")
	if err != nil {
		t.Fatal(err)
	}
	if got := d.URL(k.Get, "projects/p1/instances/shop-pg"); got != "https://sqladmin.googleapis.com/v1/projects/p1/instances/shop-pg" {
		t.Errorf("get: %s", got)
	}
	if got := d.URL(k.Create, "projects/p1"); got != "https://sqladmin.googleapis.com/v1/projects/p1/instances" {
		t.Errorf("insert: %s", got)
	}
	// A document whose paths do not all begin with the version keeps them.
	if pd, err := docs.Doc(docURL("pubsub", "v1"), ""); err != nil || pd.ServicePath != "v1/" {
		t.Errorf("pubsub: %v %q", err, pd.ServicePath)
	}

	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	if _, err := src.Seed("sqladmin", "v1", "sqladmin.googleapis.com/Instance", "DatabaseInstance", "instances", "projects/"+src.id, map[string]any{
		"name": "shop-pg", "region": "europe-west1", "databaseVersion": "POSTGRES_16",
		"settings": map[string]any{"tier": "db-custom-2-8192", "dataDiskSizeGb": "128", "ipConfiguration": map[string]any{"ipv4Enabled": true}},
	}); err != nil {
		t.Fatal(err)
	}
	a := func(f *Fake) *Adapter { return &Adapter{API: f, Docs: docs} }
	drilltest.Run(t, drilltest.Spec{Source: a(src), Target: a(dst), ExpectKeys: []string{
		APIVersion + "|sqladmin.googleapis.com/Instance||projects/{{truthform|project}}/instances/shop-pg",
	}})
	got, err := dst.Call(context.Background(), "GET", "https://sqladmin.googleapis.com/v1/projects/"+dstProject+"/instances/shop-pg", nil)
	if err != nil || got["name"] != "shop-pg" {
		t.Errorf("target: %v %v", got, err)
	}
}
