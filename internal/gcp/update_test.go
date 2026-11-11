package gcp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// restoredShop captures the shop and restores it into a second project.
func restoredShop(t *testing.T) (snapshot.Snapshot, *Fake, func(*Fake) *Adapter) {
	docs := fixtures(t)
	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	for _, f := range []*Fake{src, dst} {
		f.InventoryName = func(rel string, data map[string]any) string {
			if strings.Contains(rel, "/serviceAccounts/") {
				return parentOf(rel) + "/serviceAccounts/" + fmt.Sprint(data["uniqueId"])
			}
			return ""
		}
		f.AfterCreate = func(schema string, stored map[string]any) {
			if schema != "AlertPolicy" {
				return
			}
			for i, c := range stored["conditions"].([]any) {
				c.(map[string]any)["name"] = fmt.Sprintf("%s/conditions/%d", stored["name"], 9000+i)
			}
		}
	}
	seedShop(t, src)
	a := func(f *Fake) *Adapter { return &Adapter{API: f, Docs: docs} }
	snap, err := a(src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range a(dst).Restore(context.Background(), snap) {
		if !r.OK {
			t.Fatalf("%s: %s", r.Key, r.Detail)
		}
	}
	return snap, dst, a
}

// Every resource whose schema has a description is edited by hand: one the
// snapshot set (the log metric's) changes, the rest gain one the snapshot
// lacks. That covers a patch with a mask in the query (monitoring, roles),
// one with the mask inside a request wrapper (IAM service accounts) and a
// full update (logging metrics), and clearing a field through the mask.
func TestUpdateBringsExistingInLine(t *testing.T) {
	snap, dst, a := restoredShop(t)
	dst.w.mu.Lock()
	edited := 0
	for _, n := range sortedKeys(dst.res) {
		r := dst.res[n]
		d, _ := dst.w.docs.Doc(r.asset.DiscoveryURI, r.asset.Version)
		if _, ok := d.Schemas[r.asset.DiscoveryName].Properties["description"]; ok && !strings.Contains(n, "123456-compute") && !strings.Contains(n, "_Reserved") {
			r.data["description"] = "edited by hand"
			edited++
		}
	}
	dst.w.mu.Unlock()
	if edited < 4 {
		t.Fatalf("edited %d resources, want the shop's service account, role, metric and channel", edited)
	}

	untouched := func(key string) bool { return strings.Contains(key, "AlertPolicy") } // no description field
	for _, r := range a(dst).Restore(context.Background(), snap) {
		if untouched(r.Key) {
			continue
		}
		if r.OK || !strings.Contains(r.Detail, "--update") {
			t.Errorf("without --update: %s: ok=%v %s", r.Key, r.OK, r.Detail)
		}
	}
	if dst.Updates != 0 {
		t.Fatalf("%d updates sent without --update", dst.Updates)
	}

	ad := a(dst)
	ad.Options.Update = true
	for _, r := range ad.Restore(context.Background(), snap) {
		if untouched(r.Key) {
			continue
		}
		if !r.OK || !strings.Contains(r.Detail, "updated") || !strings.HasSuffix(r.Detail, "(description)") {
			t.Errorf("%s: ok=%v %s", r.Key, r.OK, r.Detail)
		}
	}
	got, err := ad.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snapshot.Compare(snap, got) {
		t.Errorf("after --update the target still differs: %+v", c)
	}
}
