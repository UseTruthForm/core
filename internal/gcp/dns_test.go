package gcp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// Cloud DNS's templates start with dns/v1/ and its service path is empty;
// a record set is named by its DNS name and type under its zone
// (rrsets/{name}/{type}); and its create takes clientOperationId, an
// idempotency token, not the zone's ID. A zone and its record sets
// restore, the zone first, and a second restore finds them.
func TestCloudDNSRestores(t *testing.T) {
	docs := LoadDocs(filepath.Join("..", "translate", "testdata", "gcp"))
	ann := func(schema, coll, parent string) map[string]any {
		return map[string]any{annDiscovery: "dns/v1", annSchema: schema, annCollection: coll, annParent: parent}
	}
	proj := "projects/" + tokProject
	zoneRel := proj + "/managedZones/shop"
	zone := snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "dns.googleapis.com/ManagedZone",
		"metadata": map[string]any{"name": zoneRel, "annotations": ann("ManagedZone", "managedZones", proj)},
		"spec":     map[string]any{"name": "shop", "dnsName": "shop.example.", "description": "d", "visibility": "public"}}}
	rr := func(name, typ, data string) snapshot.Object {
		return snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "dns.googleapis.com/ResourceRecordSet",
			"metadata": map[string]any{"name": zoneRel + "/rrsets/" + name + "/" + typ, "annotations": ann("ResourceRecordSet", "resourceRecordSets", zoneRel)},
			"spec":     map[string]any{"name": name, "type": typ, "ttl": float64(300), "rrdatas": []any{data}}}}
	}
	s := snapshot.Snapshot{Platform: "gcp", Objects: []snapshot.Object{rr("a.shop.example.", "A", "192.0.2.1"), rr("a.shop.example.", "TXT", `"x"`), zone}}
	// Creates run several at once: a record set waits for its zone, named
	// only as its parent.
	order, _, deps := restoreGraph(s.Objects)
	for i, o := range order {
		if o.Kind() == "dns.googleapis.com/ResourceRecordSet" && (len(deps[i]) != 1 || order[deps[i][0]].Name() != zoneRel) {
			t.Errorf("%s waits for %v", o.Name(), deps[i])
		}
	}
	f := NewWorld(docs).Project("p1", "1")
	for _, r := range Restore(context.Background(), f, docs, s, RestoreOptions{}) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	names := strings.Join(f.Names(), " ")
	for _, want := range []string{"projects/p1/managedZones/shop", "projects/p1/managedZones/shop/rrsets/a.shop.example./A", "projects/p1/managedZones/shop/rrsets/a.shop.example./TXT"} {
		if !strings.Contains(names, want) {
			t.Errorf("no %s in %s", want, names)
		}
	}
	got, err := f.Call(context.Background(), "GET", "https://dns.googleapis.com/dns/v1/projects/p1/managedZones/shop/rrsets/a.shop.example./TXT", nil)
	if err != nil || got["name"] != "a.shop.example." {
		t.Errorf("TXT: %v %v", got, err)
	}
	if z, _ := f.Call(context.Background(), "GET", "https://dns.googleapis.com/dns/v1/projects/p1/managedZones/shop", nil); z["name"] != "shop" {
		t.Errorf("zone: %v", z)
	}
	for _, r := range Restore(context.Background(), f, docs, s, RestoreOptions{}) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("again: %s: %v %s", r.Key, r.OK, r.Detail)
		}
	}
	// Under a zone that is not there, Google answers NOT_FOUND.
	g := NewWorld(docs).Project("p2", "2")
	if _, err := g.Call(context.Background(), "POST", "https://dns.googleapis.com/dns/v1/projects/p2/managedZones/none/rrsets",
		map[string]any{"name": "a.", "type": "A", "ttl": 1, "rrdatas": []any{"192.0.2.1"}}); err == nil || !strings.Contains(err.Error(), "NOT_FOUND") {
		t.Errorf("a record set with no zone: %v", err)
	}
	if idParam("clientOperationId") || !idParam("secretId") {
		t.Error("idParam")
	}
}

// A record set's parent is its zone, not the "rrsets" word before its
// two-part name.
func TestParentOfAResourceNamedByTwoFields(t *testing.T) {
	m := func(path string) *Method { return &Method{Path: path} }
	for _, c := range []struct {
		rel    string
		create *Method
		want   string
	}{
		{"projects/p/managedZones/z/rrsets/www.shop.example./A", m("dns/v1/projects/{project}/managedZones/{managedZone}/rrsets"), "projects/p/managedZones/z"},
		{"projects/p/global/networks/n", m("projects/{project}/global/networks"), "projects/p/global"},
		{"projects/p/topics/t", m("v1/{+name}"), "projects/p"},
		{"projects/p/topics/t", nil, "projects/p"},
		{"b1", m("b"), ""},
	} {
		if got := parentIn(c.rel, c.create); got != c.want {
			t.Errorf("%s: %q, want %q", c.rel, got, c.want)
		}
	}
}
