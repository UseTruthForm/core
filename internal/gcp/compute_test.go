package gcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/usetruthform/core/internal/drilltest"
	"github.com/usetruthform/core/internal/snapshot"
)

// seedNetwork builds a Compute network with a regional subnetwork and a
// firewall, both naming the network by URL, as Compute returns them.
func seedNetwork(t *testing.T, f *Fake) {
	t.Helper()
	p := "projects/" + f.id
	netURL := "https://www.googleapis.com/compute/v1/" + p + "/global/networks/shop-net"
	for _, s := range []struct {
		typ, schema, coll, parent string
		body                      map[string]any
	}{
		{"compute.googleapis.com/Network", "Network", "networks", p + "/global", map[string]any{"name": "shop-net", "autoCreateSubnetworks": false}},
		{"compute.googleapis.com/Subnetwork", "Subnetwork", "subnetworks", p + "/regions/us-central1", map[string]any{"name": "app", "ipCidrRange": "10.8.0.0/24", "network": netURL,
			"region": "https://www.googleapis.com/compute/v1/" + p + "/regions/us-central1"}},
		{"compute.googleapis.com/Firewall", "Firewall", "firewalls", p + "/global", map[string]any{"name": "allow-https", "network": netURL,
			"allowed": []any{map[string]any{"IPProtocol": "tcp", "ports": []any{"443"}}}, "sourceRanges": []any{"10.8.0.0/24"}}},
	} {
		if _, err := f.Seed("compute", "v1", s.typ, s.schema, s.coll, s.parent, s.body); err != nil {
			t.Fatalf("seed %s: %v", s.coll, err)
		}
	}
}

// Compute names each path segment ({project}, {region}, {subnetwork}) and
// references by URL; the firewall sorts before the network it names, and
// the fake, as Google, refuses a reference to a network that does not
// exist yet.
func TestComputeDrill(t *testing.T) {
	docs := fixtures(t)
	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	seedNetwork(t, src)
	a := func(f *Fake) *Adapter { return &Adapter{API: f, Docs: docs} }
	pre := APIVersion + "|compute.googleapis.com/"
	snap := drilltest.Run(t, drilltest.Spec{Source: a(src), Target: a(dst), ExpectKeys: []string{
		pre + "Network||projects/{{truthform|project}}/global/networks/shop-net",
		pre + "Subnetwork||projects/{{truthform|project}}/regions/us-central1/subnetworks/app",
		pre + "Firewall||projects/{{truthform|project}}/global/firewalls/allow-https",
	}})
	for _, o := range snap.Objects {
		if s := canon(o.Body["spec"]); strings.Contains(s, srcProject) {
			t.Errorf("%s names the source project: %s", o.Key(), s)
		}
	}
}

func TestComputeTemplates(t *testing.T) {
	d, err := fixtures(t).Doc(docURL("compute", "v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	get := d.collectionMethods("subnetworks")["get"]
	ins := d.collectionMethods("subnetworks")["insert"]
	rel := "projects/p-1/regions/us-central1/subnetworks/app"
	if !matchesName(get, rel) || matchesName(get, "projects/p-1/global/networks/app") {
		t.Error("subnetwork get template matched wrongly")
	}
	if got := d.URL(get, rel); got != "https://compute.googleapis.com/compute/v1/"+rel {
		t.Errorf("get URL %s", got)
	}
	if got := d.URL(ins, "projects/p-1/regions/us-central1"); got != "https://compute.googleapis.com/compute/v1/projects/p-1/regions/us-central1/subnetworks" {
		t.Errorf("insert URL %s", got)
	}
	// One segment: projects/{project} once built .../projects/projects/p-1.
	one := &Method{Path: "projects/{project}", Parameters: map[string]Parameter{"project": {Location: "path"}}}
	if got := d.URL(one, "projects/p-1"); got != "https://compute.googleapis.com/compute/v1/projects/p-1" {
		t.Errorf("one-segment URL %s", got)
	}
	// Reserved expansion still takes the whole name.
	aip := &Method{Path: "v1/{+name}", Parameters: map[string]Parameter{"name": {Location: "path"}}}
	if got := d.URL(aip, "projects/p-1/serviceAccounts/a"); got != "https://compute.googleapis.com/compute/v1/v1/projects/p-1/serviceAccounts/a" {
		t.Errorf("reserved URL %s", got)
	}
}

// requestId is an idempotency token, not the new resource's ID: taken as
// one, the name went into the token and out of the body.
func TestRequestIDIsNotTheResourceID(t *testing.T) {
	d, err := fixtures(t).Doc(docURL("compute", "v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	body, q, err := wrap(d, "Network", d.collectionMethods("networks")["insert"], map[string]any{"name": "shop-net"}, "shop-net")
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("requestId") != "" || body["name"] != "shop-net" {
		t.Errorf("query %v, body %v", q, body)
	}
}

// A Compute write answers with Compute's own operation: polled through its
// selfLink until DONE, then the resource it names is read. Its errors are
// the result when it fails.
func TestComputeOperation(t *testing.T) {
	op := map[string]any{"kind": "compute#operation", "name": "operation-1", "status": "RUNNING",
		"selfLink": "https://x/ops/1", "targetLink": "https://x/networks/shop-net"}
	if !isComputeOperation(op) || isOperation(op) {
		t.Fatal("a Compute operation must be recognised as one, and not as a google.longrunning one")
	}
	polls := 0
	get := func(u string) (map[string]any, error) {
		switch u {
		case "https://x/ops/1":
			polls++
			done := map[string]any{"kind": "compute#operation", "name": "operation-1", "status": "DONE", "selfLink": u, "targetLink": "https://x/networks/shop-net"}
			if polls < 2 {
				done["status"] = "RUNNING"
			}
			return done, nil
		case "https://x/networks/shop-net":
			return map[string]any{"name": "shop-net", "selfLink": u}, nil
		}
		t.Fatalf("unexpected GET %s", u)
		return nil, nil
	}
	got, err := settleCompute(context.Background(), op, get, time.Millisecond)
	if err != nil || got["name"] != "shop-net" || polls != 2 {
		t.Errorf("got %v, %v after %d polls", got, err, polls)
	}
	failed := map[string]any{"kind": "compute#operation", "name": "operation-2", "status": "DONE",
		"error": map[string]any{"errors": []any{map[string]any{"code": "RESOURCE_NOT_FOUND", "message": "network not found"}}}}
	if _, err := settleCompute(context.Background(), failed, get, time.Millisecond); err == nil || !strings.Contains(err.Error(), "network not found") {
		t.Errorf("failed operation: %v", err)
	}
}

// A drifted Compute network is put right by --update: its patch takes no
// mask (a JSON merge patch), so a field the snapshot lacks is sent as null
// to clear it, and the body carries Compute's short name, not the full one.
func TestComputeUpdate(t *testing.T) {
	docs := fixtures(t)
	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	seedNetwork(t, src)
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
	rel := "projects/" + dstProject + "/global/networks/shop-net"
	dst.w.mu.Lock()
	if dst.res[rel].data["name"] != "shop-net" {
		t.Errorf("Compute resources carry their short name, got %v", dst.res[rel].data["name"])
	}
	dst.res[rel].data["description"] = "edited by hand"
	dst.w.mu.Unlock()
	ad := a(dst)
	ad.Options.Update = true
	for _, r := range ad.Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
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
