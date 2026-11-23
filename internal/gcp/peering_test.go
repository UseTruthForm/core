package gcp

import (
	"context"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/drilltest"
	"github.com/usetruthform/core/internal/snapshot"
)

const computeRoot = "https://www.googleapis.com/compute/v1/"

// seedPeered builds two networks, a subnetwork in each with the given
// range, and nothing between them.
func seedPeered(t *testing.T, f *Fake, hubRange, spokeRange string) {
	t.Helper()
	p := "projects/" + f.id
	for _, n := range []struct{ name, cidr string }{{"hub", hubRange}, {"spoke", spokeRange}} {
		if _, err := f.Seed("compute", "v1", "compute.googleapis.com/Network", "Network", "networks", p+"/global", map[string]any{"name": n.name, "autoCreateSubnetworks": false}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Seed("compute", "v1", "compute.googleapis.com/Subnetwork", "Subnetwork", "subnetworks", p+"/regions/us-central1", map[string]any{
			"name": n.name + "-app", "ipCidrRange": n.cidr, "network": computeRoot + p + "/global/networks/" + n.name,
			"region": computeRoot + p + "/regions/us-central1"}); err != nil {
			t.Fatal(err)
		}
	}
}

// peer calls networks.addPeering as a person would.
func peer(f *Fake, network, name, with string, more map[string]any) (map[string]any, error) {
	item := map[string]any{"name": name, "network": computeRoot + "projects/" + f.id + "/global/networks/" + with, "exchangeSubnetRoutes": true}
	for k, v := range more {
		item[k] = v
	}
	return f.Call(context.Background(), "POST", "https://compute.googleapis.com/compute/v1/projects/"+f.id+"/global/networks/"+network+"/addPeering",
		map[string]any{"networkPeering": item})
}

func peeringOf(t *testing.T, f *Fake, network, name string) map[string]any {
	t.Helper()
	got, err := f.Call(context.Background(), "GET", "https://compute.googleapis.com/compute/v1/projects/"+f.id+"/global/networks/"+network, nil)
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := got["peerings"].([]any)
	for _, x := range ps {
		if m := x.(map[string]any); m["name"] == name {
			return m
		}
	}
	return nil
}

// The fake peers as Google does: one side alone is INACTIVE, both are
// ACTIVE, overlapping subnet ranges are refused, a GET shows the peerings,
// and neither an insert nor a patch takes them.
func TestFakePeering(t *testing.T) {
	docs := fixtures(t)
	f := NewWorld(docs).Project(srcProject, "111111111111")
	seedPeered(t, f, "10.10.0.0/24", "10.20.0.0/24")
	if _, err := peer(f, "hub", "to-spoke", "spoke", nil); err != nil {
		t.Fatal(err)
	}
	if p := peeringOf(t, f, "hub", "to-spoke"); p == nil || p["state"] != "INACTIVE" || p["exportSubnetRoutesWithPublicIp"] != true || p["stackType"] != "IPV4_ONLY" {
		t.Fatalf("one side only: %v", p)
	}
	if _, err := peer(f, "spoke", "to-hub", "hub", nil); err != nil {
		t.Fatal(err)
	}
	for net, name := range map[string]string{"hub": "to-spoke", "spoke": "to-hub"} {
		if p := peeringOf(t, f, net, name); p == nil || p["state"] != "ACTIVE" {
			t.Errorf("%s/%s after both sides: %v", net, name, p)
		}
	}
	for what, err := range map[string]error{
		"a second peering of the same name":        func() error { _, err := peer(f, "hub", "to-spoke", "spoke", nil); return err }(),
		"a second peering to the same network":     func() error { _, err := peer(f, "hub", "again", "spoke", nil); return err }(),
		"a peering to a network that is not there": func() error { _, err := peer(f, "hub", "to-none", "none", nil); return err }(),
		"a peering to itself":                      func() error { _, err := peer(f, "hub", "to-self", "hub", nil); return err }(),
		"a state sent by the caller":               func() error { _, err := peer(f, "hub", "x", "spoke", map[string]any{"state": "ACTIVE"}); return err }(),
		"an unresolved token": func() error {
			_, err := peer(f, "hub", "y", "spoke", map[string]any{"network": "projects/{{truthform|project}}/global/networks/spoke"})
			return err
		}(),
	} {
		if err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	p := "projects/" + srcProject
	if _, err := f.Seed("compute", "v1", "compute.googleapis.com/Network", "Network", "networks", p+"/global",
		map[string]any{"name": "third", "peerings": []any{map[string]any{"name": "p", "network": computeRoot + p + "/global/networks/hub"}}}); err == nil || !strings.Contains(err.Error(), "output only") {
		t.Errorf("an insert took peerings: %v", err)
	}
	if _, err := f.Call(context.Background(), "PATCH", "https://compute.googleapis.com/compute/v1/"+p+"/global/networks/hub",
		map[string]any{"peerings": []any{}}); err == nil || !strings.Contains(err.Error(), "output only") {
		t.Errorf("a patch took peerings: %v", err)
	}

	// Overlapping ranges: the first side is taken, the second refused.
	g := NewWorld(docs).Project(srcProject, "111111111111")
	seedPeered(t, g, "10.10.0.0/16", "10.10.4.0/24")
	if _, err := peer(g, "hub", "to-spoke", "spoke", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := peer(g, "spoke", "to-hub", "hub", nil); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Errorf("overlapping ranges peered: %v", err)
	}
	if p := peeringOf(t, g, "hub", "to-spoke"); p["state"] != "INACTIVE" || peeringOf(t, g, "spoke", "to-hub") != nil {
		t.Errorf("after a refused peering: %v", p)
	}
}

// A peering is part of each network's spec; a restore creates both
// networks, then peers them, and the two naming each other is no cycle. The
// drill captures, restores and requires the target to diff clean.
func TestPeeringDrill(t *testing.T) {
	docs := fixtures(t)
	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	seedPeered(t, src, "10.10.0.0/24", "10.20.0.0/24")
	if _, err := peer(src, "spoke", "to-hub", "hub", map[string]any{"importSubnetRoutesWithPublicIp": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer(src, "hub", "to-spoke", "spoke", nil); err != nil {
		t.Fatal(err)
	}
	a := func(f *Fake) *Adapter { return &Adapter{API: f, Docs: docs} }
	pre := APIVersion + "|compute.googleapis.com/"
	snap := drilltest.Run(t, drilltest.Spec{Source: a(src), Target: a(dst), ExpectKeys: []string{
		pre + "Network||projects/{{truthform|project}}/global/networks/hub",
		pre + "Network||projects/{{truthform|project}}/global/networks/spoke",
		pre + "Subnetwork||projects/{{truthform|project}}/regions/us-central1/subnetworks/hub-app",
		pre + "Subnetwork||projects/{{truthform|project}}/regions/us-central1/subnetworks/spoke-app",
	}})
	for _, o := range snap.Objects {
		if !strings.HasSuffix(o.Name(), "/networks/spoke") {
			continue
		}
		spec := o.Body["spec"].(map[string]any)
		want := `[{"autoCreateRoutes":true,"exchangeSubnetRoutes":true,"exportCustomRoutes":false,"exportSubnetRoutesWithPublicIp":true,"importCustomRoutes":false,"importSubnetRoutesWithPublicIp":true,"name":"to-hub","network":"` +
			computeRoot + `projects/{{truthform|project}}/global/networks/hub","stackType":"IPV4_ONLY","updateStrategy":"INDEPENDENT"}]`
		if got := canon(spec["peerings"]); got != want {
			t.Errorf("the spoke's peerings in the snapshot:\n got %s\nwant %s", got, want)
		}
		st := o.Body["status"].(map[string]any)
		if st["peerings[to-hub].state"] != "ACTIVE" || st["peerings[].state"] != nil {
			t.Errorf("a peering's state belongs in the status, by its name: %v", st)
		}
	}
	for net, name := range map[string]string{"hub": "to-spoke", "spoke": "to-hub"} {
		if p := peeringOf(t, dst, net, name); p == nil || p["state"] != "ACTIVE" {
			t.Errorf("restored %s/%s: %v", net, name, p)
		}
	}
	for _, r := range a(dst).Restore(context.Background(), snap) {
		if !r.OK || r.Detail != "already present and identical" {
			t.Errorf("second restore: %s: %s", r.Key, r.Detail)
		}
	}
	if _, cyclic := restoreOrder(snap.Objects); len(cyclic) != 0 {
		t.Errorf("two peered networks read as a cycle: %d objects", len(cyclic))
	}
}

// A peering that drifted, or is missing, is put right by --update through
// updatePeering and addPeering, and only then; one the snapshot lacks is
// reported and left.
func TestPeeringUpdate(t *testing.T) {
	docs := fixtures(t)
	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	seedPeered(t, src, "10.10.0.0/24", "10.20.0.0/24")
	peer(src, "spoke", "to-hub", "hub", map[string]any{"importCustomRoutes": true})
	peer(src, "hub", "to-spoke", "spoke", nil)
	ctx := context.Background()
	snap, err := (&Adapter{API: src, Docs: docs}).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The target has both networks, the hub's peering, and the spoke's
	// with another setting.
	seedPeered(t, dst, "10.10.0.0/24", "10.20.0.0/24")
	peer(dst, "spoke", "to-hub", "hub", nil)
	results := func(update bool) map[string]snapshot.Result {
		out := map[string]snapshot.Result{}
		for _, r := range (&Adapter{API: dst, Docs: docs, Options: RestoreOptions{Update: update}}).Restore(ctx, snap) {
			out[r.Key[strings.LastIndex(r.Key, "/")+1:]] = r
		}
		return out
	}
	for name, r := range results(false) {
		if strings.HasSuffix(name, "-app") {
			continue
		}
		if r.OK || !strings.Contains(r.Detail, "differs (spec.peerings") {
			t.Errorf("without --update, %s: %v %s", name, r.OK, r.Detail)
		}
	}
	if peeringOf(t, dst, "hub", "to-spoke") != nil || dst.Updates != 0 {
		t.Fatal("a restore without --update changed a network's peerings")
	}
	// The spoke drifted outside its peerings too: its patch carries no
	// peerings, which no patch takes.
	dst.w.mu.Lock()
	dst.res["projects/"+dstProject+"/global/networks/spoke"].data["description"] = "edited by hand"
	dst.w.mu.Unlock()
	rs := results(true)
	if r := rs["hub"]; !r.OK || !strings.Contains(r.Detail, "added peerings[to-spoke]") {
		t.Errorf("hub: %v %s", r.OK, r.Detail)
	}
	if r := rs["spoke"]; !r.OK || !strings.Contains(r.Detail, "updated peerings[to-hub]") {
		t.Errorf("spoke: %v %s", r.OK, r.Detail)
	}
	if dst.Updates != 2 {
		t.Errorf("%d updates, want the network's patch and the one updatePeering", dst.Updates)
	}
	after, err := (&Adapter{API: dst, Docs: docs}).Capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snapshot.Compare(snap, after) {
		t.Errorf("after --update the target still differs: %+v", c)
	}

	// A third network peered with the hub in the target only.
	p := "projects/" + dstProject
	if _, err := dst.Seed("compute", "v1", "compute.googleapis.com/Network", "Network", "networks", p+"/global", map[string]any{"name": "other", "autoCreateSubnetworks": false}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer(dst, "hub", "to-other", "other", nil); err != nil {
		t.Fatal(err)
	}
	if r := results(true)["hub"]; r.OK || !strings.Contains(r.Detail, "peerings[to-other] is in the target and not in the snapshot") {
		t.Errorf("a peering only the target has: %v %s", r.OK, r.Detail)
	}
	if peeringOf(t, dst, "hub", "to-other") == nil {
		t.Error("a restore removed a peering")
	}
}

// A peering whose other network is neither restored nor in the target
// fails by name, and the network itself is still created.
func TestPeeringWithoutItsPeer(t *testing.T) {
	docs := fixtures(t)
	w := NewWorld(docs)
	src, dst := w.Project(srcProject, "111111111111"), w.Project(dstProject, "222222222222")
	seedPeered(t, src, "10.10.0.0/24", "10.20.0.0/24")
	peer(src, "spoke", "to-hub", "hub", nil)
	peer(src, "hub", "to-spoke", "spoke", nil)
	snap, err := (&Adapter{API: src, Docs: docs}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var only []snapshot.Object
	for _, o := range snap.Objects {
		if strings.HasSuffix(o.Name(), "/networks/spoke") {
			only = append(only, o)
		}
	}
	snap.Objects = only
	rs := (&Adapter{API: dst, Docs: docs}).Restore(context.Background(), snap)
	if len(rs) != 1 || rs[0].OK || !strings.Contains(rs[0].Detail, "created projects/"+dstProject+"/global/networks/spoke; not finished: peerings[to-hub]") {
		t.Errorf("%+v", rs)
	}
}

// A network's peerings are kept in the order of their names, whatever
// order they were made in, so two captures of one network are the same.
func TestPeeringsCapturedInNameOrder(t *testing.T) {
	docs := fixtures(t)
	f := NewWorld(docs).Project(srcProject, "111111111111")
	seedPeered(t, f, "10.10.0.0/24", "10.20.0.0/24")
	p := "projects/" + srcProject
	if _, err := f.Seed("compute", "v1", "compute.googleapis.com/Network", "Network", "networks", p+"/global", map[string]any{"name": "third", "autoCreateSubnetworks": false}); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"z-spoke", "spoke"}, {"a-third", "third"}} {
		if _, err := peer(f, "hub", c[0], c[1], nil); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := Capture(context.Background(), f, docs, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range snap.Objects {
		if !strings.HasSuffix(o.Name(), "/networks/hub") {
			continue
		}
		ps := o.Body["spec"].(map[string]any)["peerings"].([]any)
		if len(ps) != 2 || ps[0].(map[string]any)["name"] != "a-third" || ps[1].(map[string]any)["name"] != "z-spoke" {
			t.Errorf("order: %v", ps)
		}
		if st := o.Body["status"].(map[string]any); st["peerings[a-third].state"] != "INACTIVE" || st["peerings[z-spoke].state"] != "INACTIVE" {
			t.Errorf("status: %v", st)
		}
	}
}

// A translation's check lets a network's peerings through, and holds each
// to the peering's own schema: nothing the server sets, nothing unknown.
func TestCheckSpecHoldsAppliedItems(t *testing.T) {
	d, err := fixtures(t).Doc(docURL("compute", "v1"), "")
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{"name": "to-hub", "network": "projects/p/global/networks/hub", "exchangeSubnetRoutes": true}
	if err := d.CheckSpec("Network", map[string]any{"name": "spoke", "peerings": []any{ok}}); err != nil {
		t.Errorf("a peering is refused: %v", err)
	}
	for what, item := range map[string]any{
		"a state":          map[string]any{"name": "to-hub", "state": "ACTIVE"},
		"an unknown field": map[string]any{"name": "to-hub", "transit": true},
		"not an item":      "to-hub",
	} {
		if err := d.CheckSpec("Network", map[string]any{"name": "spoke", "peerings": []any{item}}); err == nil {
			t.Errorf("%s in a peering passed the check", what)
		}
	}
	if err := d.CheckSpec("Network", map[string]any{"name": "spoke", "subnetworks": []any{}}); err == nil {
		t.Error("a list the server sets passed the check")
	}
}
