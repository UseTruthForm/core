package saas

import (
	"context"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

const hookKey = "github/webhook/shop/https://ci.example.com/hook"

// driftedOrg restores a repository with a label, a webhook, an environment
// and Actions permissions into a second organisation, then edits each there
// as a person would.
func driftedOrg(t *testing.T) (snapshot.Snapshot, *fake) {
	s := spec(t, "github.json")
	src, dst := newFake(t, GitHub, s, "acme-src"), newFake(t, GitHub, s, "acme-dst")
	dst.others = []string{"acme-src"}
	gitHub(src)
	gitHub(dst)
	src.seed(t, "/orgs/acme-src/repos", map[string]any{"name": "shop"})
	src.seed(t, "/repos/acme-src/shop/labels", map[string]any{"name": "priority", "color": "ff0000", "description": "do first"})
	src.seed(t, "/repos/acme-src/shop/hooks", map[string]any{"name": "web", "active": true, "events": []any{"push"},
		"config": map[string]any{"url": "https://ci.example.com/hook", "content_type": "json", "secret": "s3cr3t-hook"}})
	c := src.client(false)
	for _, put := range []struct {
		path string
		body map[string]any
	}{
		{"/repos/acme-src/shop/environments/production", map[string]any{"wait_timer": 30,
			"deployment_branch_policy": map[string]any{"protected_branches": true, "custom_branch_policies": false}}},
		{"/repos/acme-src/shop/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "selected"}},
	} {
		if _, _, err := c.do(t.Context(), "PUT", put.path, put.body); err != nil {
			t.Fatalf("seed %s: %v", put.path, err)
		}
	}
	snap, err := (&Adapter{Client: src.client(true)}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]map[string]any{hookKey: {"config": map[string]any{"secret": "s3cr3t-hook"}}}
	for _, r := range (&Adapter{Client: dst.client(false), Options: RestoreOptions{Values: vals}}).Restore(context.Background(), snap) {
		if !r.OK {
			t.Fatalf("%s: %s", r.Key, r.Detail)
		}
	}
	d := dst.client(false)
	hook := stringOf(dst.colls["/repos/acme-dst/shop/hooks"][0]["id"])
	for _, w := range []struct {
		method, path string
		body         map[string]any
	}{
		{"PATCH", "/repos/acme-dst/shop/labels/priority", map[string]any{"color": "00ff00"}},
		{"PUT", "/repos/acme-dst/shop/environments/production", map[string]any{
			"deployment_branch_policy": map[string]any{"protected_branches": false, "custom_branch_policies": true}}},
		{"PUT", "/repos/acme-dst/shop/actions/permissions", map[string]any{"enabled": true, "allowed_actions": "all"}},
		{"PATCH", "/repos/acme-dst/shop/hooks/" + hook, map[string]any{"events": []any{"pull_request"}}},
	} {
		if _, _, err := d.do(t.Context(), w.method, w.path, w.body); err != nil {
			t.Fatalf("drift %s: %v", w.path, err)
		}
	}
	return snap, dst
}

// Drift on an existing repository is reported and left alone, Actions
// permissions included (the repository was not created by this restore);
// with --update every item is put right.
func TestUpdateBringsExistingInLine(t *testing.T) {
	snap, dst := driftedOrg(t)
	vals := map[string]map[string]any{hookKey: {"config": map[string]any{"secret": "s3cr3t-hook"}}}

	writes := dst.writes
	n := 0
	for _, r := range (&Adapter{Client: dst.client(false), Options: RestoreOptions{Values: vals}}).Restore(context.Background(), snap) {
		if !r.OK {
			n++
			if !strings.Contains(r.Detail, "--update") {
				t.Errorf("%s: %s", r.Key, r.Detail)
			}
		}
	}
	if n != 4 || dst.writes != writes {
		t.Fatalf("without --update: %d not applied (want 4), %d writes sent (want 0)", n, dst.writes-writes)
	}

	a := &Adapter{Client: dst.client(false), Options: RestoreOptions{Values: vals, Update: true}}
	for _, r := range a.Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	got, err := a.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snapshot.Compare(snap, got) {
		t.Errorf("after --update the target still differs: %+v", c)
	}
	if hook := dst.colls["/repos/acme-dst/shop/hooks"][0]; hook["config"].(map[string]any)["secret"] != "s3cr3t-hook" {
		t.Error("webhook secret lost by the update")
	}
}

// A webhook's secret is never returned; an update without it would send
// the hook without its secret, so it is refused and nothing is sent for it.
func TestUpdateRefusesWithoutSecrets(t *testing.T) {
	snap, dst := driftedOrg(t)
	for _, r := range (&Adapter{Client: dst.client(false), Options: RestoreOptions{Update: true}}).Restore(context.Background(), snap) {
		if strings.Contains(r.Key, "webhook") && (r.OK || !strings.Contains(r.Detail, "secret fields (config.secret)")) {
			t.Errorf("webhook: ok=%v %s", r.OK, r.Detail)
		}
	}
	if hook := dst.colls["/repos/acme-dst/shop/hooks"][0]; canon(hook["events"]) != `["pull_request"]` {
		t.Errorf("webhook was changed although its update was refused: %v", hook["events"])
	}
}

// GitHub takes an environment's wait_timer on write and returns it only
// reshaped inside protection_rules, so no snapshot can hold it. That must
// be said, in the snapshot and in the restore result, not dropped.
func TestUnreadableFieldsAreNamed(t *testing.T) {
	snap, _ := driftedOrg(t)
	var env snapshot.Object
	for _, o := range snap.Objects {
		if o.Kind() == "github/repo/environments" {
			env = o
		}
	}
	if env.Body == nil {
		t.Fatal("no environment captured")
	}
	ann, _ := env.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	if u, _ := ann[annUnreadable].(string); !strings.Contains(","+u+",", ",wait_timer,") {
		t.Errorf("unreadable annotation %q does not name wait_timer", u)
	}
	empty := newFake(t, GitHub, spec(t, "github.json"), "acme-empty")
	gitHub(empty)
	for _, r := range (&Adapter{Client: empty.client(false)}).Restore(context.Background(), snap) {
		if r.Key == env.Key() && !strings.Contains(r.Detail, "never read back, so not restored: ") {
			t.Errorf("environment restored without saying what it could not carry: %s", r.Detail)
		}
	}
}
