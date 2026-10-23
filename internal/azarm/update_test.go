package azarm

import (
	"context"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// drifted restores the shop into the target, then changes the identity's
// and the VM's tags there, as someone editing in the portal would.
func drifted(t *testing.T) (env, snapshot.Snapshot, string) {
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range e.adapter(e.dst).Restore(context.Background(), snap) {
		if !r.OK {
			t.Fatalf("%s: %s", r.Key, r.Detail)
		}
	}
	ident := id(dstSub, "shop-rg", "Microsoft.ManagedIdentity/userAssignedIdentities", "shop-id")
	for _, o := range snap.Objects {
		if (o.Kind() != "Microsoft.ManagedIdentity/userAssignedIdentities" || o.Name() != "shop-id") &&
			(o.Kind() != "Microsoft.Compute/virtualMachines" || o.Name() != "shop-vm") {
			continue
		}
		b := rewriteAll(deepCopy(o.Body["spec"].(map[string]any)), func(v string) string {
			return strings.ReplaceAll(strings.ReplaceAll(v, tokSub, dstSub), tokTenant, dstTenant)
		}).(map[string]any)
		merge(b, deepCopy(e.vals["Microsoft.Compute/virtualMachines/shop-rg/shop-vm"]))
		if o.Kind() != "Microsoft.Compute/virtualMachines" {
			b = rewriteAll(deepCopy(o.Body["spec"].(map[string]any)), func(v string) string { return strings.ReplaceAll(v, tokSub, dstSub) }).(map[string]any)
		}
		b["tags"] = map[string]any{"edited": "by-hand"}
		rawPut(t, e.dst, id(dstSub, "shop-rg", o.Kind(), o.Name()), o.Kind(), b)
	}
	return e, snap, ident
}

// Drift is reported and left alone by default; with --update it is put
// right, and an identity keeps its principal, so the role assignment that
// names it still holds.
func TestUpdateBringsExistingInLine(t *testing.T) {
	e, snap, ident := drifted(t)
	principal := e.dst.Stored(ident)["properties"].(map[string]any)["principalId"]

	puts := e.dst.Puts
	n := 0
	for _, r := range e.adapter(e.dst).Restore(context.Background(), snap) {
		if !r.OK {
			n++
			if !strings.Contains(r.Detail, "--update") {
				t.Errorf("%s: %s", r.Key, r.Detail)
			}
		}
	}
	if n != 2 || e.dst.Puts != puts {
		t.Fatalf("without --update: %d not applied (want 2), %d PUTs sent (want 0)", n, e.dst.Puts-puts)
	}

	a := e.adapter(e.dst)
	a.Options.Update = true
	for _, r := range a.Restore(context.Background(), snap) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	if got := e.dst.Stored(ident)["properties"].(map[string]any)["principalId"]; got != principal {
		t.Errorf("identity principal changed on update: %v -> %v", principal, got)
	}
	got, err := a.Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snapshot.Compare(snap, got) {
		t.Errorf("after --update the target still differs: %+v", c)
	}
}

// A VM's admin password is never returned; an update without it would PUT
// the VM without its credential, so it is refused and nothing is sent.
func TestUpdateRefusesWithoutSecrets(t *testing.T) {
	e, snap, _ := drifted(t)
	a := e.adapter(e.dst)
	a.Options = RestoreOptions{Update: true}
	puts := e.dst.Puts
	for _, r := range a.Restore(context.Background(), snap) {
		if strings.Contains(r.Key, "virtualMachines") && (r.OK || !strings.Contains(r.Detail, "secret fields (properties.osProfile.adminPassword)")) {
			t.Errorf("vm: ok=%v %s", r.OK, r.Detail)
		}
	}
	if e.dst.Puts != puts+1 { // the identity's update only
		t.Errorf("%d PUTs sent, want 1 (the identity)", e.dst.Puts-puts)
	}
}
