package azarm

import (
	"context"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// A restore into another subscription renames what must be unique across
// Azure: the storage account comes back under its new name, its child
// container, the role assignment on it and the diagnostic setting that
// writes to it follow, and the target then captures to exactly the renamed
// snapshot.
func TestRenamedRestoreMatchesTheRenamedSnapshot(t *testing.T) {
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	renamed, _, err := Rename(snap, map[string]string{"Microsoft.Storage/storageAccounts/shopassets01": "shopassets99"})
	if err != nil {
		t.Fatal(err)
	}
	// What a restore sends and finds by: metadata and spec. Status keeps
	// what was observed on the source (an endpoint's host name), which no
	// restore sends and no diff compares.
	for _, o := range renamed.Objects {
		if b := canon(map[string]any{"m": o.Body["metadata"], "s": o.Body["spec"]}); strings.Contains(b, "shopassets01") {
			t.Errorf("%s still names the old account: %s", o.Key(), b)
		}
	}
	for _, r := range restoreWith(context.Background(), e.dst, e.reg, renamed, RestoreOptions{Values: e.vals}, 4) {
		if !r.OK {
			t.Errorf("%s: %s", r.Key, r.Detail)
		}
	}
	if e.dst.Stored(id(dstSub, "shop-rg", "Microsoft.Storage/storageAccounts", "shopassets99")) == nil {
		t.Fatal("the account was not created under its new name")
	}
	got, err := e.adapter(e.dst).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snapshot.Compare(renamed, got) {
		t.Errorf("target differs from the renamed snapshot: %+v", c)
	}
}

// Renaming refuses what it cannot do, before anything is sent: a resource
// not in the snapshot, a malformed entry, a new name already taken.
func TestRenameRefuses(t *testing.T) {
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for m, want := range map[string]string{
		"Microsoft.Storage/storageAccounts/nosuch=x": "not in the snapshot",
		"shopassets01=x": "want Type/name",
		"Microsoft.Storage/storageAccounts/shopassets01=a/b":    "without a /",
		"Microsoft.Network/virtualNetworks/shop-vnet=shop-vnet": "already has",
	} {
		k, v, _ := strings.Cut(m, "=")
		if _, _, err := Rename(snap, map[string]string{k: v}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", m, err, want)
		}
	}
}

// renameID renames the resource, its parents and an extension's scope.
func TestRenameID(t *testing.T) {
	m := map[string]string{"microsoft.sql/servers/old": "new", "microsoft.storage/storageaccounts/acct": "acct2"}
	for in, want := range map[string]string{
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/old":                                                        "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/new",
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/old/databases/old":                                          "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/new/databases/old",
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/locks/l": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct2/providers/Microsoft.Authorization/locks/l",
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/old":                                            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/old",
	} {
		if got := renameID(in, m); got != want {
			t.Errorf("%s\n got  %s\n want %s", in, got, want)
		}
	}
}

// A --values file is written with the snapshot's names; its keys follow a
// rename, children with their parent.
func TestRenameValues(t *testing.T) {
	m := map[string]string{"Microsoft.Sql/servers/old": "new"}
	got := RenameValues(map[string]map[string]any{
		"Microsoft.Sql/servers/rg/old":              {"a": 1},
		"Microsoft.Sql/servers/databases/rg/old/db": {"b": 1},
		"Microsoft.Compute/virtualMachines/rg/vm":   {"c": 1},
	}, m)
	for _, k := range []string{"Microsoft.Sql/servers/rg/new", "Microsoft.Sql/servers/databases/rg/new/db", "Microsoft.Compute/virtualMachines/rg/vm"} {
		if _, ok := got[k]; !ok {
			t.Errorf("no key %s in %v", k, got)
		}
	}
}

// Text that names a renamed resource outside an ID or a reference (a host
// name) is not changed, but each object holding it is named.
func TestRenameWarnsAboutNamesInText(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	acct := obj("Microsoft.Storage/storageAccounts", "rg", "acct", sub+"/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct", map[string]any{})
	site := obj("Microsoft.Web/sites", "rg", "web", sub+"/resourceGroups/rg/providers/Microsoft.Web/sites/web",
		map[string]any{"properties": map[string]any{"siteConfig": map[string]any{"appSettings": []any{map[string]any{"name": "BLOB", "value": "https://acct.blob.core.windows.net/x"}}}}})
	_, warnings, err := Rename(snapshot.Snapshot{Objects: []snapshot.Object{acct, site}}, map[string]string{"Microsoft.Storage/storageAccounts/acct": "acct2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "Microsoft.Web/sites web") {
		t.Errorf("warnings %v", warnings)
	}
}
