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
// not in the snapshot, a malformed entry, a resource group, an extension.
func TestRenameRefuses(t *testing.T) {
	e := newEnv(t)
	snap, err := e.adapter(e.src).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for m, want := range map[string]string{
		"Microsoft.Storage/storageAccounts/nosuch=x": "not in the snapshot",
		"shopassets01=x": "want Type/name",
		"Microsoft.Storage/storageAccounts/shopassets01=a/b":                                      "without a /",
		"Microsoft.Resources/resourceGroups/shop-rg=other":                                        "cannot be renamed",
		"Microsoft.Authorization/roleAssignments/6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b=x":          "not a resource that can be renamed",
		"Microsoft.Storage/storageAccounts/blobServices/containers/shopassets01/default/nosuch=x": "not in the snapshot",
	} {
		k, v, _ := strings.Cut(m, "=")
		if _, _, err := Rename(snap, map[string]string{k: v}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", m, err, want)
		}
	}
}

// No two resources may end up with one name; a swap is fine, and a new
// name another group has is warned about.
func TestRenameCollisions(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	acct := func(rg, name string) snapshot.Object {
		return obj("Microsoft.Storage/storageAccounts", rg, name, sub+"/resourceGroups/"+rg+"/providers/Microsoft.Storage/storageAccounts/"+name, map[string]any{})
	}
	snap := snapshot.Snapshot{Objects: []snapshot.Object{acct("rg", "a1"), acct("rg", "a2"), acct("rg2", "a3")}}
	const typ = "Microsoft.Storage/storageAccounts/"
	for _, m := range []map[string]string{{typ + "a1": "x", typ + "a2": "x"}, {typ + "a1": "a2"}} {
		if _, _, err := Rename(snap, m); err == nil || !strings.Contains(err.Error(), "would both be") {
			t.Errorf("%v: %v, want a collision", m, err)
		}
	}
	got, _, err := Rename(snap, map[string]string{typ + "a1": "a2", typ + "a2": "a1"})
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	if got.Objects[0].Name() != "a2" || got.Objects[1].Name() != "a1" {
		t.Errorf("swap: %s %s", got.Objects[0].Name(), got.Objects[1].Name())
	}
	_, warnings, err := Rename(snap, map[string]string{typ + "a1": "a3"})
	if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "more than one group (rg, rg2)") {
		t.Errorf("a name another group has: %v %v", warnings, err)
	}
}

// A rename reaches a child renamed on its own, IDs used as map keys (a
// site's user-assigned identities), IDs in any case or joined in one
// string, and the restore order an object waits for.
func TestRenameReachesEveryReference(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	idOf := func(n string) string {
		return sub + "/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" + n
	}
	srv := obj("Microsoft.Sql/servers", "rg", "srv", sub+"/resourceGroups/rg/providers/Microsoft.Sql/servers/srv", map[string]any{})
	db := obj("Microsoft.Sql/servers/databases", "rg", "srv/db", sub+"/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/databases/db", map[string]any{})
	id := obj("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", "id1", idOf("id1"), map[string]any{})
	site := obj("Microsoft.Web/sites", "rg", "web", sub+"/resourceGroups/rg/providers/Microsoft.Web/sites/web", map[string]any{
		"identity":   map[string]any{"userAssignedIdentities": map[string]any{idOf("id1"): map[string]any{}}},
		"properties": map[string]any{"both": idOf("id1") + "," + idOf("id1"), "lower": strings.ToLower(idOf("id1"))},
	})
	site.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annAfter] = idOf("id1")
	got, warnings, err := Rename(snapshot.Snapshot{Objects: []snapshot.Object{srv, db, id, site}}, map[string]string{
		"Microsoft.Sql/servers/databases/srv/db":               "db2",
		"Microsoft.ManagedIdentity/userAssignedIdentities/id1": "id9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := got.Objects[1].Name(); n != "srv/db2" {
		t.Errorf("child: %s", n)
	}
	if b := canon(map[string]any{"m": got.Objects[3].Body["metadata"], "s": got.Objects[3].Body["spec"]}); strings.Contains(strings.ToLower(b), "id1") {
		t.Errorf("site still names id1: %s", b)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings %v", warnings)
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
		"Microsoft.Sql/servers/rg/old":                                   {"a": 1},
		"Microsoft.Sql/servers/databases/rg/old/db":                      {"b": 1},
		"Microsoft.Compute/virtualMachines/rg/vm":                        {"c": 1},
		"X.Y/z/rg/providers/Microsoft.Sql/servers/old/providers/X.Y/z/q": {"d": 1},
	}, m)
	for _, k := range []string{"Microsoft.Sql/servers/rg/new", "Microsoft.Sql/servers/databases/rg/new/db", "Microsoft.Compute/virtualMachines/rg/vm", "X.Y/z/rg/providers/Microsoft.Sql/servers/new/providers/X.Y/z/q"} {
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

// An AI Services account renamed for a restore beside its source kept its
// customSubDomainName, its endpoint's host name and as unique across Azure as
// its name: the rehearsal of a real restore planned an account that would
// have collided with the source's. The subdomain follows the name it was.
func TestRenameMovesAnAccountsSubdomain(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	acctID := func(name string) string {
		return sub + "/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/" + name
	}
	for _, tc := range []struct {
		name, was, want string
		warn            bool
	}{
		{"Assistant", "assistant", "assistant-tst", false},
		{"assistant", "assistant", "assistant-tst", false},
		{"Assistant", "Assistant", "Assistant-tst", false},
		{"Assistant", "chat-prod", "chat-prod", true},
	} {
		acct := obj("Microsoft.CognitiveServices/accounts", "rg", tc.name, acctID(tc.name), map[string]any{"properties": map[string]any{"customSubDomainName": tc.was}})
		renamed, warnings, err := Rename(snapshot.Snapshot{Objects: []snapshot.Object{acct}}, map[string]string{"Microsoft.CognitiveServices/accounts/" + tc.name: tc.name + "-tst"})
		if err != nil {
			t.Fatal(err)
		}
		props := renamed.Objects[0].Body["spec"].(map[string]any)["properties"].(map[string]any)
		if got := props["customSubDomainName"]; got != tc.want {
			t.Errorf("%s with subdomain %s: became %v, want %s", tc.name, tc.was, got, tc.want)
		}
		warned := false
		for _, w := range warnings {
			warned = warned || strings.Contains(w, "customSubDomainName")
		}
		if warned != tc.warn {
			t.Errorf("%s with subdomain %s: warned %v, want %v: %v", tc.name, tc.was, warned, tc.warn, warnings)
		}
	}
}
