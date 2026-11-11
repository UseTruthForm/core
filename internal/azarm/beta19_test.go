package azarm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

func one(kind, name string, spec map[string]any) snapshot.Snapshot {
	return snapshot.Snapshot{Objects: []snapshot.Object{obj(kind, "rg", name, "/subscriptions/"+tokSub+"/resourceGroups/rg/providers/"+kind+"/"+name, spec)}}
}

// A destroy-and-restore drill of a real estate: each of these read as changed
// on every diff and every resumed restore, and none was a change anyone made.
func TestWhatNoOneChangedIsNotADifference(t *testing.T) {
	type c struct {
		name, kind string
		want, got  map[string]any
		same       bool
	}
	p := func(m map[string]any) map[string]any { return map[string]any{"properties": m} }
	for _, tc := range []c{
		{"a default the source never set", "Microsoft.KeyVault/vaults", p(map[string]any{}), p(map[string]any{"enabledForDiskEncryption": false}), true},
		{"a default in another case", "Microsoft.ServiceBus/namespaces", p(map[string]any{}), p(map[string]any{"dnsNamePolicy": "standard"}), true},
		{"two defaults", "Microsoft.KeyVault/vaults", p(map[string]any{}), p(map[string]any{"enabledForDiskEncryption": false, "enabledForTemplateDeployment": false}), true},
		// The source cluster had no OS updates; its copy reimages its nodes.
		{"an AKS OS upgrade channel Azure gave the copy", "Microsoft.ContainerService/managedClusters", p(map[string]any{"autoUpgradeProfile": map[string]any{}}), p(map[string]any{"autoUpgradeProfile": map[string]any{"nodeOSUpgradeChannel": "NodeImage"}}), false},
		{"a storage account's cross-tenant SAS, not known to mean false unset", "Microsoft.Storage/storageAccounts", p(map[string]any{}), p(map[string]any{"allowCrossTenantDelegationSas": false}), false},
		{"not the default", "Microsoft.Storage/storageAccounts", p(map[string]any{}), p(map[string]any{"allowCrossTenantDelegationSas": true}), false},
		{"set by the source to other than the target", "Microsoft.Storage/storageAccounts", p(map[string]any{"allowCrossTenantDelegationSas": true}), p(map[string]any{"allowCrossTenantDelegationSas": false}), false},
		{"set by the source to the default", "Microsoft.Storage/storageAccounts", p(map[string]any{"allowCrossTenantDelegationSas": false}), p(map[string]any{"allowCrossTenantDelegationSas": false}), true},
		{"auditing off in the source, on in the target", "Microsoft.Sql/servers/databases/auditingSettings", p(map[string]any{"state": "Disabled", "retentionDays": 0}), p(map[string]any{"state": "Enabled", "retentionDays": 0}), false},
		{"another type", "Microsoft.Web/sites", p(map[string]any{}), p(map[string]any{"allowCrossTenantDelegationSas": false}), false},
		{"an autoscaled pool's count", "Microsoft.ContainerService/managedClusters", p(map[string]any{"agentPoolProfiles": []any{map[string]any{"name": "a", "count": 5, "enableAutoScaling": true}}}), p(map[string]any{"agentPoolProfiles": []any{map[string]any{"name": "a", "count": 1, "enableAutoScaling": true}}}), true},
		{"a fixed pool's count", "Microsoft.ContainerService/managedClusters", p(map[string]any{"agentPoolProfiles": []any{map[string]any{"name": "a", "count": 5}}}), p(map[string]any{"agentPoolProfiles": []any{map[string]any{"name": "a", "count": 1}}}), false},
		{"auditing off on both", "Microsoft.Sql/servers/databases/auditingSettings", p(map[string]any{"state": "Disabled", "auditActionsAndGroups": []any{}}), p(map[string]any{"state": "Disabled", "auditActionsAndGroups": []any{"BATCH_COMPLETED_GROUP"}, "isManagedIdentityInUse": true}), true},
		{"extended auditing off on both", "Microsoft.Sql/servers/extendedAuditingSettings", p(map[string]any{"state": "Disabled"}), p(map[string]any{"state": "Disabled", "predicateExpression": "x"}), true},
		{"auditing on in one", "Microsoft.Sql/servers/databases/auditingSettings", p(map[string]any{"state": "Enabled", "auditActionsAndGroups": []any{}}), p(map[string]any{"state": "Disabled", "auditActionsAndGroups": []any{}}), false},
		{"auditing on in both, differently", "Microsoft.Sql/servers/databases/auditingSettings", p(map[string]any{"state": "Enabled", "retentionDays": 30}), p(map[string]any{"state": "Enabled", "retentionDays": 90}), false},
	} {
		w, g := ForCompare(one(tc.kind, "x", tc.want), one(tc.kind, "x", tc.got))
		if same := len(snapshot.Compare(w, g)) == 0; same != tc.same {
			t.Errorf("%s: same %v, want %v: %v", tc.name, same, tc.same, snapshot.Compare(w, g))
		}
	}
	// Copies: neither side is changed.
	got := one("Microsoft.KeyVault/vaults", "x", p(map[string]any{"enabledForDiskEncryption": false}))
	ForCompare(one("Microsoft.KeyVault/vaults", "x", p(map[string]any{})), got)
	if !strings.Contains(canon(got.Objects[0].Body["spec"]), "enabledForDiskEncryption") {
		t.Error("ForCompare changed what it was given")
	}
}

// The same, on a resumed restore: what the first run created and Azure filled
// in is identical, not "already exists and differs", and what is sent is the
// snapshot's, without Azure's defaults or the compare-only cuts.
func TestAResumedRestoreFindsWhatItMadeIdentical(t *testing.T) {
	reg, src, dst := worlds(t)
	ctx := context.Background()
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	kv := "Microsoft.KeyVault/vaults"
	put(t, src, "rg", kv, "kv", map[string]any{"location": "eastus", "properties": map[string]any{"tenantId": "00000000-0000-0000-0000-000000000000", "sku": map[string]any{"family": "A", "name": "standard"}, "accessPolicies": []any{}}})
	snap := capture(t, src, reg)
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "|kv"); !r.OK {
		t.Fatalf("first run: %s", r.Detail)
	}
	// Azure fills in its default.
	vault := id(dst.sub, "rg", kv, "kv")
	b, _ := dst.Get(ctx, vault, stable(reg, kv))
	b["properties"].(map[string]any)["enabledForDiskEncryption"] = false
	dst.SeedAzure(vault, stable(reg, kv), b)
	if r := resultFor(t, Restore(ctx, dst, reg, snap, RestoreOptions{}), "|kv"); !r.OK || !strings.Contains(r.Detail, "identical") {
		t.Errorf("a resumed run: %v %s", r.OK, r.Detail)
	}
}

// A drill lost a run to names held by deleted resources: both SQL servers
// (which no purge frees) and a Cognitive Services account. They are said
// before anything is sent, with how to free each.
func TestNamesHeldByDeletedResourcesAreSaid(t *testing.T) {
	_, _, dst := worlds(t)
	sub := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/"
	snap := snapshot.Snapshot{Objects: []snapshot.Object{
		obj("Microsoft.Sql/servers", "rg", "db1", sub+"Microsoft.Sql/servers/db1", map[string]any{"location": "West Europe"}),
		obj("Microsoft.Sql/servers", "rg", "db2", sub+"Microsoft.Sql/servers/db2", map[string]any{"location": "eastus"}),
		obj("Microsoft.CognitiveServices/accounts", "rg", "Ai", sub+"Microsoft.CognitiveServices/accounts/Ai", map[string]any{"location": "eastus"}),
		obj("Microsoft.KeyVault/vaults", "rg", "kv", sub+"Microsoft.KeyVault/vaults/kv", map[string]any{"location": "eastus"}),
		obj("Microsoft.Storage/storageAccounts", "rg", "db1", sub+"Microsoft.Storage/storageAccounts/db1", map[string]any{"location": "eastus"}),
	}}
	dst.Deleted = map[string][]map[string]any{
		"/providers/microsoft.sql/locations/westeurope/deletedservers": {{"name": "db1"}},
		"/providers/microsoft.sql/locations/eastus/deletedservers":     {{"name": "other"}},
		"/providers/microsoft.cognitiveservices/deletedaccounts":       {{"id": "/subscriptions/s/providers/Microsoft.CognitiveServices/locations/eastus/resourceGroups/rg/deletedAccounts/ai"}},
		"/providers/microsoft.keyvault/deletedvaults":                  {{"name": "kv", "properties": map[string]any{"purgeProtectionEnabled": true, "scheduledPurgeDate": "2026-12-01T00:00:00Z"}}},
	}
	held, unread := NamesHeld(context.Background(), dst, snap)
	got := strings.Join(held, "\n")
	for _, want := range []string{
		"Microsoft.Sql/servers/rg/db1: the name is held by a deleted one; Azure frees it when its retention ends, and no purge does",
		"Microsoft.CognitiveServices/accounts/rg/Ai: the name is held by a deleted one; purge it (az cognitiveservices account purge --name Ai --resource-group rg --location eastus)",
		// Purge protection: no purge frees it before its date (review of #75).
		"Microsoft.KeyVault/vaults/rg/kv: the name is held by a deleted one; it has purge protection, so no purge frees it: rename it with --rename, or wait until 2026-12-01T00:00:00Z",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if len(held) != 3 || len(unread) != 0 {
		t.Errorf("held %v, unread %v", held, unread)
	}
	// Without purge protection, a vault can be purged.
	dst.Deleted["/providers/microsoft.keyvault/deletedvaults"] = []map[string]any{{"name": "kv"}}
	if held, _ := NamesHeld(context.Background(), dst, snap); !strings.Contains(strings.Join(held, "\n"), "purge it (az keyvault purge --name kv)") {
		t.Errorf("a vault without purge protection: %v", held)
	}
	// Names unique across Azure can be held from another subscription, which
	// this check cannot see.
	if !HeldElsewhere(snap) || HeldElsewhere(snapshot.Snapshot{Objects: snap.Objects[:2]}) {
		t.Error("HeldElsewhere")
	}
	// A list that cannot be read is said, not taken as empty.
	dst.ListError = func(path string) error {
		if strings.Contains(strings.ToLower(path), "deletedvaults") {
			return errors.New("AuthorizationFailed")
		}
		return nil
	}
	if _, unread := NamesHeld(context.Background(), dst, snap); len(unread) != 1 || !strings.Contains(unread[0], "AuthorizationFailed") {
		t.Errorf("an unreadable list: %v", unread)
	}
}

// What --values sets is compared as sent: in the snapshot's form, without the
// secrets Azure never returns.
func TestADiffComparesWhatValuesSet(t *testing.T) {
	kind := managedClusterType
	o := obj(kind, "rg", "aks", "/subscriptions/"+tokSub+"/resourceGroups/rg/providers/"+kind+"/aks", map[string]any{"properties": map[string]any{"dnsPrefix": "aks"}})
	o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annSecrets] = "properties.windowsProfile.adminPassword"
	s := snapshot.Snapshot{Objects: []snapshot.Object{o}}
	vals := map[string]map[string]any{kind + "/rg/aks": {"properties": map[string]any{
		"windowsProfile":      map[string]any{"adminPassword": "secret", "adminUsername": "u"},
		"diskEncryptionSetID": "/subscriptions/99999999-9999-9999-9999-999999999999/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/d"}}}
	got := canon(WithValues(s, vals, "99999999-9999-9999-9999-999999999999", "88888888-8888-8888-8888-888888888888").Objects[0].Body["spec"])
	if strings.Contains(got, "secret") || !strings.Contains(got, `"adminUsername":"u"`) || !strings.Contains(got, tokSub) || strings.Contains(got, "99999999-9999") {
		t.Errorf("as compared: %s", got)
	}
	if strings.Contains(canon(s.Objects[0].Body["spec"]), "adminUsername") {
		t.Error("WithValues changed the snapshot it was given")
	}
}
