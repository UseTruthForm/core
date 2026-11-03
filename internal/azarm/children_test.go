package azarm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

const accountType = "Microsoft.CognitiveServices/accounts"

func seedAccount(t *testing.T, f *Fake) string {
	t.Helper()
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	return put(t, f, "shop-rg", accountType, "assistant", map[string]any{
		"location": "eastus", "kind": "OpenAI", "sku": map[string]any{"name": "S0"},
		"properties": map[string]any{"customSubDomainName": "assistant"}})
}

func captureByKey(t *testing.T, f *Fake, reg *Registry) (snapshot.Snapshot, map[string]snapshot.Object) {
	t.Helper()
	s, err := Capture(context.Background(), f, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		got[o.Kind()+"|"+o.Name()] = o
	}
	return s, got
}

// A real AI Services account's model deployment was never captured, and
// coverage did not say so: discovery took child types from the provider
// registration alone, and the registration does not list deployments. A
// restore would have made the account with no model behind it.
func TestDeploymentTheRegistrationDoesNotListIsCaptured(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	acct := seedAccount(t, f)
	rawPut(t, f, acct+"/deployments/chat", accountType+"/deployments", map[string]any{
		"sku":        map[string]any{"name": "GlobalStandard", "capacity": 50},
		"properties": map[string]any{"model": map[string]any{"format": "OpenAI", "name": "gpt-4.1", "version": "2025-04-14"}}})

	s, got := captureByKey(t, f, reg)
	if _, ok := got[accountType+"/deployments|assistant/chat"]; !ok {
		t.Fatalf("the model deployment was lost: %v", sortedKeys(got))
	}
	for _, c := range s.Coverage {
		if strings.EqualFold(c.Kind, accountType+"/deployments") && c.Captured != 1 {
			t.Errorf("coverage counts %d deployments, want 1", c.Captured)
		}
	}
}

// Reading children by their definitions reached what Azure makes with every
// account: three content filters, all SystemManaged, that no restore can PUT.
func TestAzuresOwnContentFiltersAreSkipped(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	acct := seedAccount(t, f)
	policy := accountType + "/raiPolicies"
	f.SeedAzure(acct+"/raiPolicies/Microsoft.DefaultV2", stable(reg, policy), map[string]any{"properties": map[string]any{"mode": "Blocking", "type": "SystemManaged"}})
	rawPut(t, f, acct+"/raiPolicies/strict", policy, map[string]any{"properties": map[string]any{"mode": "Blocking", "basePolicyName": "Microsoft.DefaultV2"}})

	s, got := captureByKey(t, f, reg)
	if _, ok := got[policy+"|assistant/Microsoft.DefaultV2"]; ok {
		t.Error("Azure's own content filter was captured")
	}
	if _, ok := got[policy+"|assistant/strict"]; !ok {
		t.Errorf("a content filter someone made was lost: %v", sortedKeys(got))
	}
	skipped := false
	for _, sk := range s.Skips {
		skipped = skipped || (sk.Reason == systemManaged && strings.HasSuffix(sk.Name, "Microsoft.DefaultV2"))
	}
	if !skipped {
		t.Errorf("the skip is not recorded: %v", s.Skips)
	}
}

// Read only because it has a definition, a child type a resource does not
// serve answers 400 (a cluster that is not a private-link cluster, for its
// private endpoint connections; a vault, for its certificates). On a real
// subscription four did, and an otherwise complete capture said incomplete.
// A 400 for a type the registration lists is still a gap.
func TestBadRequestForAnUnlistedChildIsNoneHere(t *testing.T) {
	for name, tc := range map[string]struct {
		path string
		gap  bool
	}{
		"not in the registration": {"/deployments", false},
		"in the registration":     {"/subscriptions/" + srcSub + "/resourcegroups/shop-rg/providers/microsoft.storage/storageaccounts/shopdata/blobservices", true},
	} {
		t.Run(name, func(t *testing.T) {
			reg := fixtures(t)
			f := NewWorld(reg).Subscription(srcSub, srcTenant)
			seedAccount(t, f)
			put(t, f, "shop-rg", "Microsoft.Storage/storageAccounts", "shopdata", map[string]any{"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"}})
			f.BadRequest = func(p string) bool { return strings.HasSuffix(strings.ToLower(p), tc.path) }
			s, _ := captureByKey(t, f, reg)
			gap := false
			for _, sk := range s.Skips {
				gap = gap || strings.HasPrefix(sk.Reason, Unreadable)
			}
			if gap != tc.gap {
				t.Errorf("gap = %v, want %v: %v", gap, tc.gap, s.Skips)
			}
		})
	}
}

// A cluster's GET returns its agent pools as agentPoolProfiles. Read again
// as its agentPools children, each pool was in the snapshot twice.
func TestAgentPoolsInTheClustersSpecAreNotReadAgain(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	cluster := id(srcSub, "shop-rg", managedClusterType, "aks")
	f.SeedAzure(cluster, stable(reg, managedClusterType), map[string]any{"location": "eastus", "properties": map[string]any{
		"dnsPrefix": "aks", "agentPoolProfiles": []any{map[string]any{"name": "sys", "mode": "System", "count": 1, "vmSize": "Standard_D2s_v5"}}}})
	f.SeedAzure(cluster+"/agentPools/sys", stable(reg, managedClusterType+"/agentPools"), map[string]any{"properties": map[string]any{"mode": "System", "count": 1, "vmSize": "Standard_D2s_v5"}})

	_, got := captureByKey(t, f, reg)
	if _, ok := got[managedClusterType+"|aks"]; !ok {
		t.Fatalf("the cluster was lost: %v", sortedKeys(got))
	}
	if _, ok := got[managedClusterType+"/agentPools|aks/sys"]; ok {
		t.Error("the pool in the cluster's spec was captured again as its own object")
	}
}

// A SQL server answers for auditingPolicies, the 2014 view of table auditing
// Azure retired; its state is the one auditingSettings hold. Captured, a
// restore would send the retired API what the current one already set.
func TestRetiredSQLAuditingIsSkipped(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	srv := id(srcSub, "shop-rg", "Microsoft.Sql/servers", "shopsql")
	f.SeedAzure(srv, stable(reg, "Microsoft.Sql/servers"), map[string]any{"location": "eastus", "properties": map[string]any{"administratorLogin": "admin"}})
	f.SeedAzure(srv+"/auditingPolicies/Default", "2014-04-01", map[string]any{"type": "Microsoft.Sql/servers/auditingPolicies", "properties": map[string]any{"auditingState": "Disabled"}})

	s, got := captureByKey(t, f, reg)
	if _, ok := got["Microsoft.Sql/servers/auditingPolicies|shopsql/Default"]; ok {
		t.Error("the retired auditing view was captured")
	}
	skipped := false
	for _, sk := range s.Skips {
		skipped = skipped || strings.HasPrefix(sk.Reason, "retired table auditing")
	}
	if !skipped {
		t.Errorf("the skip is not recorded: %v", s.Skips)
	}
}

// Nothing below a resource was read when its child types could not be, and
// nothing said so.
func TestUnreadableChildTypesAreAGap(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	acct := seedAccount(t, f)
	api := failingVersions{f}
	v := &versions{api: api, reg: reg, ctx: context.Background(), cache: map[string]map[string][]string{}}
	rid, _ := ParseID(acct)
	root := &captured{rid: rid}
	out := discover(context.Background(), api, v, srcTenant, []*captured{root}, 1, nil)
	for _, fd := range out {
		if strings.EqualFold(fd.typ, accountType) && strings.HasPrefix(fd.reason, Unreadable) {
			return
		}
	}
	t.Errorf("no gap recorded: %v", out)
}

type failingVersions struct{ *Fake }

func (failingVersions) APIVersions(context.Context, string) (map[string][]string, error) {
	return nil, errors.New("read provider: 503 Service Unavailable")
}
