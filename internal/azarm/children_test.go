package azarm

import (
	"context"
	"errors"
	"net/http"
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
	counted := false
	for _, c := range s.Coverage {
		counted = counted || (strings.EqualFold(c.Kind, accountType+"/deployments") && c.Captured == 1)
	}
	if !counted {
		t.Errorf("coverage does not count the deployment: %+v", s.Coverage)
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
			// As the SDK answers it, so the 400 is read through armError.
			f.ListError = func(p string) error {
				if strings.HasSuffix(strings.ToLower(p), tc.path) {
					return &armError{url: p, status: http.StatusBadRequest, code: "BadRequest", msg: "The requested action is not supported"}
				}
				return nil
			}
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

// Review of #63: with children found by definition, a network's peerings
// were listed again beside the ones made from its GET, and a list that failed
// was a gap for peerings the snapshot held.
func TestPeeringsComeFromTheirNetworkNotAList(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	a := put(t, f, "shop-rg", vnetType, "a", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}})
	b := put(t, f, "shop-rg", vnetType, "b", map[string]any{"location": "eastus", "properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.1.0.0/16"}}}})
	rawPut(t, f, a+"/virtualNetworkPeerings/to-b", vnetType+"/virtualNetworkPeerings", map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": b}}})
	f.ListError = func(p string) error {
		if strings.HasSuffix(strings.ToLower(p), "/virtualnetworkpeerings") {
			return &armError{url: p, status: http.StatusServiceUnavailable}
		}
		return nil
	}
	s, got := captureByKey(t, f, reg)
	if _, ok := got[vnetType+"/virtualNetworkPeerings|a/to-b"]; !ok {
		t.Fatalf("the peering was lost: %v", sortedKeys(got))
	}
	for _, sk := range s.Skips {
		if strings.HasPrefix(sk.Reason, Unreadable) {
			t.Errorf("a gap for what the snapshot holds: %+v", sk)
		}
	}
}

// Review of #63: a child collection inline under another name was read again
// as children, each item in the snapshot twice. Its items' IDs say what they
// are: a VPN gateway's connections are its vpnConnections.
func TestInlineCollectionsAreKnownByTheirIDs(t *testing.T) {
	gw := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/Microsoft.Network/vpnGateways/gw"
	rid, _ := ParseID(gw)
	c := &captured{rid: rid, status: map[string]any{"id": gw}, spec: map[string]any{"properties": map[string]any{
		"connections": []any{map[string]any{"id": gw + "/vpnConnections/to-office", "name": "to-office"}},
		"bgpSettings": map[string]any{"asn": 65515},
	}}}
	got := inlineCollections(c)
	if !got["vpnconnections"] || !got["connections"] {
		t.Errorf("got %v, want connections and vpnconnections", got)
	}
	cluster := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/" + managedClusterType + "/aks"
	rid, _ = ParseID(cluster)
	c = &captured{rid: rid, status: map[string]any{"id": cluster}, spec: map[string]any{"properties": map[string]any{
		"agentPoolProfiles": []any{map[string]any{"name": "sys"}}}}}
	if !inlineCollections(c)["agentpools"] {
		t.Error("a cluster's agentPoolProfiles are not its agentPools")
	}
}

// Review of #63: for a type read only because it has a definition, a 400 for
// one kind dropped the kinds that answered.
func TestOneKindsBadRequestKeepsTheOthers(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	ws := put(t, f, "shop-rg", "Microsoft.OperationalInsights/workspaces", "logs", map[string]any{"location": "eastus"})
	f.SeedAzure(ws+"/dataSources/perf", stable(reg, "Microsoft.OperationalInsights/workspaces/dataSources"), map[string]any{"kind": "WindowsPerformanceCounter", "properties": map[string]any{}})
	f.ListError = func(p string) error {
		if strings.Contains(p, "kind%20eq%20%27WindowsEvent%27") {
			return &armError{url: p, status: http.StatusBadRequest, code: "BadRequest"}
		}
		return nil
	}
	path := ws + "/dataSources"
	for _, tc := range []struct {
		unlisted bool
		wantErr  bool
	}{{true, false}, {false, true}} {
		items, _, err := listByKind(context.Background(), f, path, stable(reg, "Microsoft.OperationalInsights/workspaces/dataSources"), []string{"WindowsEvent", "WindowsPerformanceCounter"}, tc.unlisted)
		if (err != nil) != tc.wantErr {
			t.Errorf("unlisted %v: err %v, want an error: %v", tc.unlisted, err, tc.wantErr)
		}
		if !tc.wantErr && len(items) != 1 {
			t.Errorf("unlisted %v: kept %d items, want the one that answered", tc.unlisted, len(items))
		}
	}
}

// Review of #63: a type spelled two ways across versions took whichever
// spelling the map gave last, so a snapshot's kinds could change between runs.
func TestATypesSpellingDoesNotDependOnMapOrder(t *testing.T) {
	index := []byte(`{"resources":{"A.B/parents/Rules@2020-01-01":{"$ref":"f.json#/0"},"A.B/parents/rules@2024-01-01":{"$ref":"f.json#/0"},"A.B/parents@2024-01-01":{"$ref":"f.json#/0"}}}`)
	for range 50 {
		r, err := newRegistry(func(string) ([]byte, error) { return index, nil })
		if err != nil {
			t.Fatal(err)
		}
		if got := r.Children("A.B/parents"); len(got) != 1 || got[0] != "A.B/parents/Rules" {
			t.Fatalf("got %v, want [A.B/parents/Rules]", got)
		}
	}
}

// Review of #63: matched by name in any case, or by its items' IDs, a
// registered child collection that ARM also returns inline (an NSG's
// securityRules) stopped being read on its own, and left every snapshot that
// had it. Registered children are skipped only as before.
func TestRegisteredChildrenAreReadAsBefore(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	nsg := id(srcSub, "shop-rg", "Microsoft.Network/networkSecurityGroups", "web")
	rule := map[string]any{"access": "Allow", "direction": "Inbound", "priority": 100, "protocol": "Tcp",
		"sourceAddressPrefix": "*", "sourcePortRange": "*", "destinationAddressPrefix": "*", "destinationPortRange": "443"}
	// As ARM returns it: its rules inline, with their IDs.
	f.SeedAzure(nsg, stable(reg, "Microsoft.Network/networkSecurityGroups"), map[string]any{"location": "eastus", "properties": map[string]any{
		"securityRules": []any{map[string]any{"id": nsg + "/securityRules/https", "name": "https", "properties": rule}}}})
	f.SeedAzure(nsg+"/securityRules/https", stable(reg, "Microsoft.Network/networkSecurityGroups/securityRules"), map[string]any{"properties": rule})

	_, got := captureByKey(t, f, reg)
	if _, ok := got["Microsoft.Network/networkSecurityGroups/securityRules|web/https"]; !ok {
		t.Errorf("the rule is no longer its own object: %v", sortedKeys(got))
	}
}
