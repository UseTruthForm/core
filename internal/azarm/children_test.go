package azarm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
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

// offeredOnly answers the provider registration with the versions it is given.
type offeredOnly struct {
	*Fake
	offered map[string][]string
}

func (o offeredOnly) APIVersions(context.Context, string) (map[string][]string, error) {
	return o.offered, nil
}

// Review of beta.14: a child the registration does not list is read at its
// parent's versions. With none of them defined for it, nothing was read and
// nothing said so. It is read at its own newest definition now, and only a
// refusal of that version is a gap: made a gap before the list, it was one
// for every alert rule's networkSecurityPerimeterConfigurations, which no one
// can write, and for a parent with none (second review). ARM refuses such a
// version with a plain 400, NoRegisteredProviderFound, seen live for an action
// group's networkSecurityPerimeterConfigurations; read as "none here", the
// child went silent again (third review). A type the registration lists with
// no version defined is still one the subscription does not offer us.
func TestAChildWithNoVersionOfItsParentsIsReadAtItsOwn(t *testing.T) {
	reg := fixtures(t)
	ctx := context.Background()
	deployments := accountType + "/deployments"
	old := map[string][]string{strings.ToLower(accountType): {"2017-04-18"}}
	for name, tc := range map[string]struct {
		typ     string
		offered map[string][]string
		refuse  error
		want    string // "item", "gap" or "" for none
	}{
		"read at its own version":                {deployments, old, nil, "item"},
		"its own version is refused":             {deployments, old, fmt.Errorf("refused: %w", ErrAPIVersion), "gap"},
		"refused with NoRegisteredProviderFound": {deployments, old, &armError{status: http.StatusBadRequest, code: "NoRegisteredProviderFound", msg: "No registered resource provider found for location 'global' and API version '2026-09-01'"}, "gap"},
		"none at its own version":                {deployments, old, fmt.Errorf("%w: %v", ErrNotFound, &armError{status: http.StatusNotFound, code: "ResourceNotFound"}), ""},
		"no one can write it":                    {"Microsoft.Network/networkSecurityGroups/defaultSecurityRules", map[string][]string{"microsoft.network/networksecuritygroups": {"2017-04-18"}}, nil, ""},
		"in the registration":                    {deployments, map[string][]string{strings.ToLower(deployments): {"2017-04-18"}}, nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := NewWorld(reg).Subscription(srcSub, srcTenant)
			acct := seedAccount(t, f)
			rawPut(t, f, acct+"/deployments/chat", deployments, map[string]any{
				"sku":        map[string]any{"name": "GlobalStandard", "capacity": 50},
				"properties": map[string]any{"model": map[string]any{"format": "OpenAI", "name": "gpt-4.1", "version": "2025-04-14"}}})
			if tc.refuse != nil {
				f.ListError = func(string) error { return tc.refuse }
			}
			api := offeredOnly{f, tc.offered}
			v := &versions{api: api, reg: reg, ctx: ctx, cache: map[string]map[string][]string{}}
			path := acct + "/deployments"
			if tc.typ != deployments {
				path = id(srcSub, "shop-rg", "Microsoft.Network/networkSecurityGroups", "web") + "/defaultSecurityRules"
			}
			got := listOf(ctx, api, v, srcTenant, tc.typ, path, nil)
			kind := ""
			if len(got) == 1 && got[0].c != nil {
				kind = "item"
			} else if len(got) == 1 && strings.HasPrefix(got[0].reason, Unreadable+"no version its parent is offered at") {
				kind = "gap"
			}
			if kind != tc.want || (tc.want == "" && len(got) != 0) {
				t.Errorf("got %+v, want %q", got, tc.want)
			}
		})
	}
}

// failsAt refuses a list at one version and fails it otherwise.
type failsAt struct {
	*Fake
	refused string
	err     error
}

func (f failsAt) List(_ context.Context, path, version string) ([]map[string]any, error) {
	if version == f.refused {
		return nil, fmt.Errorf("%w: %s", ErrAPIVersion, path)
	}
	return nil, f.err
}

// Third review of #67, a fault already on main: when the preferred version
// was refused and the next one failed (a 403, a 500), the next one's error was
// overwritten by its schema lookup, and the collection read as empty with no
// gap. #67 tries more versions, so it was met more often.
func TestAFailureAtTheNextVersionIsAGap(t *testing.T) {
	reg := fixtures(t)
	for name, fail := range map[string]error{
		"403": &armError{status: http.StatusForbidden, code: "AuthorizationFailed"},
		"500": &armError{status: http.StatusInternalServerError, code: "InternalServerError"},
	} {
		t.Run(name, func(t *testing.T) {
			api := failsAt{NewWorld(reg).Subscription(srcSub, srcTenant), "2016-09-01", fail}
			v := &versions{api: api, reg: reg, ctx: context.Background(), cache: map[string]map[string][]string{}}
			path := id(srcSub, "shop-rg", "Microsoft.KeyVault/vaults", "kv") + "/providers/" + diagnosticType
			got := listOf(context.Background(), api, v, srcTenant, diagnosticType, path, nil)
			if len(got) != 1 || !strings.HasPrefix(got[0].reason, Unreadable) {
				t.Errorf("got %+v, want a gap", got)
			}
		})
	}
}

// A real capture held two file shares AKS's Azure Files driver made for
// volume claims. The cluster's snapshot skips their volumes, since restoring a
// claim provisions a new one, so restoring the shares as well left them beside
// it unused. A share list returns no metadata unless asked, so who made a share
// was never seen, and neither was metadata someone set.
func TestSharesAKSMadeForAClaimAreSkipped(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	acct := put(t, f, "shop-rg", "Microsoft.Storage/storageAccounts", "shopdata", map[string]any{"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"}})
	shares := "Microsoft.Storage/storageAccounts/fileServices/shares"
	rawPut(t, f, acct+"/fileServices/default", "Microsoft.Storage/storageAccounts/fileServices", map[string]any{"properties": map[string]any{}})
	rawPut(t, f, acct+"/fileServices/default/shares/pvc-1", shares, map[string]any{"properties": map[string]any{"shareQuota": 2, "metadata": map[string]any{"createdBy": "file.csi.azure.com"}}})
	rawPut(t, f, acct+"/fileServices/default/shares/reports", shares, map[string]any{"properties": map[string]any{"shareQuota": 5, "metadata": map[string]any{"team": "finance"}}})
	// Metadata names are not case sensitive (review of #68).
	rawPut(t, f, acct+"/fileServices/default/shares/pvc-2", shares, map[string]any{"properties": map[string]any{"shareQuota": 2, "metadata": map[string]any{"createdby": "file.csi.azure.com"}}})

	s, got := captureByKey(t, f, reg)
	for _, pvc := range []string{"pvc-1", "pvc-2"} {
		if _, ok := got[shares+"|shopdata/default/"+pvc]; ok {
			t.Errorf("the share AKS made for a claim was captured: %s", pvc)
		}
	}
	skipped := false
	for _, sk := range s.Skips {
		skipped = skipped || (sk.Reason == csiShare && strings.HasSuffix(sk.Name, "pvc-1"))
	}
	if !skipped {
		t.Errorf("not said: %+v", s.Skips)
	}
	o, ok := got[shares+"|shopdata/default/reports"]
	if !ok {
		t.Fatalf("a share someone made was lost: %v", sortedKeys(got))
	}
	spec, _ := o.Body["spec"].(map[string]any)
	props, _ := spec["properties"].(map[string]any)
	if md, _ := props["metadata"].(map[string]any); md["team"] != "finance" {
		t.Errorf("its metadata was not captured: %v", props)
	}
}

// Review of #68: the query a collection is listed with went into the name of
// its gap ("…/shares?$expand=metadata").
func TestAGapNamesTheCollectionNotItsQuery(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	acct := put(t, f, "shop-rg", "Microsoft.Storage/storageAccounts", "shopdata", map[string]any{"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"}})
	rawPut(t, f, acct+"/fileServices/default", "Microsoft.Storage/storageAccounts/fileServices", map[string]any{"properties": map[string]any{}})
	f.ListError = func(p string) error {
		if strings.Contains(strings.ToLower(p), "/shares") {
			return &armError{url: p, status: http.StatusServiceUnavailable}
		}
		return nil
	}
	s, _ := captureByKey(t, f, reg)
	gap := false
	for _, sk := range s.Skips {
		if strings.HasPrefix(sk.Reason, Unreadable) && strings.Contains(sk.Name, "/shares") {
			gap = true
			if strings.Contains(sk.Name, "?") {
				t.Errorf("the gap names the query: %s", sk.Name)
			}
		}
	}
	if !gap {
		t.Errorf("no gap for the shares: %+v", s.Skips)
	}
}

// Review of #68: capture made the source's own subscription a placeholder
// only where written plainly, so one escaped in a URL was restored as the
// source's and named as another subscription's.
func TestTheSourcesOwnSubscriptionInAURLIsAPlaceholder(t *testing.T) {
	reg := fixtures(t)
	f := NewWorld(reg).Subscription(srcSub, srcTenant)
	put(t, f, "", groupType, "shop-rg", map[string]any{"location": "eastus"})
	link := "https://portal.example/#resource=%2Fsubscriptions%2F" + srcSub + "%2FresourceGroups%2Fshop-rg&back=%252Fsubscriptions%252F" + srcSub
	put(t, f, "shop-rg", "Microsoft.Storage/storageAccounts", "shopdata", map[string]any{"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"}, "tags": map[string]any{"dashboard": link}})
	s, got := captureByKey(t, f, reg)
	spec, _ := got["Microsoft.Storage/storageAccounts|shopdata"].Body["spec"].(map[string]any)
	tags, _ := spec["tags"].(map[string]any)
	for _, want := range []string{"%2Fsubscriptions%2F" + tokSub + "%2F", "%252Fsubscriptions%252F" + tokSub} {
		if !strings.Contains(fmt.Sprint(tags["dashboard"]), want) {
			t.Errorf("tag %q, want %q in it", tags["dashboard"], want)
		}
	}
	if other := OtherSubscriptions(s); len(other) != 0 {
		t.Errorf("the source's own subscription named as another: %v", other)
	}
}
