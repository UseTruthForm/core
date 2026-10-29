package azarm

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

// A small estate with every kind of relationship a graph draws.
func graphSnapshot() snapshot.Snapshot {
	sub := "/subscriptions/" + tokSub
	rg := sub + "/resourceGroups/rg"
	id := func(p string) string { return rg + "/providers/" + p }
	identity := obj("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", "id1", id("Microsoft.ManagedIdentity/userAssignedIdentities/id1"), map[string]any{})
	vnet := obj("Microsoft.Network/virtualNetworks", "rg", "vnet", id("Microsoft.Network/virtualNetworks/vnet"), map[string]any{
		"location": "westus",
		"properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}},
			// Its own subnet: a part of it, not a relationship.
			"subnets": []any{map[string]any{"id": id("Microsoft.Network/virtualNetworks/vnet/subnets/app"), "name": "app", "properties": map[string]any{"addressPrefix": "10.0.1.0/24"}}},
			// Another subscription's network: outside the snapshot.
			"virtualNetworkPeerings": []any{map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": "/subscriptions/other/resourceGroups/hub/providers/Microsoft.Network/virtualNetworks/hub"}}}},
		},
	})
	nic := obj("Microsoft.Network/networkInterfaces", "rg", "nic", id("Microsoft.Network/networkInterfaces/nic"), map[string]any{
		// In lower case, as some resources write IDs.
		"properties": map[string]any{"ipConfigurations": []any{map[string]any{"properties": map[string]any{"subnet": map[string]any{"id": strings.ToLower(id("Microsoft.Network/virtualNetworks/vnet/subnets/app"))}}}}},
	})
	site := obj("Microsoft.Web/sites", "rg", "web", id("Microsoft.Web/sites/web"), map[string]any{
		"tags":     map[string]any{"env": "dev"},
		"identity": map[string]any{"userAssignedIdentities": map[string]any{id("Microsoft.ManagedIdentity/userAssignedIdentities/id1"): map[string]any{}}},
		"properties": map[string]any{
			"httpsOnly": true,
			// Two IDs joined in one string.
			"logs": id("Microsoft.Storage/storageAccounts/acct") + "," + id("Microsoft.Network/networkInterfaces/nic"),
		},
	})
	site.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annAfter] = id("Microsoft.Network/virtualNetworks/vnet")
	acct := obj("Microsoft.Storage/storageAccounts", "rg", "acct", id("Microsoft.Storage/storageAccounts/acct"), map[string]any{
		"properties": map[string]any{"publicNetworkAccess": "Disabled", "allowSharedKeyAccess": false, "networkAcls": map[string]any{"defaultAction": "Deny"}},
	})
	container := obj("Microsoft.Storage/storageAccounts/blobServices/containers", "rg", "acct/default/logs", id("Microsoft.Storage/storageAccounts/acct/blobServices/default/containers/logs"), map[string]any{})
	assign := obj("Microsoft.Authorization/roleAssignments", "rg", "providers/Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/roleAssignments/ra",
		id("Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/roleAssignments/ra"), map[string]any{
			"properties": map[string]any{
				"principalId":      "{{stackdna|ref|Microsoft.ManagedIdentity/userAssignedIdentities|rg|id1|properties.principalId}}",
				"roleDefinitionId": sub + "/providers/Microsoft.Authorization/roleDefinitions/r1",
			},
		})
	table := obj("Microsoft.OperationalInsights/workspaces/tables", "rg", "ws/T1", id("Microsoft.OperationalInsights/workspaces/ws/tables/T1"), map[string]any{})
	return snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{identity, vnet, nic, site, acct, container, assign, table}}
}

func TestGraphDrawsEveryRelationship(t *testing.T) {
	p, _, err := LoadProjection("security", nil)
	if err != nil {
		t.Fatal(err)
	}
	g := BuildGraph(graphSnapshot(), p, "security", "", "")
	rg := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/"
	want := []GraphEdge{
		{From: rg + "Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/roleAssignments/ra", To: "/subscriptions/" + tokSub + "/providers/Microsoft.Authorization/roleDefinitions/r1", Kind: "references", Path: "properties.roleDefinitionId"},
		{From: rg + "Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/roleAssignments/ra", To: rg + "Microsoft.ManagedIdentity/userAssignedIdentities/id1", Kind: "references", Path: "properties.principalId"},
		{From: rg + "Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/roleAssignments/ra", To: rg + "Microsoft.Storage/storageAccounts/acct", Kind: "extension-of"},
		{From: rg + "Microsoft.Network/networkInterfaces/nic", To: rg + "Microsoft.Network/virtualNetworks/vnet", Kind: "references", Path: "properties.ipConfigurations[].properties.subnet.id", Subresource: "subnets/app"},
		{From: rg + "Microsoft.Network/virtualNetworks/vnet", To: "/subscriptions/other/resourceGroups/hub/providers/Microsoft.Network/virtualNetworks/hub", Kind: "references", Path: "properties.virtualNetworkPeerings[].properties.remoteVirtualNetwork.id"},
		{From: rg + "Microsoft.Storage/storageAccounts/acct/blobServices/default/containers/logs", To: rg + "Microsoft.Storage/storageAccounts/acct", Kind: "references", Path: "", Subresource: "blobServices/default"},
		{From: rg + "Microsoft.Web/sites/web", To: rg + "Microsoft.ManagedIdentity/userAssignedIdentities/id1", Kind: "references", Path: "identity.userAssignedIdentities{}"},
		{From: rg + "Microsoft.Web/sites/web", To: rg + "Microsoft.Network/networkInterfaces/nic", Kind: "references", Path: "properties.logs"},
		{From: rg + "Microsoft.Web/sites/web", To: rg + "Microsoft.Network/virtualNetworks/vnet", Kind: "depends-on"},
		{From: rg + "Microsoft.Web/sites/web", To: rg + "Microsoft.Storage/storageAccounts/acct", Kind: "references", Path: "properties.logs"},
	}
	// The container's parent (blobServices/default) is not in the snapshot:
	// the child-of edge goes to the account that holds it.
	want[5].Kind = "child-of"
	sort.Slice(want, func(i, j int) bool {
		a, b := want[i], want[j]
		return a.From+"\x00"+a.To+"\x00"+a.Kind+"\x00"+a.Path < b.From+"\x00"+b.To+"\x00"+b.Kind+"\x00"+b.Path
	})
	if !reflect.DeepEqual(g.Edges, want) {
		for i := range want {
			if i >= len(g.Edges) || g.Edges[i] != want[i] {
				t.Errorf("edge %d\n got  %+v\n want %+v", i, g.Edges[min(i, len(g.Edges)-1)], want[i])
			}
		}
	}

	nodes := map[string]GraphNode{}
	for _, n := range g.Nodes {
		nodes[n.Type+"/"+n.Name] = n
	}
	if _, ok := nodes["Microsoft.OperationalInsights/workspaces/tables/ws/T1"]; ok {
		t.Error("a dropped type is in the graph")
	}
	if n := nodes["Microsoft.Network/virtualNetworks/hub"]; !n.External || n.Group != "hub" {
		t.Errorf("the other subscription's network: %+v", n)
	}
	if n := nodes["Microsoft.Authorization/roleDefinitions/r1"]; !n.External {
		t.Errorf("a role definition the snapshot does not hold: %+v", n)
	}
	acct := nodes["Microsoft.Storage/storageAccounts/acct"]
	if acct.Properties["properties.publicNetworkAccess"] != "Disabled" || acct.Properties["properties.allowSharedKeyAccess"] != false ||
		!reflect.DeepEqual(acct.Properties["properties.networkAcls"], map[string]any{"defaultAction": "Deny"}) {
		t.Errorf("storage account properties %v", acct.Properties)
	}
	vnet := nodes["Microsoft.Network/virtualNetworks/vnet"]
	if !reflect.DeepEqual(vnet.Properties["properties.subnets[].properties.addressPrefix"], []any{"10.0.1.0/24"}) || vnet.Location != "westus" {
		t.Errorf("network %+v", vnet)
	}
	if site := nodes["Microsoft.Web/sites/web"]; site.Tags["env"] != "dev" || len(site.Properties) != 1 || site.Properties["properties.httpsOnly"] != true {
		t.Errorf("a site carries what the projection lists and has: %+v", site)
	}
	if n := len(g.Nodes); n != 9 {
		t.Errorf("%d nodes, want the 7 kept and 2 external", n)
	}
}

// The real subscription goes in only when asked; without it the graph
// names none. The same snapshot always gives the same graph.
func TestGraphSubscriptionAndDeterminism(t *testing.T) {
	p, _, _ := LoadProjection("security", nil)
	a, _ := json.Marshal(BuildGraph(graphSnapshot(), p, "security", "", ""))
	b, _ := json.Marshal(BuildGraph(graphSnapshot(), p, "security", "", ""))
	if string(a) != string(b) {
		t.Error("two graphs of one snapshot differ")
	}
	real, _ := json.Marshal(BuildGraph(graphSnapshot(), p, "security", "11111111-2222-3333-4444-555555555555", ""))
	if strings.Contains(string(real), tokSub) || !strings.Contains(string(real), "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg") {
		t.Error("the subscription was not substituted everywhere")
	}
	if !strings.Contains(string(a), tokSub) {
		t.Error("without --subscription the placeholder must stay")
	}
}

func TestLoadProjection(t *testing.T) {
	if p, name, err := LoadProjection("none", nil); err != nil || name != "none" || len(p.Types) != 0 {
		t.Errorf("none: %v %v %v", p, name, err)
	}
	read := func(b string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(b), nil }
	}
	if _, _, err := LoadProjection("p.yaml", read("version: 1\ntypes:\n  X/y:\n    feilds: [a]\n")); err == nil {
		t.Error("a misspelt key was accepted")
	}
	if _, _, err := LoadProjection("p.yaml", read("version: 2\n")); err == nil {
		t.Error("an unknown version was accepted")
	}
	p, _, err := LoadProjection("p.yaml", read("version: 1\ntypes:\n  microsoft.storage/storageaccounts:\n    fields:\n      - sku.name\n"))
	if err != nil || len(p.of("Microsoft.Storage/storageAccounts").Fields) != 1 {
		t.Errorf("a type is matched in any case: %v %v", p, err)
	}
}

// What the review of #48 found: each of these gave a dangling edge, a
// bogus node, a wrong edge, a missing one or a panic.
func TestGraphEdgeCases(t *testing.T) {
	sub := "/subscriptions/" + tokSub
	rg := sub + "/resourceGroups/rg"
	id := func(p string) string { return rg + "/providers/" + p }
	group := obj("Microsoft.Resources/resourceGroups", "", "rg", rg, map[string]any{})
	identity := obj("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", "id1", id("Microsoft.ManagedIdentity/userAssignedIdentities/id1"), map[string]any{})
	identity.Body["status"] = map[string]any{"properties.principalId": "aaaaaaaa-0000-4000-8000-000000000001"}
	nic := obj("Microsoft.Network/networkInterfaces", "rg", "nic", id("Microsoft.Network/networkInterfaces/nic"), map[string]any{
		"tags": map[string]any{"hidden-link:" + id("Microsoft.Web/sites/web"): "Resource"},
		"properties": map[string]any{
			// Two subnets of one network through one path: tied in the sort.
			"ipConfigurations": []any{
				map[string]any{"subnet": map[string]any{"id": id("Microsoft.Network/virtualNetworks/vnet/subnets/b")}},
				map[string]any{"subnet": map[string]any{"id": id("Microsoft.Network/virtualNetworks/vnet/subnets/a")}},
			},
			// One external resource, in two cases.
			"a": "/subscriptions/other/resourceGroups/hub/providers/Microsoft.Network/virtualNetworks/hub/subnets/s1",
			"b": "/subscriptions/OTHER/resourcegroups/HUB/providers/microsoft.network/virtualnetworks/HUB",
			// IDs in URLs and template text end where the ID does.
			"c": "https://management.azure.com" + id("Microsoft.Web/sites/w") + "?api-version=2020-01-01",
			"f": "https://portal.azure.com/#@t/resource" + id("Microsoft.Web/sites/v") + "/overview",
			"d": "[resourceId('" + id("Microsoft.Web/sites/x") + "')]",
			// A built-in role definition, tenant level.
			"e": "/providers/Microsoft.Authorization/roleDefinitions/r9",
			"g": sub + "/providers/Microsoft.Authorization/roleDefinitions/r9",
		},
	})
	vnet := obj("Microsoft.Network/virtualNetworks", "rg", "vnet", id("Microsoft.Network/virtualNetworks/vnet"), map[string]any{})
	lock := obj("Microsoft.Authorization/locks", "rg", "nodelete", id("Microsoft.Authorization/locks/nodelete"), map[string]any{})
	assign := obj("Microsoft.Authorization/roleAssignments", "", "ra", sub+"/providers/Microsoft.Authorization/roleAssignments/ra", map[string]any{
		"properties": map[string]any{
			"principalId": "{{stackdna|ref|Microsoft.ManagedIdentity/userAssignedIdentities|rg|id1|properties.principalId}}",
			"note":        "{{stackdna|ref|Microsoft.ManagedIdentity/userAssignedIdentities|rg|id1|properties.createdBy}}",
			// An extension's token, whose name is providers/... text.
			"other": "{{stackdna|ref|Microsoft.Authorization/roleAssignments|rg|providers/Microsoft.Network/virtualNetworks/vnet/providers/Microsoft.Authorization/roleAssignments/r2|properties.createdBy}}",
		},
	})
	// No ID annotation and a nested kind: took a slice out of range.
	bare := snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": "Microsoft.Network/virtualNetworks/subnets",
		"metadata": map[string]any{"name": "s", "namespace": "rg"}, "spec": map[string]any{}}}
	snap := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{group, identity, nic, vnet, lock, assign, bare}}
	p := Projection{Version: 1, Types: map[string]ProjectionType{"Microsoft.Authorization/roleAssignments": {Fields: []string{"properties.principalId"}}}}

	first, _ := json.Marshal(BuildGraph(snap, p, "t", "", ""))
	for i := 0; i < 20; i++ {
		if b, _ := json.Marshal(BuildGraph(snap, p, "t", "", "")); string(b) != string(first) {
			t.Fatal("two graphs of one snapshot differ")
		}
	}
	g := BuildGraph(snap, p, "t", "", "")
	nodes := map[string]GraphNode{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	has := func(from, to, kind string) bool {
		for _, e := range g.Edges {
			if e.From == from && e.To == to && e.Kind == kind {
				return true
			}
		}
		return false
	}
	for _, e := range g.Edges {
		if _, ok := nodes[e.To]; !ok {
			t.Errorf("edge to no node: %+v", e)
		}
		if strings.Contains(e.To, "?") || strings.Contains(e.To, "'") {
			t.Errorf("an ID ran past its end: %s", e.To)
		}
		if strings.HasSuffix(e.Path, "note") || strings.HasSuffix(e.Path, "other") {
			t.Errorf("a token to who created something is an edge: %+v", e)
		}
	}
	hubs := 0
	for _, n := range g.Nodes {
		if strings.EqualFold(n.ID, "/subscriptions/other/resourceGroups/hub/providers/Microsoft.Network/virtualNetworks/hub") {
			hubs++
			if !n.External || n.Type != "Microsoft.Network/virtualNetworks" {
				t.Errorf("the external network, typed as the held ones: %+v", n)
			}
		}
	}
	if hubs != 1 {
		t.Errorf("%d nodes for one external network", hubs)
	}
	if !has(id("Microsoft.Authorization/locks/nodelete"), rg, "extension-of") {
		t.Error("a lock on the group is not the group's")
	}
	if !has(sub+"/providers/Microsoft.Authorization/roleAssignments/ra", sub, "extension-of") || nodes[sub].Type != "Microsoft.Resources/subscriptions" || nodes[sub].External {
		t.Errorf("an assignment on the subscription is not the subscription's: %+v", nodes[sub])
	}
	if !has(id("Microsoft.Network/networkInterfaces/nic"), sub+"/providers/Microsoft.Authorization/roleDefinitions/r9", "references") {
		t.Error("a tenant-level role definition is not referenced")
	}
	roles := 0
	for _, n := range g.Nodes {
		if n.Type == "Microsoft.Authorization/roleDefinitions" {
			roles++
		}
	}
	if roles != 1 {
		t.Errorf("one role definition in two forms is %d nodes", roles)
	}
	for _, site := range []string{"w", "v"} {
		if !has(id("Microsoft.Network/networkInterfaces/nic"), id("Microsoft.Web/sites/"+site), "references") {
			t.Errorf("the site in a URL (%s) is not found", site)
		}
	}
	for _, n := range g.Nodes {
		if n.Type == "Microsoft.Network/virtualNetworks/subnets" {
			t.Errorf("a malformed object became a node: %+v", n)
		}
	}
	withSub := BuildGraph(snap, p, "t", "11111111-2222-3333-4444-555555555555", "")
	if b, _ := json.Marshal(withSub); strings.Contains(string(b), tokSub) {
		t.Error("a placeholder is left with --subscription")
	}
	if !has(id("Microsoft.Network/networkInterfaces/nic"), id("Microsoft.Web/sites/web"), "references") {
		t.Error("a tag key naming a resource is not a reference")
	}
	if got := nodes[sub+"/providers/Microsoft.Authorization/roleAssignments/ra"].Properties["properties.principalId"]; got != "aaaaaaaa-0000-4000-8000-000000000001" {
		t.Errorf("principalId %v, want the identity's value", got)
	}
}

func TestProjectionRefusesWhatItCannotMean(t *testing.T) {
	read := func(b string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(b), nil }
	}
	for _, y := range []string{
		"version: 1\ntypes:\n  A/b:\n    fields: [x]\n  a/B:\n    fields: [y]\n",
		"version: 1\ntypes:\n  A/b:\n    drop: true\n    fields: [x]\n",
		"version: 1\ntypes:\n  A/b:\n    fields: [x..y]\n",
	} {
		if _, _, err := LoadProjection("p.yaml", read(y)); err == nil {
			t.Errorf("accepted %q", y)
		}
	}
	// Two fields of one list stay lined up.
	v, _ := project(map[string]any{"x": []any{map[string]any{"a": 1}, map[string]any{"b": 2}}}, []string{"x[]", "a"})
	if !reflect.DeepEqual(v, []any{1.0, nil}) && !reflect.DeepEqual(v, []any{1, nil}) {
		t.Errorf("x[].a = %v", v)
	}
}
