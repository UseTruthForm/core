package azarm

import (
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// A restore plan needed list-keys on another subscription's event hub rule for
// a diagnostic setting, and the report said only that a restore "needs access
// there": which access, nothing said until Azure refused it. Each reference
// Azure checks now names the action and the resource it is on.
func TestAccessElsewhereNamesTheActionAndWhere(t *testing.T) {
	rule := "/subscriptions/" + otherSub + "/resourceGroups/hub/providers/Microsoft.EventHub/namespaces/logs/authorizationRules/send"
	vnet := "/subscriptions/" + otherSub + "/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/hub"
	own := "/subscriptions/" + tokSub + "/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/spoke"
	s := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{
		obj("microsoft.insights/diagnosticSettings", "", "providers/microsoft.insights/diagnosticSettings/to-hub", "/subscriptions/"+tokSub+"/providers/microsoft.insights/diagnosticSettings/to-hub",
			map[string]any{"properties": map[string]any{"eventHubAuthorizationRuleId": rule, "eventHubName": "activity"}}),
		// ARM's keys are not case sensitive.
		obj("Microsoft.Network/privateDnsZones/virtualNetworkLinks", "rg", "corp.example/hub", "/x",
			map[string]any{"properties": map[string]any{"virtualnetwork": map[string]any{"ID": vnet}}}),
		obj("Microsoft.Network/virtualNetworks/virtualNetworkPeerings", "rg", "spoke/to-hub", "/x",
			map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": vnet}}}),
		// In the source's own subscription: the target's own grant covers it.
		obj("Microsoft.Network/virtualNetworks/virtualNetworkPeerings", "rg", "hub/to-spoke", "/x",
			map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": own}}}),
		// Not an ID, but text holding one (review of #71).
		obj("Microsoft.Network/virtualNetworks/virtualNetworkPeerings", "rg", "spoke/old", "/x",
			map[string]any{"properties": map[string]any{"remoteVirtualNetwork": map[string]any{"id": vnet + " (retired)"}}}),
		// Named, but with no check known: other subscriptions only.
		obj("Microsoft.Network/privateDnsZones", "rg", "corp.example", "/x",
			map[string]any{"tags": map[string]any{"hub": vnet}}),
	}}
	got := AccessElsewhere(s, "")
	want := []string{
		"Microsoft.Network/privateDnsZones/virtualNetworkLinks/rg/corp.example/hub: Microsoft.Network/virtualNetworks/join/action on " + vnet,
		"Microsoft.Network/virtualNetworks/virtualNetworkPeerings/rg/spoke/to-hub: Microsoft.Network/virtualNetworks/peer/action on " + vnet,
		"microsoft.insights/diagnosticSettings//providers/microsoft.insights/diagnosticSettings/to-hub: Microsoft.EventHub/namespaces/authorizationRules/listKeys/action on " + rule,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if other := OtherSubscriptions(s); len(other) != 5 {
		t.Errorf("other subscriptions: %v", other)
	}
	// Restored into the subscription they name, they are not elsewhere
	// (review of #71).
	if got := AccessElsewhere(s, strings.ToUpper(otherSub)); len(got) != 0 {
		t.Errorf("restored into %s: %v", otherSub, got)
	}
}
