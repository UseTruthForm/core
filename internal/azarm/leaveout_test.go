package azarm

import (
	"strings"
	"testing"

	"github.com/stackdna/core/internal/snapshot"
)

const otherSub = "33333333-3333-3333-3333-333333333333"

// What a rehearsal of a real restore beside its source met: a private DNS
// zone linked to a network in another subscription. A network links to one
// zone of a name, and the source's zone already has it, so the restore would
// be refused there; and nothing could hold the link back.
func linkSnapshot() snapshot.Snapshot {
	sub := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/"
	zone := obj("Microsoft.Network/privateDnsZones", "rg", "corp.example", sub+"Microsoft.Network/privateDnsZones/corp.example", map[string]any{"location": "global"})
	link := obj("Microsoft.Network/privateDnsZones/virtualNetworkLinks", "rg", "corp.example/office", sub+"Microsoft.Network/privateDnsZones/corp.example/virtualNetworkLinks/office",
		map[string]any{"location": "global", "properties": map[string]any{"virtualNetwork": map[string]any{
			"id": "/subscriptions/" + otherSub + "/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/office"}}})
	diag := obj("microsoft.insights/diagnosticSettings", "", "providers/microsoft.insights/diagnosticSettings/to-central", "/subscriptions/"+tokSub+"/providers/microsoft.insights/diagnosticSettings/to-central",
		map[string]any{"properties": map[string]any{"eventHubAuthorizationRuleId": "/subscriptions/" + strings.ToUpper(otherSub) + "/resourceGroups/sec/providers/Microsoft.EventHub/namespaces/central/authorizationRules/send"}})
	return snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{zone, link, diag}}
}

func TestLeaveOutHoldsBackALinkToAnotherSubscription(t *testing.T) {
	s := linkSnapshot()
	out, err := LeaveOut(s, []string{"Microsoft.Network/privateDnsZones/virtualNetworkLinks/rg/corp.example/office"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Objects) != 2 {
		t.Fatalf("left %d objects, want 2", len(out.Objects))
	}
	for _, o := range out.Objects {
		if o.Kind() == "Microsoft.Network/privateDnsZones/virtualNetworkLinks" {
			t.Error("the link is still there")
		}
	}
	if len(s.Objects) != 3 {
		t.Error("the snapshot it was given changed")
	}
}

// Leaving out what something left in needs would fail at the restore, after
// the rest was sent: refused first, as is an entry that names nothing.
func TestLeaveOutRefusesWhatIsStillNeeded(t *testing.T) {
	s := linkSnapshot()
	sub := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/"
	zoneID := sub + "Microsoft.Network/privateDnsZones/corp.example"
	pe := obj("Microsoft.Network/privateEndpoints/privateDnsZoneGroups", "rg", "pe/default", sub+"Microsoft.Network/privateEndpoints/pe/privateDnsZoneGroups/default",
		map[string]any{"properties": map[string]any{"privateDnsZoneConfigs": []any{map[string]any{"properties": map[string]any{"privateDnsZoneId": zoneID}}}}})
	byRef := obj("Microsoft.Network/privateEndpoints", "rg", "pe2", sub+"Microsoft.Network/privateEndpoints/pe2",
		map[string]any{"properties": map[string]any{"note": "{{stackdna|ref|Microsoft.Network/privateDnsZones|rg|corp.example|id}}"}})
	waits := obj("Microsoft.Storage/storageAccounts", "rg", "after", sub+"Microsoft.Storage/storageAccounts/after", map[string]any{})
	waits.Body["metadata"].(map[string]any)["annotations"].(map[string]any)[annAfter] = zoneID
	zone := "Microsoft.Network/privateDnsZones/rg/corp.example"
	for name, tc := range map[string]struct {
		extra []snapshot.Object
		keys  []string
		want  string
	}{
		"its child":         {nil, []string{zone}, "virtualNetworkLinks/rg/corp.example/office needs " + zone},
		"an ID in a spec":   {[]snapshot.Object{pe}, []string{zone, "Microsoft.Network/privateDnsZones/virtualNetworkLinks/rg/corp.example/office"}, "privateDnsZoneGroups/rg/pe/default needs " + zone},
		"a reference":       {[]snapshot.Object{byRef}, []string{zone, "Microsoft.Network/privateDnsZones/virtualNetworkLinks/rg/corp.example/office"}, "privateEndpoints/rg/pe2 needs " + zone},
		"what it waits for": {[]snapshot.Object{waits}, []string{zone, "Microsoft.Network/privateDnsZones/virtualNetworkLinks/rg/corp.example/office"}, "storageAccounts/rg/after needs " + zone},
		"a name not in it":  {nil, []string{"Microsoft.Network/privateDnsZones/rg/missing.example"}, "not in the snapshot: microsoft.network/privatednszones/rg/missing.example"},
	} {
		t.Run(name, func(t *testing.T) {
			in := s
			in.Objects = append(append([]snapshot.Object{}, s.Objects...), tc.extra...)
			_, err := LeaveOut(in, tc.keys)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want an error with %q", err, tc.want)
			}
		})
	}
}

// Capture writes the source subscription as a placeholder, so an ID with a
// subscription written out is another one's. A restore sends it as it is, and
// nothing said so until Azure refused.
func TestOtherSubscriptionsAreNamed(t *testing.T) {
	got := OtherSubscriptions(linkSnapshot())
	if len(got) != 2 {
		t.Fatalf("got %v, want the link and the diagnostic setting", got)
	}
	for _, g := range got {
		if !strings.Contains(g, otherSub) {
			t.Errorf("%q does not name the subscription", g)
		}
	}
	if !strings.HasPrefix(got[0], "Microsoft.Network/privateDnsZones/virtualNetworkLinks/rg/corp.example/office:") ||
		!strings.HasPrefix(got[1], "microsoft.insights/diagnosticSettings//providers/microsoft.insights/diagnosticSettings/to-central:") {
		t.Errorf("unexpected entries: %v", got)
	}
}
