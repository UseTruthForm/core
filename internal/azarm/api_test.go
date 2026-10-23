package azarm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseIDRoundTrip(t *testing.T) {
	for _, c := range []struct{ id, typ, name string }{
		{"/subscriptions/s/resourceGroups/rg", groupType, "rg"},
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet", "Microsoft.Network/virtualNetworks", "vnet"},
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/app", "Microsoft.Network/virtualNetworks/subnets", "vnet/app"},
	} {
		r, err := ParseID(c.id)
		if err != nil {
			t.Fatal(err)
		}
		if r.Type != c.typ || r.Name != c.name || r.ResourceGroup != "rg" {
			t.Errorf("%s parsed as %+v", c.id, r)
		}
		if r.String() != c.id {
			t.Errorf("round trip %s -> %s", c.id, r.String())
		}
	}
	// Extension resources, at every scope: what the subscription's resource
	// list does not return.
	for _, c := range []struct{ id, rg, scope, typ, name, local string }{
		{"/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/r1", "", "", "Microsoft.Authorization/roleDefinitions", "r1",
			"providers/Microsoft.Authorization/roleDefinitions/r1"},
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Authorization/locks/no-delete", "rg", "", "Microsoft.Authorization/locks", "no-delete",
			"no-delete"},
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/roleAssignments/g1", "rg",
			"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct", "Microsoft.Authorization/roleAssignments", "g1",
			"providers/Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/roleAssignments/g1"},
	} {
		r, err := ParseID(c.id)
		if err != nil {
			t.Fatal(err)
		}
		if r.ResourceGroup != c.rg || r.Scope != c.scope || r.Type != c.typ || r.Name != c.name || r.String() != c.id {
			t.Errorf("%s parsed as %+v, rebuilt as %s", c.id, r, r.String())
		}
		if r.LocalName() != c.local {
			t.Errorf("%s local name %q, want %q", c.id, r.LocalName(), c.local)
		}
	}
	if _, err := ParseID("/providers/Microsoft.Management/managementGroups/mg/providers/Microsoft.Authorization/roleAssignments/g"); err == nil {
		t.Error("a management-group assignment is not in a subscription")
	}
}

type offers struct {
	*Fake
	v map[string][]string
}

func (o offers) APIVersions(context.Context, string) (map[string][]string, error) { return o.v, nil }

// The newest stable version both offered and defined wins; preview only if
// nothing stable matches; no match is an error, never a silent skip.
func TestVersionChoice(t *testing.T) {
	reg := fixtures(t)
	const vnet = "microsoft.network/virtualnetworks"
	pick := func(offered ...string) (string, error) {
		v := versions{api: offers{v: map[string][]string{vnet: offered}}, reg: reg, ctx: context.Background(), cache: map[string]map[string][]string{}}
		return v.pick("Microsoft.Network/virtualNetworks")
	}
	if got, _ := pick("2025-07-01", "2099-01-01"); got != "2025-07-01" {
		t.Errorf("want the newest version that has a definition, got %s", got)
	}
	if _, err := pick("2099-01-01"); !errors.Is(err, errNoVersion) {
		t.Errorf("no defined version must be an error, got %v", err)
	}
}

func TestRelevantSecrets(t *testing.T) {
	paths := []string{"properties.osProfile.adminPassword", "properties.extensionProfile.protectedSettings", "properties.items[].secret"}
	got := relevantSecrets(map[string]any{"properties": map[string]any{"osProfile": map[string]any{"adminUsername": "x"}}}, paths)
	if strings.Join(got, ",") != "properties.osProfile.adminPassword" {
		t.Errorf("got %v", got)
	}
}
