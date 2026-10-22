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
	if _, err := ParseID("/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/x"); err == nil {
		t.Error("a subscription-level ID is not a resource-group resource")
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
