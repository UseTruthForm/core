package azarm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// Review of #24, through real captures: a lock on a group and a lock of
// the same name on a storage account in it. One snapshot has the group's
// lock; the next has lost it, and its baseline holds the account's, which
// it leaves out. That skip names the account's lock by its path below the
// group, so the group's lock is missing with no note, in either order; the
// account's own skip names it. A snapshot from before (Azure rules 0)
// named the account's lock "rg/l1", the group's lock's name: from such a
// snapshot no skip is a note on any object.
func TestSkipNamesAnExtensionByItsPath(t *testing.T) {
	reg, src, dst := worlds(t)
	lock := map[string]any{"properties": map[string]any{"level": "CanNotDelete"}}
	seed := func(f *Fake, groupLock bool) {
		put(t, f, "", groupType, "rg", map[string]any{"location": "eastus"})
		sa := put(t, f, "rg", "Microsoft.Storage/storageAccounts", "sa01", map[string]any{
			"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"},
			"properties": map[string]any{"minimumTlsVersion": "TLS1_2"},
		})
		if groupLock {
			rawPut(t, f, id(f.sub, "rg", "Microsoft.Authorization/locks", "l1"), "Microsoft.Authorization/locks", lock)
		}
		rawPut(t, f, sa+"/providers/Microsoft.Authorization/locks/l1", "Microsoft.Authorization/locks", lock)
	}
	// a has both locks; b, another subscription made the same, has lost the
	// group's.
	seed(src, true)
	seed(dst, false)
	a := capture(t, src, reg)
	if a.Rules != snapshot.AzureCaptureRules {
		t.Fatalf("rules %d", a.Rules)
	}
	b, err := Capture(context.Background(), dst, reg, Policy{}.WithBaseline(a, "sha256:a"))
	if err != nil {
		t.Fatal(err)
	}
	saLock := "providers/Microsoft.Storage/storageAccounts/sa01/providers/Microsoft.Authorization/locks/l1"
	named := false
	for _, sk := range b.Skips {
		if strings.EqualFold(sk.Resource, "Microsoft.Authorization/locks") {
			named = named || sk.Name == "rg/"+saLock
			if sk.Name == "rg/l1" {
				t.Errorf("the account's lock named as the group's: %+v", sk)
			}
		}
		if strings.EqualFold(sk.Resource, groupType) && sk.Name != "rg/rg" {
			t.Errorf("the group named %q", sk.Name)
		}
	}
	if !named {
		t.Fatalf("no skip names the account's lock: %+v", b.Skips)
	}
	groupKey := APIVersion + "|Microsoft.Authorization/locks|rg|l1"
	check := func(what string, want, got snapshot.Snapshot, kind string) {
		t.Helper()
		w, g := ForCompare(want, got)
		found := false
		for _, c := range snapshot.Compare(w, g) {
			switch {
			case strings.EqualFold(c.Key, groupKey):
				found = true
				if c.Kind != kind || c.Skipped != nil {
					t.Errorf("%s: the group's lock: %+v", what, c)
				}
			case c.Kind == kind && c.Skipped == nil:
				// Everything else b left out is the baseline's, and says so.
				t.Errorf("%s: %s %s has no note", what, c.Kind, c.Key)
			}
		}
		if !found {
			t.Errorf("%s: the group's lock is not a difference", what)
		}
	}
	check("a then b", a, b, "missing")
	check("b then a", b, a, "extra")

	// As a build before Azure rules 1 wrote b: no rules, the old name.
	old := b
	old.Rules = 0
	old.Skips = nil
	for _, sk := range b.Skips {
		if sk.Name == "rg/"+saLock {
			sk.Name = "rg/l1"
		}
		old.Skips = append(old.Skips, sk)
	}
	for _, pair := range [][2]snapshot.Snapshot{{a, old}, {old, a}} {
		w, g := ForCompare(pair[0], pair[1])
		for _, c := range snapshot.Compare(w, g) {
			if c.Skipped != nil {
				t.Errorf("a note from a snapshot under Azure rules 0: %+v", c)
			}
		}
	}
}

// The graph draws what a manager makes from its skip: a group named "g/g",
// a resource "g/name", and an extension by its path below the group, which
// under Azure rules 0 was "g/<last name>" and so drew another resource's ID.
func TestGraphReadsSkipNames(t *testing.T) {
	p, _, err := LoadProjection("security", nil)
	if err != nil {
		t.Fatal(err)
	}
	by := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks, which recreates it"
	ext := "providers/Microsoft.Network/publicIPAddresses/ip1/providers/Microsoft.Authorization/roleAssignments/ra2"
	s := snapshot.Snapshot{Platform: "azure", Rules: snapshot.AzureCaptureRules, Skips: []snapshot.Skip{
		{Resource: groupType, Name: "MC_aks/MC_aks", Reason: reasonManagedBy + by},
		{Resource: "Microsoft.Network/publicIPAddresses", Name: "MC_aks/ip1", Reason: reasonManagedGroup + by},
		{Resource: "Microsoft.Authorization/roleAssignments", Name: "MC_aks/" + ext, Reason: reasonManagedGroup + by},
	}}
	g := BuildGraph(s, p, "security", "", "")
	have := map[string]GraphNode{}
	for _, n := range g.Nodes {
		have[n.ID] = n
	}
	group := "/subscriptions/" + tokSub + "/resourceGroups/MC_aks"
	for id, name := range map[string]string{
		group: "MC_aks",
		group + "/providers/Microsoft.Network/publicIPAddresses/ip1": "ip1",
		group + "/" + ext: "ra2",
	} {
		if n, ok := have[id]; !ok || n.Name != name || n.ManagedBy == "" {
			t.Errorf("%s: %+v (nodes %v)", id, n, g.Nodes)
		}
	}
	if _, ok := have[group+"/providers/Microsoft.Authorization/roleAssignments/ra2"]; ok {
		t.Error("the extension drawn as one on the group")
	}
	if managed := len(g.Nodes) - external(g); managed != 3 {
		t.Errorf("%d managed nodes: %v", managed, g.Nodes)
	}
}

// external counts the nodes a graph draws for what the snapshot does not
// hold (here, the manager the skips name).
func external(g Graph) int {
	n := 0
	for _, x := range g.Nodes {
		if x.External {
			n++
		}
	}
	return n
}

// A resource merely named "providers" is drawn as it always was: a subnet
// "default" of a network "providers", skipped as "g/providers/default".
func TestGraphReadsAResourceNamedProviders(t *testing.T) {
	p, _, err := LoadProjection("security", nil)
	if err != nil {
		t.Fatal(err)
	}
	by := "/subscriptions/" + tokSub + "/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks, which recreates it"
	subnets := "Microsoft.Network/virtualNetworks/subnets"
	s := snapshot.Snapshot{Platform: "azure", Rules: snapshot.AzureCaptureRules, Skips: []snapshot.Skip{
		{Resource: subnets, Name: "MC_aks/providers/default", Reason: reasonManagedGroup + by},
	}}
	want := ResourceID{Subscription: tokSub, ResourceGroup: "MC_aks", Type: subnets, Name: "providers/default"}.String()
	g := BuildGraph(s, p, "security", "", "")
	drawn := false
	for _, n := range g.Nodes {
		drawn = drawn || (n.ID == want && n.Name == "providers/default" && !n.External)
	}
	if !drawn || len(g.Nodes)-external(g) != 1 {
		t.Errorf("nodes %+v, want %s", g.Nodes, want)
	}
	// A name below the group that parses to another type, or to a resource
	// that is no extension, is not taken for a path: main drew neither, as
	// neither name fits its type, and nor does this.
	for _, sk := range []snapshot.Skip{
		{Resource: subnets, Name: "MC_aks/providers/Microsoft.Authorization/locks/x", Reason: reasonManagedGroup + by},
		{Resource: subnets, Name: "MC_aks/providers/Microsoft.Network/publicIPAddresses/ip9/providers/Microsoft.Authorization/locks/x", Reason: reasonManagedGroup + by},
		{Resource: "Microsoft.Network/publicIPAddresses", Name: "MC_aks/providers/Microsoft.Network/publicIPAddresses/ip9", Reason: reasonManagedGroup + by},
	} {
		g := BuildGraph(snapshot.Snapshot{Platform: "azure", Rules: snapshot.AzureCaptureRules, Skips: []snapshot.Skip{sk}}, p, "security", "", "")
		if n := len(g.Nodes) - external(g); n != 0 {
			t.Errorf("%s drawn: %+v", sk.Name, g.Nodes)
		}
	}
}

// getFails answers every GET but one, as ARM does to a caller denied one
// resource.
type getFails struct {
	*Fake
	id string
}

func (f getFails) Get(ctx context.Context, id, version string) (map[string]any, error) {
	if strings.EqualFold(id, f.id) {
		return nil, errors.New("AuthorizationFailed: " + id)
	}
	return f.Fake.Get(ctx, id, version)
}

// The sites that skip what the resource list returns name it as skipName
// does too: something managed, and something that could not be read. ARM's
// list returns no extension, so there the name is the same either way; a
// fake that lists one (AlsoTracked) keeps the two sites to skipName.
func TestListedSkipsNameAnExtensionByItsPath(t *testing.T) {
	reg, src, _ := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	sa := put(t, src, "rg", "Microsoft.Storage/storageAccounts", "sa01", map[string]any{
		"location": "eastus", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"},
		"properties": map[string]any{"minimumTlsVersion": "TLS1_2"},
	})
	lockID := sa + "/providers/Microsoft.Authorization/locks/l1"
	rawPut(t, src, lockID, "Microsoft.Authorization/locks", map[string]any{"properties": map[string]any{"level": "CanNotDelete"}})
	src.AlsoTracked = map[string]bool{"Microsoft.Authorization/locks": true}
	want := "rg/providers/Microsoft.Storage/storageAccounts/sa01/providers/Microsoft.Authorization/locks/l1"
	named := func(what string, s snapshot.Snapshot, reason string) {
		t.Helper()
		for _, sk := range s.Skips {
			if strings.EqualFold(sk.Resource, "Microsoft.Authorization/locks") && strings.HasPrefix(sk.Reason, reason) {
				if sk.Name != want {
					t.Errorf("%s: named %q, want %q", what, sk.Name, want)
				}
				return
			}
		}
		t.Errorf("%s: no skip of the lock: %+v", what, s.Skips)
	}

	src.ManagedBy[strings.ToLower(lockID)] = "/subscriptions/" + src.sub + "/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa01"
	named("managed", capture(t, src, reg), reasonManagedBy)
	delete(src.ManagedBy, strings.ToLower(lockID))

	s, err := Capture(context.Background(), getFails{src, lockID}, reg, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	named("unreadable", s, Unreadable)
}
