package azarm

import (
	"context"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// Azure returns a type, a group and a name in either case from one read to
// the next (a diagnostic setting's type has come back as
// microsoft.insights/diagnosticSettings). Each spelling is the same object.
func TestForCompareTakesAnotherCaseAsTheSameObject(t *testing.T) {
	obj := func(kind, rg, name string) snapshot.Object {
		return snapshot.Object{Body: map[string]any{"apiVersion": APIVersion, "kind": kind, "metadata": map[string]any{
			"namespace": rg, "name": name, "annotations": map[string]any{annID: "/subscriptions/" + tokSub + "/resourceGroups/" + rg + "/providers/" + kind[:len("Microsoft.Insights")] + "/x/" + name}}, "spec": map[string]any{"properties": map[string]any{"a": 1}}}}
	}
	want := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{obj("Microsoft.Insights/components", "Logs", "Usage")}}
	for _, got := range []snapshot.Object{
		obj("microsoft.insights/components", "Logs", "Usage"),
		obj("Microsoft.Insights/components", "LOGS", "Usage"),
		obj("Microsoft.Insights/components", "Logs", "usage"),
		obj("MICROSOFT.INSIGHTS/COMPONENTS", "logs", "USAGE"),
	} {
		w, g := ForCompare(want, snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{got}})
		if ch := snapshot.Compare(w, g); len(ch) != 0 {
			t.Errorf("%s: %v", got.Key(), ch)
		}
	}
	other := obj("Microsoft.Insights/components", "Logs", "Usage2")
	w, g := ForCompare(want, snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{other}})
	if ch := snapshot.Compare(w, g); len(ch) != 2 {
		t.Errorf("another object is not the same one: %v", ch)
	}
}

// A baseline holds what a fresh subscription has. Captured with the table in
// one case and read back in the other, the table was no longer taken as the
// baseline's and was captured: compare then said it was added.
func TestABaselineMatchesInAnotherCase(t *testing.T) {
	reg, src, _ := worlds(t)
	put(t, src, "", groupType, "rg", map[string]any{"location": "eastus"})
	w := put(t, src, "rg", "Microsoft.OperationalInsights/workspaces", "law", map[string]any{"location": "eastus"})
	table := func(name string) {
		src.SeedAzure(w+"/tables/"+name, stable(reg, tablesType), map[string]any{"properties": map[string]any{"plan": "Analytics"}})
	}
	table("ACSUsage")
	base := capture(t, src, reg)
	table("AcsUsage")
	s, err := Capture(context.Background(), src, reg, Policy{}.WithBaseline(base, "sha256:b"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range s.Objects {
		t.Errorf("captured although the baseline has it: %s", o.Key())
	}
}
