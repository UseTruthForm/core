package translate

import (
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// nsWith is the fixture with settings added to its namespace.
func nsWith(extra map[string]any) snapshot.Snapshot {
	s := fixture()
	for _, o := range s.Objects {
		if o.Kind() == "Microsoft.ServiceBus/namespaces" {
			p := o.Body["spec"].(map[string]any)["properties"].(map[string]any)
			for k, v := range extra {
				p[k] = v
			}
		}
	}
	return s
}

// What Azure writes on every namespace says nothing: confidential compute
// disabled, and an empty list of errors. Read as a loss, each failed every
// translation of a real namespace.
func TestNamespaceSettingsAzureAlwaysWrites(t *testing.T) {
	const ns = "Microsoft.ServiceBus/namespaces rg/shop"
	for name, m := range maps() {
		base, err := translateFixture(t, fixture(), m)
		if err != nil {
			t.Fatal(err)
		}
		want := len(entry(t, base, ns).Losses)
		for what, extra := range map[string]map[string]any{
			"disabled":     {"platformCapabilities": map[string]any{"confidentialCompute": map[string]any{"mode": "Disabled"}}, "errors": []any{}},
			"no mode":      {"platformCapabilities": map[string]any{"confidentialCompute": map[string]any{}}},
			"empty":        {"platformCapabilities": map[string]any{}},
			"lower case":   {"platformCapabilities": map[string]any{"confidentialCompute": map[string]any{"mode": "disabled"}}},
			"errors alone": {"errors": []any{}},
			"one location": {"geoDataReplication": map[string]any{"maxReplicationLagDurationInSeconds": 0,
				"locations": []any{map[string]any{"locationName": "westeurope", "roleType": "Primary"}}}},
			"no location": {"geoDataReplication": map[string]any{"locations": []any{}}},
		} {
			r, err := translateFixture(t, nsWith(extra), m)
			if err != nil {
				t.Fatal(err)
			}
			e := entry(t, r, ns)
			if len(e.Losses) != want {
				t.Errorf("%s, %s: %d losses, want the %d it has without: %+v", name, what, len(e.Losses), want, e.Losses)
			}
		}
		// Enabled, the target is less protected, and says so.
		r, err := translateFixture(t, nsWith(map[string]any{"platformCapabilities": map[string]any{"confidentialCompute": map[string]any{"mode": "Enabled"}}}), m)
		if err != nil {
			t.Fatal(err)
		}
		if l := lossAbout(entry(t, r, ns), "confidentialCompute.mode"); l == nil || !l.Widens || !strings.Contains(l.Why, "Enabled") {
			t.Errorf("%s: confidential compute enabled: %+v", name, l)
		}
		// A second location is replication, which is named.
		r, err = translateFixture(t, nsWith(map[string]any{"geoDataReplication": map[string]any{"locations": []any{
			map[string]any{"locationName": "westeurope", "roleType": "Primary"}, map[string]any{"locationName": "northeurope", "roleType": "Secondary"}}}}), m)
		if err != nil {
			t.Fatal(err)
		}
		if l := lossAbout(entry(t, r, ns), "geoDataReplication"); l == nil || l.Widens {
			t.Errorf("%s: replication to a second region: %+v", name, l)
		}
		// What no rule reads is named as unread, not passed over: a
		// capability this does not know, a setting beside the mode, and
		// errors that are not empty.
		for field, extra := range map[string]map[string]any{
			"properties.platformCapabilities.other":                    {"platformCapabilities": map[string]any{"other": map[string]any{"mode": "Enabled"}}},
			"properties.platformCapabilities.confidentialCompute.more": {"platformCapabilities": map[string]any{"confidentialCompute": map[string]any{"mode": "Disabled", "more": true}}},
			"properties.errors": {"errors": []any{map[string]any{"code": "x"}}},
		} {
			r, err := translateFixture(t, nsWith(extra), m)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, l := range entry(t, r, ns).Losses {
				found = found || (l.Field == field && l.Unread)
			}
			if !found {
				t.Errorf("%s: %s is not named as unread: %+v", name, field, entry(t, r, ns).Losses)
			}
		}
	}
}
