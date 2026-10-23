package saas

import (
	"context"
	"strings"
	"testing"
)

// Failures from the review of #11 to #13, 2026-10-22.

// A token that sees two Cloudflare accounts captures only the one asked
// for: /zones without account.id lists both.
func TestCloudflareCapturesOnlyItsAccount(t *testing.T) {
	s := spec(t, "cloudflare.json")
	f := newFake(t, Cloudflare, s, "acct-a")
	cloudflare(f)
	f.seed(t, "/zones", map[string]any{"name": "mine.example", "account": map[string]any{"id": "acct-a"}})
	other := f.seed(t, "/zones", map[string]any{"name": "theirs.example", "account": map[string]any{"id": "acct-a"}})
	f.mu.Lock()
	for _, it := range f.colls["/zones"] {
		if it["id"] == other["id"] {
			it["account"] = map[string]any{"id": "acct-b", "name": "someone else"}
		}
	}
	f.mu.Unlock()
	snap, err := (&Adapter{Client: f.client(true)}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range snap.Objects {
		if strings.Contains(o.Name(), "theirs.example") || strings.Contains(canon(o.Body), "acct-b") {
			t.Errorf("another account's zone was captured: %s", o.Key())
		}
	}
}

// A failure stays a failure: a later parent's plan refusal must not turn
// "list failed" into "not available on this plan".
func TestFailureIsNotOverwrittenByAMilderAnswer(t *testing.T) {
	s := spec(t, "github.json")
	f := newFake(t, GitHub, s, "acme")
	gitHub(f)
	f.seed(t, "/orgs/acme/repos", map[string]any{"name": "a"})
	f.seed(t, "/orgs/acme/repos", map[string]any{"name": "b"})
	f.seed(t, "/repos/acme/a/rulesets", map[string]any{"name": "r", "target": "branch", "enforcement": "active"})
	f.mu.Lock()
	var rid string
	for _, it := range f.colls["/repos/acme/a/rulesets"] {
		rid = stringOf(it["id"])
	}
	f.refuse = map[string]string{"/repos/acme/a/rulesets/" + rid: "Server Error", "/repos/acme/b/rulesets": "Upgrade to GitHub Pro"}
	f.mu.Unlock()
	snap, err := (&Adapter{Client: f.client(true)}).Capture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range snap.Coverage {
		if c.Resource == "github/ruleset" && !strings.HasPrefix(c.NotCaptured, "list failed") {
			t.Errorf("ruleset coverage %q: a failed read must stay a failure", c.NotCaptured)
		}
	}
}

// Derived from the full description: each shape the review found broken.
func TestDerivedShapes(t *testing.T) {
	s := spec(t, "github.json")
	by := map[string]Collection{}
	for _, c := range Derive(s, GitHubDerive, GitHub.Collections) {
		by[c.Kind] = c
	}
	if c := by["github/org/properties/schema"]; c.Bind["custom_property_name"] != "item:property_name" {
		t.Errorf("custom property binds %v", c.Bind)
	}
	if c := by["github/org/hooks"]; len(c.Name) != 1 || c.Name[0] != "config.url" {
		t.Errorf("organisation webhooks named by %v, want config.url", c.Name)
	}
	if c := by["github/org/teams"]; c.Bind["team_slug"] != "item:slug" {
		t.Errorf("teams bind %v", c.Bind)
	}
	for _, k := range []string{"github/org/blocks", "github/org/actions/hosted-runners", "github/org/settings/network-configurations"} {
		if _, ok := by[k]; ok {
			t.Errorf("%s must not be derived", k)
		}
	}
}

// A value is one path segment: a label "area/api" is not two.
func TestPathValuesAreEscaped(t *testing.T) {
	p, ok := expand("/repos/{owner}/{repo}/labels/{name}", map[string]string{"owner": "account", "repo": "parent:name", "name": "item:name"},
		"acme", map[string]any{"name": "shop"}, map[string]any{"name": "area/api"})
	if !ok || p != "/repos/acme/shop/labels/area%2Fapi" {
		t.Errorf("got %q", p)
	}
}
