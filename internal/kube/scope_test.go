package kube

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
	"sigs.k8s.io/yaml"
)

// released is an object a Helm release made.
func released(apiVersion, kind, ns, name, release string, rest map[string]any) snapshot.Object {
	o := planObject(apiVersion, kind, ns, name, rest)
	md := o.Body["metadata"].(map[string]any)
	md["annotations"] = map[string]any{"meta.helm.sh/release-name": release, "meta.helm.sh/release-namespace": ns}
	labels, _ := md["labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
		md["labels"] = labels
	}
	labels["app.kubernetes.io/managed-by"] = "Helm"
	return o
}

func scopeSnapshot() snapshot.Snapshot {
	item := func(ns, name, release string) snapshot.Object {
		return released("onepassword.com/v1", "OnePasswordItem", ns, name, release, map[string]any{"spec": map[string]any{"itemPath": "vaults/apps/items/" + name}})
	}
	return snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Namespace", "", "core", nil),
		planObject("v1", "Namespace", "", "team-a", nil),
		planObject("v1", "Namespace", "", "team-b", nil),
		planObject("v1", "Namespace", "", "team-c", nil),
		planObject("v1", "Namespace", "", "platform", nil),
		// core: not narrowed.
		released("apps/v1", "Deployment", "core", "api", "api", nil),
		released("batch/v1", "Job", "core", "migrate", "migrate", nil),
		// team-a: two releases, and what belongs to none.
		released("apps/v1", "Deployment", "team-a", "a-search", "a-search", nil),
		released("keda.sh/v1alpha1", "ScaledObject", "team-a", "a-search", "a-search", nil),
		item("team-a", "a-search-cfg", "a-search"),
		planObject("v1", "Secret", "team-a", "a-search-cfg", map[string]any{"data": map[string]any{"k": ""}}), // made by the item
		released("apps/v1", "Deployment", "team-a", "a-lien", "a-lien", nil),
		item("team-a", "a-lien-cfg", "a-lien"),
		planObject("v1", "Secret", "team-a", "a-lien-cfg", map[string]any{"data": map[string]any{"k": ""}}),
		planObject("v1", "ConfigMap", "team-a", "shared", nil),
		planObject("v1", "Secret", "team-a", "by-hand", map[string]any{"data": map[string]any{"k": ""}}),
		// What a release made outside its namespace goes with it.
		func() snapshot.Object {
			o := planObject("rbac.authorization.k8s.io/v1", "ClusterRole", "", "a-lien", nil)
			o.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "a-lien", "meta.helm.sh/release-namespace": "team-a"}
			return o
		}(),
		// team-b: by label, and a release the label picks one object of.
		released("apps/v1", "Deployment", "team-b", "b-search", "b-search", map[string]any{"labels": map[string]any{"tier": "drill", "app.kubernetes.io/managed-by": "Helm"}}),
		released("v1", "Service", "team-b", "b-search", "b-search", nil),
		released("apps/v1", "Deployment", "team-b", "b-lien", "b-lien", nil),
		// team-c: fits the pattern, nothing chosen from it.
		released("apps/v1", "Deployment", "team-c", "c-search", "c-search", nil),
		planObject("v1", "ConfigMap", "team-c", "shared", nil),
		planObject("apps/v1", "Deployment", "platform", "ingress", nil),
	}}
}

func keys(s snapshot.Snapshot) []string {
	var out []string
	for _, o := range s.Objects {
		out = append(out, o.Kind()+" "+o.Namespace()+"/"+o.Name())
	}
	sort.Strings(out)
	return out
}

// A scope narrows the namespaces it names and nothing else: a release
// chosen comes whole with the Secrets its objects make, what belongs to
// no release comes with its namespace, a namespace nothing is chosen from
// is left out whole, and a Job is left out because it would run again.
func TestNarrow(t *testing.T) {
	s := scopeSnapshot()
	before := keys(s)
	sc := Scope{Narrow: []ScopeEntry{
		{Namespaces: []string{"team-*"}, Releases: []string{"a-search"}},
		{Namespaces: []string{"team-b"}, Labels: map[string]string{"tier": "drill"}},
	}}
	out, rep, err := Narrow(s, sc)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, keys(s)) {
		t.Error("the snapshot given was changed")
	}
	want := []string{
		"ConfigMap team-a/shared",
		"Deployment core/api",
		"Deployment platform/ingress",
		"Deployment team-a/a-search",
		"Deployment team-b/b-search",
		"Namespace /core", "Namespace /platform", "Namespace /team-a", "Namespace /team-b",
		"OnePasswordItem team-a/a-search-cfg",
		"ScaledObject team-a/a-search",
		"Secret team-a/a-search-cfg",
		"Secret team-a/by-hand",
		"Service team-b/b-search", // the rest of a release a label chose one object of
	}
	sort.Strings(want)
	if got := keys(out); !reflect.DeepEqual(got, want) {
		t.Errorf("brought:\n got %q\nwant %q", got, want)
	}
	if !reflect.DeepEqual(rep.Narrowed, []string{"team-a", "team-b", "team-c"}) {
		t.Errorf("narrowed %q", rep.Narrowed)
	}
	names := func(l []ScopedRelease) string {
		var out []string
		for _, r := range l {
			out = append(out, r.Release)
		}
		return strings.Join(out, " ")
	}
	if names(rep.Brought) != "team-a/a-search team-b/b-search" || names(rep.LeftOut) != "team-a/a-lien team-b/b-lien team-c/c-search" {
		t.Errorf("brought %q, left out %q", names(rep.Brought), names(rep.LeftOut))
	}
	if !reflect.DeepEqual(rep.Jobs, []string{"core/migrate"}) {
		t.Errorf("jobs left out: %q", rep.Jobs)
	}
	if rep.Kept != 10 || rep.Of != 18 {
		t.Errorf("kept %d of %d in the narrowed namespaces", rep.Kept, rep.Of)
	}

	// Asked for, the Jobs come.
	sc.Jobs = true
	out, rep, err = Narrow(s, sc)
	if err != nil || len(rep.Jobs) != 0 || !strings.Contains(strings.Join(keys(out), ","), "Job core/migrate") {
		t.Errorf("jobs: true: %v, %q", err, rep.Jobs)
	}
}

// What names nothing is refused: mistyped, it would leave out what it was
// written to bring.
func TestNarrowRefusesWhatNamesNothing(t *testing.T) {
	for want, sc := range map[string]Scope{
		"narrows nothing":                             {},
		"entry 1 names no namespaces":                 {Narrow: []ScopeEntry{{Releases: []string{"x"}}}},
		`no namespace in the snapshot fits "team-x*"`: {Narrow: []ScopeEntry{{Namespaces: []string{"team-a", "team-x*"}, Releases: []string{"a-search"}}}},
		`no release named "a-serch" in team-*`:        {Narrow: []ScopeEntry{{Namespaces: []string{"team-*"}, Releases: []string{"a-search", "a-serch"}}}},
		"nothing in team-a carries its labels":        {Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Labels: map[string]string{"tier": "none"}}}},
		`"[" is not a name or a pattern`:              {Narrow: []ScopeEntry{{Namespaces: []string{"["}}}},
	} {
		if _, _, err := Narrow(scopeSnapshot(), sc); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("got %v, want %q", err, want)
		}
	}
	// An entry with no releases and no labels brings nothing of its
	// namespaces, and says so by leaving them out: it is not an error.
	out, rep, err := Narrow(scopeSnapshot(), Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-c"}}}})
	if err != nil || strings.Contains(strings.Join(keys(out), ","), "team-c") || rep.Kept != 0 || rep.Of != 3 {
		t.Errorf("a namespace left out whole: %v, kept %d of %d, %q", err, rep.Kept, rep.Of, keys(out))
	}
}

// The draft brings everything, and reads back as the scope it shows.
func TestScopeDraft(t *testing.T) {
	s := scopeSnapshot()
	s.Objects = append(s.Objects, released("v1", "ConfigMap", "team-a", "odd", "odd\"\n- injected", nil))
	text := ScopeDraft(s)
	var sc Scope
	if err := yaml.UnmarshalStrict(text, &sc); err != nil {
		t.Fatalf("the draft is not a scope file: %v\n%s", err, text)
	}
	if len(sc.Narrow) != 4 || !strings.Contains(string(text), `- "a-search" # Deployment, OnePasswordItem, ScaledObject`) {
		t.Errorf("draft:\n%s", text)
	}
	for _, e := range sc.Narrow {
		for _, r := range e.Releases {
			if r == "injected" {
				t.Errorf("a release's name wrote a line of its own:\n%s", text)
			}
		}
	}
	sc.Jobs = true
	out, rep, err := Narrow(s, sc)
	if err != nil || len(out.Objects) != len(s.Objects) || len(rep.LeftOut) != 0 {
		t.Errorf("the draft does not bring everything: %v, %d of %d objects, left out %v", err, len(out.Objects), len(s.Objects), rep.LeftOut)
	}
	if empty := string(ScopeDraft(snapshot.Snapshot{})); !strings.Contains(empty, "narrow by labels instead") {
		t.Errorf("draft of a snapshot with no release:\n%s", empty)
	}
}

// A release is known by what Helm writes on what it makes: the
// annotations, or on an older chart the labels alone. Nothing else is one.
func TestReleaseOf(t *testing.T) {
	byLabel := planObject("apps/v1", "Deployment", "shop", "web", map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": "web"}})
	if ns, name, ok := ReleaseOf(byLabel); !ok || ns != "shop" || name != "web" {
		t.Errorf("by labels: %s/%s %v", ns, name, ok)
	}
	elsewhere := released("rbac.authorization.k8s.io/v1", "ClusterRole", "", "web", "web", nil)
	elsewhere.Body["metadata"].(map[string]any)["annotations"].(map[string]any)["meta.helm.sh/release-namespace"] = "shop"
	if ns, name, ok := ReleaseOf(elsewhere); !ok || ns != "shop" || name != "web" {
		t.Errorf("made outside its namespace: %s/%s %v", ns, name, ok)
	}
	for _, o := range []snapshot.Object{
		planObject("apps/v1", "Deployment", "shop", "plain", nil),
		planObject("apps/v1", "Deployment", "shop", "other", map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "kustomize", "app.kubernetes.io/instance": "web"}}),
	} {
		if _, name, ok := ReleaseOf(o); ok {
			t.Errorf("%s is no release's, and reads as %s's", o.Name(), name)
		}
	}
}
