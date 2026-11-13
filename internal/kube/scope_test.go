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

// A Job is left out though its release is brought, and the report says
// so; a release that is only a Job is still one the scope may name.
func TestNarrowLeavesOutAJobOfAReleaseBrought(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Namespace", "", "team-a", nil),
		released("apps/v1", "Deployment", "team-a", "a", "a", nil),
		released("batch/v1", "Job", "team-a", "a-hook", "a", nil),
		released("batch/v1", "Job", "team-a", "migrate", "migrate", nil),
		released("example.com/v1", "Job", "team-a", "not-a-batch-job", "a", nil),
	}}
	sc := Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Releases: []string{"a", "migrate"}}}}
	out, rep, err := Narrow(s, sc)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys(out), ", "); got != "Deployment team-a/a, Job team-a/not-a-batch-job, Namespace /team-a" {
		t.Errorf("brought: %s", got)
	}
	if !reflect.DeepEqual(rep.Jobs, []string{"team-a/a-hook", "team-a/migrate"}) || rep.Kept != 3 || rep.Of != 5 {
		t.Errorf("jobs %q, kept %d of %d", rep.Jobs, rep.Kept, rep.Of)
	}
	if len(rep.Brought) != 2 || rep.Brought[0].Objects != 3 || rep.Brought[1].Release != "team-a/migrate" || len(rep.LeftOut) != 0 {
		t.Errorf("brought %+v, left out %+v", rep.Brought, rep.LeftOut)
	}
	sc.Jobs = true
	if out, rep, err := Narrow(s, sc); err != nil || len(out.Objects) != 5 || len(rep.Jobs) != 0 {
		t.Errorf("jobs: true: %v, %d objects, %q", err, len(out.Objects), rep.Jobs)
	}
	// A label only a Job carries chooses its release, and is no mistake.
	hook := s.Objects[2].Body["metadata"].(map[string]any)["labels"].(map[string]any)
	hook["tier"] = "drill"
	if out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Labels: map[string]string{"tier": "drill"}}}}); err != nil || !strings.Contains(strings.Join(keys(out), ","), "Deployment team-a/a") {
		t.Errorf("a label on a Job: %v, %q", err, keys(out))
	}
}

// A namespace nothing is chosen from is left out whole: what a release of
// another namespace made in it too, and what the capture left there to a
// GitOps source.
func TestNarrowLeavesANamespaceOutWhole(t *testing.T) {
	foreign := released("v1", "ConfigMap", "team-c", "api-cfg", "api", nil)
	foreign.Body["metadata"].(map[string]any)["annotations"].(map[string]any)["meta.helm.sh/release-namespace"] = "core"
	item := released("onepassword.com/v1", "OnePasswordItem", "team-c", "api-item", "api", map[string]any{"spec": map[string]any{"itemPath": "vaults/x/items/y"}})
	item.Body["metadata"].(map[string]any)["annotations"].(map[string]any)["meta.helm.sh/release-namespace"] = "core"
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Namespace", "", "core", nil),
		planObject("v1", "Namespace", "", "team-c", nil),
		released("apps/v1", "Deployment", "core", "api", "api", nil),
		foreign, item,
		planObject("v1", "Secret", "team-c", "api-item", map[string]any{"data": map[string]any{"k": ""}}),
		planObject("v1", "ConfigMap", "team-c", "shared", nil),
	}, Skips: []snapshot.Skip{
		{Resource: "apps/v1/deployments", Namespace: "team-c", Name: "web", Reason: "rendered by Flux HelmRelease team-c/web; restoring the HelmRelease recreates it"},
		{Resource: "apps/v1/deployments", Namespace: "core", Name: "x", Reason: "rendered by Flux HelmRelease core/x; restoring the HelmRelease recreates it"},
	}}
	out, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-c"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys(out), ", "); got != "Deployment core/api, Namespace /core" {
		t.Errorf("brought: %s", got)
	}
	if rep.Kept != 0 || rep.Of != 5 {
		t.Errorf("kept %d of %d", rep.Kept, rep.Of)
	}
	if len(out.Skips) != 1 || out.Skips[0].Namespace != "core" || len(s.Skips) != 2 {
		t.Errorf("what was left to a GitOps source: %+v", out.Skips)
	}
}

// A release chosen keeps its namespace though all it made is elsewhere,
// and what belongs to no release there with it.
func TestNarrowKeepsTheNamespaceOfAReleaseMadeElsewhere(t *testing.T) {
	binding := planObject("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "a", nil)
	binding.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "a", "meta.helm.sh/release-namespace": "team-a"}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Namespace", "", "team-a", nil),
		planObject("v1", "ServiceAccount", "team-a", "runner", nil),
		binding,
	}}
	out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Releases: []string{"a"}}}})
	if err != nil || len(out.Objects) != 3 {
		t.Errorf("%v: %q", err, keys(out))
	}
	// A namespace known only by where a release was installed is one a
	// scope may name.
	s.Objects = []snapshot.Object{binding}
	if _, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}}}}); err != nil || len(rep.LeftOut) != 1 {
		t.Errorf("a namespace nothing of which is in the snapshot: %v, %+v", err, rep)
	}
}

// A Secret goes where its maker goes, whatever kind makes it.
func TestNarrowSecretsFollowEveryKindOfMaker(t *testing.T) {
	secret := func(name string) snapshot.Object {
		return planObject("v1", "Secret", "team-a", name, map[string]any{"data": map[string]any{"k": ""}})
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		released("apps/v1", "Deployment", "team-a", "search", "search", nil),
		released("external-secrets.io/v1", "ExternalSecret", "team-a", "es", "lien", map[string]any{"spec": map[string]any{"target": map[string]any{"name": "from-es"}}}),
		released("external-secrets.io/v1", "ExternalSecret", "team-a", "es-own-name", "lien", nil),
		released("bitnami.com/v1alpha1", "SealedSecret", "team-a", "sealed", "lien", nil),
		released("cert-manager.io/v1", "Certificate", "team-a", "cert", "lien", map[string]any{"spec": map[string]any{"secretName": "tls"}}),
		secret("from-es"), secret("es-own-name"), secret("sealed"), secret("tls"), secret("by-hand"),
	}}
	out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Releases: []string{"search"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys(out), ", "); got != "Deployment team-a/search, Secret team-a/by-hand" {
		t.Errorf("brought: %s", got)
	}
	if p := RebuildPlan(out); len(p.ByHand) != 1 || p.ByHand[0].Name != "by-hand" {
		t.Errorf("the plan of the part asks for what a release left out makes: %+v", p.ByHand)
	}
}

// A name given beside a pattern that also fits it is no mistake; every
// label of an entry is required; two entries on one namespace choose
// together.
func TestNarrowPatternsAndLabels(t *testing.T) {
	s := scopeSnapshot()
	for _, releases := range [][]string{{"*-search", "a-search"}, {"a-search", "*-search"}, {"a-*", "a-lien"}} {
		if _, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-*"}, Releases: releases}}}); err != nil {
			t.Errorf("%q: %v", releases, err)
		}
	}
	if _, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-b"}, Labels: map[string]string{"tier": "drill", "zone": "none"}}}}); err == nil || !strings.Contains(err.Error(), "carries its labels") {
		t.Errorf("two labels, one of which nothing carries: %v", err)
	}
	out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-b"}}, {Namespaces: []string{"team-*"}, Releases: []string{"b-lien"}}}})
	if err != nil || !strings.Contains(strings.Join(keys(out), ","), "Deployment team-b/b-lien") {
		t.Errorf("two entries on one namespace: %v, %q", err, keys(out))
	}
	if _, _, err := Narrow(s, Scope{}); err == nil {
		t.Error("a file with nothing in it narrowed")
	}
	if out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{}}); err != nil || strings.Contains(strings.Join(keys(out), ","), "Job ") || len(out.Objects) != len(s.Objects)-1 {
		t.Errorf("an empty list narrows nothing and leaves Jobs out: %v, %q", err, keys(out))
	}
}

// The draft reads back as a scope that brings everything but Jobs, for
// any snapshot: names that read as patterns, a release that is only a
// Job, one that made nothing in its own namespace, no release at all.
func TestScopeDraftRoundTrips(t *testing.T) {
	far := planObject("rbac.authorization.k8s.io/v1", "ClusterRole", "", "addon", nil)
	far.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "addon", "meta.helm.sh/release-namespace": "kube-system"}
	for name, s := range map[string]snapshot.Snapshot{
		"the usual": scopeSnapshot(),
		"odd names": {Objects: []snapshot.Object{
			released("v1", "ConfigMap", "team-a", "x", "a[b", nil), released("v1", "ConfigMap", "team-a", "y", "a*", nil),
			released("v1", "ConfigMap", "team-a", "z", "ab", nil), released("v1", "ConfigMap", "team-a", "w", "a\x01?\\b", nil),
		}},
		"only a job":        {Objects: []snapshot.Object{released("batch/v1", "Job", "team-a", "migrate", "migrate", nil), planObject("v1", "ConfigMap", "team-a", "shared", nil)}},
		"made elsewhere":    {Objects: []snapshot.Object{far, planObject("v1", "ConfigMap", "team-a", "shared", nil)}},
		"no release at all": {Objects: []snapshot.Object{planObject("v1", "ConfigMap", "team-a", "shared", nil)}},
		"nothing":           {},
	} {
		text := ScopeDraft(s)
		var sc Scope
		if err := yaml.UnmarshalStrict(text, &sc); err != nil {
			t.Errorf("%s: the draft is not a scope file: %v\n%s", name, err, text)
			continue
		}
		out, rep, err := Narrow(s, sc)
		if err != nil {
			t.Errorf("%s: the draft is refused: %v\n%s", name, err, text)
			continue
		}
		jobs := 0
		for _, o := range s.Objects {
			if isJob(o) {
				jobs++
			}
		}
		if len(out.Objects) != len(s.Objects)-jobs || len(rep.LeftOut) != 0 || len(rep.Jobs) != jobs {
			t.Errorf("%s: the draft brings %d of %d objects (%d Jobs), leaves out %v\n%s", name, len(out.Objects), len(s.Objects), jobs, rep.LeftOut, text)
		}
	}
}

// A Job alone, chosen by a label and left out, does not bring its
// namespace; and a namespace known only by its own object is one a scope
// may name.
func TestNarrowNamespaceWithOnlyAJobOrNothing(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Namespace", "", "team-a", nil),
		planObject("batch/v1", "Job", "team-a", "once", map[string]any{"labels": map[string]any{"tier": "drill"}}),
		planObject("v1", "ConfigMap", "team-a", "shared", nil),
		planObject("v1", "Namespace", "", "team-z", nil),
	}}
	out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Labels: map[string]string{"tier": "drill"}}, {Namespaces: []string{"team-z"}}}})
	if err != nil || len(out.Objects) != 0 {
		t.Errorf("%v: %q", err, keys(out))
	}
}
