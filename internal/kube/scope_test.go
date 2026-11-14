package kube

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
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
		"Deployment core/api",
		"Deployment platform/ingress",
		"Deployment team-a/a-search",
		"Deployment team-b/b-search",
		"Namespace /core", "Namespace /platform", "Namespace /team-a", "Namespace /team-b",
		"OnePasswordItem team-a/a-search-cfg",
		"ScaledObject team-a/a-search",
		"Secret team-a/a-search-cfg",
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
	if rep.Kept != 8 || rep.Of != 18 {
		t.Errorf("kept %d of %d in the narrowed namespaces", rep.Kept, rep.Of)
	}
	// What no release made is left out unless it is named, and said: not
	// the Secret an object makes, which went as its maker did.
	if want := []string{"ConfigMap team-a/shared", "ConfigMap team-c/shared", "Secret team-a/by-hand"}; !reflect.DeepEqual(rep.ObjectsLeftOut, want) || len(rep.ObjectsBrought) != 0 {
		t.Errorf("objects of no release: left out %q, brought %q", rep.ObjectsLeftOut, rep.ObjectsBrought)
	}
	named := sc
	named.Narrow = append(append([]ScopeEntry{}, sc.Narrow...), ScopeEntry{Namespaces: []string{"team-a"}, Objects: []string{"ConfigMap/shared", "Secret/*"}})
	out, rep, err = Narrow(s, named)
	if err != nil {
		t.Fatal(err)
	}
	withNamed := append(append([]string{}, want...), "ConfigMap team-a/shared", "Secret team-a/by-hand")
	sort.Strings(withNamed)
	if got := keys(out); !reflect.DeepEqual(got, withNamed) {
		t.Errorf("with objects named:\n got %q\nwant %q", got, withNamed)
	}
	// "Secret/*" fits the Secret of the release left out, and does not
	// part it from its maker.
	if want := []string{"ConfigMap team-a/shared", "Secret team-a/by-hand"}; !reflect.DeepEqual(rep.ObjectsBrought, want) {
		t.Errorf("objects brought: %q", rep.ObjectsBrought)
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
	// It says how a hold that is not whole is answered.
	if d := string(ScopeDraft(s)); !strings.Contains(d, `listed under "asTheyAre"`) {
		t.Errorf("the draft does not mention asTheyAre:\n%s", d)
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

// A release chosen keeps its namespace though all it made is elsewhere;
// what belongs to no release there comes only if it is named.
func TestNarrowKeepsTheNamespaceOfAReleaseMadeElsewhere(t *testing.T) {
	binding := planObject("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "a", nil)
	binding.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "a", "meta.helm.sh/release-namespace": "team-a"}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Namespace", "", "team-a", nil),
		planObject("v1", "ServiceAccount", "team-a", "runner", nil),
		binding,
	}}
	out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Releases: []string{"a"}, Objects: []string{"ServiceAccount/runner"}}}})
	if err != nil || len(out.Objects) != 3 {
		t.Errorf("%v: %q", err, keys(out))
	}
	out, _, err = Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Releases: []string{"a"}}}})
	if err != nil || strings.Join(keys(out), ", ") != "ClusterRoleBinding /a, Namespace /team-a" {
		t.Errorf("with nothing named: %v: %q", err, keys(out))
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
	out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Releases: []string{"search"}, Objects: []string{"Secret/*"}}}})
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

// The reviewer's case: a scope that names one release of a namespace
// brings nothing else that runs there, whatever kind it is, and says what
// it left.
func TestNarrowLeavesOutWhatNoReleaseMade(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Namespace", "", "shop", nil),
		planObject("v1", "Namespace", "", "other", nil),
		released("apps/v1", "Deployment", "shop", "web", "web", nil),
		released("apps/v1", "Deployment", "shop", "payments", "payments", nil),
		planObject("apps/v1", "Deployment", "shop", "queue-consumer", nil),
		planObject("batch/v1", "CronJob", "shop", "nightly-billing", nil),
		planObject("v1", "Pod", "shop", "one-off", nil),
		planObject("keda.sh/v1alpha1", "ScaledJob", "shop", "drain", nil),
		planObject("argoproj.io/v1alpha1", "Application", "shop", "payments", nil),
		planObject("example.com/v1", "Application", "shop", "payments", nil),
		// A release of another namespace put this here: it does not bring
		// the namespace's own things with it.
		func() snapshot.Object {
			o := planObject("v1", "ConfigMap", "other", "from-web", nil)
			o.Body["metadata"].(map[string]any)["annotations"] = map[string]any{"meta.helm.sh/release-name": "web", "meta.helm.sh/release-namespace": "shop"}
			return o
		}(),
		planObject("apps/v1", "Deployment", "other", "bare", nil),
	}}
	entry := ScopeEntry{Namespaces: []string{"shop", "other"}, Releases: []string{"web"}}
	out, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys(out), ", "); got != "ConfigMap other/from-web, Deployment shop/web, Namespace /other, Namespace /shop" {
		t.Errorf("brought: %s", got)
	}
	want := []string{"Application shop/payments", "Application shop/payments", "CronJob shop/nightly-billing", "Deployment other/bare", "Deployment shop/queue-consumer", "Pod shop/one-off", "ScaledJob shop/drain"}
	if !reflect.DeepEqual(rep.ObjectsLeftOut, want) {
		t.Errorf("left out, and said:\n got %q\nwant %q", rep.ObjectsLeftOut, want)
	}
	// Named, by kind, by group and by pattern.
	entry.Objects = []string{"CronJob/nightly-*", "Application.argoproj.io/payments", "*/bare"}
	out, rep, err = Narrow(s, Scope{Narrow: []ScopeEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Application shop/payments", "CronJob shop/nightly-billing", "Deployment other/bare"}; !reflect.DeepEqual(rep.ObjectsBrought, want) {
		t.Errorf("brought by name: %q", rep.ObjectsBrought)
	}
	for _, o := range out.Objects {
		if o.Kind() == "Application" && o.APIVersion() != "argoproj.io/v1alpha1" {
			t.Errorf("Kind.group brought the other API's %s", o.APIVersion())
		}
	}
	// One that fits nothing is refused, and so is one that is not
	// Kind/name; a release's own object is not one of these.
	for _, bad := range []string{"CronJob/nightly", "Deployment/web", "CronJob", "a/b/c", "/x", "[/x"} {
		entry.Objects = []string{bad}
		if _, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{entry}}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// An object with no namespace that names its release by label alone goes
// with the releases of that name.
func TestNarrowClusterObjectsOfAReleaseKnownByLabel(t *testing.T) {
	byLabel := func(apiVersion, kind, ns, name, release string) snapshot.Object {
		return planObject(apiVersion, kind, ns, name, map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": release}})
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		byLabel("apps/v1", "Deployment", "shop", "ledger", "ledger"),
		byLabel("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "ledger-admin", "ledger"),
		byLabel("apps/v1", "Deployment", "shop", "web", "web"),
		byLabel("rbac.authorization.k8s.io/v1", "ClusterRole", "", "web", "web"),
		// Of a release in no namespace the scope narrows: untouched.
		byLabel("apps/v1", "Deployment", "core", "api", "api"),
		byLabel("rbac.authorization.k8s.io/v1", "ClusterRole", "", "api", "api"),
		byLabel("rbac.authorization.k8s.io/v1", "ClusterRole", "", "nobody", "nobody"),
	}}
	out, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"web"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys(out), ", "); got != "ClusterRole /api, ClusterRole /nobody, ClusterRole /web, Deployment core/api, Deployment shop/web" {
		t.Errorf("brought: %s", got)
	}
	// A name two namespaces have a release of: brought while either is.
	s.Objects = append(s.Objects, byLabel("apps/v1", "Deployment", "core", "ledger", "ledger"))
	out, _, _ = Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"web"}}}})
	if !strings.Contains(strings.Join(keys(out), ", "), "ClusterRoleBinding /ledger-admin") {
		t.Errorf("left out, though a release of the name is brought: %q", keys(out))
	}
}

// skipOf is a thing a capture left to a source, with its resource written
// as a capture writes it.
func skipOf(group, version, resource, ns, name, reason string) snapshot.Skip {
	return snapshot.Skip{Resource: resourceID(schema.GroupVersionResource{Group: group, Version: version, Resource: resource}), Namespace: ns, Name: name, Reason: reason}
}

// A source that is brought goes on making what the capture left to it in
// a namespace the scope narrows: the plan of the part still says so, and
// the report names the source. What only a source that is not in the
// snapshot makes in a namespace left out whole is dropped from the plan.
func TestNarrowSaysWhatASourceBroughtStillMakes(t *testing.T) {
	const byRoot = "applied by Flux Kustomization flux-system/root; restore that"
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-system", "root", nil),
		planObject("argoproj.io/v1alpha1", "Application", "argocd", "root", nil),
		released("apps/v1", "Deployment", "team-a", "web", "web", nil),
		released("apps/v1", "Deployment", "team-c", "other", "other", nil),
	}, Skips: []snapshot.Skip{
		// root applies a HelmRelease, which renders a Deployment.
		skipOf("helm.toolkit.fluxcd.io", "v2", "helmreleases", "team-c", "payments", byRoot),
		skipOf("apps", "v1", "deployments", "team-c", "payments", "rendered by Flux HelmRelease team-c/payments; restore that"),
		// root applies a Kustomization, which applies two things.
		skipOf("kustomize.toolkit.fluxcd.io", "v1", "kustomizations", "flux-system", "apps", byRoot),
		skipOf("apps", "v1", "deployments", "team-c", "billing", "applied by Flux Kustomization flux-system/apps; restore that"),
		skipOf("batch", "v1", "cronjobs", "team-c", "nightly", "applied by Flux Kustomization flux-system/apps; restore that"),
		// An Argo application applies another, which makes a Deployment.
		skipOf("argoproj.io", "v1alpha1", "applications", "argocd", "child", "managed by Argo CD application root; restore that"),
		skipOf("apps", "v1", "deployments", "team-c", "from-argo", "managed by Argo CD application child; restore that"),
		// Sources nothing in the snapshot applies.
		skipOf("apps", "v1", "deployments", "team-c", "byhand", "rendered by Flux HelmRelease team-c/installed-by-hand; restore that"),
		skipOf("apps", "v1", "deployments", "team-a", "kept", "rendered by Flux HelmRelease team-a/installed-by-hand; restore that"),
		// In a namespace that is narrowed and brought: noted too.
		skipOf("helm.toolkit.fluxcd.io", "v2", "helmreleases", "team-a", "payments", byRoot),
	}}
	sc := Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-*"}, Releases: []string{"web"}}}}
	out, rep, err := Narrow(s, sc)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sk := range out.Skips {
		names = append(names, sk.Namespace+"/"+sk.Name)
	}
	if got := strings.Join(names, ", "); got != "team-c/payments, team-c/payments, flux-system/apps, team-c/billing, team-c/nightly, argocd/child, team-c/from-argo, team-a/kept, team-a/payments" {
		t.Errorf("what the plan of the part is told a source makes: %s", got)
	}
	want := []ScopeMade{
		{Source: "Argo CD application root", Namespace: "team-c", Objects: 1},
		{Source: "Flux Kustomization flux-system/root", Namespace: "team-a", Objects: 1},
		{Source: "Flux Kustomization flux-system/root", Namespace: "team-c", Objects: 4},
	}
	if !reflect.DeepEqual(rep.StillMade, want) {
		t.Errorf("still made:\n got %+v\nwant %+v", rep.StillMade, want)
	}
	// The plan of the part differs from the whole's only by the source
	// nothing applies in the namespace left out.
	before, after := RebuildPlan(s), RebuildPlan(out)
	if !reflect.DeepEqual(before.Follows, after.Follows) {
		t.Errorf("the plan of the part hides what a source brought applies:\n whole %+v\n part  %+v", before.Follows, after.Follows)
	}
	if len(before.Follows) != 5 || len(before.Sources) != 2 || len(after.Sources) != 1 || after.Sources[0].Name != "team-a/installed-by-hand" {
		t.Errorf("install first: whole %+v, part %+v; follows %+v", before.Sources, after.Sources, before.Follows)
	}
	// With the sources left out, nothing makes it.
	left, err := LeaveOut(s, []string{"Kustomization/flux-system/root", "Application/argocd/root"})
	if err != nil {
		t.Fatal(err)
	}
	if _, rep, _ := Narrow(left, sc); len(rep.StillMade) != 0 {
		t.Errorf("still made with the sources left out: %+v", rep.StillMade)
	}
}

// An object with no namespace kept because a release of its name is
// brought, while another of that name is left out, is named.
func TestNarrowNamesWhatASharedNameBrings(t *testing.T) {
	byLabel := func(apiVersion, kind, ns, name string) snapshot.Object {
		return planObject(apiVersion, kind, ns, name, map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": "redis"}})
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		byLabel("apps/v1", "Deployment", "team-a", "redis"),
		byLabel("apps/v1", "Deployment", "team-b", "redis"),
		byLabel("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "", "team-b-redis-admin"),
	}}
	_, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-a"}, Releases: []string{"redis"}}, {Namespaces: []string{"team-b"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ClusterRoleBinding team-b-redis-admin (it may be of team-b/redis, left out)"}; !reflect.DeepEqual(rep.SharedName, want) {
		t.Errorf("got %q", rep.SharedName)
	}
	// With both brought there is nothing to say.
	if _, rep, _ := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"team-*"}, Releases: []string{"redis"}}}}); len(rep.SharedName) != 0 {
		t.Errorf("both brought: %q", rep.SharedName)
	}
}

// A Secret an object makes is not named by itself: an entry that fits
// only such a Secret is refused, and does not pass as if it had brought
// it.
func TestNarrowRefusesToNameASecretAnObjectMakes(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		released("apps/v1", "Deployment", "shop", "web", "web", nil),
		released("external-secrets.io/v1", "ExternalSecret", "shop", "gone-db", "gone", nil),
		planObject("v1", "Secret", "shop", "gone-db", map[string]any{"data": map[string]any{"k": ""}}),
	}}
	_, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"web"}, Objects: []string{"Secret/gone-db"}}}})
	if err == nil || !strings.Contains(err.Error(), "goes with that object") {
		t.Errorf("got %v", err)
	}
}

// The small rules a scope rests on, each of which a reviewer found could
// be taken out with no test noticing.
func TestNarrowSmallRules(t *testing.T) {
	// A release annotation with no namespace beside it means the
	// object's own; an instance label that is empty names no release.
	o := planObject("v1", "ConfigMap", "shop", "c", map[string]any{"annotations": map[string]any{"meta.helm.sh/release-name": "web"}})
	if ns, name, ok := ReleaseOf(o); !ok || ns != "shop" || name != "web" {
		t.Errorf("a release with no namespace written: %q %q %v", ns, name, ok)
	}
	o = planObject("v1", "ConfigMap", "shop", "c", map[string]any{"labels": map[string]any{"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": ""}})
	if _, _, ok := ReleaseOf(o); ok {
		t.Error("an empty instance label was read as a release")
	}

	labels := func(v string) map[string]any { return map[string]any{"labels": map[string]any{"tier": v}} }
	secret := func(name string) snapshot.Object {
		return planObject("v1", "Secret", "shop", name, map[string]any{"data": map[string]any{"k": ""}})
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		released("apps/v1", "Deployment", "shop", "web", "web", nil),
		// A label's value counts, and a labelled object of no release is
		// brought by it.
		planObject("v1", "ConfigMap", "shop", "drill", labels("drill")),
		planObject("v1", "ConfigMap", "shop", "prod", labels("prod")),
		// A Secret goes with the maker that is brought; a ConfigMap of
		// the same name is not a Secret, and does not.
		released("external-secrets.io/v1", "ExternalSecret", "shop", "db", "web", nil),
		secret("db"),
		planObject("v1", "ConfigMap", "shop", "db", nil),
		released("external-secrets.io/v1", "ExternalSecret", "shop", "old", "gone", nil),
		secret("old"),
	}, Skips: []snapshot.Skip{
		// In a namespace that is brought, what a source makes stays in
		// the plan whoever the source is.
		{Resource: "deployments", Namespace: "shop", Name: "made", Reason: "rendered by Flux HelmRelease shop/by-hand; restore that"},
	}}
	out, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"web"}, Labels: map[string]string{"tier": "drill"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(keys(out), ", "); got != "ConfigMap shop/drill, Deployment shop/web, ExternalSecret shop/db, Secret shop/db" {
		t.Errorf("brought: %s", got)
	}
	if len(out.Skips) != 1 {
		t.Errorf("what a source makes in a namespace brought was dropped from the plan: %v", out.Skips)
	}
	if want := []string{"ConfigMap shop/db", "ConfigMap shop/prod"}; !reflect.DeepEqual(rep.ObjectsLeftOut, want) {
		t.Errorf("left out: %q", rep.ObjectsLeftOut)
	}
	// Jobs alone may be asked for with nothing narrowed; nothing at all
	// may not.
	if _, _, err := Narrow(s, Scope{Jobs: true}); err != nil {
		t.Errorf("jobs: true alone: %v", err)
	}
	if _, _, err := Narrow(s, Scope{}); err == nil {
		t.Error("a scope that says nothing was accepted")
	}
	if _, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{""}}}}); err == nil {
		t.Error("an empty release name was accepted")
	}
	// The draft lists what no release made, and not the Secret an object
	// makes or a release with no namespace.
	draft := string(ScopeDraft(s))
	for _, want := range []string{`- "ConfigMap/db"`, `- "ConfigMap/drill"`} {
		if !strings.Contains(draft, want) {
			t.Errorf("the draft does not list %s:\n%s", want, draft)
		}
	}
	if strings.Contains(draft, `"Secret/db"`) || strings.Contains(draft, `"Secret/old"`) {
		t.Errorf("the draft lists a Secret an object makes:\n%s", draft)
	}
}
