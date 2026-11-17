package kube

import (
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// What runs nothing as it is needs no hold, and what a hold does to an
// ApplicationSet is to its template, where nothing else can undo it.
func TestStoppedAndTheHoldOfAnApplicationSet(t *testing.T) {
	app := func(policy map[string]any) snapshot.Object {
		spec := map[string]any{"project": "default"}
		if policy != nil {
			spec["syncPolicy"] = policy
		}
		return planObject("argoproj.io/v1alpha1", "Application", "argocd", "a", map[string]any{"spec": spec})
	}
	set := func(spec map[string]any) snapshot.Object {
		return planObject("argoproj.io/v1alpha1", "ApplicationSet", "argocd", "s", map[string]any{"spec": spec})
	}
	tmpl := map[string]any{"spec": map[string]any{"syncPolicy": map[string]any{"automated": map[string]any{"selfHeal": true}, "syncOptions": []any{"CreateNamespace=true"}}}}
	for name, row := range map[string]struct {
		o       snapshot.Object
		stopped bool
	}{
		"application with automated sync":           {app(map[string]any{"automated": map[string]any{}}), false},
		"application with no sync policy":           {app(nil), true},
		"application with automated enabled: false": {app(map[string]any{"automated": map[string]any{"enabled": false}}), true},
		"application with automated enabled: true":  {app(map[string]any{"automated": map[string]any{"enabled": true}}), false},
		"suspended Kustomization":                   {planObject("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "f", "k", map[string]any{"spec": map[string]any{"suspend": true}}), true},
		"Kustomization not suspended":               {planObject("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "f", "k", map[string]any{"spec": map[string]any{"path": "."}}), false},
		"applicationset whose template syncs":       {set(map[string]any{"template": tmpl}), false},
		"applicationset whose template does not":    {set(map[string]any{"template": map[string]any{"spec": map[string]any{}}}), true},
		"applicationset with RollingSync":           {set(map[string]any{"template": map[string]any{"spec": map[string]any{}}, "strategy": map[string]any{"type": "RollingSync"}}), false},
		"applicationset with AllAtOnce":             {set(map[string]any{"template": map[string]any{"spec": map[string]any{}}, "strategy": map[string]any{"type": "AllAtOnce"}}), true},
		"applicationset whose generator has a template": {set(map[string]any{"template": map[string]any{"spec": map[string]any{}},
			"generators": []any{map[string]any{"matrix": map[string]any{"generators": []any{map[string]any{"list": map[string]any{"elements": []any{}, "template": map[string]any{}}}}}}}}), false},
	} {
		if got := stopped(row.o); got != row.stopped {
			t.Errorf("%s: stopped %v, want %v", name, got, row.stopped)
		}
	}

	// Held, the template's automated sync is taken out, and the rest of
	// its sync policy is kept.
	h, how, why, _ := held(set(map[string]any{"template": deepCopy(tmpl)}))
	if why != "" || how != "automated sync off in its template" {
		t.Fatalf("held: %q, %q", how, why)
	}
	policy := h.Body["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["syncPolicy"].(map[string]any)
	if _, there := policy["automated"]; there || policy["syncOptions"] == nil {
		t.Errorf("the held template's sync policy: %v", policy)
	}
	// A generator's own template can give what it makes a sync policy:
	// refused, as what a hold cannot stop is.
	_, _, why, _ = held(set(map[string]any{"template": deepCopy(tmpl), "generators": []any{map[string]any{"list": map[string]any{"template": map[string]any{}}}}}))
	if !strings.Contains(why, "spec.generators[0].list.template") {
		t.Errorf("held with a generator's template: %q", why)
	}
}
