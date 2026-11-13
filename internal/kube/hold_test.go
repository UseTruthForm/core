package kube

import (
	"reflect"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

func podTemplate(image string) map[string]any {
	return map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": image}}}}
}

func at(o snapshot.Object, path ...string) any {
	var v any = o.Body
	for _, p := range path {
		m, _ := v.(map[string]any)
		v = m[p]
	}
	return v
}

func find(t *testing.T, s snapshot.Snapshot, key string) snapshot.Object {
	t.Helper()
	for _, o := range s.Objects {
		if o.Kind()+" "+o.Namespace()+"/"+o.Name() == key {
			return o
		}
	}
	t.Fatalf("%s is not in the snapshot", key)
	return snapshot.Object{}
}

func holdSnapshot() snapshot.Snapshot {
	spec := func(m map[string]any) map[string]any { return map[string]any{"spec": m} }
	return snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		planObject("v1", "Namespace", "", "shop", nil),
		planObject("v1", "Namespace", "", "core", nil),
		// worker: every kind a hold knows.
		released("apps/v1", "Deployment", "shop", "worker", "worker", spec(map[string]any{"replicas": float64(3), "template": podTemplate("r.example/worker:1")})),
		released("apps/v1", "StatefulSet", "shop", "worker-db", "worker", spec(map[string]any{"template": podTemplate("r.example/db:1")})),
		released("apps/v1", "DaemonSet", "shop", "worker-agent", "worker", spec(map[string]any{"template": map[string]any{"spec": map[string]any{"nodeSelector": map[string]any{"pool": "a"}, "containers": []any{map[string]any{"name": "c", "image": "r.example/agent:1"}}}}})),
		released("batch/v1", "CronJob", "shop", "worker-nightly", "worker", spec(map[string]any{"schedule": "0 1 * * *"})),
		released("keda.sh/v1alpha1", "ScaledObject", "shop", "worker", "worker", spec(map[string]any{"minReplicaCount": float64(1)})),
		released("keda.sh/v1alpha1", "ScaledJob", "shop", "worker-jobs", "worker", nil),
		released("autoscaling/v2", "HorizontalPodAutoscaler", "shop", "worker-db", "worker", spec(map[string]any{"minReplicas": float64(2)})),
		released("argoproj.io/v1alpha1", "Rollout", "shop", "worker-canary", "worker", spec(map[string]any{"replicas": float64(2), "template": podTemplate("r.example/canary:1")})),
		released("v1", "Service", "shop", "worker", "worker", nil),
		// api: in the same namespace, and not held.
		released("apps/v1", "Deployment", "shop", "api", "api", spec(map[string]any{"replicas": float64(2), "template": podTemplate("r.example/api:1")})),
		// Of no release: goes as the namespace goes.
		planObject("apps/v1", "Deployment", "shop", "by-hand", spec(map[string]any{"replicas": float64(1), "template": podTemplate("r.example/hand:1")})),
		// Not narrowed.
		released("apps/v1", "Deployment", "core", "gateway", "gateway", spec(map[string]any{"replicas": float64(2)})),
	}}
}

// What an entry holds is brought with nothing running, each kind in the
// way that stops it; what another entry brings runs, and so does what the
// scope does not narrow.
func TestNarrowHolds(t *testing.T) {
	s := holdSnapshot()
	out, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{
		{Namespaces: []string{"shop"}, Releases: []string{"api"}},
		{Namespaces: []string{"shop"}, Releases: []string{"worker"}, Hold: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		key  string
		path []string
		want any
	}{
		{"Deployment shop/worker", []string{"spec", "replicas"}, int64(0)},
		{"StatefulSet shop/worker-db", []string{"spec", "replicas"}, int64(0)},
		{"DaemonSet shop/worker-agent", []string{"spec", "template", "spec", "nodeSelector"}, map[string]any{"pool": "a", heldSelector: "true"}},
		{"CronJob shop/worker-nightly", []string{"spec", "suspend"}, true},
		{"ScaledObject shop/worker", []string{"metadata", "annotations", kedaPausedReplicas}, "0"},
		{"ScaledJob shop/worker-jobs", []string{"metadata", "annotations", kedaPaused}, "true"},
		{"Rollout shop/worker-canary", []string{"spec", "replicas"}, int64(0)},
		{"HorizontalPodAutoscaler shop/worker-db", []string{"spec", "minReplicas"}, float64(2)},
		{"Deployment shop/api", []string{"spec", "replicas"}, float64(2)},
		{"Deployment core/gateway", []string{"spec", "replicas"}, float64(2)},
		// Hold wins for what the namespace brings along.
		{"Deployment shop/by-hand", []string{"spec", "replicas"}, int64(0)},
	} {
		if got := at(find(t, out, c.key), c.path...); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %s: got %#v, want %#v", c.key, strings.Join(c.path, "."), got, c.want)
		}
	}
	// What Helm wrote on a held object is still there.
	if got := at(find(t, out, "ScaledObject shop/worker"), "metadata", "annotations", "meta.helm.sh/release-name"); got != "worker" {
		t.Errorf("a held object lost an annotation: %v", got)
	}
	// The snapshot given is as it was.
	if got := at(find(t, s, "Deployment shop/worker"), "spec", "replicas"); got != float64(3) {
		t.Errorf("the snapshot given was changed: replicas %v", got)
	}
	if got := at(find(t, s, "DaemonSet shop/worker-agent"), "spec", "template", "spec", "nodeSelector"); !reflect.DeepEqual(got, map[string]any{"pool": "a"}) {
		t.Errorf("the snapshot given was changed: %v", got)
	}
	var held []string
	for _, h := range rep.Held {
		held = append(held, h.Object+": "+h.How)
	}
	want := []string{
		"CronJob shop/worker-nightly: suspended",
		"DaemonSet shop/worker-agent: a node selector no node has (truthform.org/held)",
		"Deployment shop/by-hand: zero replicas",
		"Deployment shop/worker: zero replicas",
		"Rollout shop/worker-canary: zero replicas",
		"ScaledJob shop/worker-jobs: paused",
		"ScaledObject shop/worker: paused at zero replicas",
		"StatefulSet shop/worker-db: zero replicas",
	}
	if !reflect.DeepEqual(held, want) {
		t.Errorf("held:\n got %q\nwant %q", held, want)
	}
}

// With no entry that holds, nothing is changed.
func TestNarrowWithoutAHoldChangesNoObject(t *testing.T) {
	s := holdSnapshot()
	out, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"*"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Held) != 0 {
		t.Errorf("held %v", rep.Held)
	}
	for _, o := range out.Objects {
		if !reflect.DeepEqual(o.Body, find(t, s, o.Kind()+" "+o.Namespace()+"/"+o.Name()).Body) {
			t.Errorf("%s was changed", o.Name())
		}
	}
}

// A release two entries choose is held if either holds, and a label's
// hold is its entry's.
func TestHoldWins(t *testing.T) {
	s := holdSnapshot()
	md := find(t, s, "Deployment shop/api").Body["metadata"].(map[string]any)
	md["labels"].(map[string]any)["tier"] = "edge"
	for name, sc := range map[string]Scope{
		"a pattern and a name": {Narrow: []ScopeEntry{
			{Namespaces: []string{"shop"}, Releases: []string{"*"}},
			{Namespaces: []string{"shop"}, Releases: []string{"api"}, Hold: true},
		}},
		"a name and a pattern": {Narrow: []ScopeEntry{
			{Namespaces: []string{"shop"}, Releases: []string{"api"}, Hold: true},
			{Namespaces: []string{"shop"}, Releases: []string{"*"}},
		}},
		"a label": {Narrow: []ScopeEntry{
			{Namespaces: []string{"shop"}, Releases: []string{"worker"}},
			{Namespaces: []string{"shop"}, Labels: map[string]string{"tier": "edge"}, Hold: true},
		}},
	} {
		out, _, err := Narrow(s, sc)
		if err != nil {
			t.Fatal(name, err)
		}
		if got := at(find(t, out, "Deployment shop/api"), "spec", "replicas"); got != int64(0) {
			t.Errorf("%s: api runs (%v replicas)", name, got)
		}
	}
}

// A Job that is brought and held is suspended.
func TestHoldSuspendsAJobBrought(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		released("batch/v1", "Job", "shop", "migrate", "migrate", nil),
	}}
	out, _, err := Narrow(s, Scope{Jobs: true, Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"migrate"}, Hold: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := at(find(t, out, "Job shop/migrate"), "spec", "suspend"); got != true {
		t.Errorf("suspend: %v", got)
	}
}

// What a hold cannot stop is refused, by name: a Pod, and another API's
// workload that does not count its pods.
func TestHoldRefusesWhatItCannotStop(t *testing.T) {
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		released("v1", "Pod", "shop", "one-off", "worker", map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "r.example/x:1"}}}}),
		released("example.com/v1", "Gadget", "shop", "odd", "worker", map[string]any{"spec": map[string]any{"template": podTemplate("r.example/odd:1")}}),
		released("apps/v1", "Deployment", "shop", "worker", "worker", nil),
	}}
	entry := ScopeEntry{Namespaces: []string{"shop"}, Releases: []string{"worker"}, Hold: true}
	_, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{entry}})
	if err == nil {
		t.Fatal("held, though a Pod and a Gadget would run")
	}
	for _, want := range []string{"Pod shop/one-off", "Gadget shop/odd", "--leave-out"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q does not say %q", err, want)
		}
	}
	// Not held, they are brought as they are.
	entry.Hold = false
	if _, _, err := Narrow(s, Scope{Narrow: []ScopeEntry{entry}}); err != nil {
		t.Errorf("without the hold: %v", err)
	}
}
