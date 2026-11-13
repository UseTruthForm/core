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
		{Namespaces: []string{"shop"}, Releases: []string{"worker"}, Objects: []string{"Deployment/by-hand"}, Hold: true},
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
		// What no release made, named by the entry that holds.
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
		"Deployment shop/by-hand: zero replicas (it had 1)",
		"Deployment shop/worker: zero replicas (it had 3)",
		"Rollout shop/worker-canary: zero replicas (it had 2)",
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

// Under a hold, what an operator or a GitOps source runs is held where
// its object says how (a count, a suspend), what runs at once is
// refused, and an object of another API with nothing to go by is named:
// the hold is not said to be whole when it may not be.
func TestHoldAndOtherAPIs(t *testing.T) {
	rel := func(apiVersion, kind, name string, spec map[string]any) snapshot.Object {
		return released(apiVersion, kind, "shop", name, "worker", map[string]any{"spec": spec})
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		rel("apps/v1", "Deployment", "worker", map[string]any{"replicas": float64(3), "template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "x"}}}}}),
		rel("monitoring.coreos.com/v1", "Alertmanager", "alerts", map[string]any{"replicas": float64(3)}),
		rel("kafka.strimzi.io/v1beta2", "KafkaConnect", "connect", map[string]any{"replicas": float64(2), "image": "x"}),
		rel("argoproj.io/v1alpha1", "CronWorkflow", "nightly", map[string]any{"schedule": "0 1 * * *"}), // no suspend key, as most are written
		rel("sparkoperator.k8s.io/v1beta2", "ScheduledSparkApplication", "hourly", map[string]any{"schedule": "@hourly", "suspend": false}),
		rel("helm.toolkit.fluxcd.io/v2", "HelmRelease", "chart", map[string]any{"interval": "5m"}),
		rel("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "apps", map[string]any{"path": "./apps"}),
		rel("argoproj.io/v1alpha1", "Application", "app", map[string]any{"syncPolicy": map[string]any{"automated": map[string]any{"prune": true}, "syncOptions": []any{"CreateNamespace=true"}}}),
		// Nothing in these says they run anything.
		rel("postgresql.cnpg.io/v1", "Cluster", "db", map[string]any{"instances": float64(3)}),
		rel("example.com/v1", "Gadget", "g", map[string]any{"size": "big"}),
		// A group that ends in k8s.io and is not Kubernetes' own.
		rel("sparkoperator.k8s.io/v1beta2", "SparkApplication", "etl", map[string]any{"type": "Scala"}),
		rel("externaldns.k8s.io/v1alpha1", "DNSEndpoint", "dns", map[string]any{"endpoints": []any{}}),
		// What acts outside the cluster.
		rel("cert-manager.io/v1", "Certificate", "tls", map[string]any{"secretName": "tls"}),
		rel("external-secrets.io/v1alpha1", "PushSecret", "push", map[string]any{"selector": map[string]any{}}),
		// A count that is not of pods.
		rel("kafka.strimzi.io/v1beta2", "KafkaTopic", "orders", map[string]any{"replicas": float64(3), "partitions": float64(6)}),
		// Known to run nothing and reach nothing.
		rel("external-secrets.io/v1", "ExternalSecret", "es", map[string]any{"refreshInterval": "1h"}),
		rel("onepassword.com/v1", "OnePasswordItem", "db", map[string]any{"itemPath": "vaults/v/items/i"}),
		rel("gateway.networking.k8s.io/v1", "HTTPRoute", "route", map[string]any{"hostnames": []any{"x"}}),
		// Kubernetes' own, which run nothing.
		rel("v1", "ConfigMap", "cfg", nil),
		rel("networking.k8s.io/v1", "Ingress", "web", map[string]any{}),
		rel("rbac.authorization.k8s.io/v1", "Role", "r", nil),
		rel("policy/v1", "PodDisruptionBudget", "pdb", map[string]any{"minAvailable": float64(1)}),
	}}
	out, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"worker"}, Hold: true}}})
	if err != nil {
		t.Fatal(err)
	}
	var held []string
	for _, h := range rep.Held {
		held = append(held, h.Object+": "+h.How)
	}
	want := []string{
		"Alertmanager shop/alerts: zero replicas (it had 3)",
		"Application shop/app: automated sync off",
		"CronWorkflow shop/nightly: suspended",
		"Deployment shop/worker: zero replicas (it had 3)",
		"HelmRelease shop/chart: suspended",
		"KafkaConnect shop/connect: zero replicas (it had 2)",
		"Kustomization shop/apps: suspended",
		"ScheduledSparkApplication shop/hourly: suspended",
	}
	if !reflect.DeepEqual(held, want) {
		t.Errorf("held:\n got %q\nwant %q", held, want)
	}
	if want := []string{"Certificate shop/tls", "Cluster shop/db", "DNSEndpoint shop/dns", "Gadget shop/g", "KafkaTopic shop/orders", "PushSecret shop/push", "SparkApplication shop/etl"}; !reflect.DeepEqual(rep.NotHeld, want) {
		t.Errorf("named as not held: %q, want %q", rep.NotHeld, want)
	}
	for key, c := range map[string]struct {
		path []string
		want any
	}{
		"Alertmanager shop/alerts":              {[]string{"spec", "replicas"}, int64(0)},
		"KafkaConnect shop/connect":             {[]string{"spec", "replicas"}, int64(0)},
		"CronWorkflow shop/nightly":             {[]string{"spec", "suspend"}, true},
		"HelmRelease shop/chart":                {[]string{"spec", "suspend"}, true},
		"Kustomization shop/apps":               {[]string{"spec", "suspend"}, true},
		"Application shop/app":                  {[]string{"spec", "syncPolicy"}, map[string]any{"syncOptions": []any{"CreateNamespace=true"}}},
		"Cluster shop/db":                       {[]string{"spec", "instances"}, float64(3)},
		"KafkaTopic shop/orders":                {[]string{"spec", "replicas"}, float64(3)},
		"ScheduledSparkApplication shop/hourly": {[]string{"spec", "suspend"}, true},
		"PodDisruptionBudget shop/pdb":          {[]string{"spec", "minAvailable"}, float64(1)},
	} {
		if got := at(find(t, out, key), c.path...); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %s: got %#v, want %#v", key, strings.Join(c.path, "."), got, c.want)
		}
	}
	// What runs as soon as it is there is refused.
	for _, o := range []snapshot.Object{
		rel("argoproj.io/v1alpha1", "Workflow", "once", map[string]any{"entrypoint": "main"}),
		rel("tekton.dev/v1", "PipelineRun", "run", map[string]any{"pipelineRef": map[string]any{"name": "p"}}),
		rel("tekton.dev/v1", "TaskRun", "task", map[string]any{"taskRef": map[string]any{"name": "t"}}),
	} {
		_, _, err := Narrow(snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{o}}, Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"worker"}, Hold: true}}})
		if err == nil || !strings.Contains(err.Error(), "runs as soon as it is restored") {
			t.Errorf("%s under a hold: %v", o.Kind(), err)
		}
	}
}

// A KEDA scaler brought without a hold would start what it scales from
// zero: it is paused with its target, and one whose target runs is not.
func TestHoldPausesTheScalerOfWhatIsHeld(t *testing.T) {
	tmpl := map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "x"}}}}
	scaler := func(name, release string, ref map[string]any) snapshot.Object {
		return released("keda.sh/v1alpha1", "ScaledObject", "shop", name, release, map[string]any{"spec": map[string]any{"scaleTargetRef": ref, "minReplicaCount": float64(1)}})
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		released("apps/v1", "Deployment", "shop", "worker", "worker", map[string]any{"spec": map[string]any{"replicas": float64(3), "template": tmpl}}),
		released("apps/v1", "StatefulSet", "shop", "store", "worker", map[string]any{"spec": map[string]any{"replicas": float64(1), "template": tmpl}}),
		released("apps/v1", "Deployment", "shop", "api", "api", map[string]any{"spec": map[string]any{"replicas": float64(2), "template": tmpl}}),
		scaler("for-worker", "scaling", map[string]any{"name": "worker"}), // a Deployment where no kind is given
		scaler("for-store", "scaling", map[string]any{"name": "store", "kind": "StatefulSet"}),
		scaler("for-api", "scaling", map[string]any{"name": "api"}),                              // its target runs
		scaler("for-other-kind", "scaling", map[string]any{"name": "worker", "kind": "Rollout"}), // not the Deployment
		// One of the same name in another namespace scales its own.
		released("apps/v1", "Deployment", "core", "worker", "worker", map[string]any{"spec": map[string]any{"replicas": float64(1), "template": tmpl}}),
		released("keda.sh/v1alpha1", "ScaledObject", "core", "for-worker", "scaling", map[string]any{"spec": map[string]any{"scaleTargetRef": map[string]any{"name": "worker"}}}),
	}}
	out, rep, err := Narrow(s, Scope{Narrow: []ScopeEntry{
		{Namespaces: []string{"shop"}, Releases: []string{"api", "scaling"}},
		{Namespaces: []string{"shop"}, Releases: []string{"worker"}, Hold: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for name, paused := range map[string]bool{"for-worker": true, "for-store": true, "for-api": false, "for-other-kind": false} {
		got := at(find(t, out, "ScaledObject shop/"+name), "metadata", "annotations", "autoscaling.keda.sh/paused-replicas")
		if (got == "0") != paused {
			t.Errorf("%s: paused-replicas is %v, want paused %v", name, got, paused)
		}
	}
	if got := at(find(t, out, "ScaledObject core/for-worker"), "metadata", "annotations", "autoscaling.keda.sh/paused-replicas"); got != nil {
		t.Errorf("a scaler in another namespace was paused: %v", got)
	}
	said := ""
	for _, h := range rep.Held {
		said += h.Object + ": " + h.How + "\n"
	}
	if !strings.Contains(said, "ScaledObject shop/for-worker: paused at zero replicas, since what it scales is held") || strings.Contains(said, "for-api") {
		t.Errorf("held:\n%s", said)
	}
}

// The annotations KEDA reads, as KEDA writes them: a constant compared
// with itself proves nothing.
func TestTheNamesOfWhatHolds(t *testing.T) {
	if kedaPausedReplicas != "autoscaling.keda.sh/paused-replicas" || kedaPaused != "autoscaling.keda.sh/paused" || heldSelector != "truthform.org/held" {
		t.Error("an annotation or a label that holds was renamed")
	}
	for kind, apiVersion := range map[string]string{"ReplicaSet": "apps/v1", "ReplicationController": "v1"} {
		o := planObject(apiVersion, kind, "shop", "x", map[string]any{"spec": map[string]any{"replicas": float64(2)}})
		ho, how, why, unknown := held(o)
		if how != "zero replicas (it had 2)" || why != "" || unknown || at(ho, "spec", "replicas") != int64(0) {
			t.Errorf("%s: %q %q %v", kind, how, why, unknown)
		}
	}
}

// What a hold does not know how to hold, a person may look at and name
// under asTheyAre: it is then listed apart, and no longer as not held.
// The key excuses only that: not what a hold refuses, not a name that
// fits nothing the hold would have named, and not an entry with no hold.
func TestAsTheyAre(t *testing.T) {
	rel := func(apiVersion, kind, name string, spec map[string]any) snapshot.Object {
		return released(apiVersion, kind, "shop", name, "worker", map[string]any{"spec": spec})
	}
	s := snapshot.Snapshot{Platform: "kubernetes", Objects: []snapshot.Object{
		rel("apps/v1", "Deployment", "worker", map[string]any{"replicas": float64(3)}),
		rel("cert-manager.io/v1", "Certificate", "tls", map[string]any{"secretName": "tls"}),
		rel("postgresql.cnpg.io/v1", "Cluster", "db", map[string]any{"instances": float64(3)}),
		rel("example.com/v1", "Cluster", "other", map[string]any{"size": "big"}),
		rel("v1", "ConfigMap", "cfg", nil),
	}}
	entry := func(as ...string) Scope {
		return Scope{Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"worker"}, Hold: true, AsTheyAre: as}}}
	}
	for _, c := range []struct {
		as            []string
		notHeld, asIs []string
	}{
		{nil, []string{"Certificate shop/tls", "Cluster shop/db", "Cluster shop/other"}, []string{}},
		{[]string{"Certificate/tls"}, []string{"Cluster shop/db", "Cluster shop/other"}, []string{"Certificate shop/tls"}},
		// By group, where two APIs share a kind.
		{[]string{"Cluster.postgresql.cnpg.io/*"}, []string{"Certificate shop/tls", "Cluster shop/other"}, []string{"Cluster shop/db"}},
		{[]string{"Certificate/*", "Cluster/*"}, []string{}, []string{"Certificate shop/tls", "Cluster shop/db", "Cluster shop/other"}},
	} {
		out, rep, err := Narrow(s, entry(c.as...))
		if err != nil {
			t.Fatalf("%q: %v", c.as, err)
		}
		if !reflect.DeepEqual(rep.NotHeld, c.notHeld) || !reflect.DeepEqual(rep.AsTheyAre, c.asIs) {
			t.Errorf("%q: not held %q, as they are %q; want %q and %q", c.as, rep.NotHeld, rep.AsTheyAre, c.notHeld, c.asIs)
		}
		if len(out.Objects) != 5 || len(rep.Held) != 1 {
			t.Errorf("%q: %d objects brought, %d held", c.as, len(out.Objects), len(rep.Held))
		}
	}
	for want, sc := range map[string]Scope{
		// Held, a ConfigMap that runs nothing, and a name that is not there.
		`asTheyAre names "Deployment/worker"`: entry("Deployment/worker"),
		`asTheyAre names "ConfigMap/cfg"`:     entry("ConfigMap/cfg"),
		`asTheyAre names "Certificate/tsl"`:   entry("Certificate/tls", "Certificate/tsl"),
		"is not Kind/name":                    entry("tls"),
		"asTheyAre is for an entry with hold": {Narrow: []ScopeEntry{{Namespaces: []string{"shop"}, Releases: []string{"worker"}, AsTheyAre: []string{"Certificate/tls"}}}},
	} {
		if _, _, err := Narrow(s, sc); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want an error with %q, got %v", want, err)
		}
	}
	// An entry names what is in its own namespaces, not another's.
	s.Objects = append(s.Objects, released("apps/v1", "Deployment", "other", "api", "api", map[string]any{"spec": map[string]any{"replicas": float64(1)}}))
	two := entry()
	two.Narrow = append(two.Narrow, ScopeEntry{Namespaces: []string{"other"}, Releases: []string{"api"}, Hold: true, AsTheyAre: []string{"Certificate/tls"}})
	if _, _, err := Narrow(s, two); err == nil || !strings.Contains(err.Error(), `entry 2: asTheyAre names "Certificate/tls"`) {
		t.Errorf("an entry of another namespace: %v", err)
	}
	// What a hold refuses stays refused.
	s.Objects = append(s.Objects, rel("v1", "Pod", "once", map[string]any{"containers": []any{map[string]any{"name": "c", "image": "x"}}}))
	if _, _, err := Narrow(s, entry("Certificate/*", "Cluster/*", "Pod/once")); err == nil || !strings.Contains(err.Error(), "Pod shop/once") {
		t.Errorf("a Pod named under asTheyAre: %v", err)
	}
}
