package kube

import (
	"fmt"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A drill restores workloads it must not let run: restored beside the
// source, with the source's settings, they would do the source's work a
// second time (take its messages, call what it calls). A scope entry that
// says "hold: true" brings its releases with nothing running: the objects
// are there, to be read, compared and started one at a time by whoever
// runs the drill. Restoring again without the hold starts them all.

const (
	// heldSelector is a node label no node carries: a DaemonSet has no
	// count to set to zero, and with this it places no pod.
	heldSelector = "truthform.org/held"
	// kedaPausedReplicas has KEDA set its target to the count and stop
	// scaling it; kedaPaused stops a ScaledJob making Jobs.
	kedaPausedReplicas = "autoscaling.keda.sh/paused-replicas"
	kedaPaused         = "autoscaling.keda.sh/paused"
)

// hasPods reports a pod template at spec.template: what the built-in
// workloads have, and what an operator's own kind has when it follows
// them (an Argo Rollout).
func hasPods(spec map[string]any) bool {
	tmpl, _ := spec["template"].(map[string]any)
	pod, _ := tmpl["spec"].(map[string]any)
	return len(list(pod["containers"])) > 0
}

// inertGroups are other APIs whose objects are known to run nothing:
// they describe a secret to fetch, a certificate, a route, what to
// scrape. An API not here is not known, and is named under a hold.
var inertGroups = map[string]bool{"onepassword.com": true, "external-secrets.io": true, "secrets-store.csi.x-k8s.io": true, "bitnami.com": true,
	"cert-manager.io": true, "acme.cert-manager.io": true, "traefik.io": true, "traefik.containo.us": true, "networking.istio.io": true, "security.istio.io": true}

// inert reports an API whose objects run nothing: Kubernetes' own
// (configuration, access, networking, storage), and those known.
func inert(group string) bool {
	return group == "" || !strings.Contains(group, ".") || strings.HasSuffix(group, ".k8s.io") || inertGroups[group]
}

// held returns an object as it is restored with nothing of it running,
// and how that was done ("" for an object that runs nothing: it is
// returned as it is). An object that runs something this cannot stop is
// an error (why), never passed: a hold that held most of a release would
// read as one that held it. unknown says an object of another API that is
// passed as it is because nothing in it says it runs anything, though
// its controller may: it is named, and the hold is not said to be whole.
func held(o snapshot.Object) (out snapshot.Object, said, why string, unknown bool) {
	group, _, versioned := strings.Cut(o.APIVersion(), "/")
	if !versioned {
		group = ""
	}
	spec, _ := o.Body["spec"].(map[string]any)
	const (
		zero = iota + 1
		noNode
		suspend
		pausedAtZero
		paused
		manual
		nothing
	)
	how := 0
	_, counted := spec["replicas"]
	_, suspends := spec["suspend"].(bool)
	switch {
	case group == "apps" && (o.Kind() == "Deployment" || o.Kind() == "StatefulSet" || o.Kind() == "ReplicaSet"),
		group == "" && o.Kind() == "ReplicationController":
		how, said = zero, "zero replicas"
	case group == "apps" && o.Kind() == "DaemonSet":
		how, said = noNode, "a node selector no node has ("+heldSelector+")"
	case group == "batch" && (o.Kind() == "CronJob" || o.Kind() == "Job"):
		how, said = suspend, "suspended"
	case group == "keda.sh" && o.Kind() == "ScaledObject":
		how, said = pausedAtZero, "paused at zero replicas"
	case group == "keda.sh" && o.Kind() == "ScaledJob":
		how, said = paused, "paused"
	case group == "autoscaling" && o.Kind() == "HorizontalPodAutoscaler":
		// It stops by itself while what it scales is at zero.
		how = nothing
	case group == "" && o.Kind() == "Pod":
		return o, "", "a Pod runs as soon as it is restored, and nothing holds one", false
	case group == "argoproj.io" && o.Kind() == "Workflow", group == "tekton.dev" && (o.Kind() == "PipelineRun" || o.Kind() == "TaskRun"):
		return o, "", "it runs as soon as it is restored, and nothing holds one", false
	case strings.HasSuffix(group, ".toolkit.fluxcd.io") && spec != nil:
		// A Flux source or what applies one: suspended, it makes nothing.
		how, said = suspend, "suspended"
	case group == "argoproj.io" && o.Kind() == "Application":
		how, said = manual, "automated sync off"
	case inert(group):
		how = nothing
	case counted:
		// Another API's workload, or an operator's object that counts
		// what it runs as the built-in ones do (an Alertmanager, a
		// Rollout): held as they are.
		how, said = zero, "zero replicas"
	case suspends:
		// One that can be suspended says so (an Argo CronWorkflow).
		how, said = suspend, "suspended"
	case hasPods(spec):
		return o, "", "it has a pod template and no spec.replicas, and how its kind is stopped is not known", false
	default:
		// Another API's object with nothing in it this reads as running:
		// a certificate, a route, or a database an operator runs.
		return o, "", "", true
	}
	if how == nothing {
		return o, "", "", false
	}
	if how == zero {
		if n, ok := spec["replicas"]; ok && n != nil {
			said += " (it had " + replicasText(n) + ")"
		}
	}
	body := deepCopy(o.Body)
	spec, _ = body["spec"].(map[string]any)
	if spec == nil {
		spec = map[string]any{}
		body["spec"] = spec
	}
	annotate := func(k, v string) {
		md, _ := body["metadata"].(map[string]any)
		if md == nil {
			md = map[string]any{}
			body["metadata"] = md
		}
		ann, _ := md["annotations"].(map[string]any)
		if ann == nil {
			ann = map[string]any{}
			md["annotations"] = ann
		}
		ann[k] = v
	}
	switch how {
	case zero:
		spec["replicas"] = int64(0)
	case suspend:
		spec["suspend"] = true
	case noNode:
		tmpl, _ := spec["template"].(map[string]any)
		pod, _ := tmpl["spec"].(map[string]any)
		if pod == nil {
			return o, "", "it has no pod template to hold", false
		}
		sel, _ := pod["nodeSelector"].(map[string]any)
		if sel == nil {
			sel = map[string]any{}
			pod["nodeSelector"] = sel
		}
		sel[heldSelector] = "true"
	case pausedAtZero:
		annotate(kedaPausedReplicas, "0")
	case paused:
		annotate(kedaPaused, "true")
	case manual:
		if policy, _ := spec["syncPolicy"].(map[string]any); policy != nil {
			delete(policy, "automated")
		}
	}
	o.Body = body
	return o, said, "", false
}

// replicasText is a count as it is written, however it was read.
func replicasText(v any) string {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return fmt.Sprint(int64(f))
	}
	return fmt.Sprint(v)
}
