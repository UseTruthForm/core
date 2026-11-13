package kube

import (
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

// held returns an object as it is restored with nothing of it running,
// and how that was done ("" for an object that runs nothing: it is
// returned as it is). An object that runs something this cannot stop is
// an error, never passed: a hold that held most of a release would read
// as one that held it.
func held(o snapshot.Object) (snapshot.Object, string, string) {
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
		nothing
	)
	how, said := 0, ""
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
		return o, "", "a Pod runs as soon as it is restored, and nothing holds one"
	case hasPods(spec):
		// Another API's workload. One that counts its pods as the
		// built-in ones do is held as they are.
		if _, counted := spec["replicas"]; !counted {
			return o, "", "it has a pod template and no spec.replicas, and how its kind is stopped is not known"
		}
		how, said = zero, "zero replicas"
	default:
		how = nothing
	}
	if how == nothing {
		return o, "", ""
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
			return o, "", "it has no pod template to hold"
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
	}
	o.Body = body
	return o, said, ""
}
