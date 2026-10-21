package kube

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/snapshot"
)

// WithheldAnnotation lists the keys of a Secret whose values StackDNA did not
// write to the snapshot. A backup is copied, committed and shared far more
// freely than a cluster, so secret values never go into it; restore has to be
// given them from somewhere else (a vault, or the live source cluster).
const WithheldAnnotation = "stackdna.org/withheld-keys"

// excludedTypes are resource types a recreation never needs. Each one is
// either derived from other objects, describes the machine or the moment
// rather than the configuration, or is a one-shot request. They are still
// listed in coverage as not captured, with this reason, so their absence is
// visible.
var excludedTypes = map[string]string{
	"/events":                          "events are a log, not configuration",
	"events.k8s.io/events":             "events are a log, not configuration",
	"/endpoints":                       "derived from Services by the endpoints controller",
	"discovery.k8s.io/endpointslices":  "derived from Services by the endpoint-slice controller",
	"coordination.k8s.io/leases":       "leader-election and heartbeat records, recreated by their owners",
	"/nodes":                           "nodes are machines; a new cluster brings its own",
	"/componentstatuses":               "deprecated health readout, not configuration",
	"apps/controllerrevisions":         "rollout history kept by controllers, recreated as they run",
	"certificates.k8s.io/certificatesigningrequests": "one-time certificate requests; the new cluster issues its own",
	"storage.k8s.io/csinodes":          "per-node driver registration",
	"storage.k8s.io/volumeattachments": "attachment of a volume to a node at this moment",
	"metrics.k8s.io/nodes":             "live metrics",
	"metrics.k8s.io/pods":              "live metrics",
}

// systemNamespaces hold the platform's own components. A fresh cluster
// recreates them, and restoring an old copy over a new control plane is how
// you break it, so they are skipped unless --include-system is given.
var systemNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
	"local-path-storage": true, // kind's default storage provisioner
}

// platformManagers are field managers that belong to the cluster itself. An
// object every one of whose fields was written by these was made by the
// platform (bootstrap RBAC, default service accounts, the root CA configmap)
// and a new cluster makes its own.
var platformManagers = map[string]bool{
	"kube-apiserver": true, "kube-controller-manager": true, "kube-scheduler": true,
	"kubelet": true, "kubeadm": true, "kube-proxy": true,
}

// Policy decides, per object, whether it belongs in a recreation backup.
type Policy struct {
	IncludeSystem bool
	// CaptureRendered keeps objects that a higher-level source (a Flux
	// HelmRelease or Kustomization, an Argo CD application, a Crossplane
	// composite) renders. By default they are skipped: restoring the source
	// recreates them, and restoring both makes two owners fight over every
	// field. On the tilt platform cluster this was 335 of 632 objects.
	CaptureRendered bool
	// Baseline is a capture of a fresh, empty cluster of the same
	// distribution (kind, EKS, AKS...). Objects identical to it are the
	// distribution's own add-ons, which a new cluster brings by itself; a
	// list of platform names can never be complete, but this can. An object
	// that differs from its baseline copy was changed by someone and is
	// captured.
	Baseline       map[string]map[string]any
	BaselineDigest string
}

// WithBaseline loads a baseline snapshot into the policy.
func (p Policy) WithBaseline(b snapshot.Snapshot, digest string) Policy {
	p.Baseline = map[string]map[string]any{}
	for _, o := range b.Objects {
		p.Baseline[o.Key()] = o.Body
	}
	p.BaselineDigest = digest
	return p
}

// matchesBaseline reports whether a normalised object is identical to the
// distribution baseline's copy of it.
func (p Policy) matchesBaseline(obj map[string]any) bool {
	if p.Baseline == nil {
		return false
	}
	o := snapshot.Object{Body: obj}
	b, ok := p.Baseline[o.Key()]
	return ok && reflect.DeepEqual(roundTrip(obj), roundTrip(b))
}

// roundTrip puts a value through JSON so numbers and nested types compare
// equal whether they came from the API (JSON) or a snapshot file (YAML).
func roundTrip(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// Name is recorded in the snapshot so diffs only compare like with like.
func (p Policy) Name() string {
	n := "default"
	if p.IncludeSystem {
		n = "include-system"
	}
	if p.CaptureRendered {
		n += "+rendered"
	}
	if p.BaselineDigest != "" {
		n += "+baseline:" + p.BaselineDigest
	}
	return n
}

// typeExcluded reports why a whole resource type is left out, or "".
func (p Policy) typeExcluded(group, resource string) string {
	return excludedTypes[group+"/"+resource]
}

// skipReason reports why one object is left out, or "" to capture it.
func (p Policy) skipReason(group, resource string, obj map[string]any) string {
	md, _ := obj["metadata"].(map[string]any)
	ns, _ := md["namespace"].(string)
	name, _ := md["name"].(string)

	if !p.IncludeSystem {
		if systemNamespaces[ns] {
			return "in system namespace " + ns
		}
		if group == "" && resource == "namespaces" && (systemNamespaces[name] || name == "default") {
			return "namespace created by the cluster itself"
		}
	}

	if !p.CaptureRendered {
		if why := renderedBy(md); why != "" {
			return why
		}
	}

	switch {
	case group == "" && resource == "persistentvolumes" && annotation(md, "pv.kubernetes.io/provisioned-by") != "":
		claim, _ := obj["spec"].(map[string]any)["claimRef"].(map[string]any)
		return "provisioned by " + annotation(md, "pv.kubernetes.io/provisioned-by") + " for claim " +
			strOf(claim["namespace"]) + "/" + strOf(claim["name"]) + "; recreated when the claim is restored. Volume DATA is not captured"
	case group == "" && resource == "secrets" && strOf(obj["type"]) == "helm.sh/release.v1":
		return "Helm release history; recreated when the release is installed again"
	}

	for _, o := range list(md["ownerReferences"]) {
		ref, _ := o.(map[string]any)
		if c, _ := ref["controller"].(bool); c {
			return "owned by " + strOf(ref["kind"]) + "/" + strOf(ref["name"]) + ", whose controller recreates it"
		}
	}

	if p.IncludeSystem {
		return ""
	}
	switch {
	case group == "" && resource == "serviceaccounts" && name == "default":
		return "created in every namespace by the cluster"
	case group == "" && resource == "configmaps" && name == "kube-root-ca.crt":
		return "created in every namespace by the cluster"
	case group == "" && resource == "services" && ns == "default" && name == "kubernetes":
		return "the API server's own service"
	case group == "" && resource == "secrets" && strOf(obj["type"]) == "kubernetes.io/service-account-token":
		return "service-account token, issued by the cluster"
	}
	if labels, _ := md["labels"].(map[string]any); labels["kubernetes.io/bootstrapping"] == "rbac-defaults" {
		return "default RBAC, created by the API server"
	}
	if ann, _ := md["annotations"].(map[string]any); ann["apf.kubernetes.io/autoupdate-spec"] == "true" {
		return "default API priority and fairness config, kept up to date by the API server"
	}
	if mgrs := managers(md); len(mgrs) > 0 && allPlatform(mgrs) {
		return "written only by the platform (" + strings.Join(mgrs, ", ") + ")"
	}
	return ""
}

// renderedBy reports which higher-level source applied an object, from the
// labels those tools stamp on everything they create, or "".
func renderedBy(md map[string]any) string {
	labels, _ := md["labels"].(map[string]any)
	l := func(k string) string { return strOf(labels[k]) }
	switch {
	case l("helm.toolkit.fluxcd.io/name") != "":
		return "rendered by Flux HelmRelease " + l("helm.toolkit.fluxcd.io/namespace") + "/" + l("helm.toolkit.fluxcd.io/name") + "; restoring the HelmRelease recreates it"
	case l("kustomize.toolkit.fluxcd.io/name") != "":
		return "applied by Flux Kustomization " + l("kustomize.toolkit.fluxcd.io/namespace") + "/" + l("kustomize.toolkit.fluxcd.io/name") + "; restoring it recreates this"
	case l("argocd.argoproj.io/instance") != "" || annotation(md, "argocd.argoproj.io/tracking-id") != "":
		app := l("argocd.argoproj.io/instance")
		if app == "" {
			app = strings.SplitN(annotation(md, "argocd.argoproj.io/tracking-id"), ":", 2)[0]
		}
		return "managed by Argo CD application " + app + "; restoring the application recreates it"
	case l("crossplane.io/composite") != "":
		return "composed by Crossplane composite " + l("crossplane.io/composite") + "; restoring the composite recreates it"
	}
	return ""
}

func annotation(md map[string]any, k string) string {
	a, _ := md["annotations"].(map[string]any)
	return strOf(a[k])
}

// serverOwnedMetadata is metadata the API server sets. Kept, it would make
// every snapshot differ (resourceVersion) or make restore fail (uid).
var serverOwnedMetadata = []string{
	"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields",
	"selfLink", "deletionTimestamp", "deletionGracePeriodSeconds", "ownerReferences",
}

// serverAnnotations are written by tools or controllers as bookkeeping.
var serverAnnotations = []string{
	"kubectl.kubernetes.io/last-applied-configuration",
	"deployment.kubernetes.io/revision",
	"pv.kubernetes.io/bind-completed",
	"pv.kubernetes.io/bound-by-controller",
	"volume.beta.kubernetes.io/storage-provisioner",
	"volume.kubernetes.io/storage-provisioner",
	"volume.kubernetes.io/selected-node",
}

// normalize strips what the server generated, so the snapshot holds only
// what someone configured and the same live state always captures the same.
// It returns the withheld secret keys, if any.
func normalize(group, resource string, obj map[string]any) []string {
	delete(obj, "status")
	md, _ := obj["metadata"].(map[string]any)
	for _, k := range serverOwnedMetadata {
		delete(md, k)
	}
	if ann, ok := md["annotations"].(map[string]any); ok {
		for _, k := range serverAnnotations {
			delete(ann, k)
		}
		if len(ann) == 0 {
			delete(md, "annotations")
		}
	}

	switch group + "/" + resource {
	case "/namespaces":
		delete(obj, "spec") // only the "kubernetes" finalizer, added by the server
		if l, ok := md["labels"].(map[string]any); ok {
			delete(l, "kubernetes.io/metadata.name") // added by the server
			if len(l) == 0 {
				delete(md, "labels")
			}
		}
	case "/services":
		if spec, ok := obj["spec"].(map[string]any); ok {
			// Cluster IPs are allocated per cluster. A headless service ("None")
			// is configuration and is kept.
			if spec["clusterIP"] != "None" {
				delete(spec, "clusterIP")
				delete(spec, "clusterIPs")
			}
			delete(spec, "healthCheckNodePort")
		}
	case "/persistentvolumeclaims":
		if spec, ok := obj["spec"].(map[string]any); ok {
			delete(spec, "volumeName") // binding to this cluster's volume
		}
	case "/serviceaccounts":
		delete(obj, "secrets") // legacy auto-created token references
	case "/secrets":
		return withhold(obj)
	}
	return nil
}

// withhold replaces every secret value with "" and records the key names.
func withhold(obj map[string]any) []string {
	keys := map[string]bool{}
	for _, field := range []string{"data", "stringData"} {
		if d, ok := obj[field].(map[string]any); ok {
			for k := range d {
				keys[k] = true
			}
		}
	}
	delete(obj, "stringData")
	if len(keys) == 0 {
		return nil
	}
	sorted := make([]string, 0, len(keys))
	data := map[string]any{}
	for k := range keys {
		sorted = append(sorted, k)
		data[k] = ""
	}
	sort.Strings(sorted)
	obj["data"] = data
	md, _ := obj["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	if ann == nil {
		ann = map[string]any{}
		md["annotations"] = ann
	}
	ann[WithheldAnnotation] = strings.Join(sorted, ",")
	return sorted
}

func managers(md map[string]any) []string {
	set := map[string]bool{}
	for _, f := range list(md["managedFields"]) {
		e, _ := f.(map[string]any)
		if m := strOf(e["manager"]); m != "" {
			set[m] = true
		}
	}
	out := make([]string, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func allPlatform(mgrs []string) bool {
	for _, m := range mgrs {
		if !platformManagers[m] {
			return false
		}
	}
	return true
}

func list(v any) []any { l, _ := v.([]any); return l }

func strOf(v any) string { s, _ := v.(string); return s }
