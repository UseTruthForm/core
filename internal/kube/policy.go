package kube

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/usetruthform/core/internal/snapshot"
)

// WithheldAnnotation lists the keys of a Secret whose values TruthForm did not
// write to the snapshot. A backup is copied, committed and shared far more
// freely than a cluster, so secret values never go into it; restore has to be
// given them from somewhere else (a vault, or the live source cluster).
const WithheldAnnotation = "truthform.org/withheld-keys"

// WithheldEnvAnnotation lists the values TruthForm did not write to the
// snapshot because they are credentials set as plain configuration: an env
// variable of a workload, or a ConfigMap key, named like one, or any such
// value that is a URL with a password in it. A key written straight into a
// Deployment is not a Secret, so it was captured as plain configuration (a
// real cluster had an API key in a Deployment's env, from its Helm values);
// it is withheld like a Secret's value, and named so the report can say
// where to move it. Each entry is a slot path (see slots), comma-separated.
const WithheldEnvAnnotation = "truthform.org/withheld-env"

// credentialNameRE matches names that say the value is a credential:
// PASSWORD and PGPASSWORD, *_SECRET, SECRETKEY, *_TOKEN, API_KEY,
// AUTH_KEY, *_KEY, *_PASSPHRASE, *_DSN, CONNECTION_STRING and the like.
var credentialNameRE = regexp.MustCompile(`(?i)(^|_)(pass|pwd|secret|token|api_?key|auth_?key|access_?key|private_?key|client_?secret|key|credentials?|conn(ection)?_?str(ing)?|sas|dsn)(_|$)|password|passwd|passphrase|secretkey|(admin|root|user|db|app)pass$`)

// notCredentialNameRE are names that mention a credential without holding
// one: where it is (*_URL, *_PATH, *_FILE), what it is called (*_NAME,
// *_ID: a vault item's ID is how a workload asks for a secret, not the
// secret), a setting about it (*_ENABLED, *_TTL, *_LENGTH, *_SECONDS,
// *_SERIALIZER), and a public key.
var notCredentialNameRE = regexp.MustCompile(`(?i)_(id|ids|name|names|url|uri|endpoint|host|port|path|file|dir|ref|type|enabled|disabled|ttl|expiry|expires|header|issuer|audience|scope|scopes|version|length|seconds|minutes|hours|days|size|count|max|min|timeout|interval|format|algorithm|serializer|deserializer|prefix|suffix|mode|policy|level|rotation)$|public_?key`)

// envRefRE is a value that is only a reference to another variable.
var envRefRE = regexp.MustCompile(`^\$\([A-Za-z_][A-Za-z0-9_]*\)$`)

// numberedRE is a trailing index: SECRET_ID_1 is read as SECRET_ID. In a
// real cluster, two vault item IDs named *_SECRET_ID_1 and _2 were
// withheld as if they were secrets.
var numberedRE = regexp.MustCompile(`_\d+$`)

// filePathRE is a value that names a file, not a credential
// (GOOGLE_APPLICATION_CREDENTIALS=/var/run/key.json).
var filePathRE = regexp.MustCompile(`^(/|[A-Za-z]:\\)\S*$`)

// urlPasswordRE is a URL with a password in it (postgres://u:p@host,
// redis://:p@host): a credential whatever the variable is called, even a
// *_URL.
var urlPasswordRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://[^/@:\s]*:[^@\s/]+@`)

// credential reports a value to withhold, by its name and its value.
func credential(name, value string) bool {
	if value == "" || envRefRE.MatchString(value) {
		return false
	}
	if urlPasswordRE.MatchString(value) {
		return true
	}
	base := numberedRE.ReplaceAllString(name, "")
	return credentialNameRE.MatchString(base) && !notCredentialNameRE.MatchString(base) && !filePathRE.MatchString(value)
}

// excludedTypes are resource types a recreation never needs. Each one is
// either derived from other objects, describes the machine or the moment
// rather than the configuration, or is a one-shot request. They are still
// listed in coverage as not captured, with this reason, so their absence is
// visible.
var excludedTypes = map[string]string{
	"/events":                         "events are a log, not configuration",
	"events.k8s.io/events":            "events are a log, not configuration",
	"/endpoints":                      "derived from Services by the endpoints controller",
	"discovery.k8s.io/endpointslices": "derived from Services by the endpoint-slice controller",
	"coordination.k8s.io/leases":      "leader-election and heartbeat records, recreated by their owners",
	"/nodes":                          "nodes are machines; a new cluster brings its own",
	"/componentstatuses":              "deprecated health readout, not configuration",
	"apps/controllerrevisions":        "rollout history kept by controllers, recreated as they run",
	"certificates.k8s.io/certificatesigningrequests": "one-time certificate requests; the new cluster issues its own",
	"storage.k8s.io/csinodes":                        "per-node driver registration",
	"storage.k8s.io/volumeattachments":               "attachment of a volume to a node at this moment",
	"networking.k8s.io/ipaddresses":                  "cluster IP allocation records, recreated when their Services are",
	"metrics.k8s.io/nodes":                           "live metrics",
	"metrics.k8s.io/pods":                            "live metrics",
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
	// CapturePlatform keeps what is only taken to be the platform's, by evidence
	// that a user object could also carry: see aksByEno. Skipped by default, and
	// each one is listed in REPORT.md, so a wrong guess can be seen and undone.
	CapturePlatform bool
	// Baseline is a capture of a fresh, empty cluster of the same
	// distribution (kind, EKS, AKS...). Objects identical to it are the
	// distribution's own add-ons, which a new cluster brings by itself; a
	// list of platform names can never be complete, but this can. An object
	// that differs from its baseline copy was changed by someone and is
	// captured.
	Baseline       map[string]map[string]any
	BaselineDigest string
	// roots are what a source that applies itself reads from (a Flux
	// GitRepository), as kind|namespace|name: see root. Capture finds them.
	roots map[string]bool
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
	if p.CapturePlatform {
		n += "+platform"
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

	// First, so what a controller makes is recorded under its owner wherever
	// it is (kube-system included): grouped by owner, a node reimage that
	// renames every DaemonSet pod changes nothing (review of #46).
	if kind, name, ok := controllerOf(md); ok {
		return ownedReason(kind, name)
	}

	// Before the system namespaces, so what a source makes there is listed
	// under the source: a HelmRelease that installs into kube-system was
	// otherwise named nowhere, and a rebuild did not know to install it.
	// What AKS labels as its own stays the cluster's to provide (below),
	// though AKS installs some of it as a HelmRelease.
	if !p.CaptureRendered && (p.IncludeSystem || !aksOwn(md)) {
		// Where GitOps starts is kept, since nothing else recreates it. A
		// credential written into it is withheld as any is, and supplied
		// from a secret sources file.
		if why := renderedBy(md); why != "" && !p.root(obj) {
			return why
		}
	}

	if !p.IncludeSystem {
		if systemNamespaces[ns] {
			return "in system namespace " + ns
		}
		if group == "" && resource == "namespaces" && (systemNamespaces[name] || name == "default") {
			return "namespace created by the cluster itself"
		}
	}

	switch {
	case group == "" && resource == "persistentvolumes" && annotation(md, "pv.kubernetes.io/provisioned-by") != "":
		claim, _ := obj["spec"].(map[string]any)["claimRef"].(map[string]any)
		return "provisioned by " + annotation(md, "pv.kubernetes.io/provisioned-by") + " for claim " +
			strOf(claim["namespace"]) + "/" + strOf(claim["name"]) + "; recreated when the claim is restored. Volume DATA is not captured"
	case group == "" && resource == "secrets" && strOf(obj["type"]) == "helm.sh/release.v1":
		return "Helm release history; recreated when the release is installed again"
	case annotation(md, "control-plane.alpha.kubernetes.io/leader") != "":
		// Older controllers (Istio among them) keep leader election in a
		// ConfigMap or Endpoints annotation that is rewritten every few
		// seconds. Captured, it shows up as drift in every scheduled capture.
		return "leader-election record, rewritten continuously by its owner"
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
	// A fact before a guess: what AKS labels as its own is listed under the guess
	// otherwise, with a flag offered that does not keep it.
	if aksOwn(md) {
		// AKS installs these (its add-ons, their namespaces and roles) and
		// upgrades them on its own schedule: captured, every upgrade showed
		// up as drift, and a restore would fight AKS for them.
		return "installed and upgraded by AKS itself; a new cluster provides it"
	}
	if !p.CapturePlatform {
		if why := aksByEno(ns, name, md); why != "" {
			return TakenAsPlatform + why + "; --capture-platform keeps it"
		}
	}
	if labels, _ := md["labels"].(map[string]any); strOf(labels["addonmanager.kubernetes.io/mode"]) == "Reconcile" {
		// The addon manager puts these back as it shipped them. EnsureExists
		// ones are only created, so what someone changed in them is theirs.
		return "kept as shipped by the cluster's addon manager; a new cluster provides it"
	}
	if labels, _ := md["labels"].(map[string]any); labels["kube-aggregator.kubernetes.io/automanaged"] != nil {
		return "registered automatically by the API server for a group it serves"
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

// controllerOf names the controller that owns an object, if one does.
func controllerOf(md map[string]any) (kind, name string, ok bool) {
	kind, name, _, ok = controllerRef(md)
	return kind, name, ok
}

// controllerRef is controllerOf with the owner's API group, which tells a
// Knative Service from a core one.
func controllerRef(md map[string]any) (kind, name, group string, ok bool) {
	for _, o := range list(md["ownerReferences"]) {
		ref, _ := o.(map[string]any)
		if c, _ := ref["controller"].(bool); c {
			group, _, _ = strings.Cut(strOf(ref["apiVersion"]), "/")
			if !strings.Contains(strOf(ref["apiVersion"]), "/") {
				group = "" // "v1": the core group
			}
			return strOf(ref["kind"]), strOf(ref["name"]), group, true
		}
	}
	return "", "", "", false
}

func ownedReason(kind, name string) string {
	return "owned by " + kind + "/" + name + ", whose controller recreates it"
}

// aksOwn reports what AKS labels as its own.
func aksOwn(md map[string]any) bool {
	labels, _ := md["labels"].(map[string]any)
	return strOf(labels["kubernetes.azure.com/managedby"]) == "aks"
}

// root reports whether a rendered object is where GitOps starts: a source
// that applies itself (the Kustomization "flux bootstrap" makes, an Argo
// CD application that manages itself), or what such a Kustomization reads
// from. Restoring the source recreates what it renders, and nothing
// recreates these: skipped as rendered, the snapshot did not say which
// repository, branch and path the cluster was built from.
func (p Policy) root(obj map[string]any) bool {
	md, _ := obj["metadata"].(map[string]any)
	kind, ns, name := strOf(obj["kind"]), strOf(md["namespace"]), strOf(md["name"])
	return selfApplied(obj) || p.roots[kind+"|"+ns+"|"+name]
}

// selfApplied reports whether an object is the source that applied it.
func selfApplied(obj map[string]any) bool {
	md, _ := obj["metadata"].(map[string]any)
	labels, _ := md["labels"].(map[string]any)
	l := func(k string) string { return strOf(labels[k]) }
	group, _, _ := strings.Cut(strOf(obj["apiVersion"]), "/")
	name := strOf(md["name"])
	switch {
	case group == "kustomize.toolkit.fluxcd.io" && strOf(obj["kind"]) == "Kustomization":
		return l("kustomize.toolkit.fluxcd.io/name") == name && l("kustomize.toolkit.fluxcd.io/namespace") == strOf(md["namespace"])
	case group == "argoproj.io" && strOf(obj["kind"]) == "Application":
		// The tracking id names the object tracked as well as the
		// application (app:group/kind:namespace/name), and the application
		// as namespace_name when it is outside Argo CD's own namespace. The
		// label names the application only: one of the same name managed
		// by another, elsewhere, reads the same.
		if id := annotation(md, "argocd.argoproj.io/tracking-id"); id != "" {
			app, tracked, _ := strings.Cut(id, ":")
			ns := strOf(md["namespace"])
			return tracked == "argoproj.io/Application:"+ns+"/"+name && (app == name || app == ns+"_"+name)
		}
		return l("argocd.argoproj.io/instance") == name
	}
	return false
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
	// "flux reconcile" stamps the time it was asked for: a request, not
	// configuration, and it differed after every manual sync.
	"reconcile.fluxcd.io/requestedAt",
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
	withholdEnv(obj)
	return nil
}

// withhold replaces every secret value with "" and records the key names.
func withhold(obj map[string]any) []string {
	if md, _ := obj["metadata"].(map[string]any); md != nil {
		if ann, ok := md["annotations"].(map[string]any); ok {
			delete(ann, WithheldAnnotation) // this capture's word, not the live object's
			if len(ann) == 0 {
				delete(md, "annotations")
			}
		}
	}
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

// withholdEnv replaces every credential set as plain configuration in obj
// with "" and records each slot's path in WithheldEnvAnnotation.
func withholdEnv(obj map[string]any) []string {
	// What the live object says was withheld from it is not this capture's
	// word: left, it would make a slot of someone's choosing one to fill.
	if md, _ := obj["metadata"].(map[string]any); md != nil {
		if ann, ok := md["annotations"].(map[string]any); ok {
			delete(ann, WithheldEnvAnnotation)
			if len(ann) == 0 {
				delete(md, "annotations")
			}
		}
	}
	var paths []string
	all := slots(obj)
	// Paths another slot had by the rule before.
	wasOf := map[string]bool{}
	for _, sl := range all {
		if sl.was != "" && sl.was != sl.path {
			wasOf[sl.was] = true
		}
	}
	for _, sl := range all {
		if sl.withheld() {
			sl.set("")
			at := sl.path
			if wasOf[at] {
				at = ownMark + at
			}
			if sl.number {
				at += numberMark
			}
			paths = append(paths, at)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	sort.Strings(paths)
	md, _ := obj["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	if ann == nil {
		ann = map[string]any{}
		md["annotations"] = ann
	}
	ann[WithheldEnvAnnotation] = strings.Join(paths, ",")
	return paths
}

func hasWithheld(obj map[string]any) bool {
	md, _ := obj["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	return strOf(ann[WithheldEnvAnnotation]) != ""
}

// How a slot is judged.
const (
	ruleVariable = iota // a variable or a ConfigMap key: the rule for names, the rule before, and its value's shape
	ruleURL             // where something is read from: a URL that signs in
	ruleNamed           // a free-form value: its name, and its value's shape
	ruleParam           // a parameter named in full: as a free-form value, and as a variable
	ruleText            // a document as text: withheld whole if a credential is in it
	ruleBinary          // a ConfigMap's binary key: its name, and what it is when read as text
)

// slot is one value withholdEnv may withhold: an env entry, a ConfigMap
// key, a URL, a value of what a GitOps source installs with.
type slot struct {
	path, name, value string
	// was is the path the rule before gave a variable or a ConfigMap key
	// (see slotsBefore). A snapshot taken by it names the slot so, and is
	// restored still.
	was  string
	set  func(any)
	rule int
	// number: the value is a number in the object, and is one again when
	// it is filled.
	number bool
	// under: it is under a name that says a credential (password: {x: y}).
	under bool
}

// withheld reports whether the slot's value is to be withheld.
func (sl slot) withheld() bool {
	v := sl.value
	switch sl.rule {
	case ruleText:
		return textHolds(v)
	case ruleURL:
		return addressSignsIn(v) || urlPasswordRE.MatchString(v) || shaped(v)
	case ruleNamed:
		if certainlyNot(v, sl.number) {
			return false
		}
		if sl.number {
			return sl.under || saysCredential(sl.name)
		}
		return sl.under || named(sl.name, v)
	case ruleParam:
		return named(sl.name, v) || (credential(sl.name, v) && !certainlyNot(v, false))
	case ruleBinary:
		if v == "" {
			return false
		}
		if saysCredential(sl.name) || credential(sl.name, v) {
			return true
		}
		b, err := base64.StdEncoding.DecodeString(v)
		return err == nil && utf8.Valid(b) && shaped(string(b))
	}
	if sl.number {
		return !certainlyNot(v, true) && (saysCredential(sl.name) || credential(sl.name, v))
	}
	return credential(sl.name, v) || named(sl.name, v)
}

// addressRE is an address with a name before its host.
var addressRE = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*)://([^/\s]*)@`)

// addressSignsIn reports an address that signs in, where an address is
// all the field holds: with a password, or with any name at all unless it
// is over SSH, where a name alone is the account. More than a URL found
// in other text is held to: what reads an address has no use for a name
// that is not a credential, bar an account some hosts want.
func addressSignsIn(url string) bool {
	m := addressRE.FindStringSubmatch(url)
	if m == nil {
		return false
	}
	return strings.Contains(m[2], ":") || !strings.Contains(strings.ToLower(m[1]), "ssh")
}

// urlFields are fields that hold an address someone may have put a
// credential in, and urlLists fields that hold several.
var (
	urlFields = map[string]bool{"url": true, "repoURL": true, "endpoint": true, "repo": true,
		"address": true, "uri": true, "dsn": true, "databaseUrl": true, "databaseURL": true, "connectionString": true}
	urlLists = map[string]bool{"urls": true, "sourceRepos": true, "valueFiles": true}
)

// valuesPart is a key as a part of a path, with what a path is written
// with written another way: so that {"a.b": x} and {a: {b: y}} are two
// paths, and a key is not taken for an index or for the mark of a number.
func valuesPart(k string) string {
	return strings.NewReplacer(".", "%2E", "#", "%23", "[", "%5B", "]", "%5D").Replace(pathPart(k))
}

// walker finds the slots of free-form values. One walk reads an object's
// values and a document written as text (holds).
type walker struct{ out []slot }

// leaf adds a scalar of free-form values; false if v is not one. Text of
// several lines, or a line that is JSON, is a document, unless its name
// says it is a credential itself (a key in PEM, an htpasswd file).
func (w *walker) leaf(v any, path, name string, under bool, set func(any)) bool {
	switch x := v.(type) {
	case string:
		rule := ruleNamed
		if (strings.Contains(x, "\n") || jsonText(x)) && !under && !saysCredential(name) {
			rule = ruleText
		}
		w.out = append(w.out, slot{path: path, name: name, value: x, set: set, rule: rule, under: under})
	case otherScalar:
		// What YAML reads as something else (a date): by its name.
		w.out = append(w.out, slot{path: path, name: name, value: string(x), set: set, rule: ruleNamed, under: under})
	case int, int64, uint64, float64:
		w.out = append(w.out, slot{path: path, name: name, value: numberText(x), set: set, rule: ruleNamed, number: true, under: under})
	default:
		return false
	}
	return true
}

// jsonText reports a map or a list written as JSON on one line.
func jsonText(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) > 1 && (s[0] == '{' || s[0] == '[') && json.Valid([]byte(s))
}

// pairs adds the entries of a list of {name, value}: variables, or
// parameters named in full (auth.token), which may also be a string, a
// list or a map (a plugin's), or have a default (a workflow's). A
// variable's value may be a number where values are free-form. was is the
// list's path by the rule before.
func (w *walker) pairs(c any, p, was string, rule int) {
	l := list(c)
	names := items(l)
	for i, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		at := p + "[" + names[i] + "]"
		name := strOf(m["name"])
		for _, field := range []string{"value", "string"} {
			if field != "value" && rule != ruleParam {
				continue
			}
			set := func(v any) { m[field] = v }
			switch x := m[field].(type) {
			case string:
				sl := slot{path: at, name: name, value: x, set: set, rule: rule}
				if rule == ruleVariable {
					sl.was = was + "[" + names[i] + "]"
				}
				w.out = append(w.out, sl)
			case int, int64, uint64, float64:
				if field != "value" {
					continue
				}
				w.out = append(w.out, slot{path: at, name: name, value: numberText(x), set: set, rule: rule, number: true})
			default:
				continue
			}
			break
		}
		if rule != ruleParam {
			continue
		}
		if s, isStr := m["default"].(string); isStr {
			w.out = append(w.out, slot{path: at + ".default", name: name, value: s, set: func(v any) { m["default"] = v }, rule: rule})
		}
		under := underSays(name)
		if arr, isList := m["array"].([]any); isList {
			for j, e := range arr {
				w.leaf(e, at+".array["+strconv.Itoa(j)+"]", name, under, func(v any) { arr[j] = v })
			}
		}
		if mm, isMap := m["map"].(map[string]any); isMap {
			for mk, mv := range mm {
				w.leaf(mv, at+".map."+valuesPart(mk), mk, under, func(v any) { mm[mk] = v })
			}
		}
	}
}

// values walks free-form values: every scalar is a slot, named by its
// key. above is the key the map is under; under says everything here is
// under a name that says a credential; was is the path by the rule
// before, which variables under here are still found by.
func (w *walker) values(v any, path, was, above string, under bool) {
	switch x := v.(type) {
	case map[string]any:
		if under && component(x) {
			// A chart or a component whose name says a credential
			// (sealed-secrets): its settings, each read by its own name.
			under = false
		}
		pair := nameValue(x)
		if pair {
			// A name and its value written as a pair, wherever
			// (extraEnv, extraEnvVars): the value by the name it is given.
			if !w.leafPair(x, join(path, "value"), under) {
				pair = false
			}
		}
		// A JSON patch's operation: the value goes where its path says.
		patched := ""
		if at, ok := x["path"].(string); ok && !pair && x["op"] != nil {
			patched = at[strings.LastIndex(at, "/")+1:]
		}
		for k, c := range x {
			p, o := join(path, valuesPart(k)), join(was, pathPart(k))
			name := k
			switch {
			case pair && (k == "value" || k == "name"):
				continue
			case placement[k]:
				continue // where a pod runs and what it is labelled
			case naming[k] && (under || refRE.MatchString(above)) && (k != "key" || refRE.MatchString(above) || keyNames(x)):
				// The name and key of a reference. A key with nothing
				// beside it that it could be a key of is the key itself
				// (secret: {key: x}).
				continue
			case k == "key" && keyNames(x) && !under:
				// The name of a key, beside what it is a key of: by its
				// shape only (tls: {secretName, key} may hold the key).
				if !w.leaf(c, p, "", false, func(v any) { x[k] = v }) {
					w.values(c, p, o, "", false)
				}
				continue
			case k == "env":
				// Variables, as anywhere: under the path they had before
				// values were read.
				if _, isList := c.([]any); isList {
					w.pairs(c, p, o, ruleVariable)
					continue
				}
			case k == "value" && patched != "":
				name = patched
			}
			below := (under || underSays(name)) && !refRE.MatchString(name)
			// What names a thing does so under any name
			// (credentials: {existingSecret: x}).
			if w.leaf(c, p, name, under && !namesAThing(name), func(v any) { x[k] = v }) {
				continue
			}
			if l, isList := c.([]any); isList {
				secrets := lastWord(name) == "secrets"
				names := items(l)
				for i, e := range l {
					at, oat := p+"["+strconv.Itoa(i)+"]", o+"["+names[i]+"]"
					set := func(v any) { l[i] = v }
					if s, isStr := e.(string); isStr && secrets && !under && dnsNameRE.MatchString(s) {
						// Secrets, named: by its shape only.
						w.leaf(e, at, "", false, set)
						continue
					}
					if !w.leaf(e, at, name, below, set) {
						w.values(e, at, oat, name, below)
					}
				}
				continue
			}
			w.values(c, p, o, name, below)
		}
	case []any:
		names := items(x)
		for i, c := range x {
			at, oat := path+"["+strconv.Itoa(i)+"]", was+"["+names[i]+"]"
			if !w.leaf(c, at, above, under, func(v any) { x[i] = v }) {
				w.values(c, at, oat, above, under)
			}
		}
	}
}

// leafPair adds the value of a {name, value} pair in free-form values as
// a slot named by the pair's name; false if the value is no scalar.
func (w *walker) leafPair(x map[string]any, path string, under bool) bool {
	name := strOf(x["name"])
	switch v := x["value"].(type) {
	case string:
		w.out = append(w.out, slot{path: path, name: name, value: v, set: func(n any) { x["value"] = n }, rule: ruleNamed, under: under})
	case int, int64, uint64, float64:
		w.out = append(w.out, slot{path: path, name: name, value: numberText(v), set: func(n any) { x["value"] = n }, rule: ruleNamed, number: true, under: under})
	default:
		return false
	}
	return true
}

// slots finds every value of obj that may be withheld:
//
//   - every env entry with a literal value (any list under "env" whose
//     items are {name, value}: pod templates, Argo's container and script,
//     Tekton's steps, Helm values)
//   - every key of a ConfigMap's data and binaryData
//   - where a repository or a chart is read from (url, repoURL, endpoint,
//     repo, urls, sourceRepos, valueFiles)
//   - what a GitOps source installs with, each value by its name: a Flux
//     HelmRelease's values and a Kustomization's postBuild substitutions;
//     an Argo CD application's or application set's valuesObject,
//     parameters (Helm's, a plugin's, jsonnet's), generator elements and
//     inputs; and as text its values, templatePatch and elementsYaml, and
//     a patch of any of them
//   - an Argo workflow's parameters and their defaults
//
// A slot is found by where it is and never by what it holds, so that a
// restore finds the same slots in a snapshot whose values are gone. Each
// has a path unique within obj: a list item is named by its "name" where
// that is unique in its list, and by its index otherwise, so two templates
// that each have a container "main" setting DB_PASSWORD are two slots
// (review of #41); a key's dots are written another way, so a key with a
// dot in it and two keys nested are two paths.
//
// Every slot the rule before found is one still (slotsBefore), and
// carries the path that rule gave it.
func slots(obj map[string]any) []slot {
	w := &walker{}
	kind := strOf(obj["kind"])
	configMap := kind == "ConfigMap"
	if configMap {
		if d, ok := obj["data"].(map[string]any); ok {
			for k, v := range d {
				if s, ok := v.(string); ok {
					at := "data[" + k + "]"
					w.out = append(w.out, slot{path: at, was: at, name: k, value: s, set: func(x any) { d[k] = x }})
				}
			}
		}
		if d, ok := obj["binaryData"].(map[string]any); ok {
			for k, v := range d {
				if s, ok := v.(string); ok {
					w.out = append(w.out, slot{path: "binaryData[" + k + "]", name: k, value: s, set: func(x any) { d[k] = x }, rule: ruleBinary})
				}
			}
		}
	}
	group, _, _ := strings.Cut(strOf(obj["apiVersion"]), "/")
	argoApp := group == "argoproj.io" && (kind == "Application" || kind == "ApplicationSet")
	argoOther := group == "argoproj.io" && !argoApp
	fluxRelease := group == "helm.toolkit.fluxcd.io" && kind == "HelmRelease"
	fluxKustomization := group == "kustomize.toolkit.fluxcd.io" && kind == "Kustomization"
	gitops := argoApp || fluxRelease || fluxKustomization

	var walk func(v any, path, was string)
	walk = func(v any, path, was string) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				p, o := join(path, valuesPart(k)), join(was, pathPart(k))
				if configMap && path == "" && (k == "data" || k == "binaryData") {
					continue // its keys are slots already
				}
				s, isStr := c.(string)
				_, isMap := c.(map[string]any)
				l, isList := c.([]any)
				switch {
				case k == "env":
					w.pairs(c, p, o, ruleVariable)
					continue
				case isStr && urlFields[k]:
					w.out = append(w.out, slot{path: p, name: k, value: s, set: func(v any) { x[k] = v }, rule: ruleURL})
					continue
				case isList && urlLists[k]:
					strs := false
					for i, e := range l {
						if es, ok := e.(string); ok {
							strs = true
							w.out = append(w.out, slot{path: p + "[" + strconv.Itoa(i) + "]", name: k, value: es, set: func(v any) { l[i] = v }, rule: ruleURL})
						}
					}
					if strs {
						continue
					}
					// A list of maps under such a name is walked as any is.
				case argoApp && isList && (k == "parameters" || k == "extVars" || k == "tlas"):
					w.pairs(c, p, o, ruleParam)
					continue
				case argoOther && k == "parameters":
					w.pairs(c, p, o, ruleParam)
					continue
				case argoApp && isStr && (k == "values" || k == "templatePatch" || k == "elementsYaml"),
					gitops && isStr && k == "patch":
					w.out = append(w.out, slot{path: p, name: k, value: s, set: func(v any) { x[k] = v }, rule: ruleText})
					continue
				case argoApp && (k == "valuesObject" || k == "elements" || k == "input") && (isMap || isList),
					argoApp && k == "values" && isMap,
					fluxRelease && path == "spec" && k == "values",
					fluxKustomization && path == "spec.postBuild" && k == "substitute":
					// The key that opens the values names nothing itself.
					w.values(c, p, o, "", false)
					continue
				}
				walk(c, p, o)
			}
		case []any:
			names := items(x)
			for i, c := range x {
				at := "[" + names[i] + "]"
				walk(c, path+at, was+at)
			}
		}
	}
	walk(obj, "", "")
	// What the rule before found and this walk passed by (variables under
	// a key this one does not read under) is a slot as it was.
	found := map[string]bool{}
	for _, sl := range w.out {
		if sl.was != "" {
			found[sl.was] = true
		}
	}
	for _, sl := range slotsBefore(obj) {
		if !found[sl.path] {
			sl.was = sl.path
			w.out = append(w.out, sl)
		}
	}
	sort.Slice(w.out, func(i, j int) bool { return w.out[i].path < w.out[j].path })
	return w.out
}

// slotsBefore are the slots as the rule before found them, at the paths
// it gave: every variable with a literal value, under any list called
// env, and every key of a ConfigMap's data. Kept as it was, so that what
// it withheld is withheld, and a snapshot it took is restored.
func slotsBefore(obj map[string]any) []slot {
	var out []slot
	if strOf(obj["kind"]) == "ConfigMap" {
		if d, ok := obj["data"].(map[string]any); ok {
			for k, v := range d {
				if s, ok := v.(string); ok {
					out = append(out, slot{path: "data[" + k + "]", name: k, value: s, set: func(x any) { d[k] = x }})
				}
			}
		}
	}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				p := join(path, pathPart(k))
				if k == "env" {
					names := items(list(c))
					for i, e := range list(c) {
						m, ok := e.(map[string]any)
						s, isStr := m["value"].(string)
						if ok && isStr {
							out = append(out, slot{path: p + "[" + names[i] + "]", name: strOf(m["name"]), value: s, set: func(v any) { m["value"] = v }})
						}
					}
					continue
				}
				walk(c, p)
			}
		case []any:
			names := items(x)
			for i, c := range x {
				walk(c, path+"["+names[i]+"]")
			}
		}
	}
	walk(obj, "")
	return out
}

// items names each element of a list: by its "name" where no other
// element shares it, else by its index. A name that is a number is not
// used: it could be another element's index, and two values would have
// one path. A comma in a name is written another way, since paths are kept
// as a list with commas between them.
func items(l []any) []string {
	count := map[string]int{}
	for _, e := range l {
		m, _ := e.(map[string]any)
		count[strOf(m["name"])]++
	}
	out := make([]string, len(l))
	for i, e := range l {
		m, _ := e.(map[string]any)
		n := strOf(m["name"])
		if n == "" || allDigits(n) || count[n] > 1 {
			out[i] = strconv.Itoa(i)
		} else {
			out[i] = pathPart(n)
		}
	}
	return out
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// pathPart is a name as a part of a slot's path, with what would end a
// path in a list of them written another way.
func pathPart(s string) string {
	return strings.NewReplacer("%", "%25", ",", "%2C").Replace(s)
}

// WithheldDisplay shortens a withheld slot path for people: the container
// and the variable (api/DB_PASSWORD), or the ConfigMap key (data/KEY).
func WithheldDisplay(path string) string {
	path, _ = pathOf(path)
	if strings.HasPrefix(path, "data[") {
		return "data/" + strings.TrimSuffix(strings.TrimPrefix(path, "data["), "]")
	}
	i := strings.LastIndex(path, ".env[")
	if i < 0 {
		return path
	}
	name := strings.TrimSuffix(path[i+len(".env["):], "]")
	owner := path[:i]
	if j := strings.LastIndex(owner, "["); j >= 0 && strings.HasSuffix(owner, "]") {
		return owner[j+1:len(owner)-1] + "/" + name
	}
	return name
}

// TakenAsPlatform begins the reason for what is skipped on evidence a user object
// could also carry, so REPORT.md can list each one where a person will see it.
const TakenAsPlatform = "taken as AKS's: "

// aksByEno says why an object is taken as made by AKS through Eno, the tool it manages some of its
// own objects with. On a real cluster an AKS update changed admission policies
// that read as drift no one made. Eno's mark alone is not enough, since Eno is
// open source and its SDK labels a user's objects the same way, so it takes a
// mark in Microsoft's own names as well: an aks-managed- name, a
// *.kubernetes.azure.com group, or a kubernetes.azure.com/* key. Only
// cluster-scoped objects: those in kube-system are skipped already, and an aks-*
// namespace is a name users pick. Without such a mark (an egress gateway's
// admission policy, some RBAC) an object stays captured, as drift. A user object
// carrying Eno's mark and one of these is still taken as AKS's.
func aksByEno(ns, name string, md map[string]any) string {
	labels, _ := md["labels"].(map[string]any)
	var eno string
	switch {
	case strings.EqualFold(strOf(labels["app.kubernetes.io/managed-by"]), "eno"):
		eno = "labelled managed-by Eno"
	case slices.Contains(managers(md), "eno"):
		eno = "applied by Eno"
	default:
		return ""
	}
	if ns != "" {
		return ""
	}
	switch {
	case strings.HasPrefix(name, "aks-managed-"):
		return eno + ", named aks-managed-"
	case strings.HasSuffix(name, ".kubernetes.azure.com"):
		return eno + ", in the kubernetes.azure.com group"
	}
	annotations, _ := md["annotations"].(map[string]any)
	for _, m := range []map[string]any{labels, annotations} {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if strings.HasPrefix(k, "kubernetes.azure.com/") {
				return eno + ", with " + k
			}
		}
	}
	return ""
}

func managers(md map[string]any) []string {
	set := map[string]bool{}
	for _, f := range list(md["managedFields"]) {
		e, _ := f.(map[string]any)
		// The API server names managers after the executable, so on Windows
		// they are "kube-apiserver.exe". Without trimming, the platform rule
		// matched nothing there and API-server-made objects were captured.
		if m := strings.TrimSuffix(strOf(e["manager"]), ".exe"); m != "" {
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
