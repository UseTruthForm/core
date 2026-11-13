package kube

import (
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Plan is what rebuilding a cluster from a snapshot needs beyond the
// snapshot: what to install first, the secrets no restore can bring back,
// and the names the rebuilt cluster answers to. It is read from the
// snapshot alone.
type Plan struct {
	// Sources are what the capture left to a higher-level source (a Flux
	// HelmRelease, an Argo CD application) that is not itself in the
	// snapshot: restoring the source recreates what it makes, and the
	// snapshot holds neither.
	Sources []PlanSource `json:"installFirst"`
	// Follows are sources that a source in the snapshot applies, directly
	// or through another: once the snapshot is restored and its GitOps
	// tool runs, they are applied again without being installed by hand.
	Follows []PlanSource `json:"follows"`
	// Origins are the Flux repository objects in the snapshot (kind
	// namespace/name): where its sources may be read from.
	Origins []string `json:"origins"`
	// Operators are API groups the snapshot has objects of and no
	// CustomResourceDefinition for: the restore needs them served first.
	Operators []PlanOperator `json:"operators"`
	// ByHand are Secrets no store in the snapshot supplies.
	ByHand []PlanSecret `json:"secretsByHand"`
	// Reissued are Secrets something in the cluster makes again by itself:
	// a certificate cert-manager issued, a driver's copy of a storage key.
	Reissued []PlanMade `json:"secretsReissued"`
	// Encrypted are the ways the snapshot shows Secrets kept encrypted
	// (Sealed Secrets, SOPS), with the keys that open them.
	Encrypted []PlanEncrypted `json:"secretsEncrypted"`
	// FromStore are the store items other Secrets are made from.
	FromStore []PlanStoreItem `json:"secretsFromStore"`
	// StoreSecrets is how many Secrets those items make: one made from
	// several items counts once.
	StoreSecrets int `json:"storeSecrets"`
	// Hosts are the names routes answer to.
	Hosts []string `json:"hosts"`
	// Images are the registries the workloads pull from: the rebuilt
	// cluster has to be allowed to pull from each, or the images have to
	// be put somewhere it can (restore --rename names the new place).
	Images []PlanImages `json:"images"`
}

type PlanSource struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Objects int    `json:"objects"`
	// SystemOnly is a source that makes objects in system namespaces only
	// (kube-system): often the cluster's platform installs it itself.
	SystemOnly bool `json:"systemOnly"`
}

type PlanOperator struct {
	Group   string         `json:"group"`
	Objects map[string]int `json:"objects"` // by kind
}

type PlanSecret struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Keys      []string `json:"keys"`
	UsedBy    []string `json:"usedBy"`
	// Note is what the Secret itself says of where it comes from, short of
	// proof that something makes it again.
	Note string `json:"note,omitempty"`
}

// PlanMade is a Secret (namespace/name) and what makes it again.
type PlanMade struct {
	Secret string `json:"secret"`
	By     string `json:"by"`
}

// PlanEncrypted is one way Secrets are kept encrypted. Objects counts the
// encrypted objects where the snapshot shows them. Keys are the Secrets
// (namespace/name) in the snapshot that hold the key, and KeysNotHeld
// those the capture saw and left out (in kube-system). Neither: the key
// is not a Secret the capture saw (for SOPS, a cloud key service).
type PlanEncrypted struct {
	By      string `json:"by"`
	Objects int    `json:"objects,omitempty"`
	// Secrets are the Secrets in the snapshot (namespace/name) that the
	// encrypted objects in it make: their controller's to write.
	Secrets     []string `json:"secrets"`
	Keys        []string `json:"keys"`
	KeysNotHeld []string `json:"keysNotInSnapshot"`
}

// PlanStoreItem is one item of a secret store and the Secrets made from
// it, as namespace/name; "*" for the namespace of a ClusterExternalSecret,
// which the snapshot does not resolve.
type PlanStoreItem struct {
	Store   string   `json:"store"`
	Item    string   `json:"item"`
	Secrets []string `json:"secrets"`
}

// sourceReason reads a skip reason renderedBy wrote back into the source
// it names.
var sourceReason = regexp.MustCompile(`^(?:rendered by (Flux HelmRelease)|applied by (Flux Kustomization)|managed by (Argo CD application)|composed by (Crossplane composite)) ([^;]+);`)

// SourceOf is the higher-level source a skip reason names ("Flux
// HelmRelease", "cert-manager/cert-manager"), if it names one.
func SourceOf(reason string) (kind, name string, ok bool) {
	m := sourceReason.FindStringSubmatch(reason)
	if m == nil {
		return "", "", false
	}
	return m[1] + m[2] + m[3] + m[4], m[5], true
}

// sourceObject is the object a source is, where the plan can tell whether
// the snapshot holds it. By group too: another API has an Application.
var sourceObject = map[string]struct{ group, kind, resource string }{
	"Flux HelmRelease":    {"helm.toolkit.fluxcd.io", "HelmRelease", "helmreleases"},
	"Flux Kustomization":  {"kustomize.toolkit.fluxcd.io", "Kustomization", "kustomizations"},
	"Argo CD application": {"argoproj.io", "Application", "applications"},
}

type source struct{ kind, name string }

// originKinds say where a Flux source is read from.
var originKinds = map[string]bool{"GitRepository": true, "OCIRepository": true, "Bucket": true}

// builtInGroups are the API groups a cluster serves with no
// CustomResourceDefinition. Others ending in .k8s.io (the Gateway API,
// volume snapshots) are installed like any operator's.
var builtInGroups = map[string]bool{
	"admissionregistration.k8s.io": true, "apiextensions.k8s.io": true, "apiregistration.k8s.io": true,
	"authentication.k8s.io": true, "authorization.k8s.io": true, "certificates.k8s.io": true,
	"coordination.k8s.io": true, "discovery.k8s.io": true, "events.k8s.io": true,
	"flowcontrol.apiserver.k8s.io": true, "internal.apiserver.k8s.io": true, "networking.k8s.io": true,
	"node.k8s.io": true, "rbac.authorization.k8s.io": true, "resource.k8s.io": true,
	"scheduling.k8s.io": true, "storage.k8s.io": true, "storagemigration.k8s.io": true,
}

// A Traefik match names hosts as Host(`a`, `b`) or HostSNI("a"). A "!"
// before it excludes the host, and "*" is every host: neither is a name
// to point anywhere.
var hostMatch = regexp.MustCompile("(!\\s*)?\\bHost(?:SNI)?\\(([^)]*)\\)")
var hostName = regexp.MustCompile("[`\"]([^`\"]+)[`\"]")

type secretKey struct{ ns, name string }

func (k secretKey) String() string { return k.ns + "/" + k.name }

// RebuildPlan reads the plan out of a Kubernetes snapshot.
func RebuildPlan(s snapshot.Snapshot) Plan {
	p := Plan{Sources: []PlanSource{}, Follows: []PlanSource{}, Origins: []string{}, Operators: []PlanOperator{}, ByHand: []PlanSecret{}, Reissued: []PlanMade{}, Encrypted: []PlanEncrypted{}, FromStore: []PlanStoreItem{}, Hosts: []string{}}

	// What the snapshot holds: a source that is in it is restored with it,
	// and a type whose definition is in it is served by the restore.
	held := map[source]bool{}
	defined := map[string]bool{}
	// An Argo CD application is named bare in Argo CD's own namespace, and
	// which that is the snapshot does not say: a bare name that
	// applications in several namespaces share is not taken as held.
	argoNamed := map[string][]string{}
	for _, o := range s.Objects {
		if group, _, _ := strings.Cut(o.APIVersion(), "/"); group == "argoproj.io" && o.Kind() == "Application" {
			argoNamed[o.Name()] = append(argoNamed[o.Name()], o.Namespace())
		}
	}
	for _, o := range s.Objects {
		group, _, _ := strings.Cut(o.APIVersion(), "/")
		for kind, obj := range sourceObject {
			if obj.group != group || obj.kind != o.Kind() {
				continue
			}
			if kind == "Argo CD application" {
				// By name, as a reason names it; namespace_name outside
				// Argo CD's own namespace.
				if len(argoNamed[o.Name()]) == 1 {
					held[source{kind, o.Name()}] = true
				}
				held[source{kind, o.Namespace() + "_" + o.Name()}] = true
			} else {
				held[source{kind, o.Namespace() + "/" + o.Name()}] = true
			}
		}
		if o.Kind() == "CustomResourceDefinition" {
			spec, _ := o.Body["spec"].(map[string]any)
			names, _ := spec["names"].(map[string]any)
			defined[strOf(spec["group"])+"/"+strOf(names["kind"])] = true
		}
	}

	// A source's own object, when the capture skipped it, names the source
	// that applies it: a HelmRelease applied by a Kustomization.
	sources := map[source]int{}
	// Whether a source makes something in a system namespace, and in another:
	// what has no namespace says neither.
	system, elsewhere := map[source]bool{}, map[source]bool{}
	parent := map[source]source{}
	for _, sk := range s.Skips {
		kind, name, ok := SourceOf(sk.Reason)
		if !ok {
			continue
		}
		sources[source{kind, name}]++
		switch {
		case systemNamespaces[sk.Namespace]:
			system[source{kind, name}] = true
		case sk.Namespace != "":
			elsewhere[source{kind, name}] = true
		}
		for k, obj := range sourceObject {
			if strings.HasPrefix(sk.Resource, obj.group+"/") && strings.HasSuffix(sk.Resource, "/"+obj.resource) {
				child := source{k, sk.Namespace + "/" + sk.Name}
				if k == "Argo CD application" {
					// As a reason names it: bare in Argo CD's own
					// namespace, namespace_name outside it.
					child.name = sk.Name
					parent[source{k, sk.Namespace + "_" + sk.Name}] = source{kind, name}
				}
				parent[child] = source{kind, name}
			}
		}
	}
	// follows: the source is in the snapshot, or one that is applies it.
	var follows func(src source, seen map[source]bool) bool
	follows = func(src source, seen map[source]bool) bool {
		if held[src] {
			return true
		}
		up, ok := parent[src]
		if !ok || seen[src] {
			return false
		}
		seen[src] = true
		return follows(up, seen)
	}
	for src, n := range sources {
		ps := PlanSource{Kind: src.kind, Name: src.name, Objects: n, SystemOnly: system[src] && !elsewhere[src]}
		if follows(src, map[source]bool{}) {
			p.Follows = append(p.Follows, ps)
		} else {
			p.Sources = append(p.Sources, ps)
		}
	}
	for _, l := range [][]PlanSource{p.Sources, p.Follows} {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Objects != l[j].Objects {
				return l[i].Objects > l[j].Objects
			}
			return l[i].Kind+" "+l[i].Name < l[j].Kind+" "+l[j].Name
		})
	}

	type origin struct{ store, item string }
	items := map[origin]map[string]bool{}
	supplied := map[secretKey]bool{}
	usedBy := map[secretKey]map[string]bool{}
	operators := map[string]map[string]int{}
	hosts := map[string]bool{}
	// acme are the account keys ACME issuers in the snapshot name, and
	// notes what an object in it says a Secret is for.
	acme := map[secretKey]string{}
	notes := map[secretKey]string{}
	reads := func(ns, name string, spec map[string]any) {
		merge := false
		if target, _ := spec["target"].(map[string]any); target != nil {
			if n := strOf(target["name"]); n != "" {
				name = n
			}
			// Merge adds to a Secret that has to be there already.
			merge = strOf(target["creationPolicy"]) == "Merge"
		}
		ref, _ := spec["secretStoreRef"].(map[string]any)
		store := strOf(ref["kind"])
		if store == "" {
			store = "SecretStore"
		}
		store += " " + strOf(ref["name"])
		for _, o := range externalItems(spec, store) {
			if items[origin(o)] == nil {
				items[origin(o)] = map[string]bool{}
			}
			items[origin(o)][ns+"/"+name] = true
		}
		if !merge {
			supplied[secretKey{ns, name}] = true
		}
	}
	for _, o := range s.Objects {
		group, _, versioned := strings.Cut(o.APIVersion(), "/")
		if versioned && strings.Contains(group, ".") && !builtInGroups[group] && !defined[group+"/"+o.Kind()] {
			if operators[group] == nil {
				operators[group] = map[string]int{}
			}
			operators[group][o.Kind()]++
		}
		if versioned && strings.HasSuffix(group, ".toolkit.fluxcd.io") && originKinds[o.Kind()] {
			p.Origins = append(p.Origins, o.Kind()+" "+o.Namespace()+"/"+o.Name())
		}
		spec, _ := o.Body["spec"].(map[string]any)
		for _, r := range storeReaders {
			if r.group != group || r.kind != o.Kind() {
				continue
			}
			store, item, secrets := r.reads(o)
			from := origin{store, item}
			if items[from] == nil {
				// Listed though it makes no Secret: the store has to be
				// reachable for what mounts it.
				items[from] = map[string]bool{}
			}
			for _, k := range secrets {
				items[from][k.String()] = true
				supplied[k] = true
			}
		}
		switch {
		case group == "bitnami.com" && o.Kind() == "SealedSecret":
			// The controller makes the Secret, of the object's own name
			// whatever its template says, from what it holds encrypted.
			supplied[secretKey{o.Namespace(), o.Name()}] = true
		case group == "cert-manager.io" && (o.Kind() == "Issuer" || o.Kind() == "ClusterIssuer"):
			// The account an ACME issuer registers: its key is made, and
			// made again, in the issuer's namespace, or for a ClusterIssuer
			// in the one cert-manager is set to, which the snapshot does
			// not say.
			// Not one the issuer is told not to make: that key is brought
			// to it.
			acmeSpec, _ := spec["acme"].(map[string]any)
			if n := first(fields(o.Body, "spec.acme.privateKeySecretRef.name")); n != "" && acmeSpec["disableAccountKeyGeneration"] != true {
				acme[secretKey{o.Namespace(), n}] = o.Kind() + " " + o.Name()
			}
		case group == "kustomize.toolkit.fluxcd.io" && o.Kind() == "Kustomization":
			if n := first(fields(o.Body, "spec.decryption.secretRef.name")); n != "" {
				notes[secretKey{o.Namespace(), n}] = "the key Flux Kustomization " + o.Namespace() + "/" + o.Name() + " decrypts with (SOPS)"
			}
		}
		switch {
		case group != "external-secrets.io":
		case o.Kind() == "ExternalSecret":
			reads(o.Namespace(), o.Name(), spec)
		case o.Kind() == "ClusterExternalSecret":
			// It makes an ExternalSecret in each namespace it selects,
			// which the snapshot does not say.
			inner, _ := spec["externalSecretSpec"].(map[string]any)
			name := strOf(spec["externalSecretName"])
			if name == "" {
				name = o.Name()
			}
			reads("*", name, inner)
		}
		if o.Kind() != "Secret" {
			who := o.Kind() + "/" + o.Name()
			for _, ref := range secretsUsed(o) {
				if usedBy[ref] == nil {
					usedBy[ref] = map[string]bool{}
				}
				usedBy[ref][who] = true
			}
			for _, h := range hostsOf(o) {
				hosts[h] = true
			}
		}
	}
	sort.Strings(p.Origins)
	for group, kinds := range operators {
		p.Operators = append(p.Operators, PlanOperator{Group: group, Objects: kinds})
	}
	sort.Slice(p.Operators, func(i, j int) bool { return p.Operators[i].Group < p.Operators[j].Group })

	// A Secret nothing above supplies may say itself that a store made it:
	// the object that asked for it is a GitOps source's, and not here.
	isSecret := func(o snapshot.Object) bool { return o.Kind() == "Secret" && o.APIVersion() == "v1" }
	for _, o := range s.Objects {
		key := secretKey{o.Namespace(), o.Name()}
		if !isSecret(o) || supplied[key] || supplied[secretKey{"*", o.Name()}] {
			continue
		}
		if store, item, ok := storeMade(o); ok {
			if items[origin{store, item}] == nil {
				items[origin{store, item}] = map[string]bool{}
			}
			items[origin{store, item}][key.String()] = true
			supplied[key] = true
		}
	}

	made := map[string]bool{}
	for o, secrets := range items {
		it := PlanStoreItem{Store: o.store, Item: o.item, Secrets: make([]string, 0, len(secrets))}
		for k := range secrets {
			it.Secrets = append(it.Secrets, k)
			made[k] = true
		}
		sort.Strings(it.Secrets)
		p.FromStore = append(p.FromStore, it)
	}
	p.StoreSecrets = len(made)
	sort.Slice(p.FromStore, func(i, j int) bool {
		a, b := p.FromStore[i], p.FromStore[j]
		if len(a.Secrets) != len(b.Secrets) {
			return len(a.Secrets) > len(b.Secrets)
		}
		return a.Store+" "+a.Item < b.Store+" "+b.Item
	})

	// lone counts, by name, the Secrets that hold a private key alone.
	lone := map[secretKey]int{}
	for _, o := range s.Objects {
		if k := secretKeys(o); isSecret(o) && len(k) == 1 && k[0] == "tls.key" {
			lone[secretKey{"", o.Name()}]++
		}
	}
	for _, o := range s.Objects {
		key := secretKey{o.Namespace(), o.Name()}
		// A service account's token is the cluster's to make.
		if !isSecret(o) || supplied[key] || supplied[secretKey{"*", o.Name()}] || strOf(o.Body["type"]) == "kubernetes.io/service-account-token" {
			continue
		}
		keys := secretKeys(o)
		by := madeAgain(o)
		if by == azureFiles && len(usedBy[key]) > 0 {
			// The driver makes one for a share it provisions. One that a
			// volume in the snapshot names is looked up, not made: where
			// the cluster cannot list the account's keys, a person put it
			// there.
			by = ""
		}
		if by == "" && len(keys) == 1 && keys[0] == "tls.key" {
			// An ACME account key holds that and nothing else.
			issuer := acme[key]
			if name := (secretKey{"", o.Name()}); issuer == "" && lone[name] == 1 && len(usedBy[key]) == 0 {
				// A ClusterIssuer's is in whichever namespace cert-manager
				// keeps such things in, which the snapshot does not say:
				// taken by name when one Secret alone has the name and the
				// shape, and nothing else uses it.
				issuer = acme[name]
			}
			if issuer != "" {
				by = "cert-manager, as the ACME account of " + issuer
			}
		}
		if by != "" {
			p.Reissued = append(p.Reissued, PlanMade{Secret: key.String(), By: by})
			continue
		}
		sec := PlanSecret{Namespace: o.Namespace(), Name: o.Name(), Keys: keys, UsedBy: []string{}, Note: notes[key]}
		if sec.Note == "" {
			sec.Note = noteOf(o)
		}
		for who := range usedBy[key] {
			sec.UsedBy = append(sec.UsedBy, who)
		}
		sort.Strings(sec.UsedBy)
		p.ByHand = append(p.ByHand, sec)
	}
	sort.Slice(p.ByHand, func(i, j int) bool {
		a, b := p.ByHand[i], p.ByHand[j]
		return a.Namespace+"/"+a.Name < b.Namespace+"/"+b.Name
	})
	sort.Slice(p.Reissued, func(i, j int) bool { return p.Reissued[i].Secret < p.Reissued[j].Secret })
	p.Encrypted = encrypted(s)

	for h := range hosts {
		p.Hosts = append(p.Hosts, h)
	}
	sort.Strings(p.Hosts)
	p.Images = ImagesOf(s)
	return p
}

// externalItems are what an ExternalSecret reads: a store's keys, a
// search of the store, or a generator in the cluster, which is no store.
func externalItems(spec map[string]any, store string) []struct{ store, item string } {
	seen := map[struct{ store, item string }]bool{}
	add := func(store, item string) { seen[struct{ store, item string }{store, item}] = true }
	key := func(ref any) {
		m, _ := ref.(map[string]any)
		if k := strOf(m["key"]); k != "" {
			add(store, k)
		}
	}
	for _, d := range list(spec["data"]) {
		m, _ := d.(map[string]any)
		key(m["remoteRef"])
	}
	for _, d := range list(spec["dataFrom"]) {
		m, _ := d.(map[string]any)
		key(m["extract"])
		if m["find"] != nil {
			add(store, "(found by a search of the store)")
		}
		src, _ := m["sourceRef"].(map[string]any)
		if gen, _ := src["generatorRef"].(map[string]any); gen != nil {
			add("generator in the cluster", strOf(gen["kind"])+" "+strOf(gen["name"]))
		}
	}
	out := make([]struct{ store, item string }, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// secretsUsed are the Secrets an object names, wherever in it: an env
// value, a volume, a pull secret, a route's certificate, an issuer's or a
// scaler's credentials. A reference that gives no namespace is to the
// object's own; from a cluster-scoped object that is no namespace, and
// the reference is not resolved.
func secretsUsed(o snapshot.Object) []secretKey {
	seen := map[secretKey]bool{}
	add := func(ns, name string) {
		if ns == "" {
			ns = o.Namespace()
		}
		if name != "" && ns != "" {
			seen[secretKey{ns, name}] = true
		}
	}
	// named takes every {name, namespace} under a reference: the name is
	// one level down in some (authSecretRef.clientId.name), in a list in
	// others (secretTargetRef).
	var named func(v any)
	named = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if n := strOf(x["name"]); n != "" {
				add(strOf(x["namespace"]), n)
				return
			}
			for _, child := range x {
				named(child)
			}
		case []any:
			for _, child := range x {
				named(child)
			}
		}
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				lower := strings.ToLower(k)
				switch {
				case strings.HasSuffix(lower, "secretref") || lower == "secretkeyref" || lower == "secrettargetref" || lower == "imagepullsecrets":
					named(child)
				case k == "secretName":
					add("", strOf(child))
				case k == "secret":
					// A volume's secret names it secretName, found above;
					// a projected volume's source names it name.
					m, _ := child.(map[string]any)
					add("", strOf(m["name"]))
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(o.Body)
	if o.Kind() == "ServiceAccount" {
		named(o.Body["secrets"])
	}
	out := make([]secretKey, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// hostsOf are the names a route answers to: an Ingress's rules and
// certificates, a Gateway's listeners and its routes' hostnames, a Traefik
// route's Host() matches. A pattern (HostRegexp) names no host.
func hostsOf(o snapshot.Object) []string {
	spec, _ := o.Body["spec"].(map[string]any)
	var out []string
	switch o.Kind() {
	case "Ingress":
		for _, r := range list(spec["rules"]) {
			m, _ := r.(map[string]any)
			out = append(out, strOf(m["host"]))
		}
		for _, t := range list(spec["tls"]) {
			m, _ := t.(map[string]any)
			for _, h := range list(m["hosts"]) {
				out = append(out, strOf(h))
			}
		}
	case "Gateway":
		for _, l := range list(spec["listeners"]) {
			m, _ := l.(map[string]any)
			out = append(out, strOf(m["hostname"]))
		}
	case "HTTPRoute", "GRPCRoute", "TLSRoute":
		for _, h := range list(spec["hostnames"]) {
			out = append(out, strOf(h))
		}
	case "IngressRoute", "IngressRouteTCP":
		for _, r := range list(spec["routes"]) {
			m, _ := r.(map[string]any)
			for _, call := range hostMatch.FindAllStringSubmatch(strOf(m["match"]), -1) {
				if call[1] != "" {
					continue
				}
				for _, h := range hostName.FindAllStringSubmatch(call[2], -1) {
					out = append(out, h[1])
				}
			}
		}
	}
	hosts := out[:0]
	for _, h := range out {
		if h != "" && h != "*" {
			hosts = append(hosts, strings.ToLower(h))
		}
	}
	return hosts
}
