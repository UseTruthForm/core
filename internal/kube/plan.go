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
	// HelmRelease, an Argo CD application): restoring the source recreates
	// what it makes, and the snapshot holds neither.
	Sources []PlanSource `json:"installFirst"`
	// OriginRecorded is whether the snapshot holds where those sources are
	// read from (a GitRepository, an OCIRepository, a Bucket, a HelmRepository).
	OriginRecorded bool `json:"originRecorded"`
	// Operators are API groups the snapshot has objects of and no
	// CustomResourceDefinition for: the restore needs them served first.
	Operators []PlanOperator `json:"operators"`
	// ByHand are Secrets no store in the snapshot supplies.
	ByHand []PlanSecret `json:"secretsByHand"`
	// Reissued are Secrets cert-manager makes again by itself
	// (namespace/name): a certificate it issued, its own CA.
	Reissued []string `json:"secretsReissued"`
	// FromStore are the store items other Secrets are made from.
	FromStore []PlanStoreItem `json:"secretsFromStore"`
	// Hosts are the names routes answer to.
	Hosts []string `json:"hosts"`
}

type PlanSource struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Objects int    `json:"objects"`
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
}

type PlanStoreItem struct {
	Store   string   `json:"store"`
	Item    string   `json:"item"`
	Secrets []string `json:"secrets"` // namespace/name
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

// originKinds say where a GitOps source is read from.
var originKinds = map[string]bool{"GitRepository": true, "OCIRepository": true, "Bucket": true, "HelmRepository": true, "HelmChart": true}

// secretRefs are the fields that name a Secret an object uses.
var secretRefs = map[string]bool{"secretKeyRef": true, "secretRef": true, "authSecretRef": true}

var hostMatch = regexp.MustCompile("Host(?:SNI)?\\(([^)]*)\\)")
var hostName = regexp.MustCompile("`([^`]+)`")

// RebuildPlan reads the plan out of a Kubernetes snapshot.
func RebuildPlan(s snapshot.Snapshot) Plan {
	p := Plan{Sources: []PlanSource{}, Operators: []PlanOperator{}, ByHand: []PlanSecret{}, Reissued: []string{}, FromStore: []PlanStoreItem{}, Hosts: []string{}}

	sources := map[PlanSource]int{}
	for _, sk := range s.Skips {
		if kind, name, ok := SourceOf(sk.Reason); ok {
			sources[PlanSource{Kind: kind, Name: name}]++
		}
	}
	for src, n := range sources {
		src.Objects = n
		p.Sources = append(p.Sources, src)
	}
	sort.Slice(p.Sources, func(i, j int) bool {
		a, b := p.Sources[i], p.Sources[j]
		if a.Objects != b.Objects {
			return a.Objects > b.Objects
		}
		return a.Kind+" "+a.Name < b.Kind+" "+b.Name
	})

	served := map[string]bool{}
	for _, o := range s.Objects {
		if o.Kind() == "CustomResourceDefinition" {
			spec, _ := o.Body["spec"].(map[string]any)
			served[strOf(spec["group"])] = true
		}
	}
	// Who supplies each Secret (namespace/name), and from which item.
	type origin struct{ store, item string }
	supplied := map[string][]origin{}
	usedBy := map[string]map[string]bool{}
	operators := map[string]map[string]int{}
	hosts := map[string]bool{}
	for _, o := range s.Objects {
		group, _, versioned := strings.Cut(o.APIVersion(), "/")
		if versioned && strings.Contains(group, ".") && !strings.HasSuffix(group, ".k8s.io") && !served[group] {
			if operators[group] == nil {
				operators[group] = map[string]int{}
			}
			operators[group][o.Kind()]++
		}
		if versioned && strings.HasSuffix(group, ".toolkit.fluxcd.io") && originKinds[o.Kind()] {
			p.OriginRecorded = true
		}
		spec, _ := o.Body["spec"].(map[string]any)
		switch {
		case o.Kind() == "OnePasswordItem":
			key := o.Namespace() + "/" + o.Name()
			supplied[key] = append(supplied[key], origin{"1Password", strOf(spec["itemPath"])})
		case o.Kind() == "ExternalSecret":
			target, _ := spec["target"].(map[string]any)
			name := strOf(target["name"])
			if name == "" {
				name = o.Name()
			}
			ref, _ := spec["secretStoreRef"].(map[string]any)
			store := strOf(ref["kind"])
			if store == "" {
				store = "SecretStore"
			}
			store += " " + strOf(ref["name"])
			key := o.Namespace() + "/" + name
			items := externalItems(spec)
			if len(items) == 0 {
				items = []string{""}
			}
			for _, item := range items {
				supplied[key] = append(supplied[key], origin{store, item})
			}
		}
		if o.Kind() != "Secret" {
			who := o.Kind() + "/" + o.Name()
			for _, name := range secretsUsed(o.Body) {
				key := o.Namespace() + "/" + name
				if usedBy[key] == nil {
					usedBy[key] = map[string]bool{}
				}
				usedBy[key][who] = true
			}
			for _, h := range hostsOf(o) {
				hosts[h] = true
			}
		}
	}
	for group, kinds := range operators {
		p.Operators = append(p.Operators, PlanOperator{Group: group, Objects: kinds})
	}
	sort.Slice(p.Operators, func(i, j int) bool { return p.Operators[i].Group < p.Operators[j].Group })

	items := map[origin][]string{}
	for key, from := range supplied {
		for _, o := range from {
			items[o] = append(items[o], key)
		}
	}
	for o, secrets := range items {
		sort.Strings(secrets)
		p.FromStore = append(p.FromStore, PlanStoreItem{Store: o.store, Item: o.item, Secrets: secrets})
	}
	sort.Slice(p.FromStore, func(i, j int) bool {
		a, b := p.FromStore[i], p.FromStore[j]
		if len(a.Secrets) != len(b.Secrets) {
			return len(a.Secrets) > len(b.Secrets)
		}
		return a.Store+" "+a.Item < b.Store+" "+b.Item
	})

	for _, o := range s.Objects {
		key := o.Namespace() + "/" + o.Name()
		// A service account's token is the cluster's to make.
		if o.Kind() != "Secret" || o.APIVersion() != "v1" || supplied[key] != nil || strOf(o.Body["type"]) == "kubernetes.io/service-account-token" {
			continue
		}
		md, _ := o.Body["metadata"].(map[string]any)
		labels, _ := md["labels"].(map[string]any)
		if annotation(md, "cert-manager.io/certificate-name") != "" || strOf(labels["app.kubernetes.io/managed-by"]) == "cert-manager" {
			p.Reissued = append(p.Reissued, key)
			continue
		}
		sec := PlanSecret{Namespace: o.Namespace(), Name: o.Name(), Keys: []string{}, UsedBy: []string{}}
		for _, field := range []string{"data", "stringData"} {
			m, _ := o.Body[field].(map[string]any)
			for k := range m {
				sec.Keys = append(sec.Keys, k)
			}
		}
		sort.Strings(sec.Keys)
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

	sort.Strings(p.Reissued)

	for h := range hosts {
		p.Hosts = append(p.Hosts, h)
	}
	sort.Strings(p.Hosts)
	return p
}

// externalItems are the store keys an ExternalSecret reads.
func externalItems(spec map[string]any) []string {
	seen := map[string]bool{}
	add := func(ref any) {
		m, _ := ref.(map[string]any)
		if k := strOf(m["key"]); k != "" {
			seen[k] = true
		}
	}
	for _, d := range list(spec["data"]) {
		m, _ := d.(map[string]any)
		add(m["remoteRef"])
	}
	for _, d := range list(spec["dataFrom"]) {
		m, _ := d.(map[string]any)
		add(m["extract"])
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// secretsUsed are the Secrets an object names, wherever in it: an env
// value, a volume, a pull secret, a route's certificate, a scaler's
// credentials.
func secretsUsed(v any) []string {
	seen := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				switch {
				case secretRefs[k]:
					m, _ := child.(map[string]any)
					if n := strOf(m["name"]); n != "" {
						seen[n] = true
					}
				case k == "secretName":
					if n := strOf(child); n != "" {
						seen[n] = true
					}
				case k == "imagePullSecrets":
					for _, e := range list(child) {
						m, _ := e.(map[string]any)
						if n := strOf(m["name"]); n != "" {
							seen[n] = true
						}
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(v)
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// hostsOf are the names a route answers to: an Ingress's rules and
// certificates, a Gateway API route's hostnames, a Traefik route's Host()
// matches.
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
	case "HTTPRoute", "GRPCRoute", "TLSRoute":
		for _, h := range list(spec["hostnames"]) {
			out = append(out, strOf(h))
		}
	case "IngressRoute", "IngressRouteTCP":
		for _, r := range list(spec["routes"]) {
			m, _ := r.(map[string]any)
			for _, call := range hostMatch.FindAllStringSubmatch(strOf(m["match"]), -1) {
				for _, h := range hostName.FindAllStringSubmatch(call[1], -1) {
					out = append(out, h[1])
				}
			}
		}
	}
	hosts := out[:0]
	for _, h := range out {
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
