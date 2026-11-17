// Package kube captures a Kubernetes cluster into a TruthForm snapshot and
// restores one back. It needs nothing but the cluster's own API: discovery
// says which types exist, and the dynamic client reads and writes any of them,
// including custom resources nobody has written code for.
package kube

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/usetruthform/core/internal/readonly"
	"github.com/usetruthform/core/internal/snapshot"
)

// Clients bundles what capture and restore need for one cluster.
type Clients struct {
	Config    *rest.Config
	Discovery discovery.DiscoveryInterface
	Dynamic   dynamic.Interface
}

// Connect builds clients from a kubeconfig. An empty context uses the
// kubeconfig's current context.
// Connect builds clients for a context. readOnly puts every request behind
// the read-only guard (capture, diff, reading secrets from a source
// cluster); only restore connects without it.
func Connect(kubeconfig, kubeContext string, readOnly bool) (*Clients, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules,
		&clientcmd.ConfigOverrides{CurrentContext: kubeContext}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	// Discovery and listing every type is many requests; the client-go default
	// of 5 QPS makes a capture crawl and trips its own throttling warnings.
	cfg.QPS, cfg.Burst = 50, 100
	if readOnly {
		cfg.Wrap(readonly.Transport)
	}
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Clients{Config: cfg, Discovery: dc, Dynamic: dyn}, nil
}

// Capture reads every capturable object in the cluster.
func Capture(ctx context.Context, c *Clients, p Policy) (snapshot.Snapshot, error) {
	snap := snapshot.Snapshot{Platform: "kubernetes", Policy: p.Name(), Rules: CaptureRules}
	if v, err := c.Discovery.ServerVersion(); err == nil {
		snap.ServerVersion = v.GitVersion
	}

	lists, err := c.Discovery.ServerPreferredResources()
	// A partial failure (one aggregated API down) still returns the groups
	// that worked. Those groups are captured; the failed ones go into coverage
	// as not captured, rather than the whole capture failing or, worse, the
	// missing groups simply not appearing.
	var groupErr *discovery.ErrGroupDiscoveryFailed
	if err != nil && !errors.As(err, &groupErr) {
		return snap, fmt.Errorf("discover resource types: %w", err)
	}
	if groupErr != nil {
		for gv, gerr := range groupErr.Groups {
			snap.Coverage = append(snap.Coverage, snapshot.Coverage{
				Resource: gv.String() + "/*", NotCaptured: "API group discovery failed: " + gerr.Error(),
			})
		}
	}

	p.roots = fluxRoots(ctx, c, lists)
	own := newOwnership()
	for _, rl := range lists {
		gv, err := schema.ParseGroupVersion(rl.GroupVersion)
		if err != nil {
			continue
		}
		for _, r := range rl.APIResources {
			if strings.Contains(r.Name, "/") {
				continue // subresources (pods/log, deployments/scale) are not objects
			}
			gvr := gv.WithResource(r.Name)
			cov := snapshot.Coverage{Resource: resourceID(gvr), Kind: r.Kind}
			switch {
			case p.typeExcluded(gv.Group, r.Name) != "":
				cov.NotCaptured = p.typeExcluded(gv.Group, r.Name)
			case !has(r.Verbs, "list"):
				cov.NotCaptured = "the API offers no list verb, so instances cannot be enumerated"
			case !has(r.Verbs, "create") && !has(r.Verbs, "patch"):
				cov.NotCaptured = "the API offers no create or patch verb, so it could not be restored"
			default:
				if err := captureType(ctx, c, p, gvr, r.Kind, &cov, &snap, own); err != nil {
					cov.NotCaptured = "list failed: " + err.Error()
				}
			}
			snap.Coverage = append(snap.Coverage, cov)
		}
	}
	own.record(&snap)
	sort.Slice(snap.Objects, func(i, j int) bool { return snap.Objects[i].Key() < snap.Objects[j].Key() })

	captured := map[schema.GroupVersionKind]bool{}
	for _, o := range snap.Objects {
		gv, err := schema.ParseGroupVersion(o.APIVersion())
		if err == nil {
			captured[gv.WithKind(o.Kind())] = true
		}
	}
	schemas, err := typeSchemas(c, captured)
	if err != nil {
		// Captured objects are still valid; only change tracking is lost, and
		// the capture says so instead of writing an empty schema set.
		return snap, fmt.Errorf("objects captured, but schemas could not be read: %w", err)
	}
	snap.Schemas = schemas
	return snap, nil
}

// fluxRoots finds what each Flux Kustomization that applies itself reads
// from (its sourceRef), as kind|namespace|name: those are captured, see
// Policy.root. It lists Kustomizations once more than the capture does. A
// cluster without Flux has none, and a list that fails finds none: the
// capture of that type then says why.
func fluxRoots(ctx context.Context, c *Clients, lists []*metav1.APIResourceList) map[string]bool {
	roots := map[string]bool{}
	for _, rl := range lists {
		gv, err := schema.ParseGroupVersion(rl.GroupVersion)
		if err != nil || gv.Group != "kustomize.toolkit.fluxcd.io" {
			continue
		}
		for _, r := range rl.APIResources {
			if r.Name != "kustomizations" || !has(r.Verbs, "list") {
				continue
			}
			cont := ""
			for {
				ul, err := c.Dynamic.Resource(gv.WithResource(r.Name)).List(ctx, metav1.ListOptions{Limit: 500, Continue: cont})
				if err != nil {
					return roots
				}
				for i := range ul.Items {
					obj := ul.Items[i].Object
					obj["apiVersion"], obj["kind"] = gv.String(), r.Kind
					if !selfApplied(obj) {
						continue
					}
					md, _ := obj["metadata"].(map[string]any)
					spec, _ := obj["spec"].(map[string]any)
					ref, _ := spec["sourceRef"].(map[string]any)
					ns := strOf(ref["namespace"])
					if ns == "" {
						ns = strOf(md["namespace"])
					}
					if strOf(ref["kind"]) != "" && strOf(ref["name"]) != "" {
						roots[strOf(ref["kind"])+"|"+ns+"|"+strOf(ref["name"])] = true
					}
				}
				if cont = ul.GetContinue(); cont == "" {
					break
				}
			}
		}
	}
	return roots
}

func captureType(ctx context.Context, c *Clients, p Policy, gvr schema.GroupVersionResource, kind string, cov *snapshot.Coverage, snap *snapshot.Snapshot, own *ownership) error {
	cont := ""
	releases := map[string]bool{} // reason, namespace and release of Helm history already listed
	for {
		ul, err := c.Dynamic.Resource(gvr).List(ctx, metav1.ListOptions{Limit: 500, Continue: cont})
		if err != nil {
			return err
		}
		for i := range ul.Items {
			obj := ul.Items[i].Object
			// The list response omits per-item apiVersion/kind in some API
			// servers; set them so the snapshot document is self-describing.
			obj["apiVersion"], obj["kind"] = gvr.GroupVersion().String(), kind
			if reason := p.skipReason(gvr.Group, gvr.Resource, obj); reason != "" {
				md, _ := obj["metadata"].(map[string]any)
				ns := strOf(md["namespace"])
				if k, n, g, ok := controllerRef(md); ok {
					own.owner[ns+"|"+gvr.Group+"|"+kind+"|"+strOf(md["name"])] = [3]string{g, k, n}
					if reason == ownedReason(k, n) {
						// Listed and counted once its owner's owner is known.
						sk := ownedSkip{resource: resourceID(gvr), ns: ns, group: g, kind: k, name: n, self: strOf(md["name"])}
						if sk.resource == servicesResource {
							sk.selector = serviceSelector(obj)
						}
						own.skips = append(own.skips, sk)
						continue
					}
				}
				if cov.Skipped == nil {
					cov.Skipped = map[string]int{}
				}
				cov.Skipped[reason]++
				name := strOf(md["name"])
				// Helm history is listed once per release, not per
				// revision: a managed add-on on AKS moves to a new revision
				// every few seconds while keeping the same number of them,
				// and listed by revision the coverage of an unchanged
				// cluster differed between two captures. The count above
				// is still per object.
				if rel, ok := helmRelease(gvr, obj); ok {
					key := reason + "\x00" + strOf(md["namespace"]) + "\x00" + rel
					if releases[key] {
						continue
					}
					releases[key] = true
					name = helmReleasePrefix + rel
				}
				snap.Skips = append(snap.Skips, snapshot.Skip{
					Resource: resourceID(gvr), Namespace: strOf(md["namespace"]), Name: name, Reason: reason,
				})
				continue
			}
			normalize(gvr.Group, gvr.Resource, obj)
			// Compared after normalising, so allocated values (IPs, UIDs)
			// that always differ between clusters don't hide a match. An
			// object with withheld credentials never matches: withheld on
			// both sides, a credential someone changed would compare equal,
			// be skipped as the distribution's, and be lost on restore
			// (review of #41).
			if !hasWithheld(obj) && p.matchesBaseline(obj) {
				md, _ := obj["metadata"].(map[string]any)
				reason := baselineReason
				snap.Skips = append(snap.Skips, snapshot.Skip{
					Resource: resourceID(gvr), Namespace: strOf(md["namespace"]), Name: strOf(md["name"]), Reason: reason,
				})
				if cov.Skipped == nil {
					cov.Skipped = map[string]int{}
				}
				cov.Skipped[reason]++
				continue
			}
			snap.Objects = append(snap.Objects, snapshot.Object{Body: obj})
			cov.Captured++
		}
		cont = ul.GetContinue()
		if cont == "" {
			return nil
		}
	}
}

// ownership collects what controllers own, so what they make (pods,
// ReplicaSets, Jobs) is recorded once per root owner (the Deployment,
// DaemonSet or CronJob) instead of once per instance. Instances come and go
// under a new name with every rollout, node reimage or scheduled run; listed
// one by one, and counted by their immediate owner (a Job named for its
// run), an unchanged cluster captured differently every time.
type ownership struct {
	owner map[string][3]string // namespace|group|Kind|name -> its controller's group, Kind, name
	skips []ownedSkip
}

func newOwnership() *ownership { return &ownership{owner: map[string][3]string{}} }

// ownedSkip is an owned object: its resource and namespace, its
// controller (group, kind, name), its own name (self), and for a Service
// its selector.
type ownedSkip struct {
	resource, ns, group, kind, name, self string
	selector                              map[string]string
}

// serviceSelector is a Service's selector: labels and their values, as
// text. They pick pods and are no credential; a value that is not text
// is no selector the API accepts, and is left.
func serviceSelector(obj map[string]any) map[string]string {
	spec, _ := obj["spec"].(map[string]any)
	sel, _ := spec["selector"].(map[string]any)
	out := map[string]string{}
	for k, v := range sel {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// root follows an owner up to the controller nothing owns.
func (o *ownership) root(ns, group, kind, name string) (string, string) {
	for i := 0; i < 10; i++ {
		up, ok := o.owner[ns+"|"+group+"|"+kind+"|"+name]
		if !ok {
			up, ok = o.owner["|"+group+"|"+kind+"|"+name] // a cluster-scoped owner
		}
		if !ok {
			break
		}
		group, kind, name = up[0], up[1], up[2]
	}
	return kind, name
}

// record lists each type's owned objects once per namespace and root owner,
// and counts them in coverage by owner, not by instance: how many pods a
// DaemonSet has right now is the cluster's, not a change to it.
func (o *ownership) record(snap *snapshot.Snapshot) {
	seen := map[string]bool{}
	byType := map[string]int{}
	for i, c := range snap.Coverage {
		byType[c.Resource] = i
	}
	// The Services an owner has are listed by name with its skip: a
	// Service keeps its name, and something may call it by that name (a
	// webhook), so that whether it will be there can be told. So are the
	// GitOps sources it has (the Applications an ApplicationSet
	// generates), which other skips name as what makes their object.
	// Pods and the rest are not: their names are the cluster's, new with
	// every rollout.
	names := map[string][]string{}
	selectors := map[string]map[string]map[string]string{}
	for _, sk := range o.skips {
		if sk.resource == servicesResource || isSourceResource(sk.resource) {
			k, n := o.root(sk.ns, sk.group, sk.kind, sk.name)
			key := sk.resource + "\x00" + sk.ns + "\x00" + ownedReason(k, n)
			names[key] = append(names[key], sk.self)
			if sk.selector != nil {
				if selectors[key] == nil {
					selectors[key] = map[string]map[string]string{}
				}
				selectors[key][sk.self] = sk.selector
			}
		}
	}
	for _, sk := range o.skips {
		k, n := o.root(sk.ns, sk.group, sk.kind, sk.name)
		reason := ownedReason(k, n)
		key := sk.resource + "\x00" + sk.ns + "\x00" + reason
		if seen[key] {
			continue
		}
		seen[key] = true
		sort.Strings(names[key])
		snap.Skips = append(snap.Skips, snapshot.Skip{Resource: sk.resource, Namespace: sk.ns, Name: "*", Reason: reason, Names: names[key], Selectors: selectors[key]})
		if i, ok := byType[sk.resource]; ok {
			c := &snap.Coverage[i]
			if c.Skipped == nil {
				c.Skipped = map[string]int{}
			}
			c.Skipped[reason]++
		}
	}
}

const helmReleasePrefix = "sh.helm.release.v1."

// baselineReason is the reason for an object identical to the baseline. It
// is decided by the object's content, so it is never read as a move: an
// object captured on one side and left out as this on the other may have
// been edited to or from the baseline.
const baselineReason = "identical to the distribution baseline; a new cluster provides it"

var helmHistoryRE = regexp.MustCompile(`^sh\.helm\.release\.v1\.(.+)\.v\d+$`)

// helmRelease names the release a Helm history Secret belongs to, from the
// name Helm gives it (sh.helm.release.v1.web.v12 is release web). A Secret
// of Helm's type named otherwise, or whose "name" label says another
// release, is not Helm's own and is listed by its name (review of #33).
func helmRelease(gvr schema.GroupVersionResource, obj map[string]any) (string, bool) {
	if gvr.Group != "" || gvr.Resource != "secrets" || strOf(obj["type"]) != "helm.sh/release.v1" {
		return "", false
	}
	md, _ := obj["metadata"].(map[string]any)
	m := helmHistoryRE.FindStringSubmatch(strOf(md["name"]))
	if m == nil {
		return "", false
	}
	labels, _ := md["labels"].(map[string]any)
	if l := strOf(labels["name"]); l != "" && l != m[1] {
		return "", false
	}
	return m[1], true
}

func resourceID(gvr schema.GroupVersionResource) string {
	g := gvr.Group
	if g == "" {
		g = "core"
	}
	return g + "/" + gvr.Version + "/" + gvr.Resource
}

func has(verbs metav1.Verbs, v string) bool {
	for _, x := range verbs {
		if x == v {
			return true
		}
	}
	return false
}

// isSourceResource reports the resource of a GitOps source's own object,
// as a capture writes it (group/version/resources).
func isSourceResource(resource string) bool {
	for _, obj := range sourceObject {
		if strings.HasPrefix(resource, obj.group+"/") && strings.HasSuffix(resource, "/"+obj.resource) {
			return true
		}
	}
	return false
}
