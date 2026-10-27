// Package kube captures a Kubernetes cluster into a StackDNA snapshot and
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

	"github.com/stackdna/core/internal/readonly"
	"github.com/stackdna/core/internal/snapshot"
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
	snap := snapshot.Snapshot{Platform: "kubernetes", Policy: p.Name()}
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
				if err := captureType(ctx, c, p, gvr, r.Kind, &cov, &snap); err != nil {
					cov.NotCaptured = "list failed: " + err.Error()
				}
			}
			snap.Coverage = append(snap.Coverage, cov)
		}
	}
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

func captureType(ctx context.Context, c *Clients, p Policy, gvr schema.GroupVersionResource, kind string, cov *snapshot.Coverage, snap *snapshot.Snapshot) error {
	cont := ""
	releases := map[string]bool{} // namespace/release of Helm history already recorded
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
				name := strOf(md["name"])
				// Helm history is recorded once per release, not per
				// revision: a managed add-on on AKS moves to a new revision
				// every few seconds, and listed by revision the coverage
				// of an unchanged cluster differed between two captures.
				if rel, ok := helmRelease(gvr, obj); ok {
					if releases[strOf(md["namespace"])+"/"+rel] {
						continue
					}
					releases[strOf(md["namespace"])+"/"+rel] = true
					name = helmReleasePrefix + rel
				}
				snap.Skips = append(snap.Skips, snapshot.Skip{
					Resource: resourceID(gvr), Namespace: strOf(md["namespace"]), Name: name, Reason: reason,
				})
				if cov.Skipped == nil {
					cov.Skipped = map[string]int{}
				}
				cov.Skipped[reason]++
				continue
			}
			normalize(gvr.Group, gvr.Resource, obj)
			// Compared after normalising, so allocated values (IPs, UIDs)
			// that always differ between clusters don't hide a match.
			if p.matchesBaseline(obj) {
				md, _ := obj["metadata"].(map[string]any)
				reason := "identical to the distribution baseline; a new cluster provides it"
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

const helmReleasePrefix = "sh.helm.release.v1."

var helmRevisionRE = regexp.MustCompile(`\.v\d+$`)

// helmRelease names the release a Helm history Secret belongs to: its
// "name" label, which Helm sets, or else its name without the prefix and
// the revision suffix (sh.helm.release.v1.web.v12 is release web).
func helmRelease(gvr schema.GroupVersionResource, obj map[string]any) (string, bool) {
	if gvr.Group != "" || gvr.Resource != "secrets" || strOf(obj["type"]) != "helm.sh/release.v1" {
		return "", false
	}
	md, _ := obj["metadata"].(map[string]any)
	labels, _ := md["labels"].(map[string]any)
	if rel := strOf(labels["name"]); rel != "" {
		return rel, true
	}
	return helmRevisionRE.ReplaceAllString(strings.TrimPrefix(strOf(md["name"]), helmReleasePrefix), ""), true
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
