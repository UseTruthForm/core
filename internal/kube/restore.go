package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/restmapper"

	"github.com/stackdna/core/internal/snapshot"
)

// FieldManager is the server-side-apply owner StackDNA writes as, so a later
// diff or a human can see which fields a restore set.
const FieldManager = "stackdna"

// RestoreOptions control where secret values come from.
type RestoreOptions struct {
	// SecretSource, if set, is a live cluster to read withheld secret values
	// from at restore time (a migration or a restore drill). Values pass
	// straight from one API to the other and are never written to disk.
	SecretSource *Clients
}

// Restore applies every object in the snapshot to the target cluster.
func Restore(ctx context.Context, c *Clients, snap snapshot.Snapshot, opt RestoreOptions) []snapshot.Result {
	var results []snapshot.Result
	phases := phase(snap.Objects)

	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(c.Discovery))
	for i, objs := range phases {
		for _, o := range objs {
			results = append(results, applyOne(ctx, c, mapper, o, opt))
		}
		if i == 0 && len(objs) > 0 {
			// New CRDs: the API server needs a moment before it serves the new
			// types, and the cached mapper has to forget what it knew.
			waitForCRDs(ctx, c, objs)
			mapper.Reset()
		}
	}
	return results
}

// phase orders objects so that what others depend on exists first:
// CRDs, then namespaces, then everything else, then admission webhooks last
// (a webhook pointing at a service that is not up yet would reject every
// apply after it).
func phase(objs []snapshot.Object) [][]snapshot.Object {
	out := make([][]snapshot.Object, 4)
	for _, o := range objs {
		switch {
		case o.Kind() == "CustomResourceDefinition":
			out[0] = append(out[0], o)
		case o.Kind() == "Namespace":
			out[1] = append(out[1], o)
		case strings.HasPrefix(o.APIVersion(), "admissionregistration.k8s.io/"):
			out[3] = append(out[3], o)
		default:
			out[2] = append(out[2], o)
		}
	}
	for _, p := range out {
		sort.Slice(p, func(i, j int) bool { return p[i].Key() < p[j].Key() })
	}
	return out
}

func applyOne(ctx context.Context, c *Clients, mapper meta.RESTMapper, o snapshot.Object, opt RestoreOptions) snapshot.Result {
	res := snapshot.Result{Key: o.Key()}
	body := deepCopy(o.Body)

	if o.Kind() == "Secret" && o.APIVersion() == "v1" {
		if keys := withheldKeys(body); len(keys) > 0 {
			if opt.SecretSource == nil {
				res.Detail = "secret values were withheld from the snapshot (keys: " + strings.Join(keys, ", ") + "); supply them with --secrets-from-context, nothing was applied"
				return res
			}
			if err := fillSecret(ctx, opt.SecretSource, body, keys); err != nil {
				res.Detail = "could not read withheld values from the source cluster: " + err.Error()
				return res
			}
		}
	}

	// A credential set as a plain env value is withheld like a Secret's: a
	// workload restored with it empty would look restored and fail at run
	// time, so it is refused without a source to read the value from.
	envNames := withheldEnv(body)
	if len(envNames) > 0 && opt.SecretSource == nil {
		res.Detail = "credentials set as plain configuration were withheld from the snapshot (" + strings.Join(displays(envNames), ", ") + "); supply them with --secrets-from-context, or move them into a Secret; nothing was applied"
		return res
	}

	gv, err := schema.ParseGroupVersion(o.APIVersion())
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	mapping, err := mapper.RESTMapping(gv.WithKind(o.Kind()).GroupKind(), gv.Version)
	if err != nil {
		res.Detail = "the target cluster does not serve " + o.APIVersion() + " " + o.Kind() + ": " + err.Error()
		return res
	}
	if len(envNames) > 0 {
		if err := fillEnv(ctx, opt.SecretSource, mapping, body, envNames); err != nil {
			res.Detail = "could not read withheld env values from the source cluster: " + err.Error()
			return res
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	ri := c.Dynamic.Resource(mapping.Resource)
	force := true
	// Strict: server-side apply already rejects undeclared fields on built-in
	// types and structural CRDs (verified on kind v1.36), but stating it means
	// a change in the server default cannot make restore drop fields quietly.
	po := metav1.PatchOptions{FieldManager: FieldManager, Force: &force, FieldValidation: "Strict"}
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		_, err = ri.Namespace(o.Namespace()).Patch(ctx, o.Name(), types.ApplyPatchType, data, po)
	} else {
		_, err = ri.Patch(ctx, o.Name(), types.ApplyPatchType, data, po)
	}
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	res.OK = true
	return res
}

func withheldKeys(body map[string]any) []string {
	md, _ := body["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	v := strOf(ann[WithheldAnnotation])
	if v == "" {
		return nil
	}
	delete(ann, WithheldAnnotation)
	if len(ann) == 0 {
		delete(md, "annotations")
	}
	return strings.Split(v, ",")
}

func displays(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = WithheldDisplay(p)
	}
	return out
}

func withheldEnv(body map[string]any) []string {
	md, _ := body["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	v := strOf(ann[WithheldEnvAnnotation])
	if v == "" {
		return nil
	}
	delete(ann, WithheldEnvAnnotation)
	if len(ann) == 0 {
		delete(md, "annotations")
	}
	return strings.Split(v, ",")
}

// fillEnv copies each withheld value from the same slot of the same object
// in the source cluster. The values go from one API to the other and are
// never written. A slot the source does not have fails the restore.
func fillEnv(ctx context.Context, src *Clients, mapping *meta.RESTMapping, body map[string]any, paths []string) error {
	md, _ := body["metadata"].(map[string]any)
	ri := src.Dynamic.Resource(mapping.Resource)
	var live *unstructured.Unstructured
	var err error
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		live, err = ri.Namespace(strOf(md["namespace"])).Get(ctx, strOf(md["name"]), metav1.GetOptions{})
	} else {
		live, err = ri.Get(ctx, strOf(md["name"]), metav1.GetOptions{})
	}
	if err != nil {
		return err
	}
	values := map[string]string{}
	for _, sl := range slots(live.Object) {
		values[sl.path] = sl.value
	}
	targets := map[string]slot{}
	for _, sl := range slots(body) {
		targets[sl.path] = sl
	}
	for _, p := range paths {
		v, ok := values[p]
		if !ok {
			return fmt.Errorf("the source has no value for %s", p)
		}
		t, ok := targets[p]
		if !ok {
			return fmt.Errorf("the snapshot has no slot %s", p)
		}
		t.set(v)
	}
	return nil
}

func fillSecret(ctx context.Context, src *Clients, body map[string]any, keys []string) error {
	md, _ := body["metadata"].(map[string]any)
	ns, name := strOf(md["namespace"]), strOf(md["name"])
	live, err := src.Dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	data, _ := live.Object["data"].(map[string]any)
	out := map[string]any{}
	for _, k := range keys {
		v, ok := data[k]
		if !ok {
			return fmt.Errorf("key %q is no longer in the source secret", k)
		}
		out[k] = v
	}
	body["data"] = out
	return nil
}

// waitForCRDs waits until each CRD is Established and its types appear in
// discovery. Established alone is not enough: the API server publishes a
// new group in discovery a moment later, and CI once restored a Widget
// inside that gap ("no matches for kind Widget"), which failed the drill on
// a run that changed no Kubernetes code. The discovery check is the very
// lookup the mapper does next. A CRD still not served at the deadline is
// left to fail in applyOne, by name, rather than passed silently.
func waitForCRDs(ctx context.Context, c *Clients, crds []snapshot.Object) {
	gvr := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	deadline := time.Now().Add(60 * time.Second)
	for _, o := range crds {
		for time.Now().Before(deadline) {
			u, err := c.Dynamic.Resource(gvr).Get(ctx, o.Name(), metav1.GetOptions{})
			if err == nil && crdEstablished(u.Object) && crdDiscoverable(c, u.Object) {
				break
			}
			if err != nil && !apierrors.IsNotFound(err) {
				break
			}
			time.Sleep(time.Second)
		}
	}
}

// crdDiscoverable reports whether discovery lists the CRD's resource for
// every served version.
func crdDiscoverable(c *Clients, crd map[string]any) bool {
	spec, _ := crd["spec"].(map[string]any)
	group, _ := spec["group"].(string)
	names, _ := spec["names"].(map[string]any)
	plural, _ := names["plural"].(string)
	for _, v := range list(spec["versions"]) {
		ver, _ := v.(map[string]any)
		if served, _ := ver["served"].(bool); !served {
			continue
		}
		name, _ := ver["name"].(string)
		res, err := c.Discovery.ServerResourcesForGroupVersion(group + "/" + name)
		if err != nil {
			return false
		}
		found := false
		for _, r := range res.APIResources {
			found = found || r.Name == plural
		}
		if !found {
			return false
		}
	}
	return true
}

func crdEstablished(obj map[string]any) bool {
	st, _ := obj["status"].(map[string]any)
	for _, c := range list(st["conditions"]) {
		cond, _ := c.(map[string]any)
		if cond["type"] == "Established" && cond["status"] == "True" {
			return true
		}
	}
	return false
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return out
}

// Adapter is the Kubernetes implementation of platform.Platform.
type Adapter struct {
	Clients *Clients
	Policy  Policy
	Options RestoreOptions
}

// Name implements platform.Platform.
func (a *Adapter) Name() string { return "kubernetes" }

// Capture implements platform.Platform.
func (a *Adapter) Capture(ctx context.Context) (snapshot.Snapshot, error) {
	return Capture(ctx, a.Clients, a.Policy)
}

// Restore implements platform.Platform.
func (a *Adapter) Restore(ctx context.Context, s snapshot.Snapshot) []snapshot.Result {
	return Restore(ctx, a.Clients, s, a.Options)
}
