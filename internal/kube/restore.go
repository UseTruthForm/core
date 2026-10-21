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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/restmapper"

	"github.com/stackdna/core/internal/snapshot"
)

// FieldManager is the server-side-apply owner StackDNA writes as, so a later
// diff or a human can see which fields a restore set.
const FieldManager = "stackdna"

// Result is the outcome for one object. Restore never drops an object
// quietly: everything in the snapshot ends up here as applied or not.
type Result struct {
	Key    string
	OK     bool
	Detail string
}

// RestoreOptions control where secret values come from.
type RestoreOptions struct {
	// SecretSource, if set, is a live cluster to read withheld secret values
	// from at restore time (a migration or a restore drill). Values pass
	// straight from one API to the other and are never written to disk.
	SecretSource *Clients
}

// Restore applies every object in the snapshot to the target cluster.
func Restore(ctx context.Context, c *Clients, snap snapshot.Snapshot, opt RestoreOptions) []Result {
	var results []Result
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

func applyOne(ctx context.Context, c *Clients, mapper meta.RESTMapper, o snapshot.Object, opt RestoreOptions) Result {
	res := Result{Key: o.Key()}
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
	data, err := json.Marshal(body)
	if err != nil {
		res.Detail = err.Error()
		return res
	}
	ri := c.Dynamic.Resource(mapping.Resource)
	force := true
	po := metav1.PatchOptions{FieldManager: FieldManager, Force: &force}
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

func waitForCRDs(ctx context.Context, c *Clients, crds []snapshot.Object) {
	gvr := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	deadline := time.Now().Add(60 * time.Second)
	for _, o := range crds {
		for time.Now().Before(deadline) {
			u, err := c.Dynamic.Resource(gvr).Get(ctx, o.Name(), metav1.GetOptions{})
			if err == nil && crdEstablished(u.Object) {
				break
			}
			if err != nil && !apierrors.IsNotFound(err) {
				break
			}
			time.Sleep(time.Second)
		}
	}
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
