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

	"github.com/usetruthform/core/internal/snapshot"
)

// FieldManager is the server-side-apply owner TruthForm writes as, so a later
// diff or a human can see which fields a restore set.
const FieldManager = "truthform"

// RestoreOptions control where secret values come from.
type RestoreOptions struct {
	// SecretSource, if set, is a live cluster to read withheld secret values
	// from at restore time (a migration or a restore drill). Values pass
	// straight from one API to the other and are never written to disk.
	SecretSource *Clients
	// Values, if set, gives the withheld values of the Secrets it knows
	// (a secret sources file): asked first, and SecretSource for the rest.
	// known false is a Secret it has nothing for.
	Values func(ctx context.Context, namespace, name string, keys []string) (values map[string][]byte, known bool, err error)
	// Settings, if set, gives the credentials withheld from an object that
	// is not a Secret (set as plain configuration: a variable, a URL that
	// signs in), by the object's key and each value's path. Asked first,
	// and SecretSource for an object it has nothing for (known false).
	Settings func(ctx context.Context, key string, paths []string) (values map[string]string, known bool, err error)
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
	// supplied are the values put into the object here, which no message
	// about it may repeat.
	var supplied []string

	if o.Kind() == "Secret" && o.APIVersion() == "v1" {
		if keys := withheldKeys(body); len(keys) > 0 {
			var given map[string][]byte
			known := false
			if opt.Values != nil {
				var err error
				if given, known, err = opt.Values(ctx, o.Namespace(), o.Name(), keys); err != nil {
					res.Detail = "could not read withheld values from their sources: " + err.Error() + "; nothing was applied"
					return res
				}
			}
			switch {
			case known:
				// encoding/json writes bytes as base64, which is what a
				// Secret's data is.
				data := map[string]any{}
				for _, k := range keys {
					v, ok := given[k]
					supplied = append(supplied, string(v))
					if !ok {
						res.Detail = "the secret sources give no value for key " + k + "; nothing was applied"
						return res
					}
					data[k] = v
				}
				body["data"] = data
			case opt.SecretSource == nil:
				res.Detail = "secret values were withheld from the snapshot (keys: " + strings.Join(keys, ", ") + "); supply them with --secrets-from or --secrets-from-context, nothing was applied"
				return res
			default:
				if err := fillSecret(ctx, opt.SecretSource, body, keys); err != nil {
					res.Detail = "could not read withheld values from the source cluster: " + err.Error()
					return res
				}
			}
		}
	}

	// A credential set as a plain env value is withheld like a Secret's: a
	// workload restored with it empty would look restored and fail at run
	// time, so it is refused without a source to read the value from.
	envNames := withheldEnv(body)
	if len(envNames) > 0 && opt.Settings != nil {
		given, known, err := opt.Settings(ctx, o.Key(), envNames)
		if err != nil {
			res.Detail = "could not read withheld values from their sources: " + err.Error() + "; nothing was applied"
			return res
		}
		if known {
			for _, v := range given {
				supplied = append(supplied, v)
			}
			if err := setSlots(body, envNames, given); err != nil {
				res.Detail = "the secret sources do not fill what was withheld: " + err.Error() + "; nothing was applied"
				return res
			}
			envNames = nil
		}
	}
	if len(envNames) > 0 && opt.SecretSource == nil {
		res.Detail = "credentials set as plain configuration were withheld from the snapshot (" + strings.Join(displays(envNames), ", ") + "); supply them with --secrets-from or --secrets-from-context, or move them into a Secret; nothing was applied"
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
		// The API server may quote a value it refuses: not one that was
		// withheld and supplied.
		res.Detail = redacted(err.Error(), supplied)
		return res
	}
	res.OK = true
	return res
}

// redacted is text with each of the values taken out of it.
func redacted(text string, values []string) string {
	for _, v := range values {
		if len(v) >= 4 {
			text = strings.ReplaceAll(text, v, "(a supplied value)")
		}
	}
	return text
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
	return fillFrom(live.Object, body, paths)
}

// fillFrom fills body's withheld slots with what the same slots of live
// hold.
func fillFrom(live, body map[string]any, paths []string) error {
	// Read by each slot's own path, whatever the snapshot calls it.
	targets, err := findSlots(body, paths)
	if err != nil {
		return fmt.Errorf("the source: %w", err)
	}
	own := map[string]string{}
	for _, sl := range slots(live) {
		own[sl.path] = sl.value
	}
	values := map[string]string{}
	for _, p := range paths {
		at, _ := pathOf(p)
		if v, ok := own[targets[at].path]; ok {
			values[p] = v
		}
	}
	if err := setSlots(body, paths, values); err != nil {
		return fmt.Errorf("the source: %w", err)
	}
	return nil
}

// findSlots finds the slot of body each path names. A path is a slot's
// own, or the one the rule before gave it (slot.was): a snapshot taken by
// that rule names its slots so. Where a path is one slot's own and was
// another's (a key with a dot in it beside the same keys nested), it is
// the one whose value is gone from the snapshot, if that is one of them;
// and where that cannot be told, an error, so that no value is put where
// another belongs.
func findSlots(body map[string]any, paths []string) (map[string]slot, error) {
	own := map[string]slot{}
	twice := map[string]bool{}
	was := map[string][]slot{}
	for _, sl := range slots(body) {
		if _, dup := own[sl.path]; dup {
			twice[sl.path] = true
		}
		own[sl.path] = sl
		if sl.was != "" && sl.was != sl.path {
			was[sl.was] = append(was[sl.was], sl)
		}
	}
	asked := map[string]bool{}
	marked := map[string]bool{}
	for _, p := range paths {
		at, isOwn := pathOf(p)
		if twice[at] || asked[at] {
			return nil, fmt.Errorf("two values of the object are at %s; which is which cannot be told", at)
		}
		asked[at] = true
		marked[at] = isOwn
	}
	out := map[string]slot{}
	for at := range asked {
		if sl, isOwn := own[at]; marked[at] && isOwn {
			// The snapshot says it is this slot's own path.
			out[at] = sl
			continue
		}
		// Not one asked for by its own path as well.
		var others []slot
		for _, sl := range was[at] {
			if !asked[sl.path] {
				others = append(others, sl)
			}
		}
		sl, isOwn := own[at]
		switch {
		case isOwn && len(others) == 0:
		case isOwn && len(others) == 1 && sl.value != "" && others[0].value == "":
			sl = others[0]
		case isOwn && sl.value == "" && !anyEmpty(others):
		case !isOwn && len(others) == 1:
			sl = others[0]
		case !isOwn && len(others) == 0:
			return nil, fmt.Errorf("the snapshot has no slot %s", at)
		default:
			return nil, fmt.Errorf("two values of the object could be at %s; which is which cannot be told", at)
		}
		out[at] = sl
	}
	return out, nil
}

func anyEmpty(l []slot) bool {
	for _, sl := range l {
		if sl.value == "" {
			return true
		}
	}
	return false
}

// setSlots writes a value into each withheld slot of body, values being
// by the paths asked for. Two slots of one path, or a path asked for twice,
// is an error: one of them would be left empty, and the object applied as
// if it were whole.
func setSlots(body map[string]any, paths []string, values map[string]string) error {
	targets, err := findSlots(body, paths)
	if err != nil {
		return err
	}
	// Every value is checked before any is written.
	fill := map[string]any{}
	for _, p := range paths {
		at, _ := pathOf(p)
		v, ok := values[p]
		if !ok {
			v, ok = values[at] // a line written without its marks
		}
		if !ok {
			return fmt.Errorf("no value for %s", p)
		}
		fill[at] = v
		if strings.HasSuffix(p, numberMark) {
			n, err := asNumber(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			fill[at] = n
		}
	}
	for at, v := range fill {
		targets[at].set(v)
	}
	return nil
}

// Withheld is an object that is not a Secret with credentials withheld
// from it, and where in it each was.
type Withheld struct {
	Key   string   `json:"object"`
	Paths []string `json:"paths"`
}

// WithheldSettings are the objects of a snapshot that a restore refuses
// until each value withheld from them is supplied.
func WithheldSettings(s snapshot.Snapshot) []Withheld {
	out := []Withheld{}
	for _, o := range s.Objects {
		md, _ := o.Body["metadata"].(map[string]any)
		if v := annotation(md, WithheldEnvAnnotation); v != "" {
			out = append(out, Withheld{Key: o.Key(), Paths: strings.Split(v, ",")})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
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
