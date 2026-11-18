package kube

import (
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A scope that holds something brings a part of a cluster with nothing
// of it running. A GitOps source it brings and does not hold undoes that:
// restored, it syncs its Git path into the drill target, and what the
// scope held back starts. So does what acts outside the cluster for Flux
// (an image automation pushes to Git, a notification provider sends).
// Such an object refuses the restore unless it is held, or accepted by
// name (sourcesRunning).

// runners are the kinds that run under a hold when brought not held: the
// GitOps sources that apply (by their kind as a reason names one), and
// Flux's objects that act outside the cluster, with what they do there.
// Flux's sources that fetch count among them: they reach real Git hosts,
// registries and buckets with the source's credentials. Not Flux's
// ImagePolicy, which only chooses a tag from what an ImageRepository
// found.
var runners = []struct{ group, kind, resource, name, reaches string }{
	{"kustomize.toolkit.fluxcd.io", "Kustomization", "kustomizations", "Flux Kustomization", ""},
	{"helm.toolkit.fluxcd.io", "HelmRelease", "helmreleases", "Flux HelmRelease", ""},
	{"argoproj.io", "Application", "applications", "Argo CD application", ""},
	{"argoproj.io", "ApplicationSet", "applicationsets", "Argo CD ApplicationSet", ""},
	{"image.toolkit.fluxcd.io", "ImageUpdateAutomation", "imageupdateautomations", "Flux ImageUpdateAutomation", "it commits and pushes image updates to its Git repository"},
	{"image.toolkit.fluxcd.io", "ImageRepository", "imagerepositories", "Flux ImageRepository", "it scans its image registry with the registry's credentials"},
	{"notification.toolkit.fluxcd.io", "Provider", "providers", "Flux notification Provider", "it sends what it is given to its chat, webhook or Git host"},
	{"notification.toolkit.fluxcd.io", "Alert", "alerts", "Flux notification Alert", "it sends the cluster's events to its Provider"},
	{"notification.toolkit.fluxcd.io", "Receiver", "receivers", "Flux notification Receiver", "it takes webhooks from outside, which have the sources it names reconcile"},
	{"source.toolkit.fluxcd.io", "GitRepository", "gitrepositories", "Flux GitRepository", "it fetches its Git repository with the source's credentials"},
	{"source.toolkit.fluxcd.io", "HelmRepository", "helmrepositories", "Flux HelmRepository", "it fetches its chart repository or registry with the source's credentials"},
	{"source.toolkit.fluxcd.io", "OCIRepository", "ocirepositories", "Flux OCIRepository", "it pulls its artifact from its OCI registry with the source's credentials"},
	{"source.toolkit.fluxcd.io", "Bucket", "buckets", "Flux Bucket", "it fetches from its storage bucket with the source's credentials"},
	// What helm-controller makes for a HelmRelease is skipped, rendered by
	// it, and the walk refuses the release for it; a held release makes
	// none (helm-controller does not reconcile a suspended one). A
	// HelmChart in the snapshot pulls for itself: with a HelmRepository of
	// type oci, which source-controller does not reconcile, it is what
	// fetches.
	{"source.toolkit.fluxcd.io", "HelmChart", "helmcharts", "Flux HelmChart", "it pulls its chart from the chart source's repository or registry with that source's credentials"},
}

// runner is what of an object brought not held runs under a hold: a
// source that applies (reaches ""), or what acts outside, and what it
// does there.
func runner(o snapshot.Object) (kind, reaches string, ok bool) {
	group, _, _ := strings.Cut(o.APIVersion(), "/")
	if staticRepo(o) {
		return "", "", false
	}
	for _, r := range runners {
		if r.group == group && r.kind == o.Kind() {
			return r.name, r.reaches, true
		}
	}
	return "", "", false
}

// staticRepo reports a HelmRepository of type oci: source-controller
// makes it static and never fetches with it (migrationToStatic returns
// before reconcileSource). Its HelmCharts pull, and are what is refused.
// One the capture left to a source has no spec in the snapshot, so its
// type is not known there, and it counts as one that fetches.
func staticRepo(o snapshot.Object) bool {
	group, _, _ := strings.Cut(o.APIVersion(), "/")
	spec, _ := o.Body["spec"].(map[string]any)
	return group == "source.toolkit.fluxcd.io" && o.Kind() == "HelmRepository" && strOf(spec["type"]) == "oci"
}

// outsideSkip is, for a skip of what acts outside (one a source applies,
// which the capture left to it), its kind and what it does there.
func outsideSkip(sk snapshot.Skip) (kind, reaches string, ok bool) {
	for _, r := range runners {
		if r.reaches != "" && strings.HasPrefix(sk.Resource, r.group+"/") && strings.HasSuffix(sk.Resource, "/"+r.resource) {
			return r.kind, r.reaches, true
		}
	}
	return "", "", false
}

// stopped reports an object that runs nothing as it is, so that it needs
// no hold, as a hold leaves one: a Flux object suspended, an Argo CD application with no
// automated sync, an ApplicationSet whose template has none and nothing
// that could give it one.
func stopped(o snapshot.Object) bool {
	group, _, _ := strings.Cut(o.APIVersion(), "/")
	spec, _ := o.Body["spec"].(map[string]any)
	switch {
	case strings.HasSuffix(group, ".toolkit.fluxcd.io"):
		return spec["suspend"] == true
	case group == "argoproj.io" && o.Kind() == "Application":
		return !automated(spec)
	case group == "argoproj.io" && o.Kind() == "ApplicationSet":
		tmpl, _ := spec["template"].(map[string]any)
		ts, _ := tmpl["spec"].(map[string]any)
		at, _ := setSyncs(spec)
		return !automated(ts) && at == ""
	}
	return false
}

// automated reports an Argo CD application spec that syncs by itself.
// automated with enabled: false (Argo CD 3) does not.
func automated(spec map[string]any) bool {
	policy, _ := spec["syncPolicy"].(map[string]any)
	a, set := policy["automated"]
	if !set || a == nil {
		return false
	}
	if am, ok := a.(map[string]any); ok && am["enabled"] == false {
		return false
	}
	return true
}

// setSyncs names what in an ApplicationSet can sync the Applications it
// makes though its template has no automated sync, and why: a
// templatePatch or a generator's own template can give them a sync policy,
// and a RollingSync strategy has the ApplicationSet controller sync them
// itself (it requires their automated sync off, and syncs them step by
// step). "" when it has none of these. AllAtOnce, the other strategy and
// the default, leaves syncing to each Application.
func setSyncs(spec map[string]any) (at, why string) {
	const patched = "can give the Applications it makes a sync policy its template does not have, and a hold changes only the template"
	if p, _ := spec["templatePatch"].(string); p != "" {
		return "spec.templatePatch", patched
	}
	if st, _ := spec["strategy"].(map[string]any); strOf(st["type"]) == "RollingSync" {
		return "spec.strategy RollingSync", "has the ApplicationSet controller sync the Applications it makes itself, whatever their sync policy, and a hold changes only the template"
	}
	var walk func(v any, at string) string
	walk = func(v any, at string) string {
		switch t := v.(type) {
		case map[string]any:
			if _, ok := t["template"]; ok {
				return at + ".template"
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if w := walk(t[k], at+"."+k); w != "" {
					return w
				}
			}
		case []any:
			for i, e := range t {
				if w := walk(e, fmt.Sprintf("%s[%d]", at, i)); w != "" {
					return w
				}
			}
		}
		return ""
	}
	if at := walk(spec["generators"], "spec.generators"); at != "" {
		return at, patched
	}
	return "", ""
}

// sources finds, for what the capture left to something in the
// namespaces a scope narrows, the object the restore brings that makes
// it: the reason is followed to its owner (an Application that an
// ApplicationSet generates is owned by it) or to its GitOps source, and
// on through what the capture left that one to, until it reaches an
// object of the snapshot as brought, as the webhook check follows it.
type sources struct {
	a    *after
	seen map[string]bool
}

// maker calls hit with the object brought that makes what a skip covers,
// if one does.
func (w *sources) maker(sk snapshot.Skip, hit func(snapshot.Object)) {
	if m := ownedBy.FindStringSubmatch(sk.Reason); m != nil {
		w.owner(m[1], sk.Namespace, m[2], hit)
		return
	}
	if kind, name, ok := SourceOf(sk.Reason); ok && kind != "Crossplane composite" {
		w.source(source{kind, name}, hit)
	}
}

func (w *sources) owner(kind, ns, name string, hit func(snapshot.Object)) {
	key := "owner\x00" + kind + "\x00" + ns + "\x00" + name
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	is := ownerIs(kind, ns, name)
	if w.brought(is, hit) {
		return
	}
	for _, sk := range w.a.s.Skips {
		if w.a.ofKind(sk, kind, ns) && covers(sk, name) {
			w.maker(sk, hit)
		}
	}
}

func (w *sources) source(src source, hit func(snapshot.Object)) {
	key := "source\x00" + src.kind + "\x00" + src.name
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	is, ofSource, name := sourceIs(src)
	if w.brought(is, hit) {
		return
	}
	for _, sk := range w.a.s.Skips {
		if ofSource(sk) && covers(sk, name) {
			w.maker(sk, hit)
		}
	}
}

// brought calls hit with each object brought that is, and says whether
// any was: the chain ends there. One the snapshot holds and this restore
// takes out is not brought, and has no skip to follow: the chain ends
// there too, with nothing.
func (w *sources) brought(is func(snapshot.Object) bool, hit func(snapshot.Object)) bool {
	found := false
	for _, o := range w.a.out.Objects {
		if is(o) {
			found = true
			hit(o)
		}
	}
	return found
}

// legacyInstance is the label Argo CD 2 tracks what an application
// manages by, unless told otherwise: the application's name, or
// namespace_name for one outside Argo CD's own namespace. Ordinary Helm
// charts set it too (to the release's name), so it is read only where an
// Application of that name is brought, and not on what Helm installed
// (meta.helm.sh/release-name): what Argo CD renders from a chart has no
// such annotation. A chart's object applied some other way, beside an
// Application of the release's name, is read as that Application's: the
// refusal is then wrong, and says so, and can be held or accepted.
const legacyInstance = "app.kubernetes.io/instance"

// sourcesNotHeld are the objects brought in out that run as brought (held
// by the scope, an object is brought stopped: see stopped), that a scope
// which holds something refuses a restore for:
//
//   - a GitOps source that makes, directly or through what it makes, what
//     the capture left to it in a namespace the scope narrows;
//   - an Application brought that Argo CD 2's tracking label names on an
//     object of the snapshot in a namespace the scope narrows;
//   - a GitOps source that applies, wherever it is, what acts outside the
//     cluster (the capture left that to it, and the restore does not
//     bring it: the source does);
//   - what acts outside, brought itself, wherever it is.
func sourcesNotHeld(s, out snapshot.Snapshot, narrowed map[string][]int) []ScopeSource {
	w := &sources{a: newAfter(s, s, out, nil), seen: map[string]bool{}}
	found := map[string]*ScopeSource{}
	entry := func(o snapshot.Object) *ScopeSource {
		kind, reaches, ok := runner(o)
		who := o.Kind() + " " + o.Namespace() + "/" + o.Name()
		// As brought: held by the scope, it is suspended, or its
		// automated sync is off, as it is when it was so already.
		if !ok || stopped(o) {
			return nil
		}
		f := found[who]
		if f == nil {
			f = &ScopeSource{Source: kind + " " + o.Namespace() + "/" + o.Name(), Object: who, Namespaces: []string{}, Reaches: reaches, Blocks: true}
			found[who] = f
		}
		return f
	}
	add := func(o snapshot.Object, ns string) {
		if f := entry(o); f != nil && !contains(f.Namespaces, ns) {
			f.Namespaces = append(f.Namespaces, ns)
		}
	}
	for _, sk := range s.Skips {
		if narrowed[sk.Namespace] != nil {
			w.seen = map[string]bool{}
			w.maker(sk, func(o snapshot.Object) { add(o, sk.Namespace) })
		}
		kind, reaches, ok := outsideSkip(sk)
		if !ok {
			continue
		}
		// By its name: one a source applies is skipped by name. What
		// acts outside and is listed per owner ("*") has an owner that is
		// no source, and the walk finds nothing for it.
		w.seen = map[string]bool{}
		w.maker(sk, func(o snapshot.Object) {
			if f := entry(o); f != nil {
				if what := kind + " " + sk.Namespace + "/" + sk.Name + " (" + reaches + ")"; !contains(f.Outside, what) {
					f.Outside = append(f.Outside, what)
				}
			}
		})
	}
	// An Application by name, as the label gives it: bare, or
	// namespace_name for one outside Argo CD's own namespace (a name has
	// no "_", so the two do not meet).
	apps := map[string][]snapshot.Object{}
	for _, o := range out.Objects {
		if group, _, _ := strings.Cut(o.APIVersion(), "/"); group == "argoproj.io" && o.Kind() == "Application" {
			apps[o.Name()] = append(apps[o.Name()], o)
			apps[o.Namespace()+"_"+o.Name()] = append(apps[o.Namespace()+"_"+o.Name()], o)
		}
	}
	for _, o := range s.Objects {
		md, _ := o.Body["metadata"].(map[string]any)
		labels, _ := md["labels"].(map[string]any)
		inst := strOf(labels[legacyInstance])
		if narrowed[o.Namespace()] == nil || inst == "" || annotation(md, "meta.helm.sh/release-name") != "" {
			continue
		}
		for _, app := range apps[inst] {
			add(app, o.Namespace())
		}
	}
	for _, o := range out.Objects {
		if _, reaches, ok := runner(o); ok && reaches != "" {
			entry(o)
		}
	}
	list := make([]ScopeSource, 0, len(found))
	for _, f := range found {
		sort.Strings(f.Namespaces)
		sort.Strings(f.Outside)
		list = append(list, *f)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Object < list[j].Object })
	return list
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// acceptSources marks the objects a scope file accepts under
// sourcesRunning, each by Kind/namespace/name of the object. A pattern is
// refused: a source is let run by a person who has read what its Git path
// applies, and a pattern would let one run that came later. A name that
// accepts nothing is an error: mistyped, it would leave the restore
// refused, or left in after the source was held, it would say a source
// runs that does not.
func acceptSources(found []ScopeSource, accept []string) error {
	for _, p := range accept {
		parts := strings.Split(p, "/")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" || strings.ContainsAny(p, `*?[\`) {
			return fmt.Errorf("sourcesRunning: %q is not Kind/namespace/name of a GitOps source's object (Kustomization/flux-system/root), with no pattern", p)
		}
		who := parts[0] + " " + parts[1] + "/" + parts[2]
		used := false
		for i, f := range found {
			if f.Object == who {
				found[i].Accepted, found[i].Blocks, used = true, false, true
			}
		}
		if !used {
			// What a source applies is not brought: the source is what
			// runs, and what is accepted.
			for _, f := range found {
				for _, o := range f.Outside {
					if strings.HasPrefix(o, who+" (") {
						// A HelmRelease makes its chart; a Kustomization or
						// an application applies what it applies.
						by := "applied"
						if strings.HasPrefix(f.Source, "Flux HelmRelease ") {
							by = "made"
						}
						return fmt.Errorf("sourcesRunning names %q, which is not brought: it is %s by %s, which makes it again once it runs. Name that in sourcesRunning (%s), or hold it", p, by, f.Source, strings.Replace(f.Object, " ", "/", 1))
					}
				}
			}
			return fmt.Errorf("sourcesRunning names %q, and no such object is brought not held that a scope which holds something refuses (a GitOps source that applies into a namespace it narrows, or what acts outside the cluster)", p)
		}
	}
	return nil
}
