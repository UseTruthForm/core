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

// runner is what of an object brought not held runs under a hold: a
// source that applies (its kind as a reason names one), or "" with
// reaches saying what it does outside.
func runner(o snapshot.Object) (kind, reaches string, ok bool) {
	group, _, _ := strings.Cut(o.APIVersion(), "/")
	switch {
	case group == "kustomize.toolkit.fluxcd.io" && o.Kind() == "Kustomization":
		return "Flux Kustomization", "", true
	case group == "helm.toolkit.fluxcd.io" && o.Kind() == "HelmRelease":
		return "Flux HelmRelease", "", true
	case group == "argoproj.io" && o.Kind() == "Application":
		return "Argo CD application", "", true
	case group == "argoproj.io" && o.Kind() == "ApplicationSet":
		return "Argo CD ApplicationSet", "", true
	case group == "image.toolkit.fluxcd.io" && o.Kind() == "ImageUpdateAutomation":
		return "Flux ImageUpdateAutomation", "it commits and pushes image updates to its Git repository", true
	case group == "image.toolkit.fluxcd.io" && o.Kind() == "ImageRepository":
		return "Flux ImageRepository", "it scans its image registry with the registry's credentials", true
	case group == "notification.toolkit.fluxcd.io" && o.Kind() == "Provider":
		return "Flux notification Provider", "it sends what it is given to its chat, webhook or Git host", true
	case group == "notification.toolkit.fluxcd.io" && o.Kind() == "Alert":
		return "Flux notification Alert", "it sends the cluster's events to its Provider", true
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
		return !automated(ts) && setTemplates(spec) == ""
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

// setTemplates names what in an ApplicationSet can give the Applications
// it makes a sync policy its template does not have: a templatePatch, or
// a generator's own template. "" when it has neither.
func setTemplates(spec map[string]any) string {
	if p, _ := spec["templatePatch"].(string); p != "" {
		return "spec.templatePatch"
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
	return walk(spec["generators"], "spec.generators")
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
// manages by, unless told otherwise. Helm charts carry it too (the
// release's name), so it is read only where an Application of that name
// is brought, and not on what Helm installed (meta.helm.sh/release-name):
// what Argo CD renders from a chart has no such annotation.
const legacyInstance = "app.kubernetes.io/instance"

// sourcesNotHeld are the objects brought in out that run as brought (held
// by the scope, an object is brought stopped: see stopped),
// that a scope which holds something refuses a restore for: a GitOps
// source that makes, directly or through what it makes, what the capture
// left to it in a namespace the scope narrows, or an object of the
// snapshot there that carries Argo CD 2's tracking label of an
// Application brought; and, wherever they are, Flux's objects that act
// outside the cluster.
func sourcesNotHeld(s, out snapshot.Snapshot, narrowed map[string][]int) []ScopeSource {
	w := &sources{a: newAfter(s, s, out, nil), seen: map[string]bool{}}
	found := map[string]*ScopeSource{}
	add := func(o snapshot.Object, ns string) {
		kind, reaches, ok := runner(o)
		who := o.Kind() + " " + o.Namespace() + "/" + o.Name()
		// As brought: held by the scope, it is suspended, or its
		// automated sync is off, as it is when it was so already.
		if !ok || stopped(o) {
			return
		}
		f := found[who]
		if f == nil {
			f = &ScopeSource{Source: kind + " " + o.Namespace() + "/" + o.Name(), Object: who, Namespaces: []string{}, Reaches: reaches, Blocks: true}
			found[who] = f
		}
		if ns != "" && !contains(f.Namespaces, ns) {
			f.Namespaces = append(f.Namespaces, ns)
		}
	}
	for _, sk := range s.Skips {
		if narrowed[sk.Namespace] == nil {
			continue
		}
		w.seen = map[string]bool{}
		w.maker(sk, func(o snapshot.Object) {
			if _, reaches, _ := runner(o); reaches == "" {
				add(o, sk.Namespace)
			}
		})
	}
	apps := map[string][]snapshot.Object{}
	for _, o := range out.Objects {
		if group, _, _ := strings.Cut(o.APIVersion(), "/"); group == "argoproj.io" && o.Kind() == "Application" {
			apps[o.Name()] = append(apps[o.Name()], o)
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
			add(o, "")
		}
	}
	list := make([]ScopeSource, 0, len(found))
	for _, f := range found {
		sort.Strings(f.Namespaces)
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
			return fmt.Errorf("sourcesRunning names %q, and no such object is brought not held that a scope which holds something refuses (a GitOps source that applies into a namespace it narrows, or what acts outside the cluster)", p)
		}
	}
	return nil
}
