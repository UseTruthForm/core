package kube

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A restore need not bring everything: a drill wants the platform, the
// core of an application and a few of its many workloads. A scope says
// which, in terms the cluster already has: namespaces, the releases Helm
// stamped on what it made, labels. It narrows the namespaces it names and
// leaves the rest of the snapshot as it is, so a file written for a drill
// does not have to know the whole cluster, and a namespace added later
// that a pattern fits is left out until someone chooses from it.

// Scope is a scope file.
type Scope struct {
	// Narrow are the namespaces of which only a part is brought.
	Narrow []ScopeEntry `json:"narrow"`
	// Jobs brings the snapshot's Jobs. A Job restored runs again, so with
	// a scope they are left out unless this says otherwise.
	Jobs bool `json:"jobs,omitempty"`
}

// ScopeEntry narrows the namespaces its patterns fit to the releases and
// labels it names. With neither, it brings nothing of those namespaces
// (another entry that fits one of them may).
type ScopeEntry struct {
	// Namespaces are names, or patterns as a shell has them (team-*).
	Namespaces []string `json:"namespaces"`
	// Releases are Helm release names or patterns, in any of the
	// namespaces.
	Releases []string `json:"releases,omitempty"`
	// Labels select objects that carry every one of them.
	Labels map[string]string `json:"labels,omitempty"`
}

// ScopeReport is what a scope did to a snapshot.
type ScopeReport struct {
	// Narrowed are the namespaces the scope narrowed.
	Narrowed []string `json:"narrowed"`
	// Of is how many objects the scope decides on (those in the narrowed
	// namespaces, and what their releases made elsewhere), and Kept how
	// many of them are brought.
	Kept int `json:"kept"`
	Of   int `json:"of"`
	// Brought and LeftOut are the releases of those namespaces
	// (namespace/release), each with how many objects it has, Jobs
	// included.
	Brought []ScopedRelease `json:"brought"`
	LeftOut []ScopedRelease `json:"leftOut"`
	// Jobs are the Jobs left out because a restored Job runs again, those
	// of a release that is brought among them.
	Jobs []string `json:"jobsLeftOut"`
}

type ScopedRelease struct {
	Release string `json:"release"` // namespace/name
	Objects int    `json:"objects"`
}

// ReleaseOf is the Helm release that made an object, as namespace and
// name, by what Helm writes on everything it makes.
func ReleaseOf(o snapshot.Object) (namespace, name string, ok bool) {
	md, _ := o.Body["metadata"].(map[string]any)
	labels, _ := md["labels"].(map[string]any)
	if name = annotation(md, "meta.helm.sh/release-name"); name != "" {
		if namespace = annotation(md, "meta.helm.sh/release-namespace"); namespace == "" {
			namespace = o.Namespace()
		}
		return namespace, name, true
	}
	if strOf(labels["app.kubernetes.io/managed-by"]) == "Helm" && strOf(labels["app.kubernetes.io/instance"]) != "" {
		return o.Namespace(), strOf(labels["app.kubernetes.io/instance"]), true
	}
	return "", "", false
}

// fits marks every pattern that fits v as used, and says whether any did.
// Every one, not the first: a name given beside a pattern that also fits
// it is not a mistake.
func fits(patterns []string, v string, used map[string]bool) bool {
	any := false
	for _, p := range patterns {
		if ok, _ := path.Match(p, v); ok {
			used[p] = true
			any = true
		}
	}
	return any
}

func isJob(o snapshot.Object) bool {
	return o.Kind() == "Job" && strings.HasPrefix(o.APIVersion(), "batch/")
}

// secretMakers says, for each Secret an object of the snapshot makes,
// which object: a store reader, an ExternalSecret, a SealedSecret, a
// cert-manager Certificate. The Secret goes where its maker goes.
func secretMakers(s snapshot.Snapshot) map[secretKey]int {
	maker := map[secretKey]int{}
	for i, o := range s.Objects {
		group, _, _ := strings.Cut(o.APIVersion(), "/")
		spec, _ := o.Body["spec"].(map[string]any)
		for _, r := range storeReaders {
			if r.group == group && r.kind == o.Kind() {
				_, _, secrets := r.reads(o)
				for _, k := range secrets {
					maker[k] = i
				}
			}
		}
		switch {
		case group == "external-secrets.io" && o.Kind() == "ExternalSecret":
			target, _ := spec["target"].(map[string]any)
			name := strOf(target["name"])
			if name == "" {
				name = o.Name()
			}
			maker[secretKey{o.Namespace(), name}] = i
		case group == "bitnami.com" && o.Kind() == "SealedSecret":
			maker[secretKey{o.Namespace(), o.Name()}] = i
		case group == "cert-manager.io" && o.Kind() == "Certificate":
			if name := strOf(spec["secretName"]); name != "" {
				maker[secretKey{o.Namespace(), name}] = i
			}
		}
	}
	return maker
}

// Narrow returns the snapshot as the scope leaves it.
//
// A release belongs to the namespace Helm installed it in. Where the
// scope narrows that namespace, the release is brought if an entry names
// it or one of its objects carries an entry's labels, and it is brought
// or left whole, wherever its objects are (a ClusterRole, an object in
// another namespace). In a narrowed namespace, what belongs to no release
// of a narrowed namespace (shared configuration, a Secret made by hand)
// comes with the namespace when anything of it is brought, and so does
// the Namespace itself; a namespace from which nothing is chosen is left
// out whole, with what the capture left there to a GitOps source. A
// Secret that an object of the snapshot makes goes where that object
// goes. A Job is left out wherever it is, though its release is brought,
// unless the scope says "jobs: true". Everything else is untouched.
//
// Two entries that fit one namespace choose from it together.
//
// A pattern that fits no namespace, and a release or a label that fits
// nothing in the namespaces of its entry, is an error: a mistyped one
// would otherwise leave out what it was written to bring.
func Narrow(s snapshot.Snapshot, sc Scope) (snapshot.Snapshot, ScopeReport, error) {
	rep := ScopeReport{Narrowed: []string{}, Brought: []ScopedRelease{}, LeftOut: []ScopedRelease{}, Jobs: []string{}}
	if sc.Narrow == nil && !sc.Jobs {
		return s, rep, fmt.Errorf("it narrows nothing: give at least one entry under narrow")
	}
	for i, e := range sc.Narrow {
		if len(e.Namespaces) == 0 {
			return s, rep, fmt.Errorf("entry %d names no namespaces", i+1)
		}
		for _, p := range append(append([]string{}, e.Namespaces...), e.Releases...) {
			if _, err := path.Match(p, ""); err != nil || p == "" {
				return s, rep, fmt.Errorf("entry %d: %q is not a name or a pattern", i+1, p)
			}
		}
	}

	// Every namespace the snapshot knows of: where an object is, a
	// Namespace object, where a release was installed.
	namespaces := map[string]bool{}
	for _, o := range s.Objects {
		if o.Namespace() != "" {
			namespaces[o.Namespace()] = true
		}
		if o.Kind() == "Namespace" && o.APIVersion() == "v1" {
			namespaces[o.Name()] = true
		}
		if rns, _, ok := ReleaseOf(o); ok && rns != "" {
			namespaces[rns] = true
		}
	}
	narrowed := map[string][]int{}
	for i, e := range sc.Narrow {
		for _, p := range e.Namespaces {
			any := false
			for ns := range namespaces {
				if ok, _ := path.Match(p, ns); ok {
					any = true
					if l := narrowed[ns]; len(l) == 0 || l[len(l)-1] != i {
						narrowed[ns] = append(narrowed[ns], i)
					}
				}
			}
			if !any {
				return s, rep, fmt.Errorf("entry %d: no namespace in the snapshot fits %q", i+1, p)
			}
		}
	}
	for ns := range narrowed {
		rep.Narrowed = append(rep.Narrowed, ns)
	}
	sort.Strings(rep.Narrowed)

	hasLabels := func(o snapshot.Object, want map[string]string) bool {
		if len(want) == 0 {
			return false
		}
		md, _ := o.Body["metadata"].(map[string]any)
		labels, _ := md["labels"].(map[string]any)
		for k, v := range want {
			if strOf(labels[k]) != v {
				return false
			}
		}
		return true
	}
	releaseUsed := make([]map[string]bool, len(sc.Narrow))
	labelsUsed := make([]bool, len(sc.Narrow))
	for i := range sc.Narrow {
		releaseUsed[i] = map[string]bool{}
	}
	labelled := func(o snapshot.Object, es []int) bool {
		yes := false
		for _, i := range es {
			if hasLabels(o, sc.Narrow[i].Labels) {
				labelsUsed[i], yes = true, true
			}
		}
		return yes
	}

	const (
		untouched = iota
		brought
		left
		ofRelease // of a release of a narrowed namespace: as the release goes
		follows   // of no such release, in a narrowed namespace: as the namespace goes
	)
	type relKey struct{ ns, name string }
	state := make([]int, len(s.Objects))
	rel := make([]relKey, len(s.Objects))
	relObjects := map[relKey]int{}
	relChosen := map[relKey]bool{}
	for i, o := range s.Objects {
		if o.Kind() == "Namespace" && o.APIVersion() == "v1" {
			continue // goes as its namespace does, below
		}
		rns, rname, isRelease := ReleaseOf(o)
		switch {
		case isRelease && narrowed[rns] != nil:
			k := relKey{rns, rname}
			rel[i], state[i] = k, ofRelease
			relObjects[k]++
			for _, e := range narrowed[rns] {
				if fits(sc.Narrow[e].Releases, rname, releaseUsed[e]) {
					relChosen[k] = true
				}
			}
			if labelled(o, narrowed[rns]) {
				relChosen[k] = true
			}
		case o.Namespace() != "" && narrowed[o.Namespace()] != nil:
			// Of no release, or of one installed in a namespace the scope
			// does not narrow: it is here, and goes as here goes.
			state[i] = follows
			if labelled(o, narrowed[o.Namespace()]) {
				state[i] = brought
			}
		}
	}
	for i, e := range sc.Narrow {
		for _, r := range e.Releases {
			if !releaseUsed[i][r] {
				return s, rep, fmt.Errorf("entry %d: no release named %q in %s", i+1, r, strings.Join(e.Namespaces, ", "))
			}
		}
		if len(e.Labels) > 0 && !labelsUsed[i] {
			return s, rep, fmt.Errorf("entry %d: nothing in %s carries its labels", i+1, strings.Join(e.Namespaces, ", "))
		}
	}
	for i := range s.Objects {
		if state[i] == ofRelease {
			state[i] = left
			if relChosen[rel[i]] {
				state[i] = brought
			}
		}
	}
	// A Secret goes where its maker goes.
	maker := secretMakers(s)
	for i, o := range s.Objects {
		if state[i] != follows || o.Kind() != "Secret" || o.APIVersion() != "v1" {
			continue
		}
		if m, ok := maker[secretKey{o.Namespace(), o.Name()}]; ok && (state[m] == brought || state[m] == left) {
			state[i] = state[m]
		}
	}
	// A Job is left out wherever it is, and whatever chose it.
	jobLeft := make([]bool, len(s.Objects))
	for i, o := range s.Objects {
		if isJob(o) && !sc.Jobs {
			jobLeft[i] = true
			rep.Jobs = append(rep.Jobs, o.Namespace()+"/"+o.Name())
		}
	}

	// A namespace is brought when anything in it is, or a release
	// installed in it is: the release needs its namespace though all it
	// made is elsewhere.
	alive := map[string]bool{}
	for i, o := range s.Objects {
		if state[i] == brought && !jobLeft[i] && o.Namespace() != "" {
			alive[o.Namespace()] = true
		}
	}
	for k, chosen := range relChosen {
		if chosen {
			alive[k.ns] = true
		}
	}

	out := s
	out.Objects = nil
	for i, o := range s.Objects {
		keep := true
		switch {
		case o.Kind() == "Namespace" && o.APIVersion() == "v1":
			if narrowed[o.Name()] == nil {
				break
			}
			rep.Of++
			keep = alive[o.Name()]
		case state[i] == untouched:
			keep = !jobLeft[i]
			if keep {
				out.Objects = append(out.Objects, o)
			}
			continue
		default:
			rep.Of++
			keep = (state[i] == brought || (state[i] == follows && alive[o.Namespace()])) && !jobLeft[i]
		}
		if keep {
			if o.Kind() != "Namespace" || narrowed[o.Name()] != nil {
				rep.Kept++
			}
			out.Objects = append(out.Objects, o)
		}
	}
	// What the capture left to a GitOps source in a namespace the scope
	// leaves out whole is not this restore's to plan for.
	out.Skips = nil
	for _, sk := range s.Skips {
		if narrowed[sk.Namespace] != nil && !alive[sk.Namespace] {
			continue
		}
		out.Skips = append(out.Skips, sk)
	}
	for k, n := range relObjects {
		r := ScopedRelease{Release: k.ns + "/" + k.name, Objects: n}
		if relChosen[k] {
			rep.Brought = append(rep.Brought, r)
		} else {
			rep.LeftOut = append(rep.LeftOut, r)
		}
	}
	for _, l := range [][]ScopedRelease{rep.Brought, rep.LeftOut} {
		sort.Slice(l, func(i, j int) bool { return l[i].Release < l[j].Release })
	}
	sort.Strings(rep.Jobs)
	return out, rep, nil
}

// ScopeDraft is a scope file that brings everything a snapshot holds but
// its Jobs: every namespace a release was installed in, and each of its
// releases, to be cut down by deleting lines. A namespace with no release
// is not listed, and so not narrowed. A name is written so that it is
// read as that name and not as a pattern.
func ScopeDraft(s snapshot.Snapshot) []byte {
	type rel struct {
		objects int
		kinds   map[string]int
	}
	byNS := map[string]map[string]*rel{}
	for _, o := range s.Objects {
		ns, name, ok := ReleaseOf(o)
		if !ok || ns == "" {
			continue
		}
		if byNS[ns] == nil {
			byNS[ns] = map[string]*rel{}
		}
		r := byNS[ns][name]
		if r == nil {
			r = &rel{kinds: map[string]int{}}
			byNS[ns][name] = r
		}
		r.objects++
		r.kinds[o.Kind()]++
	}
	var b strings.Builder
	b.WriteString("# What a restore brings (truthform restore --scope, and diff and plan with the same file).\n")
	b.WriteString("# As written it brings everything but Jobs: delete the releases a drill is not to bring.\n")
	b.WriteString("# A namespace not listed here is restored whole. One listed with no releases left\n")
	b.WriteString("# is left out whole. Names may be patterns (\"team-*\"). Jobs are left out with any\n")
	b.WriteString("# scope, since a Job restored runs again: add \"jobs: true\" to bring them.\n")
	if len(byNS) == 0 {
		b.WriteString("# The snapshot has nothing a Helm release made, so there is nothing listed to cut\n")
		b.WriteString("# down: narrow by labels instead, as\n#   - namespaces: [shop]\n#     labels: {app.kubernetes.io/part-of: checkout}\n")
		b.WriteString("narrow: []\n")
		return []byte(b.String())
	}
	b.WriteString("narrow:\n")
	nss := make([]string, 0, len(byNS))
	for ns := range byNS {
		nss = append(nss, ns)
	}
	sort.Strings(nss)
	for _, ns := range nss {
		fmt.Fprintf(&b, "  - namespaces: [%s]\n    releases:\n", quoted(literal(ns)))
		names := make([]string, 0, len(byNS[ns]))
		for n := range byNS[ns] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			r := byNS[ns][n]
			kinds := make([]string, 0, len(r.kinds))
			for k := range r.kinds {
				kinds = append(kinds, k)
			}
			sort.Strings(kinds)
			for i, k := range kinds {
				if r.kinds[k] > 1 {
					kinds[i] = fmt.Sprintf("%d %s", r.kinds[k], k)
				}
			}
			fmt.Fprintf(&b, "      - %s # %s\n", quoted(literal(n)), commentSafe(strings.Join(kinds, ", ")))
		}
	}
	return []byte(b.String())
}

// literal is a name as a pattern that fits it and nothing else.
func literal(name string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`).Replace(name)
}

// quoted is a name as a YAML string no name can break out of: a JSON
// string is one.
func quoted(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// commentSafe is text for the end of a YAML line: nothing in it ends the
// line.
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x85 || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
}
