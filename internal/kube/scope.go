package kube

import (
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
// labels it names. With neither, nothing of those namespaces is brought.
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
	// Kept is how many objects of those namespaces are brought, and Of
	// how many the snapshot holds there.
	Kept int `json:"kept"`
	Of   int `json:"of"`
	// Brought and LeftOut are the releases of those namespaces
	// (namespace/release), each with its objects.
	Brought []ScopedRelease `json:"brought"`
	LeftOut []ScopedRelease `json:"leftOut"`
	// Jobs are the Jobs left out because a restored Job runs again.
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

func fitsAny(patterns []string, v string) (int, bool) {
	for i, p := range patterns {
		if ok, _ := path.Match(p, v); ok {
			return i, true
		}
	}
	return 0, false
}

// Narrow returns the snapshot as the scope leaves it.
//
// In a namespace an entry fits: an object a release made is brought if
// the entry names its release, or it carries the entry's labels. A Secret
// that an object of the snapshot makes from a store goes where that
// object goes. What belongs to no release (shared configuration) comes
// with the namespace when anything of it is brought, and so does the
// Namespace itself; a namespace from which nothing is chosen is left out
// whole. What a release made outside its own namespace goes with the
// release. Everything else in the snapshot is untouched.
//
// A pattern that fits no namespace, and a release or a label that fits
// nothing in the namespaces of its entry, is an error: a mistyped one
// would otherwise leave out what it was written to bring.
func Narrow(s snapshot.Snapshot, sc Scope) (snapshot.Snapshot, ScopeReport, error) {
	rep := ScopeReport{Narrowed: []string{}, Brought: []ScopedRelease{}, LeftOut: []ScopedRelease{}, Jobs: []string{}}
	if len(sc.Narrow) == 0 && !sc.Jobs {
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

	// entries(ns) are the entries that narrow a namespace.
	entriesOf := func(ns string) []int {
		var out []int
		for i, e := range sc.Narrow {
			if _, ok := fitsAny(e.Namespaces, ns); ok {
				out = append(out, i)
			}
		}
		return out
	}
	namespaces := map[string]bool{}
	for _, o := range s.Objects {
		if o.Namespace() != "" {
			namespaces[o.Namespace()] = true
		}
		if o.Kind() == "Namespace" && o.APIVersion() == "v1" {
			namespaces[o.Name()] = true
		}
	}
	narrowed := map[string][]int{}
	nsFits := make([]map[string]bool, len(sc.Narrow))
	for ns := range namespaces {
		if es := entriesOf(ns); len(es) > 0 {
			narrowed[ns] = es
			rep.Narrowed = append(rep.Narrowed, ns)
		}
	}
	sort.Strings(rep.Narrowed)
	for i, e := range sc.Narrow {
		nsFits[i] = map[string]bool{}
		for _, p := range e.Namespaces {
			fits := false
			for ns := range namespaces {
				if ok, _ := path.Match(p, ns); ok {
					fits = true
				}
			}
			if !fits {
				return s, rep, fmt.Errorf("entry %d: no namespace in the snapshot fits %q", i+1, p)
			}
		}
	}

	// Which Secret each store-reading object makes, so that the Secret
	// goes where its maker goes.
	maker := map[secretKey]int{}
	for i, o := range s.Objects {
		group, _, _ := strings.Cut(o.APIVersion(), "/")
		for _, r := range storeReaders {
			if r.group == group && r.kind == o.Kind() {
				_, _, secrets := r.reads(o)
				for _, k := range secrets {
					maker[k] = i
				}
			}
		}
	}

	const (
		untouched = iota
		brought
		left
		follows // what belongs to no release: as its namespace goes
	)
	state := make([]int, len(s.Objects))
	releaseUsed := make([]map[string]bool, len(sc.Narrow))
	labelsUsed := make([]bool, len(sc.Narrow))
	for i := range sc.Narrow {
		releaseUsed[i] = map[string]bool{}
	}
	type relKey struct{ ns, name string }
	relObjects := map[relKey]int{}
	relBrought := map[relKey]bool{}

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
	// chosen says whether the entries of a namespace bring an object.
	chosen := func(o snapshot.Object, es []int, release string, isRelease bool) bool {
		yes := false
		for _, i := range es {
			if isRelease {
				if at, ok := fitsAny(sc.Narrow[i].Releases, release); ok {
					releaseUsed[i][sc.Narrow[i].Releases[at]] = true
					yes = true
				}
			}
			if hasLabels(o, sc.Narrow[i].Labels) {
				labelsUsed[i] = true
				yes = true
			}
		}
		return yes
	}
	for i, o := range s.Objects {
		if o.Kind() == "Job" && strings.HasPrefix(o.APIVersion(), "batch/") && !sc.Jobs {
			state[i] = left
			rep.Jobs = append(rep.Jobs, o.Namespace()+"/"+o.Name())
			continue
		}
		rns, rname, isRelease := ReleaseOf(o)
		ns := o.Namespace()
		if isRelease {
			ns = rns // what a release made elsewhere goes with the release
		}
		es, in := narrowed[ns]
		if !in || (o.Kind() == "Namespace" && o.APIVersion() == "v1") {
			continue
		}
		switch {
		case chosen(o, es, rname, isRelease):
			state[i] = brought
		case isRelease:
			state[i] = left
		default:
			state[i] = follows
		}
		if isRelease {
			k := relKey{rns, rname}
			relObjects[k]++
			relBrought[k] = relBrought[k] || state[i] == brought
		}
	}
	// A release is brought whole: an object of it chosen by a label brings
	// the rest, which would not run without it.
	for i, o := range s.Objects {
		if rns, rname, ok := ReleaseOf(o); ok && state[i] == left && relBrought[relKey{rns, rname}] {
			state[i] = brought
		}
	}
	// A Secret made from a store goes where its maker goes.
	for i, o := range s.Objects {
		if state[i] != follows || o.Kind() != "Secret" || o.APIVersion() != "v1" {
			continue
		}
		if m, ok := maker[secretKey{o.Namespace(), o.Name()}]; ok && state[m] != follows && state[m] != untouched {
			state[i] = state[m]
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

	// A namespace with anything brought keeps what belongs to no release,
	// and itself.
	alive := map[string]bool{}
	for i, o := range s.Objects {
		if state[i] == brought && o.Namespace() != "" {
			alive[o.Namespace()] = true
		}
	}
	out := s
	out.Objects = nil
	for i, o := range s.Objects {
		ns := o.Namespace()
		if o.Kind() == "Namespace" && o.APIVersion() == "v1" {
			if _, in := narrowed[o.Name()]; in && !alive[o.Name()] {
				rep.Of++
				continue
			} else if in {
				rep.Of++
				rep.Kept++
			}
			out.Objects = append(out.Objects, o)
			continue
		}
		switch state[i] {
		case follows:
			rep.Of++
			if !alive[ns] {
				continue
			}
			rep.Kept++
		case brought:
			rep.Of++
			rep.Kept++
		case left:
			if !(o.Kind() == "Job" && strings.HasPrefix(o.APIVersion(), "batch/") && !sc.Jobs) || narrowed[ns] != nil {
				rep.Of++
			}
			continue
		}
		out.Objects = append(out.Objects, o)
	}
	for k, n := range relObjects {
		r := ScopedRelease{Release: k.ns + "/" + k.name, Objects: n}
		if relBrought[k] {
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

// ScopeDraft is a scope file that brings everything a snapshot holds:
// every namespace with a release in it, and each of its releases, to be
// cut down by deleting lines. A namespace with no release is not listed,
// and so not narrowed.
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
	b.WriteString("# As written it brings everything: delete the releases a drill is not to bring.\n")
	b.WriteString("# A namespace not listed here is restored whole. One listed with no releases left\n")
	b.WriteString("# is left out whole. Names may be patterns (\"team-*\"). Jobs are left out with any\n")
	b.WriteString("# scope, since a Job restored runs again: add \"jobs: true\" to bring them.\n")
	b.WriteString("narrow:\n")
	nss := make([]string, 0, len(byNS))
	for ns := range byNS {
		nss = append(nss, ns)
	}
	sort.Strings(nss)
	for _, ns := range nss {
		fmt.Fprintf(&b, "  - namespaces: [%s]\n    releases:\n", quoted(ns))
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
			fmt.Fprintf(&b, "      - %s # %s\n", quoted(n), commentSafe(strings.Join(kinds, ", ")))
		}
	}
	if len(nss) == 0 {
		b.WriteString("  []\n# The snapshot has nothing a Helm release made: narrow by labels instead, as\n#   - namespaces: [shop]\n#     labels: {app.kubernetes.io/part-of: checkout}\n")
	}
	return []byte(b.String())
}

// quoted is a name as a YAML string no name can break out of.
func quoted(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\u0085", `\N`, " ", `\L`, " ", `\P`).Replace(s) + `"`
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
