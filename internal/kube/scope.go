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
	// Hold brings what this entry chooses with nothing running: workloads
	// at zero replicas, autoscalers paused, CronJobs suspended.
	Hold bool `json:"hold,omitempty"`
	// Objects are objects of the namespaces that no release made, as
	// Kind/name (Kind.group where two APIs share a kind); either part may
	// be a pattern. One not named is left out.
	Objects []string `json:"objects,omitempty"`
	// AsTheyAre are objects a hold does not know how to hold that a
	// person has looked at and brings as they are, as Kind/name like
	// Objects. One a hold names and this does not makes the run end
	// other than 0.
	AsTheyAre []string `json:"asTheyAre,omitempty"`
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
	// Held are the objects brought with nothing running, each with how.
	Held []ScopeHeld `json:"held"`
	// NotHeld are objects of other APIs under a hold that are brought as
	// they are: nothing in one says it runs anything, and its controller
	// may run something for it all the same.
	NotHeld []string `json:"broughtNotHeld"`
	// AsTheyAre are those of them the scope file names under asTheyAre:
	// looked at, and brought as they are by a person's word. They are not
	// in NotHeld.
	AsTheyAre []string `json:"broughtAsTheyAre"`
	// SharedName are objects with no namespace brought because a release
	// of their name is, though another release of that name is left out:
	// which of the two made one, the object does not say.
	SharedName []string `json:"broughtBySharedName"`
	// ObjectsBrought and ObjectsLeftOut are the objects of those
	// namespaces that no release made (Kind namespace/name).
	ObjectsBrought []string `json:"objectsBrought"`
	ObjectsLeftOut []string `json:"objectsLeftOut"`
	// StillMade are what a GitOps source that is brought makes in a
	// namespace the scope narrows, left out whole or not: the scope
	// chooses among the snapshot's objects, and cannot stop a source
	// restored from making what it makes.
	StillMade []ScopeMade `json:"stillMade"`
}

type ScopeHeld struct {
	Object string `json:"object"` // Kind namespace/name
	How    string `json:"how"`
}

// ScopeMade is a source that is brought, and how many objects the capture
// left to it in a namespace the scope leaves out.
type ScopeMade struct {
	Source    string `json:"source"`
	Namespace string `json:"namespace"`
	Objects   int    `json:"objects"`
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

// fitsObject says whether a Kind/name pattern (Kind.group where two APIs
// share a kind) fits an object.
func fitsObject(p string, o snapshot.Object, group string) bool {
	kind, name, _ := strings.Cut(p, "/")
	okK, _ := path.Match(kind, o.Kind())
	okG, _ := path.Match(kind, o.Kind()+"."+group)
	okN, _ := path.Match(name, o.Name())
	return okN && (okK || okG)
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
// another namespace). An object with no namespace that names its release
// by label alone does not say which namespace that release is in: it goes
// with the releases of that name, brought if any of them is.
//
// In a narrowed namespace, what no release of a narrowed namespace made
// (shared configuration, a Secret made by hand, a workload applied by
// hand) is brought only if an entry names it under objects, or it carries
// an entry's labels: what is not chosen is left out, whatever made it.
// The Namespace itself comes when anything of it is brought; a namespace
// from which nothing is chosen is left out whole, with what the capture
// left there to a GitOps source, unless a source that is brought makes
// it (said in the report: a scope cannot stop that). A Secret that an
// object of the snapshot makes goes where that object goes. A Job is left
// out wherever it is, though its release is brought, unless the scope
// says "jobs: true". Everything else is untouched.
//
// Two entries that fit one namespace choose from it together.
//
// What an entry with "hold: true" chooses is brought with nothing
// running (see held): the releases it names, the objects it names, what
// carries its labels. Hold wins: what two entries choose is held if
// either holds. An object that runs something a hold cannot stop is an
// error.
//
// A pattern that fits no namespace, and a release, a label or an object
// that fits nothing in the namespaces of its entry, is an error: a
// mistyped one would otherwise leave out what it was written to bring.
func Narrow(s snapshot.Snapshot, sc Scope) (snapshot.Snapshot, ScopeReport, error) {
	rep := ScopeReport{Narrowed: []string{}, Brought: []ScopedRelease{}, LeftOut: []ScopedRelease{}, Jobs: []string{}, Held: []ScopeHeld{}, NotHeld: []string{}, AsTheyAre: []string{}, SharedName: []string{}, ObjectsBrought: []string{}, ObjectsLeftOut: []string{}, StillMade: []ScopeMade{}}
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
		if len(e.AsTheyAre) > 0 && !e.Hold {
			return s, rep, fmt.Errorf("entry %d: asTheyAre is for an entry with hold: true", i+1)
		}
		for _, p := range e.AsTheyAre {
			// Any kind would take in whatever API a later snapshot has:
			// what is looked at is at least a kind.
			if kind, _, _ := strings.Cut(p, "/"); strings.Trim(kind, "*?") == "" && kind != "" {
				return s, rep, fmt.Errorf("entry %d: asTheyAre %q names no kind: name the kind looked at (Certificate/*)", i+1, p)
			}
		}
		for _, p := range append(append([]string{}, e.Objects...), e.AsTheyAre...) {
			kind, name, ok := strings.Cut(p, "/")
			_, errK := path.Match(kind, "")
			_, errN := path.Match(name, "")
			if !ok || kind == "" || name == "" || strings.Contains(name, "/") || errK != nil || errN != nil {
				return s, rep, fmt.Errorf("entry %d: %q is not Kind/name (either may be a pattern)", i+1, p)
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
	objectUsed := make([]map[string]bool, len(sc.Narrow))
	labelsUsed := make([]bool, len(sc.Narrow))
	for i := range sc.Narrow {
		releaseUsed[i], objectUsed[i] = map[string]bool{}, map[string]bool{}
	}
	// named says whether an entry names the object under objects.
	named := func(o snapshot.Object, es []int) (yes, hold bool) {
		group, _, versioned := strings.Cut(o.APIVersion(), "/")
		if !versioned {
			group = ""
		}
		for _, i := range es {
			for _, p := range sc.Narrow[i].Objects {
				if fitsObject(p, o, group) {
					objectUsed[i][p], yes = true, true
					hold = hold || sc.Narrow[i].Hold
				}
			}
		}
		return yes, hold
	}
	// The namespaces that have a release of each name.
	relNS := map[string]map[string]bool{}
	for _, o := range s.Objects {
		if rns, rname, ok := ReleaseOf(o); ok && rns != "" {
			if relNS[rname] == nil {
				relNS[rname] = map[string]bool{}
			}
			relNS[rname][rns] = true
		}
	}
	// asItIs says whether a holding entry names the object under
	// asTheyAre: an entry of the object's namespace, or of the namespace
	// of the release that made it (a release may make an object in a
	// namespace other than its own, or with none; where only a label says
	// which release, any namespace that has a release of the name).
	// Nothing is held but by one of these.
	asUsed := make([]map[string]bool, len(sc.Narrow))
	for i := range sc.Narrow {
		asUsed[i] = map[string]bool{}
	}
	asItIs := func(o snapshot.Object) (yes bool) {
		group, _, versioned := strings.Cut(o.APIVersion(), "/")
		if !versioned {
			group = ""
		}
		es := append([]int{}, narrowed[o.Namespace()]...)
		if rns, rname, ok := ReleaseOf(o); ok && rns != o.Namespace() {
			es = append(es, narrowed[rns]...)
		} else if ok && rns == "" {
			// Of a release by label alone, with no namespace: of any
			// namespace that has a release of the name.
			for ns := range relNS[rname] {
				es = append(es, narrowed[ns]...)
			}
		}
		for _, i := range es {
			for _, p := range sc.Narrow[i].AsTheyAre {
				if fitsObject(p, o, group) {
					asUsed[i][p], yes = true, true
				}
			}
		}
		return yes
	}
	// labelled says whether an entry's labels choose the object, and
	// whether one that does holds.
	labelled := func(o snapshot.Object, es []int) (yes, hold bool) {
		for _, i := range es {
			if hasLabels(o, sc.Narrow[i].Labels) {
				labelsUsed[i], yes = true, true
				hold = hold || sc.Narrow[i].Hold
			}
		}
		return yes, hold
	}

	const (
		untouched = iota
		brought
		left
		ofRelease // of a release of a narrowed namespace: as the release goes
		ofName    // with no namespace, of a release named by label alone: as the releases of that name go
	)
	type relKey struct{ ns, name string }
	state := make([]int, len(s.Objects))
	rel := make([]relKey, len(s.Objects))
	relObjects := map[relKey]int{}
	relChosen := map[relKey]bool{}
	relHeld := map[relKey]bool{}
	holdIt := make([]bool, len(s.Objects))
	maker := secretMakers(s)
	made := make([]bool, len(s.Objects))
	// loose are the objects in a narrowed namespace that no release of a
	// narrowed namespace made.
	loose := make([]bool, len(s.Objects))
	for i, o := range s.Objects {
		if o.Kind() == "Namespace" && o.APIVersion() == "v1" {
			continue // goes as its namespace does, below
		}
		rns, rname, isRelease := ReleaseOf(o)
		switch {
		case isRelease && rns == "" && o.Namespace() == "":
			for ns := range relNS[rname] {
				if narrowed[ns] != nil {
					rel[i], state[i] = relKey{"", rname}, ofName
				}
			}
		case isRelease && narrowed[rns] != nil:
			k := relKey{rns, rname}
			rel[i], state[i] = k, ofRelease
			relObjects[k]++
			for _, e := range narrowed[rns] {
				if fits(sc.Narrow[e].Releases, rname, releaseUsed[e]) {
					relChosen[k] = true
					relHeld[k] = relHeld[k] || sc.Narrow[e].Hold
				}
			}
			if yes, hold := labelled(o, narrowed[rns]); yes {
				relChosen[k] = true
				relHeld[k] = relHeld[k] || hold
			}
		case o.Namespace() != "" && narrowed[o.Namespace()] != nil:
			// Of no release, or of one installed in a namespace the scope
			// does not narrow: it is here, and goes as here goes.
			state[i], loose[i] = left, true
			if _, isMade := maker[secretKey{o.Namespace(), o.Name()}]; isMade && o.Kind() == "Secret" && o.APIVersion() == "v1" {
				// A Secret an object makes goes with that object, and
				// is not chosen by itself: a pattern that fits only such
				// Secrets fits nothing, and is refused as one.
				made[i] = true
				break
			}
			es := narrowed[o.Namespace()]
			// Both asked, so that each marks what it fits as used.
			byName, nameHolds := named(o, es)
			byLabel, labelHolds := labelled(o, es)
			if byName || byLabel {
				state[i] = brought
				holdIt[i] = nameHolds || labelHolds
			}
		}
	}
	for i, e := range sc.Narrow {
		for _, r := range e.Releases {
			if !releaseUsed[i][r] {
				return s, rep, fmt.Errorf("entry %d: no release named %q in %s", i+1, r, strings.Join(e.Namespaces, ", "))
			}
		}
		for _, p := range e.Objects {
			if !objectUsed[i][p] {
				return s, rep, fmt.Errorf("entry %d: no object that no release made fits %q in %s (a Secret that an object of the snapshot makes goes with that object, and is not named by itself)", i+1, p, strings.Join(e.Namespaces, ", "))
			}
		}
		if len(e.Labels) > 0 && !labelsUsed[i] {
			return s, rep, fmt.Errorf("entry %d: nothing in %s carries its labels", i+1, strings.Join(e.Namespaces, ", "))
		}
	}
	for i := range s.Objects {
		switch state[i] {
		case ofRelease:
			state[i] = left
			if relChosen[rel[i]] {
				state[i] = brought
				holdIt[i] = relHeld[rel[i]]
			}
		case ofName:
			// Left only when every release of the name is one the scope
			// leaves out.
			state[i] = left
			var leftIn []string
			for ns := range relNS[rel[i].name] {
				if narrowed[ns] == nil || relChosen[relKey{ns, rel[i].name}] {
					state[i] = brought
					// Held with any release of the name that is: which
					// of them made it, the object does not say.
					holdIt[i] = holdIt[i] || relHeld[relKey{ns, rel[i].name}]
				} else {
					leftIn = append(leftIn, ns+"/"+rel[i].name)
				}
			}
			if state[i] == brought && len(leftIn) > 0 {
				sort.Strings(leftIn)
				o := s.Objects[i]
				rep.SharedName = append(rep.SharedName, o.Kind()+" "+o.Name()+" (it may be of "+strings.Join(leftIn, ", ")+", left out)")
			}
		}
	}
	// A Secret goes where its maker goes: left out with one left out,
	// brought with one brought or one the scope does not touch.
	for i, o := range s.Objects {
		if made[i] {
			state[i] = brought
			if m := maker[secretKey{o.Namespace(), o.Name()}]; state[m] == left {
				state[i] = left
			}
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
	var cannot []string
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
			keep = state[i] == brought && !jobLeft[i]
			// Named in the report, but for a Secret that went as its
			// maker did, and a Job, which has its own list.
			if loose[i] && !made[i] && !jobLeft[i] {
				who := o.Kind() + " " + o.Namespace() + "/" + o.Name()
				if keep {
					rep.ObjectsBrought = append(rep.ObjectsBrought, who)
				} else {
					rep.ObjectsLeftOut = append(rep.ObjectsLeftOut, who)
				}
			}
		}
		if keep {
			if o.Kind() != "Namespace" || narrowed[o.Name()] != nil {
				rep.Kept++
			}
			if holdIt[i] {
				ho, how, why, unknown := held(o)
				who := o.Kind() + " " + o.Namespace() + "/" + o.Name()
				if why != "" {
					cannot = append(cannot, who+": "+why)
				}
				switch {
				case unknown && asItIs(o):
					rep.AsTheyAre = append(rep.AsTheyAre, who)
				case unknown:
					rep.NotHeld = append(rep.NotHeld, who)
				}
				if how != "" {
					rep.Held = append(rep.Held, ScopeHeld{Object: who, How: how})
				}
				o = ho
			}
			out.Objects = append(out.Objects, o)
		}
	}
	if len(cannot) > 0 {
		sort.Strings(cannot)
		return s, rep, fmt.Errorf("these are to be held, and would run all the same; leave each out (--leave-out), or bring its release without the hold: %s", strings.Join(cannot, "; "))
	}
	for i, e := range sc.Narrow {
		for _, p := range e.AsTheyAre {
			if !asUsed[i][p] {
				return s, rep, fmt.Errorf("entry %d: asTheyAre names %q, and the hold names no such object as not held in %s: it is for what a hold brings and does not know how to hold", i+1, p, strings.Join(e.Namespaces, ", "))
			}
		}
	}
	// A KEDA scaler that is brought without a hold, and scales what is
	// held, would start it again from zero: it is paused with it.
	isHeld := map[string]bool{}
	for _, h := range rep.Held {
		isHeld[h.Object] = true
	}
	for i, o := range out.Objects {
		group, _, _ := strings.Cut(o.APIVersion(), "/")
		who := o.Kind() + " " + o.Namespace() + "/" + o.Name()
		if group != "keda.sh" || o.Kind() != "ScaledObject" || isHeld[who] {
			continue
		}
		spec, _ := o.Body["spec"].(map[string]any)
		ref, _ := spec["scaleTargetRef"].(map[string]any)
		kind := strOf(ref["kind"])
		if kind == "" {
			kind = "Deployment"
		}
		if !isHeld[kind+" "+o.Namespace()+"/"+strOf(ref["name"])] {
			continue
		}
		ho, how, _, _ := held(o)
		out.Objects[i] = ho
		rep.Held = append(rep.Held, ScopeHeld{Object: who, How: how + ", since what it scales is held"})
	}
	sort.Strings(rep.NotHeld)
	sort.Strings(rep.AsTheyAre)
	sort.Slice(rep.Held, func(i, j int) bool { return rep.Held[i].Object < rep.Held[j].Object })
	// What the capture left to a GitOps source in a namespace the scope
	// leaves out whole is not this restore's to plan for.
	// But a source that is brought makes it all the same, and the plan
	// has to go on saying so.
	out.Skips = nil
	applied := stillApplied(s, out)
	stillMade := map[ScopeMade]int{}
	for i, sk := range s.Skips {
		if narrowed[sk.Namespace] != nil {
			// Left out whole, the namespace is not the plan's to ask
			// for, unless a source that is brought makes this.
			if applied[i] == "" && !alive[sk.Namespace] {
				continue
			}
			// In any namespace the scope narrows, what a source brought
			// makes is there again whatever the scope chose.
			if applied[i] != "" {
				stillMade[ScopeMade{Source: applied[i], Namespace: sk.Namespace}]++
			}
		}
		out.Skips = append(out.Skips, sk)
	}
	for m, n := range stillMade {
		m.Objects = n
		rep.StillMade = append(rep.StillMade, m)
	}
	sort.Slice(rep.StillMade, func(i, j int) bool {
		a, b := rep.StillMade[i], rep.StillMade[j]
		return a.Source+"\x00"+a.Namespace < b.Source+"\x00"+b.Namespace
	})
	sort.Strings(rep.ObjectsBrought)
	sort.Strings(rep.ObjectsLeftOut)
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

// stillApplied says, for each thing the capture left to a GitOps source,
// the source object in the snapshot as brought that makes it, directly or
// through sources it makes ("" where none does).
func stillApplied(s, out snapshot.Snapshot) []string {
	held := heldSources(out)
	// A source the capture left to another source.
	parent := map[source]source{}
	for _, sk := range s.Skips {
		if pk, pn, ok := SourceOf(sk.Reason); ok {
			for _, child := range skippedSource(sk) {
				parent[child] = source{pk, pn}
			}
		}
	}
	res := make([]string, len(s.Skips))
	for i, sk := range s.Skips {
		k, n, ok := SourceOf(sk.Reason)
		at := source{k, n}
		for hops := 0; ok && hops < 64; hops++ {
			if held[at] {
				res[i] = at.kind + " " + at.name
				break
			}
			at, ok = parent[at]
		}
	}
	return res
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
	// What no release made, by namespace: listed, so that it can be seen
	// and cut. Not a Secret an object makes, which goes with that object.
	others := map[string][]string{}
	maker := secretMakers(s)
	for _, o := range s.Objects {
		ns, name, ok := ReleaseOf(o)
		if !ok && o.Namespace() != "" {
			if _, isMade := maker[secretKey{o.Namespace(), o.Name()}]; !isMade || o.Kind() != "Secret" || o.APIVersion() != "v1" {
				others[o.Namespace()] = append(others[o.Namespace()], literal(o.Kind())+"/"+literal(o.Name()))
			}
		}
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
	b.WriteString("# is left out whole. Names may be patterns (\"team-*\"). Under objects is what no\n")
	b.WriteString("# release made (Kind/name): one not listed is left out too. Jobs are left out with any\n")
	b.WriteString("# scope, since a Job restored runs again: add \"jobs: true\" to bring them.\n")
	b.WriteString("# \"hold: true\" on an entry brings its releases with their workloads stopped (zero\n")
	b.WriteString("# replicas, autoscalers paused): split an entry in two to hold some and run others.\n")
	b.WriteString("# What a hold does not know how to hold is named, and the run does not end 0 until\n")
	b.WriteString("# each is left out or, looked at, listed under \"asTheyAre\" on that entry (Kind/name).\n")
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
		if l := others[ns]; len(l) > 0 {
			sort.Strings(l)
			b.WriteString("    objects:\n")
			for i, e := range l {
				if i == 0 || l[i-1] != e {
					fmt.Fprintf(&b, "      - %s\n", quoted(e))
				}
			}
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
