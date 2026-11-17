package snapshot

import (
	"sort"
	"strings"
)

// Moved is an object that one snapshot captured and the other left out on
// purpose. Compare sees it as missing or extra, and nothing in the system
// changed: what changed is how a capture accounts for it (a GitOps tool
// began to apply it, or a version of the capture stopped leaving it out).
type Moved struct {
	Key string
	// Kind is "no longer captured" (captured in want, skipped in got) or
	// "no longer skipped" (skipped in want, captured in got).
	Kind string
	// Reason is the skip's reason, as the snapshot that skipped it gives it.
	Reason string
}

// Kinds of Moved.
const (
	NoLongerCaptured = "no longer captured"
	NoLongerSkipped  = "no longer skipped"
)

// SplitMoved takes out of changes each "missing" object that got skipped and
// each "extra" object that want skipped, and returns them apart. What is
// left is what differs; a missing or extra object no skip names stays one.
func SplitMoved(want, got Snapshot, changes []Change) ([]Change, []Moved) {
	var gotSkips, wantSkips *skipIndex
	var real []Change
	var moved []Moved
	for _, c := range changes {
		var o Object
		var ok bool
		switch c.Kind {
		case "missing":
			o, ok = findObject(want, c.Key)
			if ok {
				if gotSkips == nil {
					gotSkips = indexSkips(got, want)
				}
				if r, hit := gotSkips.reason(o); hit {
					moved = append(moved, Moved{Key: c.Key, Kind: NoLongerCaptured, Reason: r})
					continue
				}
			}
		case "extra":
			o, ok = findObject(got, c.Key)
			if ok {
				if wantSkips == nil {
					wantSkips = indexSkips(want, got)
				}
				if r, hit := wantSkips.reason(o); hit {
					moved = append(moved, Moved{Key: c.Key, Kind: NoLongerSkipped, Reason: r})
					continue
				}
			}
		}
		real = append(real, c)
	}
	sort.Slice(moved, func(i, j int) bool { return moved[i].Key < moved[j].Key })
	return real, moved
}

// Describe says what a Moved is, in a line.
func (m Moved) Describe() string {
	if m.Kind == NoLongerSkipped {
		return "no longer skipped (was: " + m.Reason + "), so now captured"
	}
	return "no longer captured: " + m.Reason
}

func findObject(s Snapshot, key string) (Object, bool) {
	for _, o := range s.Objects {
		if o.Key() == key {
			return o, true
		}
	}
	// Compare may match keys as its platform does (Azure's without regard
	// to case); find as loosely.
	for _, o := range s.Objects {
		if strings.EqualFold(o.Key(), key) {
			return o, true
		}
	}
	return Object{}, false
}

// skipIndex answers which skip, if any, names an object.
type skipIndex struct {
	fold bool
	// by resource|namespace|name; a skip of "*" is under each of its Names.
	reasons map[string]string
	// kind -> the resources the coverage of either snapshot gives for it
	resources map[string][]string
}

// indexSkips indexes s's skips. Coverage, of s and of other, says which
// resource ("group/version/plural" on Kubernetes) an object's kind is.
func indexSkips(s, other Snapshot) *skipIndex {
	ix := &skipIndex{fold: movedFoldsCase(s.Platform) || movedFoldsCase(other.Platform), reasons: map[string]string{}, resources: map[string][]string{}}
	for _, sk := range s.Skips {
		names := []string{sk.Name}
		if sk.Name == "*" {
			// A skip of "*" without names stands for objects it does not name:
			// none of them can be told from a real removal.
			names = sk.Names
		}
		for _, n := range names {
			k := ix.key(sk.Resource, sk.Namespace, n)
			if _, dup := ix.reasons[k]; !dup {
				ix.reasons[k] = sk.Reason
			}
		}
	}
	seen := map[string]bool{}
	for _, cov := range append(append([]Coverage(nil), s.Coverage...), other.Coverage...) {
		if cov.Kind == "" || seen[cov.Kind+"|"+cov.Resource] {
			continue
		}
		seen[cov.Kind+"|"+cov.Resource] = true
		ix.resources[ix.norm(cov.Kind)] = append(ix.resources[ix.norm(cov.Kind)], cov.Resource)
	}
	return ix
}

func (ix *skipIndex) norm(s string) string {
	if ix.fold {
		return strings.ToLower(s)
	}
	return s
}

func (ix *skipIndex) key(resource, ns, name string) string {
	return ix.norm(resource + "|" + ns + "|" + name)
}

func (ix *skipIndex) reason(o Object) (string, bool) {
	gv := o.APIVersion()
	if !strings.Contains(gv, "/") {
		gv = "core/" + gv
	}
	var resources []string
	for _, r := range ix.resources[ix.norm(o.Kind())] {
		// Kubernetes names a resource by group, version and plural; the
		// object's kind is that resource only in its own group and version.
		// Elsewhere the resource is the kind.
		if strings.HasPrefix(ix.norm(r), ix.norm(gv+"/")) || ix.norm(r) == ix.norm(o.Kind()) {
			resources = append(resources, r)
		}
	}
	ns, name := o.Namespace(), o.Name()
	for _, r := range resources {
		// As a capture records a skip: in its namespace, or (where the
		// platform has none for it, as Azure's resource groups) with the
		// group as part of its name. Never by name alone for an object in a
		// namespace: one of that name elsewhere is another object, and its
		// skip would hide a real removal.
		keys := []string{ix.key(r, "", name)}
		if ns != "" {
			keys = []string{ix.key(r, ns, name), ix.key(r, "", ns+"/"+name)}
		}
		for _, k := range keys {
			if why, ok := ix.reasons[k]; ok {
				return why, true
			}
		}
	}
	return "", false
}

// movedFoldsCase says whether a platform's names match without regard to
// case: Azure Resource Manager's do.
func movedFoldsCase(platform string) bool { return platform == "azure" }
