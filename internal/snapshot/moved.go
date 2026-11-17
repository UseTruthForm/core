package snapshot

import (
	"sort"
	"strings"
)

// Moved is an object that one snapshot captured and the other left out
// because something else makes it now: a controller that owns it, or a
// GitOps source that applies it (MadeElsewhere). Compare sees it as missing
// or extra; what changed is who makes it, not what the system holds.
type Moved struct {
	Key string
	// Kind is "no longer captured" (captured in want, left out of got) or
	// "no longer skipped" (left out of want, captured in got).
	Kind string
	// Reason is the skip's reason, as the snapshot that left it out gives it.
	Reason string
}

// Kinds of Moved.
const (
	NoLongerCaptured = "no longer captured"
	NoLongerSkipped  = "no longer skipped"
)

// SplitMoved takes out of changes each "missing" object that got left out
// because something else makes it, and each "extra" object that want left
// out for that reason, and returns them apart. What is left is what
// differs. A skip for any other reason is not a move: one left out as
// identical to a baseline was left out for its content, and one left out
// as unreadable was not seen, so across either an object may have changed.
func SplitMoved(want, got Snapshot, changes []Change) ([]Change, []Moved) {
	var gotSkips, wantSkips *skipIndex
	var real []Change
	var moved []Moved
	for _, c := range changes {
		switch c.Kind {
		case "missing":
			if o, ok := findObject(want, c.Key); ok {
				if gotSkips == nil {
					gotSkips = indexSkips(got)
				}
				if r, hit := gotSkips.reason(o); hit {
					moved = append(moved, Moved{Key: c.Key, Kind: NoLongerCaptured, Reason: r})
					continue
				}
			}
		case "extra":
			if o, ok := findObject(got, c.Key); ok {
				if wantSkips == nil {
					wantSkips = indexSkips(want)
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
	return Object{}, false
}

// skipIndex answers which skip, if any, says an object is made elsewhere.
type skipIndex struct {
	platform string
	// by resource|namespace|name, every reason given; a skip of "*" is
	// under each of its Names.
	reasons map[string][]string
	// kind -> the resources the snapshot's coverage gives for it
	resources map[string][]string
}

// indexSkips indexes s's skips. Its coverage, which lists every type it
// left anything out of, says which resource ("group/version/plural") an
// object's kind is.
func indexSkips(s Snapshot) *skipIndex {
	ix := &skipIndex{platform: s.Platform, reasons: map[string][]string{}, resources: map[string][]string{}}
	for _, sk := range s.Skips {
		names := []string{sk.Name}
		if sk.Name == "*" {
			// A skip of "*" without names stands for objects it does not
			// name: none of them can be told from a real removal.
			names = sk.Names
		}
		for _, n := range names {
			k := sk.Resource + "|" + sk.Namespace + "|" + n
			ix.reasons[k] = append(ix.reasons[k], sk.Reason)
		}
	}
	for _, cov := range s.Coverage {
		ix.resources[cov.Kind] = append(ix.resources[cov.Kind], cov.Resource)
	}
	return ix
}

// reason is the reason a skip gives o, when every skip that names it says
// something else makes it.
func (ix *skipIndex) reason(o Object) (string, bool) {
	gv := o.APIVersion()
	if !strings.Contains(gv, "/") {
		gv = "core/" + gv
	}
	for _, r := range ix.resources[o.Kind()] {
		// A resource is group/version/plural: the object's kind is it only
		// in its own group and version.
		if !strings.HasPrefix(r, gv+"/") {
			continue
		}
		reasons := ix.reasons[r+"|"+o.Namespace()+"|"+o.Name()]
		if len(reasons) == 0 {
			continue
		}
		for _, why := range reasons {
			if !MadeElsewhere(ix.platform, why) {
				return "", false
			}
		}
		return reasons[0], true
	}
	return "", false
}
