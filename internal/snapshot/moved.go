package snapshot

import (
	"sort"
	"strings"
)

// Moved is an object that one snapshot captured and the other left out
// because a GitOps source applies it (MadeElsewhere), where the captured copy
// itself already says so. Compare sees it as missing or extra; what changed
// is how a capture accounts for it, not what the system holds.
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
// because a GitOps source applies it, and each "extra" object that want left
// out for that reason, and returns them apart. What is left is what differs.
//
// madeBy is the capture's own classifier: what reason it gives an object
// for leaving it out to the source that applies it, from the object alone.
// A move is accepted only if madeBy, run on the copy that was captured,
// gives exactly the reason the other side's skip gives. A copy that does
// not carry its maker's marks (a label added in the cluster since, to hide
// an edit) was not left out for that reason, and stays a difference. A skip
// for any other reason is never a move: one left out as identical to a
// baseline was left out for its content, one left out as unreadable was not
// seen, and one left out as owned by a controller cannot be checked, since a
// capture keeps no owner references. A nil madeBy finds no moves.
func SplitMoved(want, got Snapshot, changes []Change, madeBy func(Object) string) ([]Change, []Moved) {
	if madeBy == nil {
		return changes, nil
	}
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
				if r, hit := gotSkips.reason(o, madeBy); hit {
					moved = append(moved, Moved{Key: c.Key, Kind: NoLongerCaptured, Reason: r})
					continue
				}
			}
		case "extra":
			if o, ok := findObject(got, c.Key); ok {
				if wantSkips == nil {
					wantSkips = indexSkips(want)
				}
				if r, hit := wantSkips.reason(o, madeBy); hit {
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

// skipIndex answers which skip, if any, says a GitOps source applies an object.
type skipIndex struct {
	platform string
	// by resource|namespace|name, every reason given
	reasons map[string][]string
	// kind -> the resources the snapshot's coverage gives for it
	resources map[string][]string
}

// indexSkips indexes s's skips. Its coverage, which lists every type it
// left anything out of, says which resource ("group/version/plural") an
// object's kind is. A skip of "*" stands for what a controller owns, which
// is never a move.
func indexSkips(s Snapshot) *skipIndex {
	ix := &skipIndex{platform: s.Platform, reasons: map[string][]string{}, resources: map[string][]string{}}
	for _, sk := range s.Skips {
		if sk.Name == "*" {
			continue
		}
		k := sk.Resource + "|" + sk.Namespace + "|" + sk.Name
		ix.reasons[k] = append(ix.reasons[k], sk.Reason)
	}
	for _, cov := range s.Coverage {
		ix.resources[cov.Kind] = append(ix.resources[cov.Kind], cov.Resource)
	}
	return ix
}

// reason is the reason the skips give o, when every skip that names it says
// a GitOps source applies it and madeBy, run on o as captured, says the same.
func (ix *skipIndex) reason(o Object, madeBy func(Object) string) (string, bool) {
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
		own := madeBy(o)
		for _, why := range reasons {
			if !MadeElsewhere(ix.platform, why) || why != own {
				return "", false
			}
		}
		return reasons[0], true
	}
	return "", false
}
