package snapshot

import (
	"sort"
	"strings"
)

// Moved is an object that a snapshot under older capture rules left out to
// the GitOps source that applies it, and one under newer rules captured,
// because a change of rules keeps it (a self-applying root). Compare sees it
// as missing or extra; what changed is how a capture accounts for it, not
// what the system holds.
type Moved struct {
	Key string
	// Kind is "no longer captured" (captured in want, left out of got: want
	// is the newer) or "no longer skipped" (left out of want, captured in
	// got: got is the newer).
	Kind string
	// Reason is the skip's reason, as the snapshot that left it out gives it.
	Reason string
}

// Kinds of Moved.
const (
	NoLongerCaptured = "no longer captured"
	NoLongerSkipped  = "no longer skipped"
)

// Moves is what SplitMoved needs to know of a platform's capture rules,
// from the package that has them (kube.Moves).
type Moves struct {
	// MadeBy is the capture's own classifier: the reason it gives an object
	// for leaving it out to the source that applies it, from the object
	// alone, or "".
	MadeBy func(Object) string
	// Kept says whether s, captured under rules hi, kept o because of a
	// change of rules after lo: o is what the rules of lo left out and a
	// later change keeps (a self-applying root, from rules 1).
	Kept func(o Object, s Snapshot, lo, hi int) bool
}

// SplitMoved takes out of changes what a change of capture rules moved,
// and returns it apart. What is left is what differs.
//
// A move is read in one direction only: the snapshot under the lower rules
// (Snapshot.Rules; one that does not say counts as 0) left the object out,
// and the one under the higher rules captured it because a change between
// the two keeps it (Moves.Kept). Whichever argument each is. And the
// capture's classifier, run on the captured copy, must give exactly the
// skip's reason, which must be one a GitOps source gives (MadeElsewhere).
// Anything else is a difference:
//
//   - Under one set of rules (two old snapshots among them) nothing moves:
//     an object captured or left out by what it holds and what is around
//     it, which crossed, was changed.
//   - An object captured under the lower rules and left out under the
//     higher was not moved by any change of rules made so far, all of which
//     keep what was left out: an edit that also took away its root status
//     reads that way.
//   - A skip for any other reason: one left out as identical to a baseline
//     was left out for its content, one left out as unreadable was not
//     seen, and one left out as owned by a controller cannot be checked,
//     since a capture keeps no owner references.
func SplitMoved(want, got Snapshot, changes []Change, m Moves) ([]Change, []Moved) {
	if m.MadeBy == nil || m.Kept == nil {
		return changes, nil
	}
	var real []Change
	var moved []Moved
	for _, c := range changes {
		switch {
		case c.Kind == "missing" && want.Rules > got.Rules:
			if r, ok := keptByRules(want, got, c.Key, m); ok {
				moved = append(moved, Moved{Key: c.Key, Kind: NoLongerCaptured, Reason: r})
				continue
			}
		case c.Kind == "extra" && got.Rules > want.Rules:
			if r, ok := keptByRules(got, want, c.Key, m); ok {
				moved = append(moved, Moved{Key: c.Key, Kind: NoLongerSkipped, Reason: r})
				continue
			}
		}
		real = append(real, c)
	}
	sort.Slice(moved, func(i, j int) bool { return moved[i].Key < moved[j].Key })
	return real, moved
}

// keptByRules is the reason lower left the object of key out, when higher,
// under higher rules, captured it because a change of rules keeps it, and
// its captured copy says the same.
func keptByRules(higher, lower Snapshot, key string, m Moves) (string, bool) {
	o, ok := findObject(higher, key)
	if !ok || !m.Kept(o, higher, lower.Rules, higher.Rules) {
		return "", false
	}
	return indexSkips(lower).reason(o, m.MadeBy)
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
