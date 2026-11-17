package snapshot

import (
	"sort"
	"strings"
)

// SkippedOtherSide says why the other snapshot left out an object that one
// side has and the other does not. The object is still a difference: a
// note never changes what Compare reports or what a diff exits with.
type SkippedOtherSide struct {
	// Reason is the skip's reason, as the snapshot that left it out gives it.
	Reason string
	// OlderRules: the snapshot that left it out does not say its capture
	// rules (a build up to beta.23 wrote it), and the reason is one a GitOps
	// source gives. A build before beta.23 left out a self-applying root and
	// the source it reads from, which later ones capture: the difference may
	// be that, and not a change in the system.
	OlderRules bool
}

// skipIndex finds the skip, if any, that names an object.
type skipIndex struct {
	platform string
	rules    int
	fold     bool
	// by resource|namespace|name, every reason given; a skip of "*" is
	// under each of its Names.
	reasons map[string][]string
	// kind -> the resources the snapshot's coverage gives for it
	resources map[string][]string
}

// indexSkips indexes s's skips. Its coverage, which lists every type it
// left anything out of, says which resource an object's kind is
// ("group/version/plural" on Kubernetes, the type itself elsewhere).
func indexSkips(s Snapshot) *skipIndex {
	ix := &skipIndex{platform: s.Platform, rules: s.Rules, fold: FoldsCase(s.Platform), reasons: map[string][]string{}, resources: map[string][]string{}}
	for _, sk := range s.Skips {
		names := []string{sk.Name}
		if sk.Name == "*" {
			// What a skip of "*" stands for, where the capture lists it.
			names = sk.Names
		}
		for _, n := range names {
			k := ix.key(sk.Resource, sk.Namespace, n)
			ix.reasons[k] = append(ix.reasons[k], sk.Reason)
		}
	}
	for _, cov := range s.Coverage {
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

// note is why the snapshot indexed left o out, or nil where nothing says.
func (ix *skipIndex) note(o Object) *SkippedOtherSide {
	gv := o.APIVersion()
	if !strings.Contains(gv, "/") {
		gv = "core/" + gv
	}
	ns, name := o.Namespace(), o.Name()
	var reasons []string
	for _, r := range ix.resources[ix.norm(o.Kind())] {
		// A Kubernetes resource is the kind only in its own group and
		// version; elsewhere the resource is the kind.
		if !strings.HasPrefix(ix.norm(r), ix.norm(gv+"/")) && ix.norm(r) != ix.norm(o.Kind()) {
			continue
		}
		// As a capture records a skip: in its namespace, or (where the
		// platform has none for it, as Azure's resource groups) with the
		// group in its name. Never by name alone for an object in a
		// namespace: one of that name elsewhere is another object.
		keys := []string{ix.key(r, "", name)}
		if ns != "" {
			keys = []string{ix.key(r, ns, name), ix.key(r, "", ns+"/"+name)}
		}
		for _, k := range keys {
			reasons = append(reasons, ix.reasons[k]...)
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	sort.Strings(reasons)
	why := strings.Join(compactStrings(reasons), "; ")
	older := ix.rules == 0
	for _, r := range reasons {
		older = older && appliedByGitOps(ix.platform, r)
	}
	return &SkippedOtherSide{Reason: why, OlderRules: older}
}

func compactStrings(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
