package snapshot

import (
	"regexp"
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
	// rules (a build up to beta.23 wrote it), and every reason it gives is
	// one a GitOps source gives. A build before beta.23 left out a
	// self-applying root and the source it reads from, which later ones
	// capture: the difference may be that, and not a change in the system.
	OlderRules bool
	// NoSourceRules: the snapshot that left it out is under Kubernetes
	// capture rules before 3 (a build up to beta.24 wrote it), and every
	// reason it gives is one a GitOps source gives. Such a build left out
	// what is labelled as a source's where the cluster holds no such
	// source, which later ones capture: the difference may be that.
	NoSourceRules bool
}

// namesObjects says whether s's skips name objects as s keys them, so that
// a skip can be read as naming one object and no other:
//
//   - Kubernetes: by resource, namespace and name; Helm history by family,
//     from rules 2 (before, a family was written as a Secret's bare name,
//     so a Helm history skip from such a snapshot is no note).
//   - Azure from rules 1 (AzureCaptureRules): by group and name as keyed.
//     Under 0 an extension was named by its group and last name alone, the
//     same as one of that name on the group or another resource, so a skip
//     from such a snapshot is no note on any object.
//   - GCP: by the name the snapshot keys it by.
//   - AWS and the SaaS platforms: no. A skip there names a resource by its
//     identifier, and a snapshot by a logical name that may be another's
//     identifier.
func namesObjects(s Snapshot) bool {
	switch s.Platform {
	case "kubernetes", "gcp":
		return true
	case "azure":
		return s.Rules >= AzureCaptureRules
	}
	return false
}

// skipIndex finds the skip, if any, that names an object.
type skipIndex struct {
	platform string
	rules    int
	fold     bool
	// by resource|namespace|name, every reason given; a skip of "*" is
	// under each of its Names.
	reasons map[string][]string
	// Helm history, by resource|namespace|prefix and release: what stands
	// for the family's .v<N> Secrets, never for a Secret of that name.
	families map[string][]string
	// kind -> the resources the snapshot's coverage gives for it
	resources map[string][]string
}

// indexSkips indexes s's skips, where they name objects (namesObjects). Its
// coverage, which lists every type it left anything out of, says which
// resource an object's kind is ("group/version/plural" on Kubernetes, the
// type itself elsewhere).
func indexSkips(s Snapshot) *skipIndex {
	ix := &skipIndex{platform: s.Platform, rules: s.Rules, fold: FoldsCase(s.Platform), reasons: map[string][]string{}, families: map[string][]string{}, resources: map[string][]string{}}
	if !namesObjects(s) {
		return ix
	}
	for _, sk := range s.Skips {
		k := ix.key(sk.Resource, sk.Namespace, sk.Name)
		switch {
		case s.Platform == "kubernetes" && sk.Reason == HelmHistoryReason && s.Rules < 2:
			// A family and a Secret's own name were written alike.
		case s.Platform == "kubernetes" && sk.Reason == HelmHistoryReason && strings.HasSuffix(sk.Name, HelmHistoryFamily):
			fk := ix.key(sk.Resource, sk.Namespace, strings.TrimSuffix(sk.Name, HelmHistoryFamily))
			ix.families[fk] = append(ix.families[fk], sk.Reason)
		case sk.Name == "*":
			// What a skip of "*" stands for, where the capture lists it.
			for _, n := range sk.Names {
				nk := ix.key(sk.Resource, sk.Namespace, n)
				ix.reasons[nk] = append(ix.reasons[nk], sk.Reason)
			}
		default:
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

// HelmFamilyNote is what a Helm history family says of a Secret of one of
// its revision names. The family records the release, not its revisions: the
// other side may never have had this one (re-review of #24), so the note
// says only what is recorded.
func HelmFamilyNote(release string) string {
	return "Helm release " + release + " history in this namespace, which revisions not recorded; recreated when the release is installed again"
}

var helmHistory = regexp.MustCompile(`^` + regexp.QuoteMeta(HelmHistoryPrefix) + `(.+)\.v\d+$`)

const azureGroupType = "microsoft.resources/resourcegroups"

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
		if ix.platform == "kubernetes" {
			if !strings.HasPrefix(r, gv+"/") {
				continue
			}
		} else if ix.norm(r) != ix.norm(o.Kind()) {
			continue
		}
		switch ix.platform {
		case "azure":
			// As skipName writes it: the group, and the name as keyed; a
			// group as itself twice.
			n := ns + "/" + name
			if strings.EqualFold(o.Kind(), azureGroupType) {
				n = name + "/" + name
			}
			reasons = append(reasons, ix.reasons[ix.key(r, "", n)]...)
		default:
			reasons = append(reasons, ix.reasons[ix.key(r, ns, name)]...)
			if m := helmHistory.FindStringSubmatch(name); m != nil && ix.platform == "kubernetes" {
				if len(ix.families[ix.key(r, ns, HelmHistoryPrefix+m[1])]) > 0 {
					reasons = append(reasons, HelmFamilyNote(m[1]))
				}
			}
		}
	}
	if len(reasons) == 0 {
		return nil
	}
	sort.Strings(reasons)
	reasons = compactStrings(reasons)
	older := ix.platform == "kubernetes" && ix.rules < 3
	for _, r := range reasons {
		if !appliedByGitOps(ix.platform, r) {
			older = false
		}
	}
	return &SkippedOtherSide{Reason: strings.Join(reasons, "; "), OlderRules: older && ix.rules == 0, NoSourceRules: older}
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
