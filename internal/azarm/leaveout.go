package azarm

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/snapshot"
)

// LeaveOut removes objects from a snapshot before a restore or a diff, keyed
// "Kind/resourceGroup/name" as --values is, with the names the snapshot has.
// A restore beside its source may have to leave one out: a private DNS zone's
// link to a network in another subscription, which a network allows to only
// one zone of a name, was refused there, and nothing could hold it back.
//
// It refuses an entry that names no object, and an object left out that
// another still needs: one that names it, waits for it, or is its child or an
// extension on it. Left in, those would fail at the restore, after the rest was
// sent.
func LeaveOut(s snapshot.Snapshot, keys []string) (snapshot.Snapshot, error) {
	if len(keys) == 0 {
		return s, nil
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[strings.ToLower(k)] = true
	}
	out := s
	out.Objects = nil
	var gone []snapshot.Object
	found := map[string]bool{}
	for _, o := range s.Objects {
		if k := strings.ToLower(leaveOutKey(o)); want[k] {
			found[k] = true
			gone = append(gone, o)
			continue
		}
		out.Objects = append(out.Objects, o)
	}
	var unknown []string
	for k := range want {
		if !found[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return s, fmt.Errorf("leave out: not in the snapshot: %s", strings.Join(unknown, ", "))
	}
	// What a restore orders by is what it needs: references and parents
	// (deps), any left-out ID written anywhere in a spec (a policy
	// assignment's policyDefinitionId, at subscription scope), and a
	// cluster's grants to its identity, which nothing in the cluster names.
	// Ordering alone (a lock last, credentials one at a time) is not a need.
	byKey := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		byKey[strings.ToLower(o.Key())] = o
	}
	goneKeys, goneIDs := map[string]string{}, map[string]string{}
	for _, o := range gone {
		goneKeys[strings.ToLower(o.Key())] = leaveOutKey(o)
		goneIDs[strings.ToLower(objectID(o, tokSub).String())] = leaveOutKey(o)
	}
	var needed []string
	for _, o := range out.Objects {
		for _, by := range needs(o, goneKeys, goneIDs, byKey) {
			needed = append(needed, leaveOutKey(o)+" needs "+by)
		}
	}
	if len(needed) > 0 {
		sort.Strings(needed)
		return s, fmt.Errorf("leave out: still needed, so leave these out too or keep what they need: %s", strings.Join(slicesCompact(needed), "; "))
	}
	return out, nil
}

// leaveOutKey is an object's key as --values and --leave-out write it.
func leaveOutKey(o snapshot.Object) string {
	return o.Kind() + "/" + o.Namespace() + "/" + o.Name()
}

// needs lists the left-out objects o needs, as restoreGraph orders by them:
// its own ID below one (a child, an extension), deps, an ID in its spec, and
// for a cluster, its identity's grants.
func needs(o snapshot.Object, goneKeys, goneIDs map[string]string, byKey map[string]snapshot.Object) []string {
	var out []string
	self := strings.ToLower(objectID(o, tokSub).String())
	spec := strings.ToLower(canon(o.Body["spec"]))
	for id, k := range goneIDs {
		if strings.HasPrefix(self, id+"/") || strings.Contains(spec, id+`"`) || strings.Contains(spec, id+"/") {
			out = append(out, k)
		}
	}
	for _, d := range deps(o) {
		if k, ok := goneKeys[d]; ok {
			out = append(out, k)
		}
	}
	if strings.EqualFold(o.Kind(), managedClusterType) {
		for _, d := range grantsToIdentitiesOf(strings.ToLower(o.Key()), spec, byKey) {
			if k, ok := goneKeys[d]; ok {
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return slicesCompact(out)
}

// otherSubRE is a resource ID in a subscription named outright: capture writes
// the source's own as a placeholder, so any other is another subscription's.
var otherSubRE = regexp.MustCompile(`(?i)/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/[^"\s,;]*)?`)

// OtherSubscriptions lists each object whose spec names a resource in another
// subscription. A restore sends those IDs as they are: it needs access there,
// and what it makes reaches there (logs sent to another subscription's event
// hub, a DNS zone linked to its network). Before, nothing said so until Azure
// refused one.
func OtherSubscriptions(s snapshot.Snapshot) []string {
	var out []string
	for _, o := range s.Objects {
		spec, ok := o.Body["spec"].(map[string]any)
		if !ok {
			continue
		}
		subs := map[string]bool{}
		rewriteAll(deepCopy(spec), func(v string) string {
			// An ID inside a URL is escaped ("%2Fsubscriptions%2F…"), and
			// read only as written it was not seen (review of beta.14).
			for _, text := range []string{v, unescaped(v)} {
				for _, g := range otherSubRE.FindAllStringSubmatch(text, -1) {
					subs[strings.ToLower(g[1])] = true
				}
			}
			return v
		})
		if len(subs) > 0 {
			out = append(out, leaveOutKey(o)+": names subscription "+strings.Join(sortedKeys(subs), ", "))
		}
	}
	sort.Strings(out)
	return out
}

// unescaped is v with its escaped slashes undone, once or twice escaped
// ("%2F", "%252F"), or "" when it has none. Only the slashes: undoing every
// escape failed on a stray "%" ("100% sure"), and the ID beside it was missed.
func unescaped(v string) string {
	if !strings.Contains(strings.ToLower(v), "%2f") && !strings.Contains(strings.ToLower(v), "%252f") {
		return ""
	}
	return slashEscapes.Replace(v)
}

var slashEscapes = strings.NewReplacer("%252F", "/", "%252f", "/", "%2F", "/", "%2f", "/")
