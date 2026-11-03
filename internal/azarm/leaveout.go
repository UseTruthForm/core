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
	for _, o := range s.Objects {
		if k := strings.ToLower(leaveOutKey(o)); want[k] {
			delete(want, k)
			gone = append(gone, o)
			continue
		}
		out.Objects = append(out.Objects, o)
	}
	if len(want) > 0 {
		return s, fmt.Errorf("leave out: not in the snapshot: %s", strings.Join(sortedKeys(want), ", "))
	}
	ids, refs := map[string]string{}, map[string]string{}
	for _, o := range gone {
		rid := objectID(o, tokSub)
		ids[strings.ToLower(rid.String())] = leaveOutKey(o)
		refs[strings.ToLower(o.Kind()+"|"+o.Namespace()+"|"+o.Name())] = leaveOutKey(o)
	}
	var needed []string
	for _, o := range out.Objects {
		for _, by := range needs(o, ids, refs) {
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

// needs lists the left-out objects o depends on: by ID (its own, as a child or
// an extension, or in its spec), by reference, or as what it waits for.
func needs(o snapshot.Object, ids, refs map[string]string) []string {
	var out []string
	self := strings.ToLower(objectID(o, tokSub).String())
	for id, k := range ids {
		if strings.HasPrefix(self, id+"/") {
			out = append(out, k)
		}
	}
	look := func(v string) string {
		for _, m := range anyIDRE.FindAllString(v, -1) {
			m = strings.ToLower(m)
			for id, k := range ids {
				if m == id || strings.HasPrefix(m, id+"/") {
					out = append(out, k)
				}
			}
		}
		for _, g := range refAnyRE.FindAllStringSubmatch(v, -1) {
			if k, ok := refs[strings.ToLower(g[1]+"|"+g[2]+"|"+g[3])]; ok {
				out = append(out, k)
			}
		}
		return v
	}
	if spec, ok := o.Body["spec"].(map[string]any); ok {
		rewriteAll(deepCopy(spec), look)
	}
	md, _ := o.Body["metadata"].(map[string]any)
	ann, _ := md["annotations"].(map[string]any)
	if after, _ := ann[annAfter].(string); after != "" {
		look(after)
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
			for _, g := range otherSubRE.FindAllStringSubmatch(v, -1) {
				subs[strings.ToLower(g[1])] = true
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
