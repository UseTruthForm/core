package awscc

import (
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A reference cycle is ordinary in IAM: a role lists the managed policy it
// holds (ManagedPolicyArns) and the policy lists the role (Roles), one
// attachment recorded on both sides. No creation order exists, and the
// first real IAM drill created the role first, with the policy's ARN still
// literal, and AWS refused it: "NotFound Policy ... truthform-drill-read"
// (2026-10-24).
//
// A cycle is broken by creating one member without the properties that
// name the others, then setting them once the others exist. Only when each
// of those properties may be left out at creation (not required) and set
// later (not create-only); otherwise the cycle is reported, never guessed.

// deferral is one object created without some properties, set afterwards.
type deferral struct {
	full  snapshot.Object // the object as captured
	props []string        // the top-level properties left out at creation
}

// breakCycles returns the cyclic objects with the fewest properties
// deferred that leaves no cycle, in a stable order: members are tried in
// key order, and one is deferred at a time until the rest can be ordered.
// unbroken are the objects still in a cycle.
func breakCycles(reg *Registry, ordered, cyclic []snapshot.Object) (stripped []snapshot.Object, defs []deferral, unbroken []snapshot.Object) {
	members := map[string]bool{}
	for _, o := range cyclic {
		members[o.Kind()+"/"+o.Name()] = true
	}
	sort.SliceStable(cyclic, func(i, j int) bool { return cyclic[i].Key() < cyclic[j].Key() })
	work := append([]snapshot.Object{}, cyclic...)
	for i, o := range work {
		props := cycleProps(o, members)
		if len(props) == 0 || !deferrable(reg.Types[o.Kind()], props) {
			continue
		}
		work[i] = without(o, props)
		defs = append(defs, deferral{full: o, props: props})
		if _, still := restoreOrder(append(append([]snapshot.Object{}, ordered...), work...)); len(still) == 0 {
			return work, defs, nil
		}
	}
	_, still := restoreOrder(append(append([]snapshot.Object{}, ordered...), work...))
	return work, defs, still
}

// cycleProps are the top-level properties of o whose values name another
// member of the cycle.
func cycleProps(o snapshot.Object, members map[string]bool) []string {
	spec, _ := o.Body["spec"].(map[string]any)
	self := o.Kind() + "/" + o.Name()
	var out []string
	for _, k := range sortedKeys(spec) {
		for _, m := range tokenRE.FindAllStringSubmatch(canon(spec[k]), -1) {
			if d := m[1] + "/" + m[2]; d != self && members[d] {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

// deferrable reports whether every property may be left out at creation
// and set by an update.
func deferrable(t *TypeInfo, props []string) bool {
	if t == nil || !t.Handlers["update"] {
		return false
	}
	for _, p := range props {
		if hasTop(t.CreateOnly, p) || hasTop(t.WriteOnly, p) {
			return false
		}
		for _, r := range t.Required {
			if r == p {
				return false
			}
		}
	}
	return true
}

func without(o snapshot.Object, props []string) snapshot.Object {
	body := deepCopy(o.Body)
	spec, _ := body["spec"].(map[string]any)
	for _, p := range props {
		delete(spec, p)
	}
	return snapshot.Object{Body: body}
}

func deferredNote(props []string) string {
	return "; " + strings.Join(props, ", ") + " set after the resources it names existed (a reference cycle)"
}
