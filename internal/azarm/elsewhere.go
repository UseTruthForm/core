package azarm

import (
	"sort"
	"strings"

	"github.com/stackdna/core/internal/snapshot"
)

// accessRule is a reference Azure checks the caller's access to when a
// resource is written: the property, on which type, and the action the
// caller needs on the resource it names.
type accessRule struct {
	kind, path, action string
}

// accessRules are the references whose check is known. From Azure's
// documentation; not yet verified by a StackDNA restore.
var accessRules = []accessRule{
	// Sending to an event hub through an authorization rule: Azure reads
	// the rule's keys as the caller.
	{"microsoft.insights/diagnosticsettings", "properties.eventhubauthorizationruleid", "Microsoft.EventHub/namespaces/authorizationRules/listKeys/action"},
	{"microsoft.network/privatednszones/virtualnetworklinks", "properties.virtualnetwork.id", "Microsoft.Network/virtualNetworks/join/action"},
	{"microsoft.network/virtualnetworks/virtualnetworkpeerings", "properties.remotevirtualnetwork.id", "Microsoft.Network/virtualNetworks/peer/action"},
}

// AccessElsewhere lists what a restore of s needs outside its target: each
// reference to another subscription's resource that Azure checks access to,
// with the action and the resource it is needed on. OtherSubscriptions said
// only that a restore "needs access there"; which access was found when Azure
// refused the write, after the rest had been sent (a diagnostic setting to
// another subscription's event hub needs its rule's keys). A reference with
// no known check is in OtherSubscriptions only. Only the checks StackDNA
// knows are listed: any other reference may need access there too. A
// reference to target, the subscription restored into, is not elsewhere
// ("" when it is not known, as for a report).
func AccessElsewhere(s snapshot.Snapshot, target string) []string {
	var out []string
	for _, o := range s.Objects {
		spec, ok := o.Body["spec"].(map[string]any)
		if !ok {
			continue
		}
		for _, r := range accessRules {
			if !strings.EqualFold(o.Kind(), r.kind) {
				continue
			}
			v, _ := lookupPath(spec, r.path).(string)
			m := otherSubRE.FindStringSubmatch(v)
			if m != nil && m[0] == v && !strings.EqualFold(m[1], target) {
				out = append(out, leaveOutKey(o)+": "+r.action+" on "+v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// lookupPath reads a dotted path, matching each key without regard to case,
// as ARM does.
func lookupPath(v any, path string) any {
	for _, k := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = nil
		for mk, mv := range m {
			if strings.EqualFold(mk, k) {
				v = mv
				break
			}
		}
	}
	return v
}
