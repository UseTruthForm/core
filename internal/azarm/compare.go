package azarm

import (
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// unsetDefaults are what Azure answers for a property a snapshot does not set,
// where not setting it behaves as that value: a source made before the
// property existed has none, and its restored copy has Azure's default. A
// destroy-and-restore drill of a real estate showed each as a difference on
// every diff and every resumed restore; the source read at the same API
// version returned none of them. Only these two are known to behave as their
// default when unset (Key Vault's enabledFor* are false unless set; Service
// Bus's dnsNamePolicy is Standard unless set). Not AKS's nodeOSUpgradeChannel:
// the source cluster had none and so no OS updates, and its copy got
// NodeImage, which reimages its nodes; that is a difference (review of #75).
// Only for comparing: what a restore sends is unchanged.
var unsetDefaults = map[string]map[string]any{
	"microsoft.servicebus/namespaces": {"properties.dnsNamePolicy": "Standard"},
	"microsoft.keyvault/vaults":       {"properties.enabledForDiskEncryption": false, "properties.enabledForTemplateDeployment": false},
}

// ForCompare makes want and got comparable: what Azure set and the snapshot
// does not (unsetDefaults), a pool's node count when its autoscaler sets it,
// and an auditing setting's details when it is off on both. Each is drift no
// one made. Copies; neither snapshot is changed.
func ForCompare(want, got snapshot.Snapshot) (snapshot.Snapshot, snapshot.Snapshot) {
	byKey := map[string]int{}
	w := want
	w.Objects = append([]snapshot.Object(nil), want.Objects...)
	for i, o := range w.Objects {
		byKey[strings.ToLower(o.Key())] = i
	}
	g := got
	g.Objects = append([]snapshot.Object(nil), got.Objects...)
	for i, o := range g.Objects {
		j, ok := byKey[strings.ToLower(o.Key())]
		if !ok {
			continue
		}
		ws0, _ := w.Objects[j].Body["spec"].(map[string]any)
		gs0, _ := o.Body["spec"].(map[string]any)
		if ws0 == nil || gs0 == nil {
			continue
		}
		ws, gs := deepCopy(ws0), deepCopy(gs0)
		comparable(o.Kind(), ws, gs)
		wb, gb := deepCopy(w.Objects[j].Body), deepCopy(o.Body)
		wb["spec"], gb["spec"] = ws, gs
		w.Objects[j], g.Objects[i] = snapshot.Object{Body: wb}, snapshot.Object{Body: gb}
	}
	return w, g
}

// comparable applies ForCompare's rules to one object's two specs, in place.
func comparable(typ string, want, got map[string]any) {
	t := strings.ToLower(typ)
	for path, def := range unsetDefaults[t] {
		keys := strings.Split(path, ".")
		if _, set := lookupFold(want, keys); set {
			continue
		}
		if v, ok := lookupFold(got, keys); ok && equalValue(v, def) {
			dropPrune(got, want, keys)
		}
	}
	// A pool's autoscaler sets its node count, so the count read from one
	// cluster says nothing of the other: the source had 5 and its restored
	// copy 1, and each diff called it changed.
	if t == "microsoft.containerservice/managedclusters" {
		for _, spec := range []map[string]any{want, got} {
			props, _ := spec["properties"].(map[string]any)
			pools, _ := props["agentPoolProfiles"].([]any)
			for _, p := range pools {
				if pm, _ := p.(map[string]any); pm != nil && pm["enableAutoScaling"] == true {
					delete(pm, "count")
				}
			}
		}
	}
	// Off on both, an auditing setting's other fields are Azure's defaults
	// for one made with its database or server, and say nothing.
	if strings.HasPrefix(t, "microsoft.sql/servers/") && strings.HasSuffix(t, "auditingsettings") && auditOff(want) && auditOff(got) {
		for _, spec := range []map[string]any{want, got} {
			spec["properties"] = map[string]any{"state": "Disabled"}
		}
	}
}

func auditOff(spec map[string]any) bool {
	props, _ := spec["properties"].(map[string]any)
	s, _ := props["state"].(string)
	return strings.EqualFold(s, "Disabled")
}

// lookupFold reads a dotted path, matching keys without regard to case.
func lookupFold(m map[string]any, keys []string) (any, bool) {
	var v any = m
	for _, k := range keys {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		found := false
		for mk, mv := range mm {
			if strings.EqualFold(mk, k) {
				v, found = mv, true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return v, true
}

// dropPrune removes a path from got, and then each map on the way that is
// left empty and that want does not have.
func dropPrune(got, want map[string]any, keys []string) {
	dropPath(got, keys)
	for n := len(keys) - 1; n > 0; n-- {
		parent, ok := lookupFold(got, keys[:n])
		pm, _ := parent.(map[string]any)
		if !ok || len(pm) != 0 {
			return
		}
		if _, there := lookupFold(want, keys[:n]); there {
			return
		}
		dropPath(got, keys[:n])
	}
}

func equalValue(a, b any) bool {
	if sa, ok := a.(string); ok {
		sb, ok := b.(string)
		return ok && strings.EqualFold(sa, sb)
	}
	return a == b
}

// WithValues is s with what --values sets on each object, as a restore sends
// it, for a diff to compare: secrets aside, which Azure never returns, and IDs
// in the snapshot's form. Without it, every value a restore set read as drift.
func WithValues(s snapshot.Snapshot, values map[string]map[string]any, sub, tenant string) snapshot.Snapshot {
	if len(values) == 0 {
		return s
	}
	out := s
	out.Objects = append([]snapshot.Object(nil), s.Objects...)
	for i, o := range out.Objects {
		v := values[valuesRef(o, objectID(o, tokSub))]
		if v == nil {
			continue
		}
		b := deepCopy(o.Body)
		spec, _ := b["spec"].(map[string]any)
		if spec == nil {
			continue
		}
		ann, _ := b["metadata"].(map[string]any)["annotations"].(map[string]any)
		mergeGiven(spec, v, ann, sub, tenant)
		out.Objects[i] = snapshot.Object{Body: b}
	}
	return out
}

// mergeGiven merges what --values gives into spec as a restore compares it:
// in the snapshot's form, and without the secrets, which Azure never returns.
func mergeGiven(spec, v, ann map[string]any, sub, tenant string) {
	given := rewriteAll(deepCopy(v), func(s string) string { return tokenizeString(s, sub, tenant) }).(map[string]any)
	if secrets, _ := ann[annSecrets].(string); secrets != "" {
		for _, p := range strings.Split(secrets, ",") {
			dropPath(given, strings.Split(p, "."))
		}
	}
	merge(spec, given)
}
