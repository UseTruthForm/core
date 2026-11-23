package gcp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// appliedField is a list a resource holds that neither its create nor its
// patch takes: the document flags it output only, and methods of the
// resource's own add and change its items one at a time. It is
// configuration all the same, so a snapshot keeps it in the resource's
// spec, and a restore applies it once every resource exists.
type appliedField struct {
	api, schema, field string
	// key is the property that names an item within the list.
	key string
	// add and update are methods of the resource's collection. Each takes
	// a request holding one item, in the property whose schema is the
	// item's (Compute's NetworksAddPeeringRequest.networkPeering).
	add, update string
}

// appliedFields are those known. A VPC Network Peering is not a resource:
// it is an entry in each network's peerings, "[Output Only] A list of
// network peerings for the resource", made by networks.addPeering and
// changed by networks.updatePeering
// (https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks/addPeering).
// The two networks name each other, which is no cycle: both are created
// first, then peered.
var appliedFields = []appliedField{
	{api: "compute", schema: "Network", field: "peerings", key: "name", add: "addPeering", update: "updatePeering"},
}

// flagApplied marks the applied fields in a loaded document, so capture
// keeps them and a translation's check lets them through.
func (d *Doc) flagApplied() {
	for _, a := range appliedFields {
		if s := d.Schemas[a.schema]; a.api == d.Name && s != nil && s.Properties[a.field] != nil {
			s.Properties[a.field].Applied = true
		}
	}
}

// appliedOf are the applied fields of an API's schema (compute, Network).
func appliedOf(api, schema string) []appliedField {
	var out []appliedField
	for _, a := range appliedFields {
		if a.api == api && a.schema == schema {
			out = append(out, a)
		}
	}
	return out
}

// appliedOfObject are the applied fields of a snapshot object's type.
func appliedOfObject(o snapshot.Object) []appliedField {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	d, _ := ann[annDiscovery].(string)
	s, _ := ann[annSchema].(string)
	api, _, _ := strings.Cut(d, "/")
	return appliedOf(api, s)
}

// withoutApplied is a spec as the resource's create and patch take it:
// without its applied fields. The spec itself is not changed.
func withoutApplied(spec map[string]any, fields []appliedField) map[string]any {
	if len(fields) == 0 {
		return spec
	}
	out := make(map[string]any, len(spec))
	for k, v := range spec {
		out[k] = v
	}
	for _, a := range fields {
		delete(out, a.field)
	}
	return out
}

// items reads an applied list by each item's key.
func (a appliedField) items(spec map[string]any) (map[string]map[string]any, []string) {
	by := map[string]map[string]any{}
	var order []string
	list, _ := spec[a.field].([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		k, _ := m[a.key].(string)
		if m == nil || k == "" {
			continue
		}
		by[k] = m
		order = append(order, k)
	}
	return by, order
}

// itemStatus moves what the server reports of each item (a peering's
// state) out of the generic status, where every item's shared one key, and
// names it by the item: peerings[to-hub].state.
func (a appliedField) itemStatus(d *Doc, data, status map[string]any) {
	for k := range status {
		if strings.HasPrefix(k, a.field+"[].") {
			delete(status, k)
		}
	}
	prop := d.Schemas[a.schema].Properties[a.field]
	if prop == nil || prop.Items == nil {
		return
	}
	item := d.resolve(prop.Items)
	list, _ := data[a.field].([]any)
	for _, x := range list {
		m, _ := x.(map[string]any)
		name, _ := m[a.key].(string)
		if item == nil || name == "" {
			continue
		}
		for k, v := range m {
			if p := item.Properties[k]; p != nil && outputOnly(p) && isScalar(v) {
				status[a.field+"["+name+"]."+k] = v
			}
		}
	}
}

// sort orders an applied list by its items' keys, and drops an empty one.
func (a appliedField) sort(spec map[string]any) {
	list, ok := spec[a.field].([]any)
	if !ok {
		return
	}
	if len(list) == 0 {
		delete(spec, a.field)
		return
	}
	key := func(x any) string { m, _ := x.(map[string]any); s, _ := m[a.key].(string); return s }
	sort.SliceStable(list, func(i, j int) bool { return key(list[i]) < key(list[j]) })
}

// sameSpecs reports two specs equal, whatever the order of their applied
// lists.
func sameSpecs(a, b map[string]any, fields []appliedField) bool {
	if len(fields) == 0 {
		return canon(a) == canon(b)
	}
	a, b = deepCopy(a), deepCopy(b)
	for _, f := range fields {
		f.sort(a)
		f.sort(b)
	}
	return canon(a) == canon(b)
}

// applyFields brings an existing resource's applied lists to the
// snapshot's: an item the target lacks is added, one that differs is
// changed. current is the resource's spec in the target as read before the
// restore (nil when the restore has just created it). An item only the
// target has is left and reported: a restore removes nothing.
func applyFields(ctx context.Context, api API, docs *Docs, o snapshot.Object, name string, current map[string]any,
	project, number string, resolved *names) (string, error) {
	ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	str := func(k string) string { s, _ := ann[k].(string); return s }
	apiName, ver, _ := strings.Cut(str(annDiscovery), "/")
	doc, err := docs.Doc(docURL(apiName, ver), "")
	if err != nil {
		return "", err
	}
	spec, _ := o.Body["spec"].(map[string]any)
	var did []string
	for _, a := range appliedOf(apiName, str(annSchema)) {
		want, order := a.items(spec)
		have, extra := a.items(current)
		for _, k := range extra {
			if _, ok := want[k]; !ok {
				return strings.Join(did, ", "), fmt.Errorf("%s[%s] is in the target and not in the snapshot; not removed (a restore removes nothing)", a.field, k)
			}
		}
		for _, k := range order {
			verb, method := "added", a.add
			if cur, ok := have[k]; ok {
				if canon(cur) == canon(want[k]) {
					continue
				}
				verb, method = "updated", a.update
			}
			item, why := resolveSpec(want[k], resolved, project, number)
			if why != "" {
				return strings.Join(did, ", "), fmt.Errorf("%s[%s] %s", a.field, k, why)
			}
			m := doc.collectionMethods(str(annCollection))[method]
			body, err := a.request(doc, m, item)
			if err != nil {
				return strings.Join(did, ", "), err
			}
			if _, err := api.Call(ctx, m.HTTPMethod, doc.URL(m, name), body); err != nil {
				return strings.Join(did, ", "), fmt.Errorf("%s[%s]: %w", a.field, k, err)
			}
			did = append(did, verb+" "+a.field+"["+k+"]")
		}
	}
	return strings.Join(did, ", "), nil
}

// request wraps one item as the method takes it: in the property of the
// request's schema that holds the item's schema.
func (a appliedField) request(d *Doc, m *Method, item map[string]any) (map[string]any, error) {
	if m == nil || m.Request == nil {
		return nil, fmt.Errorf("the %s %s document declares no %s or %s method taking a request for %s.%s", d.Name, d.Version, a.add, a.update, a.schema, a.field)
	}
	holder := a.holder(d, m)
	if holder == "" {
		return nil, fmt.Errorf("%s: request %s holds no item of %s.%s", m.ID, m.Request.Ref, a.schema, a.field)
	}
	return map[string]any{holder: item}, nil
}

func (a appliedField) holder(d *Doc, m *Method) string {
	prop := d.Schemas[a.schema].Properties[a.field]
	w := d.Schemas[m.Request.Ref]
	if prop == nil || prop.Items == nil || w == nil {
		return ""
	}
	for _, k := range sortedKeys(w.Properties) {
		if w.Properties[k].Ref != "" && w.Properties[k].Ref == prop.Items.Ref {
			return k
		}
	}
	return ""
}

// differsOutsideApplied reports whether two specs differ in anything but
// their applied fields.
func differsOutsideApplied(a, b map[string]any, fields []appliedField) bool {
	return canon(withoutApplied(a, fields)) != canon(withoutApplied(b, fields))
}
