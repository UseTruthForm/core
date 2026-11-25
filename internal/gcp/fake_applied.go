package gcp

import (
	"fmt"
	"net/netip"
	"strings"
)

// applyItem serves the methods that set a resource's applied lists
// (networks.addPeering, networks.updatePeering): ok is false when the URL
// is not one. What every such method does is here; what Google does for
// one list beyond its document is in fakeItemRules.
func (f *Fake) applyItem(method, url string, body map[string]any) (map[string]any, bool, error) {
	path, _, _ := strings.Cut(url, "?")
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return nil, false, nil
	}
	base, verb := path[:i], path[i+1:]
	for rel, r := range f.res {
		if !strings.HasSuffix(base, "/"+rel) {
			continue
		}
		d, err := f.w.docs.Doc(r.asset.DiscoveryURI, r.asset.Version)
		if err != nil {
			return nil, true, err
		}
		for _, a := range appliedOf(d.Name, r.asset.DiscoveryName) {
			if verb != a.add && verb != a.update {
				continue
			}
			var m *Method
			for _, c := range d.collections() {
				if c.schema == r.asset.DiscoveryName && c.methods[verb] != nil {
					m = c.methods[verb]
				}
			}
			if m == nil || m.Request == nil || m.HTTPMethod != method {
				return nil, true, fmt.Errorf("fake: no %s %s for %s", method, verb, r.asset.DiscoveryName)
			}
			out, err := f.applyTo(d, a, rel, m, verb == a.add, body)
			return out, true, err
		}
	}
	return nil, false, nil
}

func (f *Fake) applyTo(d *Doc, a appliedField, rel string, m *Method, adding bool, body map[string]any) (map[string]any, error) {
	item, _ := body[a.holder(d, m)].(map[string]any)
	if item == nil {
		return nil, fmt.Errorf("INVALID_ARGUMENT: %s needs %s", m.Request.Ref, a.holder(d, m))
	}
	item = deepCopy(item)
	key, _ := item[a.key].(string)
	if key == "" {
		return nil, fmt.Errorf("INVALID_ARGUMENT: an item of %s.%s needs its %s", a.schema, a.field, a.key)
	}
	schema := d.resolve(d.Schemas[a.schema].Properties[a.field].Items)
	for k := range item {
		if p, ok := schema.Properties[k]; !ok {
			return nil, fmt.Errorf("INVALID_ARGUMENT: %s.%s has no field %s", a.schema, a.field, k)
		} else if outputOnly(p) {
			return nil, fmt.Errorf("INVALID_ARGUMENT: %s.%s.%s is output only", a.schema, a.field, k)
		}
	}
	if err := f.refusedStrings(item); err != nil {
		return nil, err
	}
	next := deepCopy(f.res[rel].data)
	list, _ := next[a.field].([]any)
	at := -1
	for i, x := range list {
		if m, _ := x.(map[string]any); m[a.key] == key {
			at = i
		}
	}
	switch {
	case adding && at >= 0:
		return nil, fmt.Errorf("ALREADY_EXISTS: %s already has %s %s", rel, a.field, key)
	case !adding && at < 0:
		return nil, fmt.Errorf("NOT_FOUND: %s has no %s %s", rel, a.field, key)
	}
	var old map[string]any
	if at >= 0 {
		old, _ = list[at].(map[string]any)
	}
	if rule := fakeItemRules[a.schema+"."+a.field]; rule != nil {
		if err := rule(f, rel, list, old, item); err != nil {
			return nil, err
		}
	}
	if adding {
		list = append(list, item)
	} else {
		// A patch: what the request leaves out is kept.
		for k, v := range item {
			old[k] = v
		}
		f.Updates++
	}
	next[a.field] = list
	f.w.seq++
	next["etag"] = fmt.Sprintf("e%d", f.w.seq)
	f.res[rel] = fakeRes{asset: f.res[rel].asset, data: next}
	return deepCopy(next), nil
}

// refusedStrings refuses what Google would of any string sent to it: a
// TruthForm token left unresolved, and a reference to another project.
func (f *Fake) refusedStrings(v map[string]any) error {
	var bad error
	walkStrings(deepCopy(v), func(s string) string {
		if bad == nil && strings.Contains(s, "{{truthform") {
			bad = fmt.Errorf("INVALID_ARGUMENT: unresolved TruthForm reference %q sent to Google", s)
		}
		for other := range f.w.projects {
			if bad == nil && other != f.id && (strings.Contains(s, "projects/"+other+"/") || strings.Contains(s, "@"+other+".")) {
				bad = fmt.Errorf("PERMISSION_DENIED: %q refers to project %s, which this one cannot see", s, other)
			}
		}
		return s
	})
	return bad
}

// fakeItemRules is what Google does for one applied list beyond its
// document, by schema and field: rel is the resource, list its items so
// far, old the item being changed (nil for a new one), item the request's,
// which the rule may complete.
var fakeItemRules = map[string]func(f *Fake, rel string, list []any, old, item map[string]any) error{
	"Network.peerings": fakePeering,
}

// fakePeeringDefaults are what a peering made with nothing but a name and
// a network reads back as
// (https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks/addPeering:
// exportCustomRoutes and importCustomRoutes "default value is false",
// exportSubnetRoutesWithPublicIp "default value is true",
// importSubnetRoutesWithPublicIp "default value is false", stackType "default
// value is IPV4_ONLY"; "By default, the update strategy is INDEPENDENT",
// https://docs.cloud.google.com/vpc/docs/using-vpc-peering).
var fakePeeringDefaults = map[string]any{
	"autoCreateRoutes": true, "exchangeSubnetRoutes": true,
	"exportCustomRoutes": false, "importCustomRoutes": false,
	"exportSubnetRoutesWithPublicIp": true, "importSubnetRoutesWithPublicIp": false,
	"stackType": "IPV4_ONLY", "updateStrategy": "INDEPENDENT",
}

// fakePeering is VPC Network Peering as Google documents it: a peering
// added on one network alone is INACTIVE, and both are ACTIVE once "each
// network has a peering configuration that references the other network"
// (https://docs.cloud.google.com/vpc/docs/using-vpc-peering); "at the time
// of peering, Google Cloud checks if subnets with overlapping IP ranges
// exist; if they do, then the peering fails"
// (https://docs.cloud.google.com/vpc/docs/vpc-peering).
func fakePeering(f *Fake, rel string, list []any, old, item map[string]any) error {
	peer := func(m map[string]any) string {
		s, _ := m["network"].(string)
		if i := strings.Index(s, "projects/"); i >= 0 {
			return s[i:]
		}
		return s
	}
	if old != nil {
		if n, ok := item["network"]; ok && peer(map[string]any{"network": n}) != peer(old) {
			return fmt.Errorf("INVALID_ARGUMENT: a peering's network cannot be changed")
		}
		return nil
	}
	p := peer(item)
	other, ok := f.res[p]
	switch {
	case !ok || !strings.HasSuffix(other.asset.Type, "/Network"):
		return fmt.Errorf("NOT_FOUND: The resource '%s' was not found", p)
	case p == rel:
		return fmt.Errorf("INVALID_ARGUMENT: a network cannot peer with itself")
	}
	for _, x := range list {
		if m, _ := x.(map[string]any); peer(m) == p {
			return fmt.Errorf("INVALID_ARGUMENT: %s already peers with %s (peering %v)", rel, p, m["name"])
		}
	}
	for k, v := range fakePeeringDefaults {
		if _, set := item[k]; !set {
			item[k] = v
		}
	}
	if item["exchangeSubnetRoutes"] != true {
		return fmt.Errorf("INVALID_ARGUMENT: exchangeSubnetRoutes must be true")
	}
	item["state"], item["stateDetails"] = "INACTIVE", "Waiting for peer network to connect."
	back, _ := other.data["peerings"].([]any)
	for _, x := range back {
		m, _ := x.(map[string]any)
		if peer(m) != rel {
			continue
		}
		if a, b := f.overlap(rel, p); a != "" {
			return fmt.Errorf("INVALID_ARGUMENT: An IP range in the peer network (%s) overlaps with an IP range in the local network (%s)", b, a)
		}
		for _, side := range []map[string]any{m, item} {
			side["state"], side["stateDetails"] = "ACTIVE", "Connected."
		}
	}
	return nil
}

// overlap finds a subnetwork range of one network that overlaps one of the
// other's.
func (f *Fake) overlap(a, b string) (string, string) {
	ranges := func(net string) []netip.Prefix {
		var out []netip.Prefix
		for _, r := range f.res {
			n, _ := r.data["network"].(string)
			if !strings.HasSuffix(r.asset.Type, "/Subnetwork") || !strings.HasSuffix(n, "/"+net) {
				continue
			}
			all := []any{r.data["ipCidrRange"]}
			sec, _ := r.data["secondaryIpRanges"].([]any)
			for _, s := range sec {
				m, _ := s.(map[string]any)
				all = append(all, m["ipCidrRange"])
			}
			for _, x := range all {
				if p, err := netip.ParsePrefix(fmt.Sprint(x)); err == nil {
					out = append(out, p)
				}
			}
		}
		return out
	}
	for _, x := range ranges(a) {
		for _, y := range ranges(b) {
			if x.Overlaps(y) {
				return x.String(), y.String()
			}
		}
	}
	return "", ""
}
