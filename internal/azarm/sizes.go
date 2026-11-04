package azarm

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/stackdna/core/internal/snapshot"
)

// A size a subscription is not offered is refused, and Azure does not say so:
// a real restore's cluster was refused with AvailabilityZoneNotSupported, the
// region's supported zones given as none, because its node size was
// NotAvailableForSubscription in the target, though offered in the source. The
// rest of the restore had run by then, and 22 objects that needed the cluster
// were not made.
const skusVersion = "2021-07-01"

// sizeUse is a VM size one object asks for, where.
type sizeUse struct {
	key, size, location, set string
}

// sizesOf lists the VM sizes s uses: a cluster's pools, a pool on its own, a
// VM and a scale set, as --values leaves them. set is the property --values
// can override.
func sizesOf(s snapshot.Snapshot, values map[string]map[string]any) []sizeUse {
	byKey := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		byKey[strings.ToLower(o.Key())] = o
	}
	var out []sizeUse
	for _, o := range s.Objects {
		spec, _ := o.Body["spec"].(map[string]any)
		if v := values[leaveOutKey(o)]; v != nil {
			spec = deepCopy(spec)
			merge(spec, deepCopy(v))
		}
		loc, _ := spec["location"].(string)
		add := func(size any, set string) {
			if v, _ := size.(string); v != "" && loc != "" {
				out = append(out, sizeUse{leaveOutKey(o), v, loc, set})
			}
		}
		switch strings.ToLower(o.Kind()) {
		case "microsoft.containerservice/managedclusters":
			pools, _ := lookupPath(spec, "properties.agentPoolProfiles").([]any)
			for _, p := range pools {
				add(lookupPath(p, "vmSize"), "properties.agentPoolProfiles, the whole list")
			}
		case "microsoft.containerservice/managedclusters/agentpools":
			name := o.Name()
			if i := strings.LastIndex(name, "/"); i > 0 {
				cluster := byKey[strings.ToLower(APIVersion+"|"+managedClusterType+"|"+o.Namespace()+"|"+name[:i])]
				cs, _ := cluster.Body["spec"].(map[string]any)
				loc, _ = cs["location"].(string)
			}
			add(lookupPath(spec, "properties.vmSize"), "properties.vmSize")
		case "microsoft.compute/virtualmachines":
			add(lookupPath(spec, "properties.hardwareProfile.vmSize"), "properties.hardwareProfile.vmSize")
		case "microsoft.compute/virtualmachinescalesets":
			add(lookupPath(spec, "sku.name"), "sku")
		}
	}
	return out
}

// SizesRefused says which VM sizes s uses that api's subscription cannot have
// where s uses them, with values as a restore applies them, and how to
// restore at another size. A list that cannot be read is said too: nothing
// was checked there.
func SizesRefused(ctx context.Context, api ARM, s snapshot.Snapshot, values map[string]map[string]any) []string {
	uses := sizesOf(s, values)
	byLoc := map[string][]sizeUse{}
	var locs []string
	for _, u := range uses {
		l := strings.ToLower(strings.ReplaceAll(u.location, " ", ""))
		if byLoc[l] == nil {
			locs = append(locs, l)
		}
		byLoc[l] = append(byLoc[l], u)
	}
	sort.Strings(locs)
	var out []string
	for _, l := range locs {
		path := "/subscriptions/" + api.Subscription() + "/providers/Microsoft.Compute/skus?$filter=" +
			strings.ReplaceAll(url.QueryEscape("location eq '"+l+"'"), "+", "%20")
		skus, err := api.List(ctx, path, skusVersion)
		if err != nil {
			out = append(out, fmt.Sprintf("cannot read the VM sizes offered in %s, so they were not checked: %v", l, err))
			continue
		}
		offered := map[string]map[string]any{}
		for _, k := range skus {
			if t, _ := k["resourceType"].(string); strings.EqualFold(t, "virtualMachines") {
				n, _ := k["name"].(string)
				offered[strings.ToLower(n)] = k
			}
		}
		for _, u := range byLoc[l] {
			if why := refused(offered[strings.ToLower(u.size)]); why != "" {
				out = append(out, fmt.Sprintf("%s uses %s in %s, where this subscription cannot have it: %s. Azure will refuse it; ask Azure to offer it, or give another size with --values (%s)", u.key, u.size, l, why, u.set))
			}
		}
	}
	return out
}

// refused says why a size cannot be had: not offered, restricted in the
// region, or restricted in some of its zones (a pool or VM pinned to one is
// refused). "" when it can.
func refused(sku map[string]any) string {
	if sku == nil {
		return "it is not offered there"
	}
	rs, _ := sku["restrictions"].([]any)
	var zones []string
	for _, r := range rs {
		m, _ := r.(map[string]any)
		code, _ := m["reasonCode"].(string)
		switch t, _ := m["type"].(string); {
		case strings.EqualFold(t, "Location"):
			return "Azure restricts it (" + code + ")"
		case strings.EqualFold(t, "Zone"):
			info, _ := m["restrictionInfo"].(map[string]any)
			zs, _ := info["zones"].([]any)
			for _, z := range zs {
				zones = append(zones, fmt.Sprint(z))
			}
		}
	}
	if len(zones) > 0 {
		sort.Strings(zones)
		return "Azure restricts it in zones " + strings.Join(zones, ", ")
	}
	return ""
}
