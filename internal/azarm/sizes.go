package azarm

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A size a subscription is not offered is refused, and Azure does not say so:
// a real restore's cluster was refused with AvailabilityZoneNotSupported, the
// region's supported zones given as none, because its node size was
// NotAvailableForSubscription in the target, though offered in the source. The
// rest of the restore had run by then, and 22 objects that needed the cluster
// were not made.
const skusVersion = "2021-07-01"

// sizeUse is a VM size one object asks for, where, and in which zones.
type sizeUse struct {
	key, size, location, set string
	zones                    []string
}

// SizeCheck is what SizesRefused found. Nothing in Refused is not the same as
// every size being fine: NotChecked says what was not looked at.
type SizeCheck struct {
	Refused    []string `json:"refused"`
	NotChecked []string `json:"not_checked"`
	Sizes      int      `json:"sizes"`
	Regions    int      `json:"regions"`
}

// sizeHolders are where each type keeps its VM size: its path, the zones it
// asks for, and the property --values sets to change it. A child's region is
// its parent's when it has none of its own.
var sizeHolders = map[string]struct{ size, zones, set string }{
	"microsoft.containerservice/managedclusters/agentpools": {"properties.vmSize", "properties.availabilityZones", "properties.vmSize"},
	"microsoft.compute/virtualmachines":                     {"properties.hardwareProfile.vmSize", "zones", "properties.hardwareProfile.vmSize"},
	"microsoft.compute/virtualmachinescalesets":             {"sku.name", "zones", "sku"},
	"microsoft.servicefabric/managedclusters/nodetypes":     {"properties.vmSize", "properties.zones", "properties.vmSize"},
}

// sizesOf lists the VM sizes s uses, as --values leaves them, and what holds a
// size it does not read.
func sizesOf(s snapshot.Snapshot, values map[string]map[string]any) (uses []sizeUse, notChecked []string) {
	byKey := map[string]snapshot.Object{}
	for _, o := range s.Objects {
		byKey[strings.ToLower(o.Key())] = o
	}
	specOf := func(o snapshot.Object) map[string]any {
		spec, _ := o.Body["spec"].(map[string]any)
		if v := values[leaveOutKey(o)]; v != nil {
			spec = deepCopy(spec)
			merge(spec, deepCopy(v))
		}
		return spec
	}
	for _, o := range s.Objects {
		spec := specOf(o)
		loc, _ := spec["location"].(string)
		if loc == "" {
			kind, name := o.Kind(), o.Name()
			if i, j := strings.LastIndex(kind, "/"), strings.LastIndex(name, "/"); strings.Count(kind, "/") > 1 && j > 0 {
				parent := byKey[strings.ToLower(APIVersion+"|"+kind[:i]+"|"+o.Namespace()+"|"+name[:j])]
				if parent.Body != nil {
					loc, _ = specOf(parent)["location"].(string)
				}
			}
		}
		add := func(size, zones any, set string) {
			v, _ := size.(string)
			if v == "" {
				return
			}
			if loc == "" {
				notChecked = append(notChecked, fmt.Sprintf("%s uses %s, and its region is not in the snapshot", leaveOutKey(o), v))
				return
			}
			u := sizeUse{key: leaveOutKey(o), size: v, location: loc, set: set}
			zs, _ := zones.([]any)
			for _, z := range zs {
				u.zones = append(u.zones, fmt.Sprint(z))
			}
			uses = append(uses, u)
		}
		kind := strings.ToLower(o.Kind())
		if kind == strings.ToLower(managedClusterType) {
			pools, _ := lookupPath(spec, "properties.agentPoolProfiles").([]any)
			for _, p := range pools {
				add(lookupPath(p, "vmSize"), lookupPath(p, "availabilityZones"), "properties.agentPoolProfiles, the whole list")
			}
			continue
		}
		if h, ok := sizeHolders[kind]; ok {
			add(lookupPath(spec, h.size), lookupPath(spec, h.zones), h.set)
			continue
		}
		// Any other type that names a VM size (a Batch pool, a machine learning
		// compute) is said, so a check that found nothing is not read as all clear.
		if p := sizePath(spec, ""); p != "" {
			notChecked = append(notChecked, fmt.Sprintf("%s has a VM size at %s, which is not checked", leaveOutKey(o), p))
		}
	}
	return uses, notChecked
}

// vmSizeRE is a value spelled as a VM size is, the whole value
// (Standard_D2s_v5, Standard_DS3_v2, and a GPU size that names its
// accelerator, Standard_NC24ads_A100_v4, a confidential one,
// Standard_DC2ads_cc_v5, and a constrained-vCPU one, Standard_M128-64ms), not a
// storage or network SKU
// (Standard_LRS, Standard). notVMSizeRE are SKUs spelled like one: an
// application gateway's Standard_v2 and WAF_v2, a SignalR or Web PubSub
// Standard_S1, a Premium_P1 (review of #72).
var (
	vmSizeRE    = regexp.MustCompile(`(?i)^(standard|basic)_[a-z]{1,4}\d+(-\d+)?[a-z]*(_[a-z]+\d*)?(_v\d+)?$`)
	notVMSizeRE = regexp.MustCompile(`(?i)^([a-z]+_v\d+|(standard|premium|basic)_[sp]\d+)$`)
)

// sizePath is the first path under v whose key names a VM size, or whose
// value is spelled as one.
func sizePath(v any, at string) string {
	switch c := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(c) {
			// A tag is a person's note, whatever it says.
			if strings.EqualFold(k, "tags") {
				continue
			}
			p := join(at, k)
			if (strings.EqualFold(k, "vmSize") || strings.EqualFold(k, "vmSku")) && c[k] != nil {
				return p
			}
			if str, ok := c[k].(string); ok && vmSizeRE.MatchString(str) && !notVMSizeRE.MatchString(str) {
				return p
			}
			if q := sizePath(c[k], p); q != "" {
				return q
			}
		}
	case []any:
		for _, x := range c {
			if q := sizePath(x, at+"[]"); q != "" {
				return q
			}
		}
	}
	return ""
}

// SizesRefused says which VM sizes s uses that api's subscription cannot have
// where s uses them, in the zones they ask for, with values as a restore applies
// them, and how to restore at another size. What it could not check is said
// too: a list that cannot be read, a size with no region, a type it does not
// read.
func SizesRefused(ctx context.Context, api ARM, s snapshot.Snapshot, values map[string]map[string]any) SizeCheck {
	uses, notChecked := sizesOf(s, values)
	out := SizeCheck{NotChecked: notChecked}
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
	for _, l := range locs {
		path := "/subscriptions/" + api.Subscription() + "/providers/Microsoft.Compute/skus?$filter=" +
			strings.ReplaceAll(url.QueryEscape("location eq '"+l+"'"), "+", "%20")
		skus, err := api.List(ctx, path, skusVersion)
		if err != nil {
			out.NotChecked = append(out.NotChecked, fmt.Sprintf("cannot read the VM sizes offered in %s, so %d uses there were not checked: %v", l, len(byLoc[l]), err))
			continue
		}
		out.Regions++
		offered := map[string]map[string]any{}
		for _, k := range skus {
			if t, _ := k["resourceType"].(string); strings.EqualFold(t, "virtualMachines") {
				n, _ := k["name"].(string)
				offered[strings.ToLower(n)] = k
			}
		}
		for _, u := range byLoc[l] {
			out.Sizes++
			if why := refused(offered[strings.ToLower(u.size)], u.zones); why != "" {
				out.Refused = append(out.Refused, fmt.Sprintf("%s uses %s in %s, where this subscription cannot have it: %s. Azure will refuse it; ask Azure to offer it, or give another size with --values (%s)", u.key, u.size, l, why, u.set))
			}
		}
	}
	return out
}

// refused says why a size cannot be had in the zones asked for: not offered,
// restricted in the region, or not offered in a zone asked for, whether
// restricted there or not in the region's zones at all (a pool or VM pinned
// to one is refused AvailabilityZoneNotSupported). "" when it can.
func refused(sku map[string]any, asked []string) string {
	if sku == nil {
		return "it is not offered there"
	}
	rs, _ := sku["restrictions"].([]any)
	restricted := map[string]bool{}
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
				restricted[fmt.Sprint(z)] = true
			}
		}
	}
	offered := map[string]bool{}
	infos, _ := sku["locationInfo"].([]any)
	for _, x := range infos {
		info, _ := x.(map[string]any)
		zs, _ := info["zones"].([]any)
		for _, z := range zs {
			if !restricted[fmt.Sprint(z)] {
				offered[fmt.Sprint(z)] = true
			}
		}
	}
	var missing []string
	for _, z := range asked {
		if !offered[z] {
			missing = append(missing, z)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	sort.Strings(missing)
	have := sortedKeys(offered)
	if len(have) == 0 {
		return "it is asked for in zones " + strings.Join(missing, ", ") + ", and offered in no zone there"
	}
	return "it is asked for in zones " + strings.Join(missing, ", ") + ", and offered only in zones " + strings.Join(have, ", ")
}
