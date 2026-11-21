package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Clusters on GCP: a regional GKE cluster in the map's region, in the
// subnetwork the network family wrote for its pools, with its pools inline
// (GKE creates a cluster with its node pools). The cluster is VPC-native:
// pods and Services take addresses from secondary ranges written on the
// subnetwork, the source's pod and service ranges. Nodes have no public
// address unless the pool's had one.

const (
	gkeCluster = "container.googleapis.com/Cluster"
	// The source's version, in no release channel: GKE does not move it
	// on its own until its support ends.
	gkeNoChannel = "UNSPECIFIED"
)

type gke struct{ m Map }

var gkeLabelKey, gkeLabelValue = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`), regexp.MustCompile(`^[a-z0-9_-]{0,63}$`)

func (d gke) name(c *aksCluster) string {
	n := gcpName(c.name)
	if len(n) > 40 {
		n = strings.TrimRight(n[:40], "-")
	}
	return d.m.name(c.src, n)
}

func (d gke) cluster(c *aksCluster, o *out) bool {
	key := c.group + "/" + c.name
	cm := d.m.clusterMap(key)
	at := "clusters[" + key + "]"
	why := append([]string(nil), c.refuse...)
	if d.m.Region == "" {
		why = append(why, "the map names no region (region): a GKE cluster is written as a regional one")
	}
	if len(c.pools) == 0 {
		why = append(why, "it has no node pools in the snapshot")
	}
	var ns *netSub
	for _, p := range c.pools {
		pm := cm.pool(p.name)
		if pm.MachineType == "" {
			why = append(why, fmt.Sprintf("the map names no machine type for pool %s (%s.pools.%s.machineType; its Azure size is %s): VM sizes are not translated", p.name, at, p.name, orDefault(p.vmSize, "not in the snapshot")))
		}
		if pm.ServiceAccount == "" && cm.ServiceAccount == "" {
			why = append(why, fmt.Sprintf("the map names no service account for pool %s's nodes (%s.pools.%s.serviceAccount, or %s.serviceAccount): without one GKE runs them as the Compute Engine default service account, which holds the project's Editor role unless an organization policy prevents it, and every pod could act with it", p.name, at, p.name, at))
		}
		switch {
		case len(pm.Zones) == 0:
			why = append(why, fmt.Sprintf("the map names no zones for pool %s (%s.pools.%s.zones): a pool of a regional GKE cluster has the same number of nodes in each of the zones it is given", p.name, at, p.name))
		case d.m.Region != "":
			for _, z := range pm.Zones {
				if !strings.HasPrefix(z, d.m.Region+"-") {
					why = append(why, fmt.Sprintf("zone %s of pool %s (%s.pools.%s.zones) is not in region %s", z, p.name, at, p.name, d.m.Region))
				}
			}
			if p.count != nil && !p.auto && *p.count%len(pm.Zones) != 0 {
				why = append(why, fmt.Sprintf("pool %s has %d nodes, which GKE cannot put the same number of in each of its %d zones (%s.pools.%s.zones)", p.name, *p.count, len(pm.Zones), at, p.name))
			}
		}
		sk := p.subnet
		if sk == "" {
			sk = strings.ToLower(pm.Subnet)
		}
		if sk == "" {
			why = append(why, fmt.Sprintf("pool %s is in the network AKS made for it, which no snapshot holds: name one of the translated subnets in %s.pools.%s.subnet", p.name, at, p.name))
			continue
		}
		s, no := subnetFor(o, sk)
		switch {
		case s == nil:
			why = append(why, fmt.Sprintf("pool %s's subnet %s is not translated: %s", p.name, sk, no))
		case ns != nil && ns != s:
			why = append(why, "its pools are in more than one subnet; a GKE cluster's pools here share its one subnetwork (not translated yet)")
		default:
			ns = s
		}
	}
	podRange := c.podCidr
	if c.plugin == "azure" && c.pluginMode != "overlay" {
		// Azure CNI gave pods addresses from the VNet's subnets: GKE's
		// come from a range of their own, which is a choice.
		podRange = cm.PodCIDR
		if podRange == "" {
			why = append(why, fmt.Sprintf("its pods took addresses from the network's subnets (Azure CNI), and a GKE cluster's take them from a secondary range of the subnetwork: name it in %s.podCidr", at))
		}
	} else if cm.PodCIDR != "" {
		why = append(why, fmt.Sprintf("%s.podCidr is set, and the cluster has its own pod range (%s), which is carried over", at, c.podCidr))
	}
	if len(why) > 0 {
		o.entries = append(o.entries, Entry{Source: c.src, State: Refused, Reason: strings.Join(dedupe(why), "; ")})
		return false
	}

	name := d.name(c)
	region := gcpProject + "/locations/" + d.m.Region
	e := Entry{Source: c.src, State: Mapped, Losses: forTarget(c.losses, "gcp")}
	pods, svcs := gcpName(name, "pods"), gcpName(name, "services")
	ns.spec["secondaryIpRanges"] = append(list(ns.spec["secondaryIpRanges"]),
		map[string]any{"rangeName": pods, "ipCidrRange": podRange}, map[string]any{"rangeName": svcs, "ipCidrRange": c.serviceCidr})
	channel := gkeNoChannel
	if c.lts {
		channel = "EXTENDED"
	}
	ip := map[string]any{"enabled": true, "enablePublicEndpoint": c.public}
	if c.public && len(c.authorized) > 0 {
		cidrs, bad := validCIDRs(c.authorized)
		var blocks []any
		for _, x := range cidrs {
			blocks = append(blocks, map[string]any{"cidrBlock": x})
		}
		if len(bad) > 0 {
			e.Losses = append(e.Losses, Loss{Field: "properties.apiServerAccessProfile.authorizedIPRanges", Why: fmt.Sprintf("%v are not IPv4 ranges GKE takes; they are left out, so those addresses lose access", bad)})
		}
		if len(blocks) == 0 {
			ip["enablePublicEndpoint"] = false
			e.Losses = append(e.Losses, Loss{Field: "properties.apiServerAccessProfile.authorizedIPRanges", Why: "none of the allowed ranges can be written, so the public endpoint is shut"})
		} else {
			// Google Cloud's own addresses are not let in by being
			// Google's: only what the source allowed.
			ip["authorizedNetworksConfig"] = map[string]any{"enabled": true, "cidrBlocks": blocks, "gcpPublicCidrsAccessEnabled": false}
		}
	}
	spec := map[string]any{
		"description":           "From Azure Kubernetes Service cluster " + key,
		"initialClusterVersion": c.version,
		"releaseChannel":        map[string]any{"channel": channel},
		"network":               ns.network,
		"subnetwork":            ns.subnetwork,
		"ipAllocationPolicy": map[string]any{"useIpAliases": true, "stackType": "IPV4",
			"clusterSecondaryRangeName": pods, "servicesSecondaryRangeName": svcs},
		// No node has a public address unless its pool says so, as on AKS.
		"networkConfig": map[string]any{"defaultEnablePrivateNodes": true},
		// GKE's DNS endpoint answers from anywhere with IAM credentials;
		// AKS had none.
		"controlPlaneEndpointsConfig": map[string]any{"ipEndpointsConfig": ip, "dnsEndpointConfig": map[string]any{"allowExternalTraffic": false}},
	}
	if l, losses := gkeLabels(c.tags, "tags"); len(l) > 0 || len(losses) > 0 {
		if len(l) > 0 {
			spec["resourceLabels"] = l
		}
		e.Losses = append(e.Losses, losses...)
	}
	if c.plugin == "kubenet" || c.pluginMode == "overlay" {
		e.Losses = append(e.Losses, Loss{Field: "properties.networkProfile.podCidr", Why: c.podCidr + ": the pods' range is a secondary range of the subnetwork, so pod addresses are routable in the VPC network; what reaches a pod is what the firewall rules let through"})
	}
	switch c.policy {
	case "":
		if c.dataplane == "cilium" {
			spec["networkConfig"].(map[string]any)["datapathProvider"] = "ADVANCED_DATAPATH"
		}
	case "azure", "cilium":
		// GKE Dataplane V2 enforces Kubernetes NetworkPolicy.
		spec["networkConfig"].(map[string]any)["datapathProvider"] = "ADVANCED_DATAPATH"
		if c.policy == "cilium" {
			e.Losses = append(e.Losses, Loss{Field: "properties.networkProfile.networkPolicy", Widens: true,
				Why: "cilium: GKE Dataplane V2 enforces Kubernetes NetworkPolicy objects, not Cilium's own (CiliumNetworkPolicy); whatever those denied is let through"})
		}
	case "calico":
		spec["networkPolicy"] = map[string]any{"enabled": true, "provider": "CALICO"}
		spec["addonsConfig"] = map[string]any{"networkPolicyConfig": map[string]any{"disabled": false}}
	default:
		e.Losses = append(e.Losses, Loss{Field: "properties.networkProfile.networkPolicy", Widens: true, Why: c.policy + " is not a policy engine this reads: its policies are not enforced on the target"})
	}
	switch {
	case cm.KMSKey != "":
		spec["databaseEncryption"] = map[string]any{"state": "ENCRYPTED", "keyName": cm.KMSKey}
	case c.kms:
		e.Losses = append(e.Losses, Loss{Field: "properties.securityProfile.azureKeyVaultKms", Widens: true,
			Why: "the cluster's secrets were encrypted with the customer's own key; GKE does not encrypt them at the application layer until the map names a Cloud KMS key (" + at + ".kmsKey)"})
	}
	if c.vpa {
		spec["verticalPodAutoscaling"] = map[string]any{"enabled": true}
	}
	var pools []any
	for _, p := range c.pools {
		pools = append(pools, d.nodePool(c, p, cm, ns, &e))
	}
	spec["nodePools"] = pools
	e.Targets = append(e.Targets, o.add("gcp", c.src, gkeObject(region, name, spec)))
	sort.Strings(e.Targets)
	o.require(fmt.Sprintf("GKE validates Kubernetes %s at restore: if it no longer offers that version, a person chooses one, as the translation never upgrades", c.version))
	o.require(fmt.Sprintf("GKE cluster %s takes no one's access from Azure: grant the people and tools that use it IAM roles on the project, and RBAC in the cluster, before restoring its workloads (#32)", name))
	if !c.public {
		o.require(fmt.Sprintf("GKE cluster %s's API server answers only inside its VPC network: kubectl and the restore of its workloads run from there", name))
	}
	clusterRequirements(c, o, "GKE")
	o.entries = append(o.entries, e)
	return true
}

func (d gke) nodePool(c *aksCluster, p *aksPool, cm ClusterMap, ns *netSub, e *Entry) map[string]any {
	pm := cm.pool(p.name)
	at := p.field
	sa := pm.ServiceAccount
	if sa == "" {
		sa = cm.ServiceAccount
	}
	if !strings.Contains(sa, "@") {
		sa += "@{{truthform|project}}.iam.gserviceaccount.com"
	}
	conf := map[string]any{"machineType": pm.MachineType, "serviceAccount": sa,
		"shieldedInstanceConfig": map[string]any{"enableSecureBoot": p.secureBoot, "enableIntegrityMonitoring": true}}
	if p.disk != nil {
		conf["diskSizeGb"] = *p.disk
	}
	switch {
	case p.windows != "":
		conf["imageType"] = "WINDOWS_LTSC_CONTAINERD"
		conf["windowsNodeConfig"] = map[string]any{"osVersion": "OS_VERSION_LTSC" + p.windows}
	case p.ubuntu:
		conf["imageType"] = "UBUNTU_CONTAINERD"
	default:
		conf["imageType"] = "COS_CONTAINERD"
	}
	if p.spot {
		conf["spot"] = true
	}
	if len(p.labels) > 0 {
		l := map[string]any{}
		for k, v := range p.labels {
			l[k] = v
		}
		conf["labels"] = l
	}
	if len(p.taints) > 0 {
		var ts []any
		for _, t := range p.taints {
			ts = append(ts, map[string]any{"key": t.key, "value": t.value, "effect": taintEffect(t.effect)})
		}
		conf["taints"] = ts
	}
	if l, losses := gkeLabels(p.tags, at+"tags"); len(l) > 0 || len(losses) > 0 {
		if len(l) > 0 {
			conf["resourceLabels"] = l
		}
		e.Losses = append(e.Losses, losses...)
	}
	if ns.tag != "" {
		// The firewall rules translated from the subnet's NSG apply by
		// this tag.
		conf["tags"] = []any{ns.tag}
	}
	if p.streaming {
		conf["gcfsConfig"] = map[string]any{"enabled": true}
	}
	if p.sshOff {
		conf["metadata"] = map[string]any{"block-project-ssh-keys": "true"}
	}
	np := map[string]any{"name": p.name, "config": conf, "locations": anyList(pm.Zones),
		"management":    map[string]any{"autoRepair": true, "autoUpgrade": c.autoUpgrade || c.lts},
		"networkConfig": map[string]any{"enablePrivateNodes": !p.publicIP}}
	zones := len(pm.Zones)
	if p.auto {
		np["autoscaling"] = map[string]any{"enabled": true, "totalMinNodeCount": *p.min, "totalMaxNodeCount": *p.max, "locationPolicy": "BALANCED"}
		np["initialNodeCount"] = (*p.count + zones - 1) / zones
	} else {
		np["initialNodeCount"] = *p.count / zones
	}
	if p.maxPods != nil {
		np["maxPodsConstraint"] = map[string]any{"maxPodsPerNode": fmt.Sprint(*p.maxPods)}
	}
	if p.version != "" {
		np["version"] = p.version
	}
	if p.surge != nil || p.unavailble != nil {
		us := map[string]any{"strategy": "SURGE"}
		if p.surge != nil {
			us["maxSurge"] = *p.surge
		}
		if p.unavailble != nil {
			us["maxUnavailable"] = *p.unavailble
		}
		np["upgradeSettings"] = us
	}
	if len(p.zones) > zones {
		e.Losses = append(e.Losses, Loss{Field: at + "availabilityZones", Why: fmt.Sprintf("the pool's nodes were spread over %d zones; the map gives it %d", len(p.zones), zones)})
	}
	if p.vtpm && !p.secureBoot {
		e.Losses = append(e.Losses, Loss{Field: at + "securityProfile.enableVTPM", Why: "GKE's shielded nodes always have a vTPM, used for integrity monitoring"})
	}
	return np
}

func gkeObject(parent, name string, spec map[string]any) snapshot.Object {
	s := map[string]any{"name": name}
	for k, v := range spec {
		s[k] = v
	}
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": gkeCluster,
		"metadata": map[string]any{"name": parent + "/clusters/" + name, "annotations": map[string]any{
			"truthform.org/discovery":  "container/v1",
			"truthform.org/schema":     "Cluster",
			"truthform.org/collection": "projects.locations.clusters",
			"truthform.org/parent":     parent,
		}}, "spec": s}}
}

// gkeLabels are the tags GKE's label rules let through.
func gkeLabels(tags map[string]string, field string) (map[string]any, []Loss) {
	out := map[string]any{}
	var bad []string
	for _, k := range sortedMapKeys(tags) {
		if gkeLabelKey.MatchString(k) && gkeLabelValue.MatchString(tags[k]) {
			out[k] = tags[k]
		} else {
			bad = append(bad, k)
		}
	}
	if len(bad) == 0 {
		return out, nil
	}
	return out, []Loss{{Field: field, Why: fmt.Sprintf("tag(s) %s are not GKE labels (lower case letters, digits, - and _): not carried over", strings.Join(bad, ", "))}}
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
