package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Clusters on AWS: an EKS cluster in the subnets the network family wrote
// for its pools, and a managed node group per pool. Pods take addresses
// from the VPC (the VPC CNI), as Azure CNI's did from the VNet; an overlay
// or kubenet cluster's pod range is not carried over.

const (
	awsEKS       = "AWS::EKS::Cluster"
	awsNodegroup = "AWS::EKS::Nodegroup"
	awsAddon     = "AWS::EKS::Addon"
)

type eks struct{ m Map }

func (d eks) cluster(c *aksCluster, o *out) bool {
	key := c.group + "/" + c.name
	cm := d.m.clusterMap(key)
	at := "clusters[" + key + "]"
	why := append([]string(nil), c.refuse...)
	role, nodeRole := iamRole(cm.RoleARN), iamRole(cm.NodeRoleARN)
	switch {
	case cm.RoleARN == "":
		why = append(why, "the map names no IAM role for the control plane ("+at+".roleArn): identity is not translated (#32), so it names a role that exists")
	case role == "":
		why = append(why, fmt.Sprintf("%s.roleArn %q is not an IAM role's ARN", at, cm.RoleARN))
	}
	switch {
	case cm.NodeRoleARN == "":
		why = append(why, "the map names no IAM role for the nodes ("+at+".nodeRoleArn): identity is not translated (#32), so it names a role that exists")
	case nodeRole == "":
		why = append(why, fmt.Sprintf("%s.nodeRoleArn %q is not an IAM role's ARN", at, cm.NodeRoleARN))
	}
	kmsKey := ""
	if cm.KMSKey != "" {
		if kmsKey = d.kmsKey(cm.KMSKey); kmsKey == "" {
			why = append(why, fmt.Sprintf("%s.kmsKey %q is neither a KMS key's ARN nor its ID", at, cm.KMSKey))
		}
	}
	if len(c.pools) == 0 {
		why = append(why, "it has no node pools in the snapshot")
	}
	subnets := map[string]*netSub{} // pool -> subnet
	vnets := map[string]bool{}
	zones := map[string]bool{}
	var subnetIDs []any
	seen := map[string]bool{}
	addSubnet := func(ns *netSub) {
		vnets[ns.vnet] = true
		zones[ns.zone] = true
		if !seen[ns.awsName] {
			seen[ns.awsName] = true
			subnetIDs = append(subnetIDs, awsRef(awsSN, ns.awsName, "SubnetId"))
		}
	}
	for _, p := range c.pools {
		pm := cm.pool(p.name)
		if pm.InstanceType == "" {
			why = append(why, fmt.Sprintf("the map names no instance type for pool %s (%s.pools.%s.instanceType; its Azure size is %s): VM sizes are not translated", p.name, at, p.name, orDefault(p.vmSize, "not in the snapshot")))
		}
		sk := p.subnet
		if sk == "" {
			sk = strings.ToLower(pm.Subnet)
		}
		if sk == "" {
			why = append(why, fmt.Sprintf("pool %s is in the network AKS made for it, which no snapshot holds: name one of the translated subnets in %s.pools.%s.subnet", p.name, at, p.name))
			continue
		}
		ns, no := subnetFor(o, sk)
		if ns == nil {
			why = append(why, fmt.Sprintf("pool %s's subnet %s is not translated: %s", p.name, sk, no))
			continue
		}
		subnets[p.name] = ns
		addSubnet(ns)
	}
	for _, s := range cm.Subnets {
		ns, no := subnetFor(o, strings.ToLower(s))
		if ns == nil {
			why = append(why, fmt.Sprintf("subnet %s (%s.subnets) is not translated: %s", s, at, no))
			continue
		}
		addSubnet(ns)
	}
	if len(vnets) > 1 {
		why = append(why, "its pools are in more than one network; an EKS cluster is in one VPC")
	}
	if len(zones) == 1 && len(why) == 0 {
		var z string
		for k := range zones {
			z = k
		}
		why = append(why, fmt.Sprintf("EKS needs the cluster's subnets in at least two availability zones, and its pools' subnets are all in %s: put another of the network's subnets in a second zone (network.zones) and name it in %s.subnets", z, at))
	}
	if len(why) > 0 {
		o.entries = append(o.entries, Entry{Source: c.src, State: Refused, Reason: strings.Join(why, "; ")})
		return false
	}

	name := d.m.name(c.src, c.name)
	e := Entry{Source: c.src, State: Mapped, Losses: forTarget(c.losses, "aws")}
	vpc := map[string]any{"SubnetIds": subnetIDs, "EndpointPublicAccess": c.public, "EndpointPrivateAccess": !c.public}
	if c.public {
		cidrs, bad := validCIDRs(c.authorized)
		if len(c.authorized) == 0 {
			cidrs = []string{"0.0.0.0/0"}
		} else if len(cidrs) == 0 {
			// Every range it allowed is one EKS cannot take: allowing
			// all would widen, so the public endpoint is shut.
			vpc["EndpointPublicAccess"], vpc["EndpointPrivateAccess"] = false, true
			e.Losses = append(e.Losses, Loss{Field: "properties.apiServerAccessProfile.authorizedIPRanges", Why: fmt.Sprintf("%v: none is an IPv4 range EKS takes, so the public endpoint is shut and the API server answers inside the VPC only", bad)})
		}
		if len(bad) > 0 && len(cidrs) > 0 {
			e.Losses = append(e.Losses, Loss{Field: "properties.apiServerAccessProfile.authorizedIPRanges", Why: fmt.Sprintf("%v are not IPv4 ranges EKS takes; they are left out, so those addresses lose access", bad)})
		}
		if vpc["EndpointPublicAccess"] == true {
			vpc["PublicAccessCidrs"] = anyList(cidrs)
			o.require(fmt.Sprintf("EKS cluster %s answers on its public endpoint only, as the AKS one did: its nodes reach it through the subnets' internet egress, so they need a NAT gateway, and its address must be among the allowed ranges (%s)", name, strings.Join(cidrs, ", ")))
		}
	}
	spec := map[string]any{
		"Name": name, "Version": c.version, "RoleArn": role,
		"ResourcesVpcConfig":      vpc,
		"KubernetesNetworkConfig": map[string]any{"ServiceIpv4Cidr": c.serviceCidr, "IpFamily": "ipv4"},
		// Who may use the cluster is set by access entries alone, and
		// whoever restores it is not made its admin: identity is not
		// translated (#32).
		"AccessConfig":  map[string]any{"AuthenticationMode": "API", "BootstrapClusterCreatorAdminPermissions": false},
		"UpgradePolicy": map[string]any{"SupportType": map[bool]string{false: "STANDARD", true: "EXTENDED"}[c.lts]},
	}
	if tags, losses := eksTags(c.tags); len(tags) > 0 || len(losses) > 0 {
		if len(tags) > 0 {
			spec["Tags"] = tags
		}
		e.Losses = append(e.Losses, losses...)
	}
	switch {
	case kmsKey != "":
		spec["EncryptionConfig"] = []any{map[string]any{"Provider": map[string]any{"KeyArn": kmsKey}, "Resources": []any{"secrets"}}}
	case c.kms:
		e.Losses = append(e.Losses, Loss{Field: "properties.securityProfile.azureKeyVaultKms", Widens: true,
			Why: "the cluster's secrets were encrypted with the customer's own key; EKS encrypts them with an AWS-owned key until the map names one (" + "clusters[" + key + "].kmsKey)"})
	}
	if c.plugin == "kubenet" || c.pluginMode == "overlay" {
		e.Losses = append(e.Losses, Loss{Field: "properties.networkProfile.podCidr", Why: c.podCidr + ": EKS's pods take addresses from the nodes' subnets (VPC CNI), not from a range of their own: the subnets must have room for every node's pods, and what reaches a pod is what the node's security group lets through"})
	}
	if c.dataplane == "cilium" {
		e.Losses = append(e.Losses, Loss{Field: "properties.networkProfile.networkDataplane", Why: "Azure CNI powered by Cilium is replaced by the VPC CNI"})
	}
	e.Targets = append(e.Targets, o.add("aws", c.src, awsObject(awsEKS, name, spec)))
	switch c.policy {
	case "":
	case "azure", "calico", "cilium":
		// The VPC CNI enforces Kubernetes NetworkPolicy once told to.
		// Named as a capture names it: its identifier, cluster|addon, made
		// safe.
		e.Targets = append(e.Targets, o.add("aws", c.src, awsObject(awsAddon, name+"_vpc-cni", map[string]any{
			"ClusterName": awsRef(awsEKS, name, "identifier"), "AddonName": "vpc-cni",
			"ConfigurationValues": `{"enableNetworkPolicy":"true"}`, "ResolveConflicts": "OVERWRITE",
		})))
		if c.policy != "azure" {
			e.Losses = append(e.Losses, Loss{Field: "properties.networkProfile.networkPolicy", Widens: true,
				Why: c.policy + ": the VPC CNI enforces Kubernetes NetworkPolicy objects, not " + map[string]string{"calico": "Calico's own (NetworkPolicy and GlobalNetworkPolicy in projectcalico.org)", "cilium": "Cilium's own (CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy)"}[c.policy] + "; whatever those denied is let through until that engine is installed on the cluster"})
		}
	default:
		e.Losses = append(e.Losses, Loss{Field: "properties.networkProfile.networkPolicy", Widens: true, Why: c.policy + " is not a policy engine this reads: its policies are not enforced on the target"})
	}
	for _, p := range c.pools {
		e.Targets = append(e.Targets, d.nodegroup(c, p, name, subnets[p.name], cm, nodeRole, &e, o))
	}
	sort.Strings(e.Targets)
	o.require(fmt.Sprintf("EKS validates Kubernetes %s at restore: if it no longer offers that version, a person chooses one, as the translation never upgrades", c.version))
	o.require(fmt.Sprintf("EKS cluster %s takes no one's access from Azure: add access entries for the people and tools that use it before restoring its workloads (#32)", name))
	if !c.public {
		o.require(fmt.Sprintf("EKS cluster %s's API server answers only inside its VPC: kubectl and the restore of its workloads run from there", name))
	}
	clusterRequirements(c, o, "EKS")
	o.entries = append(o.entries, e)
	return true
}

func (d eks) nodegroup(c *aksCluster, p *aksPool, cluster string, ns *netSub, cm ClusterMap, nodeRole string, e *Entry, o *out) string {
	name := d.m.name(c.group+"/"+c.name+"/"+p.name, cluster+"-"+p.name)
	at := p.field
	spec := map[string]any{
		"ClusterName": awsRef(awsEKS, cluster, "identifier"), "NodegroupName": name, "NodeRole": nodeRole,
		"Subnets": []any{awsRef(awsSN, ns.awsName, "SubnetId")}, "InstanceTypes": []any{cm.pool(p.name).InstanceType},
		"CapacityType": map[bool]string{false: "ON_DEMAND", true: "SPOT"}[p.spot],
		// AKS repairs its nodes itself.
		"NodeRepairConfig": map[string]any{"Enabled": true},
	}
	count := *p.count
	if p.auto {
		spec["ScalingConfig"] = map[string]any{"MinSize": *p.min, "MaxSize": *p.max, "DesiredSize": count}
		e.Losses = append(e.Losses, Loss{Field: at + "enableAutoScaling", Why: "EKS does not scale node groups itself: the bounds are written, and the Cluster Autoscaler or Karpenter, installed on the cluster, does the scaling"})
	} else {
		max := count
		if max < 1 {
			max = 1 // EKS's least; with no autoscaler the group stays at its desired size
		}
		spec["ScalingConfig"] = map[string]any{"MinSize": count, "MaxSize": max, "DesiredSize": count}
	}
	if p.disk != nil {
		spec["DiskSize"] = *p.disk
	}
	if p.version != "" {
		spec["Version"] = p.version
	}
	if p.windows != "" {
		spec["AmiType"] = "WINDOWS_CORE_" + p.windows + "_x86_64"
		o.require("EKS cluster " + cluster + " runs Windows nodes: Windows support (the VPC CNI's Windows IPAM) is turned on, and a Linux node group runs the cluster's own pods")
	}
	if len(p.labels) > 0 {
		l := map[string]any{}
		for k, v := range p.labels {
			l[k] = v
		}
		spec["Labels"] = l
	}
	if len(p.taints) > 0 {
		var ts []any
		for _, t := range p.taints {
			m := map[string]any{"Key": t.key, "Effect": taintEffect(t.effect)}
			if t.value != "" {
				m["Value"] = t.value
			}
			ts = append(ts, m)
		}
		spec["Taints"] = ts
	}
	if len(p.tags) > 0 {
		t := map[string]any{}
		for k, v := range p.tags {
			t[k] = v
		}
		spec["Tags"] = t
		e.Losses = append(e.Losses, Loss{Field: at + "tags", Why: "the tags are put on the node group; EKS does not put a node group's tags on its instances"})
	}
	if len(p.zones) > 1 {
		e.Losses = append(e.Losses, Loss{Field: at + "availabilityZones", Why: fmt.Sprintf("the pool's nodes were spread over zones %s; an AWS subnet is in one zone, so they are all in %s", strings.Join(p.zones, ", "), ns.zone)})
	}
	if p.maxPods != nil {
		e.Losses = append(e.Losses, Loss{Field: at + "maxPods", Why: fmt.Sprintf("%d: the VPC CNI sets how many pods a node takes from its instance type's network interfaces", *p.maxPods)})
	}
	if p.publicIP {
		e.Losses = append(e.Losses, Loss{Field: at + "enableNodePublicIP", Why: "the nodes had public addresses; the translated subnets give none, so they are reachable only inside the VPC"})
	}
	if p.surge != nil || p.unavailble != nil {
		e.Losses = append(e.Losses, Loss{Field: at + "upgradeSettings", Why: "EKS upgrades a node group with its own surge; the source's surge is not carried over"})
	}
	if ns.tag != "" {
		o.require(fmt.Sprintf("EKS node group %s's nodes are in the cluster's security group; security group %s, translated from their subnet's NSG, applies to them only through a launch template (not translated)", name, ns.tag))
	}
	return o.add("aws", c.src, awsObject(awsNodegroup, name, spec))
}

var (
	iamRoleRE = regexp.MustCompile(`^(arn:aws[a-z-]*:iam::)(\d{12})(:role/.+)$`)
	kmsKeyRE  = regexp.MustCompile(`^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(key|alias)/.+$`)
	keyIDRE   = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)
)

// iamRole is a role ARN with its account as the account restored into: an
// EKS cluster's roles are in its own account, and a capture of it writes
// them so. "" when it is not a role's ARN.
func iamRole(arn string) string {
	m := iamRoleRE.FindStringSubmatch(arn)
	if m == nil {
		return ""
	}
	return m[1] + awsRef("account", "self", "id") + m[3]
}

// kmsKey is the key the map names: an ARN as it is (the key can be in
// another account), or a key ID in the account restored into.
func (d eks) kmsKey(k string) string {
	switch {
	case kmsKeyRE.MatchString(k):
		return k
	case keyIDRE.MatchString(k):
		return "arn:aws:kms:" + d.m.Region + ":" + awsRef("account", "self", "id") + ":key/" + k
	}
	return ""
}

// eksTags are an EKS cluster's tags, without the ones AWS reserves.
func eksTags(tags map[string]string) ([]any, []Loss) {
	var out []any
	var losses []Loss
	for _, k := range sortedMapKeys(tags) {
		if strings.HasPrefix(strings.ToLower(k), "aws:") {
			losses = append(losses, Loss{Field: "tags." + k, Why: "AWS reserves tags that begin aws:"})
			continue
		}
		out = append(out, map[string]any{"Key": k, "Value": tags[k]})
	}
	return out, losses
}
