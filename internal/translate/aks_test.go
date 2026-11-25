package translate

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

const azSubnetID = "/subscriptions/{{truthform|subscription}}/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/core/subnets/"

// aksFixture is a made-up network and two clusters on it: shop, public
// behind authorized ranges, Azure CNI overlay with Azure's network policy,
// a system, a spot, a Windows pool and one kept as an object of its own;
// priv, a private kubenet cluster with Calico. Around them, children the
// translation decides without a target, and a pool whose cluster is gone.
func aksFixture() snapshot.Snapshot {
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.Network/virtualNetworks", "net", "core", map[string]any{"location": "westeurope",
			"properties": map[string]any{
				"addressSpace": map[string]any{"addressPrefixes": []any{"10.20.0.0/16"}},
				"subnets": []any{
					map[string]any{"name": "app", "properties": map[string]any{"addressPrefix": "10.20.1.0/24", "networkSecurityGroup": nsgRef("net", "web")}},
					map[string]any{"name": "data", "properties": map[string]any{"addressPrefix": "10.20.2.0/24"}},
					map[string]any{"name": "spare", "properties": map[string]any{"addressPrefix": "10.20.3.0/24"}},
				},
			}}),
		az("Microsoft.Network/networkSecurityGroups", "net", "web", map[string]any{"location": "westeurope",
			"properties": map[string]any{"securityRules": []any{rule("allow-https", "Allow", "Inbound", 100, "Tcp", "Internet", "*", "443")}}}),
		az("Microsoft.ContainerService/managedClusters", "rg", "shop", map[string]any{"location": "westeurope",
			"tags":     map[string]any{"env": "prod", "Cost Centre": "42"},
			"sku":      map[string]any{"name": "Base", "tier": "Standard"},
			"identity": map[string]any{"type": "SystemAssigned"},
			"properties": map[string]any{
				"kubernetesVersion": "1.31.2", "dnsPrefix": "shop", "enableRBAC": true, "disableLocalAccounts": false,
				"supportPlan": "KubernetesOfficial", "nodeResourceGroup": "MC_rg_shop_westeurope",
				"agentPoolProfiles": []any{
					map[string]any{"name": "system", "mode": "System", "count": 3, "vmSize": "Standard_D4s_v5", "osDiskSizeGB": 128,
						"osType": "Linux", "osSKU": "Ubuntu", "type": "VirtualMachineScaleSets", "availabilityZones": []any{"1", "2", "3"},
						"vnetSubnetID": azSubnetID + "app", "nodeTaints": []any{"CriticalAddonsOnly=true:NoSchedule"}, "maxPods": 30,
						"orchestratorVersion": "1.31.2", "enableNodePublicIP": false, "scaleSetPriority": "Regular"},
					map[string]any{"name": "user", "mode": "User", "count": 2, "minCount": 2, "maxCount": 6, "enableAutoScaling": true,
						"vmSize": "Standard_D8s_v5", "osDiskSizeGB": 256, "osType": "Linux", "osSKU": "AzureLinux",
						"vnetSubnetID": azSubnetID + "app", "scaleSetPriority": "Spot", "scaleSetEvictionPolicy": "Delete", "spotMaxPrice": -1,
						"nodeLabels": map[string]any{"workload": "web"}, "maxPods": 50, "enableEncryptionAtHost": true,
						"upgradeSettings": map[string]any{"maxSurge": "1"}},
					map[string]any{"name": "win", "mode": "User", "count": 2, "vmSize": "Standard_D4s_v5", "osDiskSizeGB": 128,
						"osType": "Windows", "osSKU": "Windows2022", "vnetSubnetID": azSubnetID + "app",
						"nodeTaints": []any{"os=windows:NoSchedule"}},
				},
				"networkProfile": map[string]any{"networkPlugin": "azure", "networkPluginMode": "overlay", "networkPolicy": "azure",
					"podCidr": "10.244.0.0/16", "serviceCidr": "10.0.0.0/16", "dnsServiceIP": "10.0.0.10", "outboundType": "loadBalancer",
					"loadBalancerSku": "standard", "ipFamilies": []any{"IPv4"}},
				"apiServerAccessProfile": map[string]any{"authorizedIPRanges": []any{"203.0.113.0/24"}, "enablePrivateCluster": false},
				"securityProfile": map[string]any{"azureKeyVaultKms": map[string]any{"enabled": true, "keyId": "https://kv/keys/k"},
					"workloadIdentity": map[string]any{"enabled": true}},
				"oidcIssuerProfile":  map[string]any{"enabled": true},
				"aadProfile":         map[string]any{"managed": true, "enableAzureRBAC": true},
				"autoUpgradeProfile": map[string]any{"upgradeChannel": "patch", "nodeOSUpgradeChannel": "NodeImage"},
				"addonProfiles": map[string]any{
					"azurepolicy":   map[string]any{"enabled": true},
					"omsagent":      map[string]any{"enabled": true, "config": map[string]any{"logAnalyticsWorkspaceResourceID": "x"}},
					"kubeDashboard": map[string]any{"enabled": false},
				},
				"identityProfile": map[string]any{"kubeletidentity": map[string]any{"resourceId": "x"}},
				"storageProfile":  map[string]any{"diskCSIDriver": map[string]any{"enabled": true}},
			}}),
		az("Microsoft.ContainerService/managedClusters/agentPools", "rg", "shop/batch", pr(map[string]any{
			"mode": "User", "count": 2, "vmSize": "Standard_E4s_v5", "osDiskSizeGB": 128, "osType": "Linux",
			"vnetSubnetID": azSubnetID + "app"})),
		az("Microsoft.ContainerService/managedClusters", "rg", "priv", map[string]any{"location": "westeurope",
			"properties": map[string]any{
				"kubernetesVersion": "1.30", "enableRBAC": true, "disableLocalAccounts": true,
				"agentPoolProfiles": []any{
					map[string]any{"name": "nodes", "mode": "System", "count": 2, "vmSize": "Standard_D2s_v5", "osDiskSizeGB": 64,
						"osType": "Linux", "vnetSubnetID": azSubnetID + "data",
						"securityProfile": map[string]any{"sshAccess": "Disabled"}},
				},
				"networkProfile": map[string]any{"networkPlugin": "kubenet", "networkPolicy": "calico",
					"podCidr": "10.245.0.0/16", "serviceCidr": "10.1.0.0/16", "outboundType": "userDefinedRouting"},
				"apiServerAccessProfile": map[string]any{"enablePrivateCluster": true, "privateDNSZone": "system"},
				"publicNetworkAccess":    "Disabled",
			}}),
		az("Microsoft.ContainerService/managedClusters/maintenanceConfigurations", "rg", "shop/default", pr(map[string]any{"timeInWeek": []any{}})),
		az("Microsoft.ContainerService/managedClusters/trustedAccessRoleBindings", "rg", "shop/backup", pr(map[string]any{"roles": []any{"x"}})),
		az("Microsoft.ContainerService/managedClusters/upgradeProfiles", "rg", "shop/default", nil),
		az("Microsoft.ContainerService/managedClusters/agentPools", "rg", "gone/pool", pr(map[string]any{"count": 1})),
	}}
}

func aksMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Zones: map[string]string{
		"net/core/app": "eu-west-1a", "net/core/data": "eu-west-1b", "net/core/spare": "eu-west-1c"}}}
	a.Destinations.Network, a.Destinations.Clusters = "vpc", "eks"
	a.Clusters = map[string]ClusterMap{
		"rg/shop": {RoleARN: "arn:aws:iam::111111111111:role/eks-shop", NodeRoleARN: "arn:aws:iam::111111111111:role/eks-shop-nodes",
			KMSKey: "0b2c3d4e-1111-2222-3333-444455556666", Subnets: []string{"net/core/data"},
			Pools: map[string]PoolMap{"system": {InstanceType: "m7i.xlarge"}, "user": {InstanceType: "m7i.2xlarge"}, "win": {InstanceType: "m7i.xlarge"}, "batch": {InstanceType: "r7i.xlarge"}}},
		"rg/priv": {RoleARN: "arn:aws:iam::111111111111:role/eks-priv", NodeRoleARN: "arn:aws:iam::111111111111:role/eks-priv-nodes",
			Subnets: []string{"net/core/spare"}, Pools: map[string]PoolMap{"nodes": {InstanceType: "m7i.large"}}},
	}
	g := Map{To: "gcp", Region: "europe-west1"}
	g.Destinations.Network, g.Destinations.Clusters = "vpc", "gke"
	three := []string{"europe-west1-b", "europe-west1-c", "europe-west1-d"}
	g.Clusters = map[string]ClusterMap{
		"rg/shop": {KMSKey: "projects/kms-project/locations/europe-west1/keyRings/r/cryptoKeys/k", ServiceAccount: "gke-shop-nodes",
			Pools: map[string]PoolMap{"system": {MachineType: "n2-standard-4", Zones: three}, "user": {MachineType: "n2-standard-8", Zones: three},
				"win": {MachineType: "n2-standard-4", Zones: three[:2]}, "batch": {MachineType: "n2-highmem-4", Zones: three[:2]}}},
		"rg/priv": {Pools: map[string]PoolMap{"nodes": {MachineType: "e2-standard-2", Zones: three[:1], ServiceAccount: "gke-priv@shared-accounts.iam.gserviceaccount.com"}}},
	}
	return map[string]Map{"aws": a, "gcp": g}
}

func runAKS(t *testing.T, s snapshot.Snapshot, m Map) Result {
	t.Helper()
	r, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// aksSpec is the fixture with one setting of a cluster changed.
func aksSpec(t *testing.T, cluster string, edit func(props map[string]any)) snapshot.Snapshot {
	t.Helper()
	s := aksFixture()
	for _, o := range s.Objects {
		if o.Kind() == "Microsoft.ContainerService/managedClusters" && o.Name() == cluster {
			edit(obj(o.Body["spec"])["properties"].(map[string]any))
			return s
		}
	}
	t.Fatalf("no cluster %s", cluster)
	return s
}

func pool(props map[string]any, name string) map[string]any {
	for _, x := range list(props["agentPoolProfiles"]) {
		if obj(x)["name"] == name {
			return obj(x)
		}
	}
	return nil
}

func gkeSpec(t *testing.T, r Result, name string) map[string]any {
	t.Helper()
	return object(t, r, "gcp", gkeCluster, gcpProject+"/locations/europe-west1/clusters/"+name)
}

func gkePool(t *testing.T, c map[string]any, name string) map[string]any {
	t.Helper()
	for _, x := range list(c["nodePools"]) {
		if obj(x)["name"] == name {
			return obj(x)
		}
	}
	t.Fatalf("no node pool %s in %v", name, c["nodePools"])
	return nil
}

func TestClustersGolden(t *testing.T) {
	for name, m := range aksMaps() {
		r := runAKS(t, aksFixture(), m)
		golden(t, "clusters-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
		}
		for _, o := range aksFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
		for _, e := range r.Report.Entries {
			for _, l := range e.Losses {
				if l.Unread || strings.Contains(l.Field, "|") {
					t.Errorf("%s: %s: %+v", name, e.Source, l)
				}
			}
		}
	}
}

func TestClustersToEKS(t *testing.T) {
	r := runAKS(t, aksFixture(), aksMaps()["aws"])
	shop := object(t, r, "aws", awsEKS, "shop")
	if shop["Version"] != "1.31" || shop["RoleArn"] != "arn:aws:iam::{{truthform|account|self|id}}:role/eks-shop" {
		t.Errorf("shop: %v %v", shop["Version"], shop["RoleArn"])
	}
	vpc := obj(shop["ResourcesVpcConfig"])
	if vpc["EndpointPublicAccess"] != true || vpc["EndpointPrivateAccess"] != false || fmt.Sprint(vpc["PublicAccessCidrs"]) != "[203.0.113.0/24]" {
		t.Errorf("shop's endpoint: %v", vpc)
	}
	if n := len(list(vpc["SubnetIds"])); n != 2 {
		t.Errorf("shop's subnets: %v", vpc["SubnetIds"])
	}
	if !strings.Contains(fmt.Sprint(vpc["SubnetIds"]), awsRef(awsSN, "core-app", "SubnetId")) {
		t.Errorf("shop is not in the translated app subnet: %v", vpc["SubnetIds"])
	}
	if obj(shop["KubernetesNetworkConfig"])["ServiceIpv4Cidr"] != "10.0.0.0/16" {
		t.Errorf("service range: %v", shop["KubernetesNetworkConfig"])
	}
	if ec := list(shop["EncryptionConfig"]); len(ec) != 1 || obj(obj(ec[0])["Provider"])["KeyArn"] != "arn:aws:kms:eu-west-1:{{truthform|account|self|id}}:key/0b2c3d4e-1111-2222-3333-444455556666" {
		t.Errorf("secrets encryption: %v", shop["EncryptionConfig"])
	}
	if ac := obj(shop["AccessConfig"]); ac["AuthenticationMode"] != "API" || ac["BootstrapClusterCreatorAdminPermissions"] != false {
		t.Errorf("access: %v", ac)
	}
	if obj(shop["UpgradePolicy"])["SupportType"] != "STANDARD" {
		t.Errorf("support: %v", shop["UpgradePolicy"])
	}
	if fmt.Sprint(shop["Tags"]) != "[map[Key:Cost Centre Value:42] map[Key:env Value:prod]]" {
		t.Errorf("tags: %v", shop["Tags"])
	}
	priv := obj(object(t, r, "aws", awsEKS, "priv")["ResourcesVpcConfig"])
	if priv["EndpointPublicAccess"] != false || priv["EndpointPrivateAccess"] != true || priv["PublicAccessCidrs"] != nil {
		t.Errorf("priv's endpoint: %v", priv)
	}
	sys := object(t, r, "aws", awsNodegroup, "shop-system")
	if sc := obj(sys["ScalingConfig"]); sc["MinSize"] != 3 || sc["MaxSize"] != 3 || sc["DesiredSize"] != 3 {
		t.Errorf("system scaling: %v", sc)
	}
	if sys["DiskSize"] != 128 || fmt.Sprint(sys["InstanceTypes"]) != "[m7i.xlarge]" || sys["CapacityType"] != "ON_DEMAND" || sys["NodeRole"] != "arn:aws:iam::{{truthform|account|self|id}}:role/eks-shop-nodes" {
		t.Errorf("system: %v", sys)
	}
	if fmt.Sprint(sys["Taints"]) != "[map[Effect:NO_SCHEDULE Key:CriticalAddonsOnly Value:true]]" || sys["Version"] != "1.31" {
		t.Errorf("system taints, version: %v %v", sys["Taints"], sys["Version"])
	}
	if sys["ClusterName"] != awsRef(awsEKS, "shop", "identifier") || fmt.Sprint(sys["Subnets"]) != "["+awsRef(awsSN, "core-app", "SubnetId")+"]" {
		t.Errorf("system cluster, subnets: %v %v", sys["ClusterName"], sys["Subnets"])
	}
	user := object(t, r, "aws", awsNodegroup, "shop-user")
	if sc := obj(user["ScalingConfig"]); sc["MinSize"] != 2 || sc["MaxSize"] != 6 || sc["DesiredSize"] != 2 || user["CapacityType"] != "SPOT" {
		t.Errorf("user: %v %v", sc, user["CapacityType"])
	}
	if fmt.Sprint(user["Labels"]) != "map[workload:web]" {
		t.Errorf("user labels: %v", user["Labels"])
	}
	if win := object(t, r, "aws", awsNodegroup, "shop-win"); win["AmiType"] != "WINDOWS_CORE_2022_x86_64" {
		t.Errorf("win: %v", win["AmiType"])
	}
	if b := object(t, r, "aws", awsNodegroup, "shop-batch"); fmt.Sprint(b["InstanceTypes"]) != "[r7i.xlarge]" {
		t.Errorf("batch, read with its cluster: %v", b)
	}
	if a := object(t, r, "aws", awsAddon, "shop_vpc-cni"); a["ConfigurationValues"] != `{"enableNetworkPolicy":"true"}` || a["ClusterName"] != awsRef(awsEKS, "shop", "identifier") {
		t.Errorf("network policy: %v", a)
	}
	e := entry(t, r, "Microsoft.ContainerService/managedClusters rg/shop")
	if l := hasLoss(e, "properties.kubernetesVersion"); l == nil || l.Widens || !strings.Contains(l.Why, "1.31.2") {
		t.Errorf("patch version: %+v", l)
	}
	if l := hasLoss(e, "properties.agentPoolProfiles[user].enableEncryptionAtHost"); l == nil || !l.Widens {
		t.Errorf("encryption at host: %+v", l)
	}
	if l := hasLoss(e, "properties.addonProfiles.azurepolicy"); l == nil || !l.Widens {
		t.Errorf("azure policy: %+v", l)
	}
	if l := hasLoss(e, "properties.agentPoolProfiles[system].availabilityZones"); l == nil || !strings.Contains(l.Why, "eu-west-1a") {
		t.Errorf("zones: %+v", l)
	}
	if l := hasLoss(e, "properties.agentPoolProfiles[user].maxPods"); l == nil || l.Widens {
		t.Errorf("max pods: %+v", l)
	}
	if l := hasLoss(e, "properties.networkProfile.podCidr"); l == nil || l.Widens {
		t.Errorf("overlay pods: %+v", l)
	}
	if l := hasLoss(e, "properties.agentPoolProfiles[system].mode"); l == nil || l.Widens {
		t.Errorf("system mode: %+v", l)
	}
	p := entry(t, r, "Microsoft.ContainerService/managedClusters rg/priv")
	if l := hasLoss(p, "properties.networkProfile.networkPolicy"); l == nil || !l.Widens || !strings.Contains(l.Why, "Calico") {
		t.Errorf("calico on EKS: %+v", l)
	}
	if !anyRequirement(r, "security group web, translated from their subnet's NSG") {
		t.Errorf("no security group requirement: %v", r.Report.Requirements)
	}
	if !anyRequirement(r, "EKS validates Kubernetes 1.31") || !anyRequirement(r, "data is not moved") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
	for _, src := range []string{"Microsoft.ContainerService/managedClusters/agentPools rg/shop/batch", "Microsoft.ContainerService/managedClusters/upgradeProfiles rg/shop/default"} {
		if e := entry(t, r, src); e.State != Mapped {
			t.Errorf("%s: %s", src, e.State)
		}
	}
	for src, about := range map[string]string{
		"Microsoft.ContainerService/managedClusters/agentPools rg/gone/pool":                   "not in the snapshot",
		"Microsoft.ContainerService/managedClusters/trustedAccessRoleBindings rg/shop/backup":  "identity",
		"Microsoft.ContainerService/managedClusters/maintenanceConfigurations rg/shop/default": "maintenance",
	} {
		if e := entry(t, r, src); e.State != Refused || !strings.Contains(e.Reason, about) {
			t.Errorf("%s: %s %s", src, e.State, e.Reason)
		}
	}
}

// A pool that autoscales starts within its own range: five nodes over
// three zones, with five the most, start as one in each and not two.
func TestAGKEPoolStartsWithinItsMaximum(t *testing.T) {
	for _, c := range []struct{ count, min, max, want int }{{5, 1, 5, 1}, {5, 1, 6, 2}, {2, 2, 6, 1}, {4, 0, 2, 0}} {
		s := aksSpec(t, "shop", func(p map[string]any) {
			u := pool(p, "user")
			u["count"], u["minCount"], u["maxCount"] = c.count, c.min, c.max
		})
		user := gkePool(t, gkeSpec(t, runAKS(t, s, aksMaps()["gcp"]), "shop"), "user")
		if user["initialNodeCount"] != c.want || len(list(user["locations"])) != 3 {
			t.Errorf("%d nodes, %d to %d: starts with %v in each of %v", c.count, c.min, c.max, user["initialNodeCount"], user["locations"])
		}
	}
}

func TestClustersToGKE(t *testing.T) {
	r := runAKS(t, aksFixture(), aksMaps()["gcp"])
	shop := gkeSpec(t, r, "shop")
	if shop["initialClusterVersion"] != "1.31" || obj(shop["releaseChannel"])["channel"] != "UNSPECIFIED" {
		t.Errorf("version: %v %v", shop["initialClusterVersion"], shop["releaseChannel"])
	}
	if shop["network"] != gcpProject+"/global/networks/core" || shop["subnetwork"] != gcpProject+"/regions/europe-west1/subnetworks/core-app" {
		t.Errorf("network: %v %v", shop["network"], shop["subnetwork"])
	}
	ipa := obj(shop["ipAllocationPolicy"])
	if ipa["useIpAliases"] != true || ipa["clusterSecondaryRangeName"] != "shop-pods" || ipa["servicesSecondaryRangeName"] != "shop-services" {
		t.Errorf("ip allocation: %v", ipa)
	}
	sn := object(t, r, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/core-app")
	if got := fmt.Sprint(sn["secondaryIpRanges"]); got != "[map[ipCidrRange:10.244.0.0/16 rangeName:shop-pods] map[ipCidrRange:10.0.0.0/16 rangeName:shop-services]]" {
		t.Errorf("secondary ranges: %s", got)
	}
	ip := obj(obj(shop["controlPlaneEndpointsConfig"])["ipEndpointsConfig"])
	an := obj(ip["authorizedNetworksConfig"])
	if ip["enablePublicEndpoint"] != true || an["enabled"] != true || fmt.Sprint(an["cidrBlocks"]) != "[map[cidrBlock:203.0.113.0/24]]" || an["gcpPublicCidrsAccessEnabled"] != false {
		t.Errorf("shop's endpoint: %v", ip)
	}
	if obj(obj(shop["controlPlaneEndpointsConfig"])["dnsEndpointConfig"])["allowExternalTraffic"] != false {
		t.Error("the DNS endpoint is open")
	}
	nc := obj(shop["networkConfig"])
	if nc["defaultEnablePrivateNodes"] != true || nc["datapathProvider"] != "ADVANCED_DATAPATH" {
		t.Errorf("network config: %v", nc)
	}
	if obj(shop["databaseEncryption"])["keyName"] != "projects/kms-project/locations/europe-west1/keyRings/r/cryptoKeys/k" {
		t.Errorf("secrets encryption: %v", shop["databaseEncryption"])
	}
	if fmt.Sprint(shop["resourceLabels"]) != "map[env:prod]" {
		t.Errorf("labels: %v", shop["resourceLabels"])
	}
	sys := gkePool(t, shop, "system")
	conf := obj(sys["config"])
	if sys["initialNodeCount"] != 1 || fmt.Sprint(sys["locations"]) != "[europe-west1-b europe-west1-c europe-west1-d]" {
		t.Errorf("system: %v %v", sys["initialNodeCount"], sys["locations"])
	}
	if conf["machineType"] != "n2-standard-4" || conf["diskSizeGb"] != 128 || conf["imageType"] != "UBUNTU_CONTAINERD" || conf["serviceAccount"] != "gke-shop-nodes@{{truthform|project}}.iam.gserviceaccount.com" {
		t.Errorf("system config: %v", conf)
	}
	if fmt.Sprint(conf["taints"]) != "[map[effect:NO_SCHEDULE key:CriticalAddonsOnly value:true]]" || fmt.Sprint(conf["tags"]) != "[web]" {
		t.Errorf("system taints, tags: %v %v", conf["taints"], conf["tags"])
	}
	if obj(sys["maxPodsConstraint"])["maxPodsPerNode"] != "30" || obj(sys["networkConfig"])["enablePrivateNodes"] != true {
		t.Errorf("system pods, private: %v %v", sys["maxPodsConstraint"], sys["networkConfig"])
	}
	user := gkePool(t, shop, "user")
	if as := obj(user["autoscaling"]); as["totalMinNodeCount"] != 2 || as["totalMaxNodeCount"] != 6 || as["enabled"] != true || user["initialNodeCount"] != 1 {
		t.Errorf("user scaling: %v %v", as, user["initialNodeCount"])
	}
	if obj(user["config"])["spot"] != true || obj(user["upgradeSettings"])["maxSurge"] != 1 {
		t.Errorf("user: %v", user)
	}
	win := gkePool(t, shop, "win")
	if obj(win["config"])["imageType"] != "WINDOWS_LTSC_CONTAINERD" || obj(obj(win["config"])["windowsNodeConfig"])["osVersion"] != "OS_VERSION_LTSC2022" || win["initialNodeCount"] != 1 {
		t.Errorf("win: %v", win)
	}
	gkePool(t, shop, "batch")
	priv := gkeSpec(t, r, "priv")
	if ip := obj(obj(priv["controlPlaneEndpointsConfig"])["ipEndpointsConfig"]); ip["enablePublicEndpoint"] != false || ip["authorizedNetworksConfig"] != nil {
		t.Errorf("priv's endpoint: %v", ip)
	}
	if np := obj(priv["networkPolicy"]); np["provider"] != "CALICO" || np["enabled"] != true {
		t.Errorf("calico: %v", priv["networkPolicy"])
	}
	nodes := gkePool(t, priv, "nodes")
	if obj(nodes["config"])["serviceAccount"] != "gke-priv@shared-accounts.iam.gserviceaccount.com" || fmt.Sprint(obj(obj(nodes["config"])["metadata"])) != "map[block-project-ssh-keys:true]" {
		t.Errorf("priv nodes: %v", nodes["config"])
	}
	e := entry(t, r, "Microsoft.ContainerService/managedClusters rg/shop")
	if l := hasLoss(e, "properties.agentPoolProfiles[user].enableEncryptionAtHost"); l != nil {
		t.Errorf("GKE encrypts node disks itself: %+v", l)
	}
	if l := hasLoss(e, "properties.addonProfiles.azurepolicy"); l == nil || !l.Widens {
		t.Errorf("azure policy: %+v", l)
	}
	if l := hasLoss(e, "tags"); l == nil || !strings.Contains(l.Why, "Cost Centre") {
		t.Errorf("labels: %+v", l)
	}
	if p := entry(t, r, "Microsoft.ContainerService/managedClusters rg/priv"); hasLoss(p, "properties.networkProfile.networkPolicy") != nil {
		t.Errorf("calico on GKE is Calico: %+v", p.Losses)
	}
	if !anyRequirement(r, "GKE validates Kubernetes 1.30") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
}

// What the map does not choose is refused, naming the key; nothing is
// filled in.
func TestClustersNeedTheirChoices(t *testing.T) {
	refused := func(t *testing.T, r Result, cluster string, about ...string) {
		t.Helper()
		e := entry(t, r, "Microsoft.ContainerService/managedClusters rg/"+cluster)
		if e.State != Refused {
			t.Errorf("%s: %s, want refused for %v", cluster, e.State, about)
			return
		}
		for _, a := range about {
			if !strings.Contains(e.Reason, a) {
				t.Errorf("%s: the reason does not name %q: %s", cluster, a, e.Reason)
			}
		}
	}
	a := aksMaps()["aws"]
	a.Clusters = map[string]ClusterMap{"rg/priv": a.Clusters["rg/priv"]}
	r := runAKS(t, aksFixture(), a)
	refused(t, r, "shop", "clusters[rg/shop].roleArn", "clusters[rg/shop].nodeRoleArn", "clusters[rg/shop].pools.system.instanceType", "Standard_D4s_v5", "Standard_E4s_v5")
	if e := entry(t, r, "Microsoft.ContainerService/managedClusters/agentPools rg/shop/batch"); e.State != Refused || !strings.Contains(e.Reason, "is refused") {
		t.Errorf("a pool of a refused cluster: %s %s", e.State, e.Reason)
	}
	a = aksMaps()["aws"]
	pm := a.Clusters["rg/priv"]
	pm.Subnets = nil
	a.Clusters["rg/priv"] = pm
	refused(t, runAKS(t, aksFixture(), a), "priv", "two availability zones", "eu-west-1b", "clusters[rg/priv].subnets")
	a = aksMaps()["aws"]
	a.Destinations.Network, a.Network = "", nil
	refused(t, runAKS(t, aksFixture(), a), "shop", "net/core/app", "is refused", "destinations.network")
	refused(t, runAKS(t, aksFixture(), Map{To: "aws", Region: "eu-west-1"}), "shop", "destinations.clusters")
	// A pool in the network AKS made for it.
	s := aksSpec(t, "priv", func(p map[string]any) { delete(pool(p, "nodes"), "vnetSubnetID") })
	refused(t, runAKS(t, s, aksMaps()["aws"]), "priv", "clusters[rg/priv].pools.nodes.subnet")
	pm = aksMaps()["aws"].Clusters["rg/priv"]
	pm.Pools = map[string]PoolMap{"nodes": {InstanceType: "m7i.large", Subnet: "net/core/data"}}
	a = aksMaps()["aws"]
	a.Clusters["rg/priv"] = pm
	if e := entry(t, runAKS(t, s, a), "Microsoft.ContainerService/managedClusters rg/priv"); e.State == Refused {
		t.Errorf("the map's subnet: %s", e.Reason)
	}
	// Only one role missing, or not a role.
	a = aksMaps()["aws"]
	pm = a.Clusters["rg/priv"]
	pm.RoleARN = ""
	a.Clusters["rg/priv"] = pm
	refused(t, runAKS(t, aksFixture(), a), "priv", "no IAM role for the control plane (clusters[rg/priv].roleArn)")
	pm.RoleARN, pm.NodeRoleARN = "arn:aws:iam::111111111111:role/eks-priv", "arn:aws:iam::111111111111:user/someone"
	a.Clusters["rg/priv"] = pm
	refused(t, runAKS(t, aksFixture(), a), "priv", "clusters[rg/priv].nodeRoleArn", "not an IAM role's ARN")
	pm.NodeRoleARN = ""
	a.Clusters["rg/priv"] = pm
	refused(t, runAKS(t, aksFixture(), a), "priv", "no IAM role for the nodes (clusters[rg/priv].nodeRoleArn)")
	// A taint that cannot be read is never dropped.
	s = aksSpec(t, "priv", func(p map[string]any) { pool(p, "nodes")["nodeTaints"] = []any{"dedicated=db"} })
	refused(t, runAKS(t, s, aksMaps()["aws"]), "priv", "taint", "dedicated=db")
	// A pool kept both inline and as an object of its own is one pool.
	s = aksFixture()
	s.Objects = append(s.Objects, az("Microsoft.ContainerService/managedClusters/agentPools", "rg", "shop/system", pr(map[string]any{"count": 9, "osType": "Linux"})))
	r = runAKS(t, s, aksMaps()["aws"])
	if sc := obj(object(t, r, "aws", awsNodegroup, "shop-system")["ScalingConfig"]); sc["DesiredSize"] != 3 {
		t.Errorf("the inline pool: %v", sc)
	}
	// No version: the target's default would be an upgrade.
	s = aksSpec(t, "priv", func(p map[string]any) { delete(p, "kubernetesVersion") })
	refused(t, runAKS(t, s, aksMaps()["aws"]), "priv", "kubernetesVersion", "upgrade")

	g := aksMaps()["gcp"]
	sm := g.Clusters["rg/shop"]
	sm.ServiceAccount = ""
	sm.Pools = map[string]PoolMap{"system": {MachineType: "n2-standard-4"}, "user": {Zones: []string{"europe-west1-b"}}, "win": {MachineType: "n2-standard-4", Zones: []string{"europe-west1-b", "europe-west1-c", "europe-west1-d"}}, "batch": {MachineType: "x", Zones: []string{"us-east1-b"}}}
	g.Clusters["rg/shop"] = sm
	refused(t, runAKS(t, aksFixture(), g), "shop", "clusters[rg/shop].pools.system.serviceAccount", "Editor",
		"clusters[rg/shop].pools.system.zones", "clusters[rg/shop].pools.user.machineType", "Standard_D8s_v5",
		"pool win has 2 nodes", "zone us-east1-b of pool batch")
	g = aksMaps()["gcp"]
	g.Region = ""
	refused(t, runAKS(t, aksFixture(), g), "priv", "region")
	// Azure CNI without overlay: the pods' range is the map's to choose.
	flat := aksSpec(t, "shop", func(p map[string]any) {
		n := obj(p["networkProfile"])
		delete(n, "networkPluginMode")
		delete(n, "podCidr")
	})
	refused(t, runAKS(t, flat, aksMaps()["gcp"]), "shop", "clusters[rg/shop].podCidr")
	g = aksMaps()["gcp"]
	sm = g.Clusters["rg/shop"]
	sm.PodCIDR = "10.250.0.0/16"
	g.Clusters["rg/shop"] = sm
	r = runAKS(t, flat, g)
	if e := entry(t, r, "Microsoft.ContainerService/managedClusters rg/shop"); e.State == Refused {
		t.Fatalf("flat with a pod range: %s", e.Reason)
	}
	if sn := object(t, r, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/core-app"); !strings.Contains(fmt.Sprint(sn["secondaryIpRanges"]), "10.250.0.0/16") {
		t.Errorf("the map's pod range: %v", sn["secondaryIpRanges"])
	}
	if e := entry(t, runAKS(t, flat, aksMaps()["aws"]), "Microsoft.ContainerService/managedClusters rg/shop"); e.State == Refused || hasLoss(e, "properties.networkProfile.podCidr") != nil {
		t.Errorf("flat Azure CNI is the VPC CNI's model: %s %+v", e.State, e.Losses)
	}
	// Pools in two subnets: GKE puts the cluster in one.
	two := aksSpec(t, "shop", func(p map[string]any) { pool(p, "win")["vnetSubnetID"] = azSubnetID + "data" })
	refused(t, runAKS(t, two, aksMaps()["gcp"]), "shop", "more than one subnet")
}

// Each setting whose loss leaves the target less protected is named as
// widening, on the targets where it does.
func TestClustersNeverWidenSilently(t *testing.T) {
	cases := []struct {
		name, field string
		aws, gcp    bool // widens there
		edit        func(map[string]any)
		noKey       bool // the map names no KMS key
	}{
		{"customer key, none named", "properties.securityProfile.azureKeyVaultKms", true, true, func(map[string]any) {}, true},
		{"azure policy", "properties.addonProfiles.azurepolicy", true, true, func(map[string]any) {}, false},
		{"encryption at host", "properties.agentPoolProfiles[user].enableEncryptionAtHost", true, false, func(map[string]any) {}, false},
		{"cilium policy", "properties.networkProfile.networkPolicy", true, true, func(p map[string]any) { obj(p["networkProfile"])["networkPolicy"] = "cilium" }, false},
		{"http proxy", "properties.httpProxyConfig", true, true, func(p map[string]any) { p["httpProxyConfig"] = map[string]any{"httpProxy": "http://proxy:3128"} }, false},
		{"istio", "properties.serviceMeshProfile", true, true, func(p map[string]any) { p["serviceMeshProfile"] = map[string]any{"mode": "Istio"} }, false},
		{"FIPS", "properties.agentPoolProfiles[system].enableFIPS", true, true, func(p map[string]any) { pool(p, "system")["enableFIPS"] = true }, false},
		{"host ports", "properties.agentPoolProfiles[system].networkProfile.allowedHostPorts", true, true, func(p map[string]any) {
			pool(p, "system")["networkProfile"] = map[string]any{"allowedHostPorts": []any{map[string]any{"portStart": 80, "portEnd": 80, "protocol": "TCP"}}}
		}, false},
		{"dedicated hosts", "properties.agentPoolProfiles[system].hostGroupID", true, true, func(p map[string]any) { pool(p, "system")["hostGroupID"] = "x" }, false},
		{"kata", "properties.agentPoolProfiles[system].workloadRuntime", true, true, func(p map[string]any) { pool(p, "system")["workloadRuntime"] = "KataVmIsolation" }, false},
		{"trusted launch", "properties.agentPoolProfiles[system].securityProfile", true, false, func(p map[string]any) {
			pool(p, "system")["securityProfile"] = map[string]any{"enableSecureBoot": true, "enableVTPM": true}
		}, false},
		{"disk key", "properties.diskEncryptionSetID", true, true, func(p map[string]any) { p["diskEncryptionSetID"] = "x" }, false},
		{"locked nodes", "properties.nodeResourceGroupProfile", true, true, func(p map[string]any) { p["nodeResourceGroupProfile"] = map[string]any{"restrictionLevel": "ReadOnly"} }, false},
		{"FQDN policies", "properties.networkProfile.advancedNetworking.security", true, true, func(p map[string]any) {
			obj(p["networkProfile"])["advancedNetworking"] = map[string]any{"enabled": true, "security": map[string]any{"enabled": true, "advancedNetworkPolicies": "FQDN"}}
		}, false},
		{"double encryption", "properties.securityProfile.kubernetesResourceObjectEncryptionProfile", false, true, func(p map[string]any) {
			sp := obj(p["securityProfile"])
			delete(sp, "azureKeyVaultKms")
			sp["kubernetesResourceObjectEncryptionProfile"] = map[string]any{"infrastructureEncryption": "Enabled"}
		}, true},
	}
	for _, tc := range cases {
		s := aksSpec(t, "shop", tc.edit)
		for to, want := range map[string]bool{"aws": tc.aws, "gcp": tc.gcp} {
			m := aksMaps()[to]
			if tc.noKey {
				cm := m.Clusters["rg/shop"]
				cm.KMSKey = ""
				m.Clusters["rg/shop"] = cm
			}
			e := entry(t, runAKS(t, s, m), "Microsoft.ContainerService/managedClusters rg/shop")
			l := hasLoss(e, tc.field)
			switch {
			case e.State == Refused:
				t.Errorf("%s on %s: refused: %s", tc.name, to, e.Reason)
			case tc.noKey && want && (l == nil || !strings.Contains(l.Why, "clusters[rg/shop].kmsKey") && !strings.Contains(l.Why, "clusters.<key>.kmsKey")):
				t.Errorf("%s on %s: the loss does not name the map's key: %+v", tc.name, to, l)
			case want && (l == nil || !l.Widens):
				t.Errorf("%s on %s: not named as widening: %+v", tc.name, to, l)
			case !want && l != nil && l.Widens:
				t.Errorf("%s on %s: named as widening: %+v", tc.name, to, l)
			}
		}
	}
	// Calico on GKE is Calico; on EKS it widens (above, for priv).
	// Nothing else in the fixture widens but Azure Policy.
	for to, m := range aksMaps() {
		for _, e := range runAKS(t, aksFixture(), m).Report.Entries {
			for _, l := range e.Losses {
				if l.Widens && !strings.Contains(l.Field, "azurepolicy") && !strings.Contains(l.Field, "enableEncryptionAtHost") &&
					!(e.Source == "Microsoft.ContainerService/managedClusters rg/priv" && to == "aws" && strings.Contains(l.Field, "networkPolicy")) {
					t.Errorf("%s: %s %s widens: %s", to, e.Source, l.Field, l.Why)
				}
			}
		}
	}
}

// A public cluster with no authorized ranges is public to all, as it was;
// one whose ranges cannot be written is shut, never opened.
func TestClustersAPIAccess(t *testing.T) {
	open := aksSpec(t, "shop", func(p map[string]any) { delete(obj(p["apiServerAccessProfile"]), "authorizedIPRanges") })
	r := runAKS(t, open, aksMaps()["aws"])
	if vpc := obj(object(t, r, "aws", awsEKS, "shop")["ResourcesVpcConfig"]); fmt.Sprint(vpc["PublicAccessCidrs"]) != "[0.0.0.0/0]" {
		t.Errorf("open: %v", vpc)
	}
	if ip := obj(obj(gkeSpec(t, runAKS(t, open, aksMaps()["gcp"]), "shop")["controlPlaneEndpointsConfig"])["ipEndpointsConfig"]); ip["authorizedNetworksConfig"] != nil || ip["enablePublicEndpoint"] != true {
		t.Errorf("open on GKE: %v", ip)
	}
	v6 := aksSpec(t, "shop", func(p map[string]any) {
		obj(p["apiServerAccessProfile"])["authorizedIPRanges"] = []any{"2001:db8::/32"}
	})
	if vpc := obj(object(t, runAKS(t, v6, aksMaps()["aws"]), "aws", awsEKS, "shop")["ResourcesVpcConfig"]); vpc["EndpointPublicAccess"] != false || vpc["PublicAccessCidrs"] != nil {
		t.Errorf("unwritable ranges on EKS: %v", vpc)
	}
	if ip := obj(obj(gkeSpec(t, runAKS(t, v6, aksMaps()["gcp"]), "shop")["controlPlaneEndpointsConfig"])["ipEndpointsConfig"]); ip["enablePublicEndpoint"] != false {
		t.Errorf("unwritable ranges on GKE: %v", ip)
	}
	lts := aksSpec(t, "priv", func(p map[string]any) { p["supportPlan"] = "AKSLongTermSupport" })
	if obj(object(t, runAKS(t, lts, aksMaps()["aws"]), "aws", awsEKS, "priv")["UpgradePolicy"])["SupportType"] != "EXTENDED" {
		t.Error("long-term support on EKS")
	}
	if obj(gkeSpec(t, runAKS(t, lts, aksMaps()["gcp"]), "priv")["releaseChannel"])["channel"] != "EXTENDED" {
		t.Error("long-term support on GKE")
	}
}

func TestClustersRestore(t *testing.T) {
	tg := targets(t)
	s := runAKS(t, aksFixture(), aksMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	if c := f.Count(); c[awsEKS] != 2 || c[awsNodegroup] != 5 || c[awsAddon] != 2 {
		t.Errorf("aws created %v", c)
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runAKS(t, aksFixture(), aksMaps()["gcp"]).Snapshots["gcp"]
	gf := gcp.NewWorld(tg.GCP).Project("target-project", "123456789")
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK {
			t.Errorf("gcp %s: %s", res.Key, res.Detail)
		}
	}
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("gcp again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}

func TestClusterMapIsChecked(t *testing.T) {
	m := aksMaps()["aws"]
	m.To = "gcp"
	m.Network = nil
	if _, err := Translate(aksFixture(), m, targets(t)); err == nil || !strings.Contains(err.Error(), "eks") {
		t.Errorf("eks to gcp: %v", err)
	}
	m = aksMaps()["aws"]
	cm := m.Clusters["rg/shop"]
	cm.Pools = map[string]PoolMap{"system": {MachineType: "n2-standard-4"}}
	m.Clusters["rg/shop"] = cm
	if _, err := Translate(aksFixture(), m, targets(t)); err == nil || !strings.Contains(err.Error(), "machineType") {
		t.Errorf("a GKE key on eks: %v", err)
	}
	m = aksMaps()["gcp"]
	m.Destinations.Clusters = ""
	if _, err := Translate(aksFixture(), m, targets(t)); err == nil || !strings.Contains(err.Error(), "destinations.clusters") {
		t.Errorf("clusters with no destination: %v", err)
	}
}
