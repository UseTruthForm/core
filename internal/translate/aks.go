package translate

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Azure Kubernetes Service clusters, read into a model the EKS and GKE
// writers share.
//
// What is translated is the cluster's configuration: its Kubernetes
// version, where its API server answers and from where, its nodes, its
// network plugin and policy engine, and how its secrets are encrypted. The
// workloads are not: they travel through TruthForm's Kubernetes snapshot,
// restored into the new cluster once it runs.
//
// Two things a cluster needs are never guessed. Identity is not translated
// (#32): the IAM roles (EKS) and service accounts (GKE) the control plane
// and nodes run as are ones that exist, named in the map. VM sizes are not
// translated either: Azure's sizes and the target's machine types differ in
// CPU, memory, disks and networking, so each pool's machine is named in the
// map, and a refusal prints the Azure size as a hint.

const (
	azAKS     = "microsoft.containerservice/managedclusters"
	azAKSPool = azAKS + "/agentpools"
)

type clusters struct{}

func (clusters) claims(kind string) bool {
	return kind == azAKS || strings.HasPrefix(kind, azAKS+"/")
}

// aksChildren are the cluster's other child types, decided here: what
// they hold has no place in the cluster's own configuration on the target,
// or is Azure's own record.
var aksChildren = map[string]struct {
	state State
	why   string
}{
	azAKS + "/maintenanceconfigurations":  {Refused, "planned maintenance windows are not translated: EKS has none, and GKE's maintenance policy is set on its own, so upgrades would run when the target schedules them"},
	azAKS + "/trustedaccessrolebindings":  {Refused, "identity is not translated (#32): a trusted access binding lets another Azure resource's managed identity into the cluster; the target's equivalent (EKS access entries, GKE IAM) is set on its own"},
	azAKS + "/identitybindings":           {Refused, "identity is not translated (#32): an identity binding ties a managed identity to the cluster's workloads; the target's (EKS Pod Identity, GKE workload identity) is set on its own"},
	azAKS + "/privateendpointconnections": {Refused, "a private endpoint into the cluster's API from another network is not translated (#32): the target's private access (EKS private endpoint in the VPC, GKE Private Service Connect) is set on its own"},
	azAKS + "/managednamespaces":          {Refused, "a managed namespace carries default network policies, a quota and access that the target's namespaces do not: dropped, its pods would be less isolated; the namespace itself travels through the Kubernetes snapshot"},
	azAKS + "/namespaces":                 {Refused, "a managed namespace carries default network policies, a quota and access that the target's namespaces do not: dropped, its pods would be less isolated; the namespace itself travels through the Kubernetes snapshot"},
	azAKS + "/loadbalancers":              {Refused, "AKS's extra standard load balancers are not translated: the target's load balancers are made by its own controllers for each Service"},
	azAKS + "/meshmemberships":            {Refused, "a fleet's cluster mesh membership is not translated (#32)"},
	azAKS + "/upgradeprofiles":            {Mapped, "Azure's report of the upgrades open to the cluster: nothing to translate"},
	azAKS + "/meshupgradeprofiles":        {Mapped, "Azure's report of the service mesh upgrades open to the cluster: nothing to translate"},
	azAKSPool + "/upgradeprofiles":        {Mapped, "Azure's report of the upgrades open to the pool: nothing to translate"},
	azAKSPool + "/machines":               {Mapped, "one of its pool's machines: the target's node group or pool makes its own"},
}

type aksCluster struct {
	src, group, name, key string
	version               string // major.minor
	tags                  map[string]string
	public, private       bool
	authorized            []string // the API server's allowed ranges, when public
	plugin, pluginMode    string
	policy, dataplane     string
	podCidr, serviceCidr  string
	pools                 []*aksPool
	kms                   bool // secrets encrypted with the customer's key
	lts                   bool
	autoUpgrade           bool // anything upgrades itself on the source
	vpa                   bool
	losses                []Loss // a loss only one target has is marked "<target>|<field>"
	refuse                []string
	reqs                  []string
}

type aksPool struct {
	name, field       string
	count, min, max   *int
	auto              bool
	vmSize            string
	disk              *int
	taints            []aksTaint
	labels, tags      map[string]string
	zones             []string
	windows           string // "", "2019", "2022"
	ubuntu            bool
	spot              bool
	maxPods           *int
	subnet            string // group/network/subnet, lower case
	version           string
	publicIP          bool
	secureBoot, vtpm  bool
	streaming         bool
	surge, unavailble *int
	sshOff            bool
}

type aksTaint struct{ key, value, effect string }

func (c *aksCluster) lose(field, why string, widens bool) {
	c.losses = append(c.losses, Loss{Field: field, Why: why, Widens: widens})
}

// loseOn is a loss only one target has.
func (c *aksCluster) loseOn(to, field, why string, widens bool) {
	c.losses = append(c.losses, Loss{Field: to + "|" + field, Why: why, Widens: widens})
}

func (clusters) translate(objs []snapshot.Object, o *out) {
	cs := map[string]*aksCluster{}
	var poolObjs []snapshot.Object
	sort.Slice(objs, func(i, j int) bool { return source(objs[i]) < source(objs[j]) })
	for _, obj := range objs {
		switch k := strings.ToLower(obj.Kind()); {
		case k == azAKS:
			c := readCluster(obj)
			cs[c.key] = c
		case k == azAKSPool:
			poolObjs = append(poolObjs, obj)
		default:
			if d, ok := aksChildren[k]; ok {
				o.entries = append(o.entries, Entry{Source: source(obj), State: d.state, Reason: d.why})
			} else {
				o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
			}
		}
	}
	// A pool a capture keeps as an object of its own is read with its
	// cluster, as if inline; one already inline is not read twice.
	pending := map[*aksCluster][]string{}
	for _, obj := range poolObjs {
		parent, name, _ := strings.Cut(obj.Name(), "/")
		c := cs[strings.ToLower(obj.Namespace()+"/"+parent)]
		if c == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its cluster is not in the snapshot"})
			continue
		}
		pending[c] = append(pending[c], source(obj))
		if c.pool(name) != nil {
			continue
		}
		p, losses := readPool(name, obj.Body["spec"], "agentPools/"+name+": ")
		c.addPool(p, losses)
	}
	var w clusterWriter
	switch o.m.Destinations.Clusters {
	case "eks":
		w = eks{m: o.m}
	case "gke":
		w = gke{m: o.m}
	}
	for _, c := range sortedClusters(cs) {
		ok := false
		if w == nil {
			o.entries = append(o.entries, Entry{Source: c.src, State: Refused, Reason: "the map chooses no destination for clusters (destinations.clusters)"})
		} else {
			ok = w.cluster(c, o)
		}
		for _, src := range pending[c] {
			if ok {
				o.entries = append(o.entries, Entry{Source: src, State: Mapped, Reason: "read with its cluster " + c.src})
			} else {
				o.entries = append(o.entries, Entry{Source: src, State: Refused, Reason: "its cluster " + c.src + " is refused"})
			}
		}
	}
}

// clusterWriter writes the model for one target.
type clusterWriter interface {
	cluster(c *aksCluster, o *out) bool // false: refused
}

func sortedClusters(m map[string]*aksCluster) []*aksCluster {
	out := make([]*aksCluster, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

func (c *aksCluster) pool(name string) *aksPool {
	for _, p := range c.pools {
		if strings.EqualFold(p.name, name) {
			return p
		}
	}
	return nil
}

func (c *aksCluster) addPool(p *aksPool, losses []Loss) {
	c.pools = append(c.pools, p)
	for _, l := range losses {
		if strings.HasPrefix(l.Why, "refuse: ") {
			c.refuse = append(c.refuse, "pool "+p.name+": "+strings.TrimPrefix(l.Why, "refuse: "))
			continue
		}
		c.losses = append(c.losses, l)
	}
}

var aksVersionRE = regexp.MustCompile(`^(1\.\d+)(\.\d+)?$`)

func readCluster(so snapshot.Object) *aksCluster {
	c := &aksCluster{src: source(so), group: so.Namespace(), name: so.Name(), key: strings.ToLower(so.Namespace() + "/" + so.Name())}
	top := newProps(spec(so), "")
	top.quiet("location", "properties", "name")
	// kind is a label the portal writes; it configures nothing.
	top.quiet("kind")
	c.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	if sku := obj(top.m["sku"]); sku != nil {
		if n, _ := sku["name"].(string); strings.EqualFold(n, "Automatic") {
			c.lose("sku.name", "AKS Automatic chooses node sizes, scaling and safeguards itself; the target is a standard cluster, configured as this one is now", false)
		}
		// The tier is the API server's SLA (Free has none): EKS and a
		// regional GKE cluster have one. Premium is long-term support,
		// read from supportPlan.
	}
	top.quiet("sku")
	if el := obj(top.m["extendedLocation"]); len(el) > 0 {
		c.lose("extendedLocation", "an edge zone has no equivalent here: the cluster is written to the map's region", false)
	}
	top.quiet("extendedLocation")
	if id := obj(top.m["identity"]); len(id) > 0 && !strings.EqualFold(fmt.Sprint(id["type"]), "None") {
		c.loseOn("aws", "identity", "the cluster's managed identity is not translated (#32): the control plane runs as the IAM role the map names", false)
		c.loseOn("gcp", "identity", "the cluster's managed identity is not translated (#32): GKE's control plane runs as Google's own service agent", false)
		c.reqs = append(c.reqs, "what the cluster's managed identity was granted in Azure (its network, its node resources, a key vault for secrets encryption) is granted to the target's cluster role on its own (#32)")
	}
	top.quiet("identity")

	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "powerState", "maxAgentPools", "currentKubernetesVersion", "fqdn", "privateFQDN", "azurePortalFQDN", "resourceUID", "status")
	// Derived from the API server's private link; not set by anyone.
	p.quiet("privateLinkResources")
	// Azure's group for the nodes' own resources; the target keeps nodes
	// in the account or project.
	p.quiet("nodeResourceGroup")
	switch v := p.str("kubernetesVersion"); {
	case v == "":
		c.refuse = append(c.refuse, "the snapshot gives no Kubernetes version (properties.kubernetesVersion); the target's default would be a newer one, which is an upgrade nobody chose")
	case !aksVersionRE.MatchString(v):
		c.refuse = append(c.refuse, fmt.Sprintf("its Kubernetes version %q is not one this reads (1.N or 1.N.P)", v))
	default:
		m := aksVersionRE.FindStringSubmatch(v)
		c.version = m[1]
		if m[2] != "" {
			c.lose("properties.kubernetesVersion", v+": the target runs its own patch release of "+m[1]+"; only the minor version is carried over", false)
		}
	}
	if dns, sub := p.str("dnsPrefix"), p.str("fqdnSubdomain"); dns != "" || sub != "" {
		c.reqs = append(c.reqs, "the API server's address changes: kubeconfigs, CI and anything else that names the AKS address take the target's")
	}
	for _, x := range list(p.m["agentPoolProfiles"]) {
		m := obj(x)
		name, _ := m["name"].(string)
		pl, losses := readPool(name, map[string]any{"properties": m}, fmt.Sprintf("properties.agentPoolProfiles[%s].", name))
		c.addPool(pl, losses)
	}
	p.quiet("agentPoolProfiles")
	if lp := obj(p.m["linuxProfile"]); len(lp) > 0 {
		p.lose("linuxProfile", "the nodes' SSH user and keys are not carried over: the target's nodes take none, so nobody can SSH to them until a key is set on the target", false)
	}
	p.quiet("linuxProfile")
	if wp := obj(p.m["windowsProfile"]); len(wp) > 0 {
		p.lose("windowsProfile", "the Windows nodes' administrator and password are not carried over (a secret is never moved), nor its gMSA or license settings: the target's Windows nodes are set up by their own", false)
	}
	p.quiet("windowsProfile")
	if sp := obj(p.m["servicePrincipalProfile"]); len(sp) > 0 {
		p.lose("servicePrincipalProfile", "the cluster's service principal is not translated (#32)", false)
	}
	p.quiet("servicePrincipalProfile")
	readAddons(c, obj(p.m["addonProfiles"]))
	p.quiet("addonProfiles")
	if ip := obj(p.m["podIdentityProfile"]); truthy(ip["enabled"]) {
		p.lose("podIdentityProfile", "pod-managed identities are not translated (#32): pods that used them get their credentials through the target's workload identity, which is a change to the app", false)
	}
	p.quiet("podIdentityProfile")
	if truthy(obj(p.m["oidcIssuerProfile"])["enabled"]) {
		c.reqs = append(c.reqs, "the cluster's service account token issuer changes: federated credentials that trusted the AKS issuer are carried over with destinations.identity: workload (EKS Pod Identity, GKE workload identity), and made again by hand otherwise")
	}
	p.quiet("oidcIssuerProfile")
	if strings.EqualFold(fmt.Sprint(obj(p.m["nodeResourceGroupProfile"])["restrictionLevel"]), "ReadOnly") {
		p.lose("nodeResourceGroupProfile", "the nodes' own resources were locked against changes by anyone but AKS; on the target, whoever IAM lets change instances can change the nodes", true)
	}
	p.quiet("nodeResourceGroupProfile")
	if v, ok := p.take("enableRBAC"); ok && v == false {
		p.lose("enableRBAC", "the cluster did not authorize with Kubernetes RBAC; the target always does, so what it let everyone do needs RoleBindings there", false)
	}
	switch sp := p.str("supportPlan"); sp {
	case "", "KubernetesOfficial":
	case "AKSLongTermSupport":
		c.lts = true
	default:
		p.lose("supportPlan", sp+" is not a support plan this reads", false)
	}
	if p.boolean("enableFIPS") {
		p.lose("enableFIPS", "the cluster used FIPS 140-validated crypto modules; the target's are not set up to (not translated)", true)
	}
	readClusterNetwork(c, obj(p.m["networkProfile"]))
	p.quiet("networkProfile")
	if aad := obj(p.m["aadProfile"]); len(aad) > 0 {
		p.lose("aadProfile", "Entra ID sign-in, its admin groups and Azure RBAC for Kubernetes are not translated (#32)", false)
		c.reqs = append(c.reqs, "who may use the cluster is set on the target on its own (#32): EKS access entries, or GKE's IAM and Google Groups for RBAC, for the people and groups Entra ID let in")
	}
	p.quiet("aadProfile")
	if au := obj(p.m["autoUpgradeProfile"]); au != nil {
		ch, _ := au["upgradeChannel"].(string)
		nodeOS, _ := au["nodeOSUpgradeChannel"].(string)
		if (ch != "" && !strings.EqualFold(ch, "none")) || nodeOS == "NodeImage" || nodeOS == "SecurityPatch" {
			c.autoUpgrade = true
		}
		if ch != "" && !strings.EqualFold(ch, "none") {
			c.loseOn("aws", "properties.autoUpgradeProfile.upgradeChannel", ch+": EKS does not upgrade the cluster's Kubernetes version itself; upgrades are run by hand", false)
			c.loseOn("gcp", "properties.autoUpgradeProfile.upgradeChannel", ch+": the cluster is written in no release channel, at the version the source runs; GKE upgrades it itself only when that version's support ends", false)
		}
		if nodeOS == "NodeImage" || nodeOS == "SecurityPatch" {
			c.loseOn("aws", "properties.autoUpgradeProfile.nodeOSUpgradeChannel", nodeOS+": EKS managed node groups do not take new node images themselves; update them by hand or on a schedule", false)
		}
	}
	p.quiet("autoUpgradeProfile")
	// A one-time override of upgrade checks, for an upgrade in flight.
	p.quiet("upgradeSettings")
	if asp := obj(p.m["autoScalerProfile"]); len(asp) > 0 {
		p.lose("autoScalerProfile", "the cluster autoscaler's settings are not carried over: the target's autoscaler runs with its own", false)
	}
	p.quiet("autoScalerProfile")
	readAPIAccess(c, obj(p.m["apiServerAccessProfile"]), p.str("publicNetworkAccess"))
	p.quiet("apiServerAccessProfile")
	if p.str("diskEncryptionSetID") != "" {
		p.lose("diskEncryptionSetID", "the nodes' disks were encrypted with the customer's own key; the target's are encrypted with the cloud's until a key is set for them (not translated)", true)
	}
	if ip := obj(p.m["identityProfile"]); len(ip) > 0 {
		p.lose("identityProfile", "the kubelet's managed identity is not translated (#32)", false)
		c.reqs = append(c.reqs, "what the kubelet's managed identity was granted (pulling from a container registry, above all) is granted to the target's node role or service account on its own (#32)")
	}
	p.quiet("identityProfile")
	if v, ok := p.take("disableLocalAccounts"); !ok || v != true {
		c.reqs = append(c.reqs, "the cluster had local accounts (its admin kubeconfig); the target has none: tools that used them sign in through the target's IAM")
	}
	if hp := obj(p.m["httpProxyConfig"]); truthy(hp["enabled"]) || hp["httpProxy"] != nil || hp["httpsProxy"] != nil {
		p.lose("httpProxyConfig", "the nodes sent their traffic through an HTTP proxy; the target's do not, so whatever the proxy filtered goes out unfiltered", true)
	}
	p.quiet("httpProxyConfig")
	readSecurityProfile(c, obj(p.m["securityProfile"]))
	p.quiet("securityProfile")
	if st := obj(p.m["storageProfile"]); len(st) > 0 {
		var on []string
		for _, k := range sortedMapKeys(st) {
			if truthy(obj(st[k])["enabled"]) {
				on = append(on, k)
			}
		}
		if len(on) > 0 {
			c.reqs = append(c.reqs, "the cluster provisioned storage through Azure's CSI drivers ("+strings.Join(on, ", ")+"): StorageClasses that name disk.csi.azure.com or file.csi.azure.com are rewritten for the target's (EBS CSI driver, which needs its own IAM role, or GKE's Persistent Disk driver), and the volumes' data is not moved")
		}
	}
	p.quiet("storageProfile")
	if ing := obj(p.m["ingressProfile"]); len(ing) > 0 {
		if truthy(obj(ing["webAppRouting"])["enabled"]) {
			p.lose("ingressProfile.webAppRouting", "AKS's managed NGINX ingress is not translated: the target's ingress controller (AWS Load Balancer Controller, GKE Ingress) is installed on its own, and Ingresses naming webapprouting.kubernetes.azure.com change class", false)
		}
		if gw := fmt.Sprint(obj(ing["gatewayAPI"])["installation"]); gw == "Standard" {
			p.lose("ingressProfile.gatewayAPI", "AKS's managed Gateway API CRDs are not translated: install the target's Gateway API implementation", false)
		}
	}
	p.quiet("ingressProfile")
	if wa := obj(p.m["workloadAutoScalerProfile"]); len(wa) > 0 {
		if truthy(obj(wa["keda"])["enabled"]) {
			p.lose("workloadAutoScalerProfile.keda", "AKS's KEDA add-on is not translated: install KEDA on the target before its ScaledObjects are restored", false)
		}
		if truthy(obj(wa["verticalPodAutoscaler"])["enabled"]) {
			c.vpa = true
			c.loseOn("aws", "properties.workloadAutoScalerProfile.verticalPodAutoscaler", "EKS has no managed Vertical Pod Autoscaler: install it on the target before its objects are restored", false)
		}
	}
	p.quiet("workloadAutoScalerProfile")
	if am := obj(p.m["azureMonitorProfile"]); anyEnabled(am) {
		p.lose("azureMonitorProfile", "Azure Monitor's metrics, Container Insights and app monitoring are not translated (#32): the target's (CloudWatch Container Insights, Cloud Monitoring) is set on its own", false)
	}
	p.quiet("azureMonitorProfile")
	if sm := obj(p.m["serviceMeshProfile"]); strings.EqualFold(fmt.Sprint(sm["mode"]), "Istio") {
		p.lose("serviceMeshProfile", "AKS's managed Istio is not translated: until Istio (EKS) or Cloud Service Mesh (GKE) is installed, the mesh's mutual TLS and authorization policies are not enforced and its pods talk in plain text", true)
	}
	p.quiet("serviceMeshProfile")
	if anyEnabled(obj(p.m["metricsProfile"])) {
		p.lose("metricsProfile", "AKS cost analysis is not translated", false)
	}
	p.quiet("metricsProfile")
	if np := obj(p.m["nodeProvisioningProfile"]); strings.EqualFold(fmt.Sprint(np["mode"]), "Auto") {
		p.lose("nodeProvisioningProfile", "AKS's node auto-provisioning (Karpenter) is not translated: the target's pools are the ones written here; install Karpenter (EKS) or turn on node auto-provisioning (GKE) on its own", false)
	}
	p.quiet("nodeProvisioningProfile")
	if bp := obj(p.m["bootstrapProfile"]); strings.EqualFold(fmt.Sprint(bp["artifactSource"]), "Cache") {
		p.lose("bootstrapProfile", "the nodes pulled their own images from a private registry cache; the target's pull from the cloud's public registries", false)
	}
	p.quiet("bootstrapProfile")
	if truthy(obj(p.m["aiToolchainOperatorProfile"])["enabled"]) {
		p.lose("aiToolchainOperatorProfile", "the AI toolchain operator (KAITO) is not translated", false)
	}
	p.quiet("aiToolchainOperatorProfile")
	if sc := obj(obj(p.m["schedulerProfile"])["upstream"]); strings.EqualFold(fmt.Sprint(sc["schedulerConfigMode"]), "ManagedByCRD") {
		p.lose("schedulerProfile", "the scheduler's own configuration is not carried over: the target's scheduler runs with its defaults", false)
	}
	p.quiet("schedulerProfile")
	if truthy(obj(p.m["hostedSystemProfile"])["enabled"]) {
		p.lose("hostedSystemProfile", "AKS ran the cluster's system components on nodes of its own; on the target they run on the cluster's pools", false)
	}
	p.quiet("hostedSystemProfile")
	c.losses = append(append(top.rest(), p.rest()...), c.losses...)
	return c
}

// readAddons names what each enabled add-on did, and the target's
// equivalent. None is translated.
func readAddons(c *aksCluster, addons map[string]any) {
	known := map[string]struct {
		why    string
		widens bool
	}{
		"azurepolicy":                  {"the Azure Policy add-on enforced policies at admission (Gatekeeper); until the target's (Gatekeeper, Kyverno or GKE Policy Controller) is installed with the same policies, what it denied is let in", true},
		"omsagent":                     {"Container Insights monitoring is not translated (#32): the target's (CloudWatch Container Insights, Cloud Monitoring) is set on its own", false},
		"azurekeyvaultsecretsprovider": {"the Key Vault secrets provider is not translated: pods that mount secrets through it fail to start until the target's Secrets Store CSI provider (AWS Secrets Manager, Google Secret Manager) is installed and their SecretProviderClasses rewritten", false},
		"ingressapplicationgateway":    {"the Application Gateway ingress controller is not translated: the target's (AWS Load Balancer Controller, GKE Ingress) is installed on its own", false},
		"httpapplicationrouting":       {"HTTP application routing is not translated: the target's ingress is installed on its own", false},
		"opensourcemesh":               {"Open Service Mesh is not translated: until a mesh is installed on the target, its mutual TLS is not enforced", true},
		"openservicemesh":              {"Open Service Mesh is not translated: until a mesh is installed on the target, its mutual TLS is not enforced", true},
		"aciconnectorlinux":            {"virtual nodes on Azure Container Instances are not translated (EKS on Fargate, GKE Autopilot are set up on their own)", false},
		"kubedashboard":                {"the Kubernetes dashboard add-on is not translated", false},
		"acccsgxdeviceplugin":          {"the confidential computing (SGX) device plugin is not translated: the target's nodes have no SGX", false},
		"gitops":                       {"the GitOps (Flux) extension is not translated: install Flux on the target", false},
	}
	for _, name := range sortedMapKeys(addons) {
		a := obj(addons[name])
		if !truthy(a["enabled"]) {
			continue
		}
		k := known[strings.ToLower(name)]
		if k.why == "" {
			c.losses = append(c.losses, Loss{Field: "properties.addonProfiles." + name, Why: "no rule reads this add-on yet: it is not carried over", Unread: true})
			continue
		}
		c.lose("properties.addonProfiles."+name, k.why, k.widens)
	}
}

func readClusterNetwork(c *aksCluster, m map[string]any) {
	p := newProps(m, "properties.networkProfile.")
	c.plugin = strings.ToLower(p.str("networkPlugin"))
	c.pluginMode = strings.ToLower(p.str("networkPluginMode"))
	c.policy = strings.ToLower(p.str("networkPolicy"))
	c.dataplane = strings.ToLower(p.str("networkDataplane"))
	switch c.plugin {
	case "azure", "kubenet":
	case "none":
		c.refuse = append(c.refuse, "it runs a network plugin of its own (networkPlugin none), which the target's networking would replace: not translated")
	case "":
		c.refuse = append(c.refuse, "the snapshot gives no network plugin (properties.networkProfile.networkPlugin)")
	default:
		c.refuse = append(c.refuse, fmt.Sprintf("network plugin %q is not one this reads", c.plugin))
	}
	if c.policy == "none" {
		c.policy = ""
	}
	// bridge or transparent: how Azure CNI wires a node's pods, which the
	// target's plugin does its own way.
	p.quiet("networkMode")
	// The load balancer's SKU: the target's are made by its own
	// controllers, for each Service.
	p.quiet("loadBalancerSku")
	c.podCidr, c.serviceCidr = p.str("podCidr"), p.str("serviceCidr")
	for _, k := range []string{"podCidrs", "serviceCidrs", "ipFamilies"} {
		for _, x := range list(p.m[k]) {
			s := fmt.Sprint(x)
			if strings.EqualFold(s, "IPv6") || (strings.Contains(s, ":") && strings.Contains(s, "/")) {
				c.refuse = append(c.refuse, "it is dual-stack or IPv6 (properties.networkProfile."+k+"), which is not translated yet")
				break
			}
		}
		p.quiet(k)
	}
	if c.serviceCidr == "" {
		c.refuse = append(c.refuse, "the snapshot gives no service range (properties.networkProfile.serviceCidr); the target's default would change every Service's address")
	}
	if (c.plugin == "kubenet" || c.pluginMode == "overlay") && c.podCidr == "" {
		c.refuse = append(c.refuse, "the snapshot gives no pod range (properties.networkProfile.podCidr)")
	}
	if p.str("dnsServiceIP") != "" {
		p.lose("dnsServiceIP", "the target puts the cluster's DNS at an address of its own in the service range: pods resolve through it as before, and anything that names the address itself (not kube-dns) is changed", false)
	}
	switch ot := p.str("outboundType"); ot {
	case "", "loadBalancer", "managedNATGateway", "userAssignedNATGateway":
		c.reqs = append(c.reqs, "the nodes reached the internet through Azure's outbound ("+orDefault(ot, "loadBalancer")+"); the target's subnets have no internet egress until a NAT gateway (AWS) or Cloud NAT (GCP) is added, and nodes cannot pull public images without it")
	case "userDefinedRouting":
		p.lose("outboundType", "the nodes' traffic out followed the subnet's route table (to a firewall, as a rule); see that subnet's routeTable loss on its network", false)
	case "none":
	default:
		p.lose("outboundType", ot+" is not an outbound type this reads", false)
	}
	for _, k := range []string{"loadBalancerProfile", "natGatewayProfile"} {
		if len(obj(p.m[k])) > 0 {
			p.lose(k, "the outbound addresses and ports Azure gave the nodes are not carried over: the target's NAT has addresses of its own, so anything that allowed the old ones by address is changed", false)
		}
		p.quiet(k)
	}
	if truthy(obj(p.m["staticEgressGatewayProfile"])["enabled"]) {
		p.lose("staticEgressGatewayProfile", "static egress gateways are not translated: pods go out through the subnets' NAT", false)
	}
	p.quiet("staticEgressGatewayProfile")
	if an := obj(p.m["advancedNetworking"]); truthy(an["enabled"]) {
		sec := obj(an["security"])
		if truthy(sec["enabled"]) && !strings.EqualFold(fmt.Sprint(sec["advancedNetworkPolicies"]), "None") {
			p.lose("advancedNetworking.security", "Cilium's FQDN and L7 network policies were enforced; the target does not enforce them, so what they denied is let through", true)
		}
		if te := obj(sec["transitEncryption"]); len(te) > 0 && !strings.EqualFold(fmt.Sprint(te["type"]), "None") {
			p.lose("advancedNetworking.security.transitEncryption", "pod traffic between nodes was encrypted (WireGuard); on the target it is not (not translated)", true)
		}
		if truthy(obj(an["observability"])["enabled"]) {
			p.lose("advancedNetworking.observability", "network observability is not translated", false)
		}
	}
	p.quiet("advancedNetworking")
	c.losses = append(c.losses, p.rest()...)
}

func readAPIAccess(c *aksCluster, m map[string]any, publicNetworkAccess string) {
	p := newProps(m, "properties.apiServerAccessProfile.")
	c.private = p.boolean("enablePrivateCluster")
	c.public = !c.private && !strings.EqualFold(publicNetworkAccess, "Disabled")
	for _, x := range list(p.m["authorizedIPRanges"]) {
		c.authorized = append(c.authorized, fmt.Sprint(x))
	}
	p.quiet("authorizedIPRanges")
	if c.private && p.boolean("enablePrivateClusterPublicFQDN") {
		p.lose("enablePrivateClusterPublicFQDN", "the private API server's name resolved in public DNS; the target's private endpoint resolves only inside its network", false)
	}
	if pz := p.str("privateDNSZone"); pz != "" && !strings.EqualFold(pz, "system") && !strings.EqualFold(pz, "none") {
		p.lose("privateDNSZone", "the private API server's name was in a DNS zone of the customer's; the target's private endpoint has a name of its own", false)
	}
	if p.boolean("enableVnetIntegration") || p.str("subnetId") != "" {
		p.lose("enableVnetIntegration", "the API server was put in a subnet of the cluster's network; the target reaches its nodes through interfaces of its own in the cluster's subnets", false)
	}
	p.quiet("subnetId")
	if v, ok := p.take("disableRunCommand"); ok && v == false {
		p.lose("disableRunCommand", "AKS's run command let Azure users run kubectl through ARM; the target has no such door, so it is closed", false)
	}
	c.losses = append(c.losses, p.rest()...)
}

func readSecurityProfile(c *aksCluster, m map[string]any) {
	p := newProps(m, "properties.securityProfile.")
	if d := obj(p.m["defender"]); truthy(obj(d["securityMonitoring"])["enabled"]) || truthy(obj(d["securityGating"])["enabled"]) {
		p.lose("defender", "Defender for Containers is not translated (#32): the target's threat detection (GuardDuty EKS protection, GKE security posture) is set on its own", false)
	}
	p.quiet("defender")
	if kms := obj(p.m["azureKeyVaultKms"]); truthy(kms["enabled"]) {
		c.kms = true
	}
	p.quiet("azureKeyVaultKms")
	if ie := obj(p.m["kubernetesResourceObjectEncryptionProfile"]); strings.EqualFold(fmt.Sprint(ie["infrastructureEncryption"]), "Enabled") {
		c.loseOn("aws", "properties.securityProfile.kubernetesResourceObjectEncryptionProfile", "AKS encrypted the cluster's objects at rest a second time; EKS encrypts all of them with KMS envelope encryption itself", false)
		if !c.kms {
			c.loseOn("gcp", "properties.securityProfile.kubernetesResourceObjectEncryptionProfile", "AKS encrypted the cluster's objects at rest a second time; GKE encrypts its control plane's storage once, unless the map names a key (clusters.<key>.kmsKey) for application-layer encryption of secrets", true)
		}
	}
	p.quiet("kubernetesResourceObjectEncryptionProfile")
	if truthy(obj(p.m["workloadIdentity"])["enabled"]) {
		c.reqs = append(c.reqs, "workloads signed in to Azure with workload identity; on the target they use EKS Pod Identity or GKE workload identity, which destinations.identity: workload writes for each managed identity; without it, set it up on its own. Either way the app's credentials change")
	}
	p.quiet("workloadIdentity")
	if truthy(obj(p.m["imageCleaner"])["enabled"]) {
		p.lose("imageCleaner", "AKS removed unused, vulnerable images from the nodes; the target's kubelet removes images only for disk space", false)
	}
	p.quiet("imageCleaner")
	if len(list(p.m["customCATrustCertificates"])) > 0 {
		p.lose("customCATrustCertificates", "the nodes trusted extra certificate authorities; the target's trust only their own", false)
	}
	p.quiet("customCATrustCertificates")
	c.losses = append(c.losses, p.rest()...)
}

// readPool reads a node pool, inline in its cluster or an object of its
// own (spec is {properties: ...} either way). A loss whose Why begins
// "refuse: " refuses the cluster.
func readPool(name string, spec any, field string) (*aksPool, []Loss) {
	pl := &aksPool{name: name, field: field}
	top := newProps(obj(spec), field)
	top.quiet("properties", "name", "id", "type")
	p := newProps(obj(top.m["properties"]), field)
	if !strings.HasPrefix(field, "properties.") {
		p.prefix = field + "properties."
	}
	refuse := func(why string) { p.losses = append(p.losses, Loss{Field: p.prefix, Why: "refuse: " + why}) }
	p.quiet("name", "eTag", "provisioningState", "currentOrchestratorVersion", "status", "virtualMachineNodesStatus")
	// The node image Azure put on the nodes: the target's are its own.
	p.quiet("nodeImageVersion")
	pl.count = p.integer("count")
	if pl.count == nil {
		refuse("the snapshot gives no node count")
	}
	pl.vmSize = p.str("vmSize")
	if pl.disk = p.integer("osDiskSizeGB"); pl.disk == nil || *pl.disk == 0 {
		pl.disk = nil
		p.lose("osDiskSizeGB", "the snapshot gives no OS disk size: the target's default is used", false)
	}
	if p.str("osDiskType") == "Ephemeral" {
		p.lose("osDiskType", "the OS disk was on the VM's local storage (ephemeral); on the target it is a network disk", false)
	}
	if p.str("kubeletDiskType") == "Temporary" {
		p.lose("kubeletDiskType", "the kubelet's data was on the VM's temporary disk; on the target it is on the OS disk", false)
	}
	switch rt := p.str("workloadRuntime"); rt {
	case "", "OCIContainer":
	case "KataVmIsolation":
		p.lose("workloadRuntime", "pods ran in their own VMs (Kata); on the target they share the node's kernel, so a pod that breaks out reaches the node", true)
	default:
		p.lose("workloadRuntime", rt+": the target runs OCI containers only", false)
	}
	if p.str("messageOfTheDay") != "" {
		p.lose("messageOfTheDay", "the nodes' login message is not carried over", false)
	}
	pl.subnet = azSubnetKey(p.str("vnetSubnetID"))
	if p.has("vnetSubnetID") && p.str("vnetSubnetID") != "" && pl.subnet == "" {
		refuse("its subnet could not be read from " + p.str("vnetSubnetID"))
	}
	if p.str("podSubnetID") != "" {
		p.lose("podSubnetID", "its pods took addresses from a subnet of their own; on the target they take them as the target's network plugin does (EKS: the nodes' subnets, GKE: the cluster's pod range)", false)
	}
	p.quiet("podIPAllocationMode")
	pl.maxPods = p.integer("maxPods")
	sku := p.str("osSKU")
	switch os := p.str("osType"); os {
	case "", "Linux":
		pl.ubuntu = strings.HasPrefix(sku, "Ubuntu")
		if sku != "" {
			p.lose("osSKU", sku+": the target's nodes run the target's own Linux (EKS: the Amazon Linux AMI it gives the instance type; GKE: Ubuntu where this was Ubuntu, Container-Optimized OS otherwise)", false)
		}
	case "Windows":
		switch sku {
		case "Windows2019":
			pl.windows = "2019"
		case "Windows2022":
			pl.windows = "2022"
		case "":
			refuse("a Windows pool with no osSKU in the snapshot: which Windows Server it runs is not known")
		default:
			refuse(sku + " nodes are not translated yet")
		}
	default:
		refuse(fmt.Sprintf("osType %q is not one this reads", os))
	}
	pl.max, pl.min = p.integer("maxCount"), p.integer("minCount")
	pl.auto = p.boolean("enableAutoScaling")
	if pl.auto && (pl.min == nil || pl.max == nil) {
		refuse("it autoscales, and the snapshot gives no minCount or maxCount")
	}
	if p.str("scaleDownMode") == "Deallocate" {
		p.lose("scaleDownMode", "scaled-down nodes were kept deallocated to start faster; the target removes them", false)
	}
	switch t := p.str("type"); t {
	case "", "VirtualMachineScaleSets", "AvailabilitySet":
	case "VirtualMachines":
		if len(obj(p.m["virtualMachinesProfile"])) > 0 {
			p.lose("virtualMachinesProfile", "its nodes were of several sizes; on the target they are all of the one machine type the map names", false)
		}
	default:
		p.lose("type", t+" is not a pool type this reads", false)
	}
	p.quiet("virtualMachinesProfile")
	switch mode := p.str("mode"); mode {
	case "", "User":
	case "System":
		p.lose("mode", "a System pool was kept for the cluster's own pods; the target has no such pool, so they schedule on any node unless the pool is tainted for them", false)
	case "Gateway":
		refuse("a Gateway pool (for static egress gateways) is not translated")
	default:
		p.lose("mode", mode+" is not a pool mode this reads", false)
	}
	if v := p.str("orchestratorVersion"); v != "" {
		if m := aksVersionRE.FindStringSubmatch(v); m != nil {
			pl.version = m[1]
		} else {
			refuse(fmt.Sprintf("its Kubernetes version %q is not one this reads", v))
		}
	}
	if us := obj(p.m["upgradeSettings"]); len(us) > 0 {
		u := newProps(us, p.prefix+"upgradeSettings.")
		pl.surge = wholeNumber(u.str("maxSurge"))
		pl.unavailble = wholeNumber(u.str("maxUnavailable"))
		if (u.has("maxSurge") && pl.surge == nil) || (u.has("maxUnavailable") && pl.unavailble == nil) {
			u.lose("maxSurge", "a surge given as a percentage is not carried over: the target upgrades with its own", false)
		}
		for _, k := range []string{"drainTimeoutInMinutes", "nodeSoakDurationInMinutes", "undrainableNodeBehavior"} {
			if u.has(k) {
				u.lose(k, "how long the upgrade waits on each node is not carried over", false)
			}
			u.quiet(k)
		}
		p.losses = append(p.losses, u.rest()...)
	}
	p.quiet("upgradeSettings")
	if strings.EqualFold(fmt.Sprint(obj(p.m["powerState"])["code"]), "Stopped") {
		p.lose("powerState", "the pool is stopped; on the target it runs", false)
	}
	p.quiet("powerState")
	for _, z := range list(p.m["availabilityZones"]) {
		pl.zones = append(pl.zones, fmt.Sprint(z))
	}
	p.quiet("availabilityZones")
	pl.publicIP = p.boolean("enableNodePublicIP")
	if p.str("nodePublicIPPrefixID") != "" {
		p.lose("nodePublicIPPrefixID", "the nodes' public addresses came from a prefix of the customer's; the target's are the cloud's", false)
	}
	switch pr := p.str("scaleSetPriority"); pr {
	case "", "Regular":
	case "Spot":
		pl.spot = true
	default:
		p.lose("scaleSetPriority", pr+" is not a priority this reads", false)
	}
	if p.str("scaleSetEvictionPolicy") == "Deallocate" {
		p.lose("scaleSetEvictionPolicy", "evicted spot nodes were kept deallocated; the target removes them", false)
	}
	if mp := p.integer("spotMaxPrice"); mp != nil && *mp != -1 {
		p.lose("spotMaxPrice", "a highest price for spot nodes is not carried over: the target pays up to the on-demand price", false)
	}
	pl.tags = stringTags(p.m["tags"])
	p.quiet("tags")
	pl.labels = stringTags(p.m["nodeLabels"])
	p.quiet("nodeLabels")
	for _, x := range list(p.m["nodeTaints"]) {
		t, ok := parseTaint(fmt.Sprint(x))
		if !ok {
			refuse(fmt.Sprintf("its taint %q cannot be read: dropped, pods it kept off the nodes would land on them", x))
			continue
		}
		pl.taints = append(pl.taints, t)
	}
	p.quiet("nodeTaints")
	if p.str("proximityPlacementGroupID") != "" {
		p.lose("proximityPlacementGroupID", "the nodes were kept close together (a proximity placement group); the target places them as it does", false)
	}
	if len(obj(p.m["kubeletConfig"])) > 0 || len(obj(p.m["linuxOSConfig"])) > 0 {
		p.lose("kubeletConfig", "the kubelet's and the node OS's own settings (sysctls, CPU manager, image GC, pod PID limit) are not carried over: the target's nodes run with their defaults", false)
	}
	p.quiet("kubeletConfig", "linuxOSConfig")
	if p.boolean("enableEncryptionAtHost") {
		p.byTarget("aws", "enableEncryptionAtHost", "the nodes' temporary disks and caches were encrypted on the host; EKS's node volumes are not encrypted unless the account encrypts EBS by default (not translated)", true)
	}
	if p.boolean("enableUltraSSD") {
		p.lose("enableUltraSSD", "Ultra disks are not translated", false)
	}
	if p.boolean("enableFIPS") {
		p.lose("enableFIPS", "the nodes ran FIPS 140-validated crypto modules; the target's are not set up to (not translated)", true)
	}
	if p.str("gpuInstanceProfile") != "" || len(obj(p.m["gpuProfile"])) > 0 {
		p.lose("gpuProfile", "GPU partitioning and driver settings are not carried over: the target's GPU nodes are set up on their own", false)
	}
	p.quiet("gpuInstanceProfile", "gpuProfile")
	if sid := fmt.Sprint(obj(p.m["creationData"])["sourceResourceId"]); len(obj(p.m["creationData"])) > 0 && sid != "" {
		p.lose("creationData", "the pool was made from a node image snapshot; the target's nodes take the target's image", false)
	}
	p.quiet("creationData")
	if p.str("capacityReservationGroupID") != "" {
		p.lose("capacityReservationGroupID", "the nodes used reserved capacity; the target's take what is free", false)
	}
	if p.str("hostGroupID") != "" {
		p.lose("hostGroupID", "the nodes ran on dedicated hosts, apart from other customers'; the target's run on shared hosts", true)
	}
	if np := obj(p.m["networkProfile"]); len(np) > 0 {
		n := newProps(np, p.prefix+"networkProfile.")
		if len(list(n.m["allowedHostPorts"])) > 0 {
			n.lose("allowedHostPorts", "only these ports were open on the nodes; on the target every port the node security group or firewall allows is", true)
		}
		if len(list(n.m["applicationSecurityGroups"])) > 0 {
			n.lose("applicationSecurityGroups", "the nodes were in application security groups; NSG rules that name them are not carried over (see the network's losses)", false)
		}
		if len(list(n.m["nodePublicIPTags"])) > 0 {
			n.lose("nodePublicIPTags", "the public addresses' IP tags are not carried over", false)
		}
		if len(obj(n.m["dranet"])) > 0 {
			n.lose("dranet", "has no equivalent here", false)
		}
		n.quiet("allowedHostPorts", "applicationSecurityGroups", "nodePublicIPTags", "dranet")
		p.losses = append(p.losses, n.rest()...)
	}
	p.quiet("networkProfile")
	if truthy(obj(p.m["windowsProfile"])["disableOutboundNat"]) {
		p.lose("windowsProfile", "Windows nodes' outbound NAT was off; on the target it is as the target does it", false)
	}
	p.quiet("windowsProfile")
	if sp := obj(p.m["securityProfile"]); len(sp) > 0 {
		s := newProps(sp, p.prefix+"securityProfile.")
		pl.secureBoot, pl.vtpm = s.boolean("enableSecureBoot"), s.boolean("enableVTPM")
		if pl.secureBoot || pl.vtpm {
			p.byTarget("aws", "securityProfile", "the nodes booted with Trusted Launch (secure boot, vTPM); EKS's managed node groups do not", true)
		}
		switch ssh := s.str("sshAccess"); ssh {
		case "", "LocalUser":
		case "Disabled":
			pl.sshOff = true
		case "EntraId":
			s.lose("sshAccess", "SSH to the nodes signed in with Entra ID; on the target nobody has SSH to them until it is set up", false)
		default:
			s.lose("sshAccess", ssh+" is not an SSH setting this reads", false)
		}
		p.losses = append(p.losses, s.rest()...)
	}
	p.quiet("securityProfile")
	if len(obj(p.m["gatewayProfile"])) > 0 {
		p.lose("gatewayProfile", "has no equivalent here", false)
	}
	p.quiet("gatewayProfile")
	pl.streaming = truthy(obj(p.m["artifactStreamingProfile"])["enabled"])
	if pl.streaming {
		p.byTarget("aws", "artifactStreamingProfile", "images were streamed to the nodes; EKS pulls them whole", false)
	}
	p.quiet("artifactStreamingProfile")
	if ld := obj(p.m["localDNSProfile"]); len(ld) > 0 && !strings.EqualFold(fmt.Sprint(ld["mode"]), "Disabled") {
		p.lose("localDNSProfile", "a DNS cache on each node and its overrides are not carried over: pods resolve through the cluster's DNS", false)
	}
	p.quiet("localDNSProfile")
	return pl, append(top.rest(), p.rest()...)
}

// byTarget records a loss only one target has, in a pool: its Field is
// prefixed "<target>|" until the writer takes the ones for its target.
func (p *props) byTarget(to, k, why string, widens bool) {
	p.losses = append(p.losses, Loss{Field: to + "|" + p.prefix + k, Why: why, Widens: widens})
}

// forTarget keeps the losses for one target, without their marks.
func forTarget(ls []Loss, to string) []Loss {
	var out []Loss
	for _, l := range ls {
		if t, f, ok := strings.Cut(l.Field, "|"); ok {
			if t != to {
				continue
			}
			l.Field = f
		}
		out = append(out, l)
	}
	return out
}

// parseTaint reads key[=value]:Effect.
func parseTaint(s string) (aksTaint, bool) {
	kv, eff, ok := strings.Cut(s, ":")
	if !ok || kv == "" {
		return aksTaint{}, false
	}
	k, v, _ := strings.Cut(kv, "=")
	switch eff {
	case "NoSchedule", "PreferNoSchedule", "NoExecute":
		return aksTaint{key: k, value: v, effect: eff}, true
	}
	return aksTaint{}, false
}

// taintEffect is the target's name for a Kubernetes taint effect.
func taintEffect(e string) string {
	return map[string]string{"NoSchedule": "NO_SCHEDULE", "PreferNoSchedule": "PREFER_NO_SCHEDULE", "NoExecute": "NO_EXECUTE"}[e]
}

func wholeNumber(s string) *int {
	if s == "" {
		return nil
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return nil
		}
		n = n*10 + int(r-'0')
	}
	return &n
}

// azSubnetKey is the group/network/subnet a subnet ID or reference names,
// lower case.
func azSubnetKey(s string) string {
	if m := azRefRE.FindStringSubmatch(s); m != nil && strings.EqualFold(m[1], "Microsoft.Network/virtualNetworks/subnets") && strings.Count(m[3], "/") == 1 {
		return strings.ToLower(m[2] + "/" + m[3])
	}
	parts := strings.Split(s, "/")
	for i := 0; i+1 < len(parts); i++ {
		if !strings.EqualFold(parts[i], "resourceGroups") {
			continue
		}
		for j := i + 2; j+4 < len(parts); j++ {
			if strings.EqualFold(parts[j]+"/"+parts[j+1], "Microsoft.Network/virtualNetworks") && strings.EqualFold(parts[j+3], "subnets") && j+5 == len(parts) {
				return strings.ToLower(parts[i+1] + "/" + parts[j+2] + "/" + parts[j+4])
			}
		}
	}
	return ""
}

func truthy(v any) bool { b, _ := v.(bool); return b }

// anyEnabled reports an "enabled": true anywhere in a profile.
func anyEnabled(v any) bool {
	switch c := v.(type) {
	case map[string]any:
		for k, x := range c {
			if k == "enabled" && truthy(x) {
				return true
			}
			if anyEnabled(x) {
				return true
			}
		}
	case []any:
		for _, x := range c {
			if anyEnabled(x) {
				return true
			}
		}
	}
	return false
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// subnetFor is the subnet the network family wrote for an Azure subnet,
// or why there is none.
func subnetFor(o *out, key string) (*netSub, string) {
	if ns := o.netSubs[key]; ns != nil {
		return ns, ""
	}
	parts := strings.Split(key, "/")
	if len(parts) == 3 {
		want := azVNet + " " + parts[0] + "/" + parts[1]
		for _, e := range o.entries {
			if strings.ToLower(e.Source) == want && e.State == Refused {
				return nil, "its network " + e.Source + " is refused (" + e.Reason + ")"
			}
		}
	}
	return nil, "it is not in the snapshot"
}

// clusterRequirements are what every translated cluster needs, whichever
// the target.
func clusterRequirements(c *aksCluster, o *out, target string) {
	o.require("A cluster's workloads are not in this translation: restore TruthForm's Kubernetes snapshot of " + c.src + " into the " + target + " cluster once it runs; persistent volumes' data is not moved, and is copied on its own")
	for _, r := range c.reqs {
		o.require(c.src + ": " + r)
	}
}

// validCIDRs keeps the IPv4 ranges among s.
func validCIDRs(s []string) (ok, bad []string) {
	for _, x := range s {
		if p, err := netip.ParsePrefix(x); err == nil && p.Addr().Is4() {
			ok = append(ok, p.Masked().String())
		} else if a, err := netip.ParseAddr(x); err == nil && a.Is4() {
			ok = append(ok, a.String()+"/32")
		} else {
			bad = append(bad, x)
		}
	}
	return ok, bad
}
