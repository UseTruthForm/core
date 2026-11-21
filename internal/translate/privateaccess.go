package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Private access: Azure private endpoints, which give a service an address
// in a network, so that the network reaches the service privately by the
// service's own name (through Azure's privatelink.* zones, which dns.go
// does not copy).
//
// The target reaches its own services privately its own way. On AWS a
// private endpoint becomes an interface VPC endpoint for the service the
// target was translated to, in the same subnets, with private DNS on: the
// AWS service's own name answers with the endpoint's addresses inside the
// VPC. Endpoints are per VPC and service, so several private endpoints to
// one kind of service share one. On GCP the network's subnetworks get
// Private Google Access: its machines reach Google's APIs by their own
// names without leaving Google's network. A database needs neither: RDS
// and Cloud SQL answer inside the network.

const (
	azPE        = "microsoft.network/privateendpoints"
	azPEDNS     = azPE + "/privatednszonegroups"
	awsEndpoint = "AWS::EC2::VPCEndpoint"
)

type privateAccess struct{}

func (privateAccess) claims(kind string) bool {
	return kind == azPE || strings.HasPrefix(kind, azPE+"/")
}

// peTarget is what one Azure service's private endpoint needs on each
// target: the AWS endpoint services, whether GCP reaches it through
// Private Google Access, and the map's destination it depends on.
type peTarget struct {
	what  string
	aws   func(Map) []string // nil: nothing to write on AWS
	gcp   func(Map) bool     // reached through Private Google Access
	dest  func(Map) string   // the destination chosen for its class, or ""
	key   string             // that destination's map key
	inVPC string             // set when the service answers in the network itself
}

var peTargets = map[string]map[string]peTarget{
	"microsoft.servicebus/namespaces": {"namespace": {what: "Service Bus",
		aws: func(m Map) []string {
			if m.Destinations.Messaging == "sqs-sns" {
				return []string{"sqs", "sns"}
			}
			return nil
		},
		gcp: func(m Map) bool { return m.Destinations.Messaging == "pubsub" }, dest: func(m Map) string { return m.Destinations.Messaging }, key: "destinations.messaging"}},
	"microsoft.storage/storageaccounts": {
		"blob":           {what: "Blob storage", aws: always("s3"), gcp: yes, dest: func(m Map) string { return m.Destinations.Storage }, key: "destinations.storage"},
		"blob_secondary": {what: "Blob storage", aws: always("s3"), gcp: yes, dest: func(m Map) string { return m.Destinations.Storage }, key: "destinations.storage"},
		"dfs":            {what: "Data Lake storage", aws: always("s3"), gcp: yes, dest: func(m Map) string { return m.Destinations.Storage }, key: "destinations.storage"},
		"dfs_secondary":  {what: "Data Lake storage", aws: always("s3"), gcp: yes, dest: func(m Map) string { return m.Destinations.Storage }, key: "destinations.storage"},
	},
	"microsoft.keyvault/vaults": {"vault": {what: "Key Vault", aws: always("secretsmanager"), gcp: yes,
		dest: func(m Map) string { return m.Destinations.Secrets }, key: "destinations.secrets"}},
	"microsoft.containerregistry/registries": {"registry": {what: "Container Registry", aws: always("ecr.api", "ecr.dkr", "s3"), gcp: yes,
		dest: func(m Map) string { return m.Destinations.Registry }, key: "destinations.registry"}},
	"microsoft.dbforpostgresql/flexibleservers": {"postgresqlserver": {what: "PostgreSQL", inVPC: "RDS and Cloud SQL answer inside the network the server is placed in",
		dest: func(m Map) string { return m.Destinations.Databases }, key: "destinations.databases"}},
	"microsoft.sql/servers": {"sqlserver": {what: "Azure SQL", inVPC: "RDS and Cloud SQL answer inside the network the server is placed in",
		dest: func(m Map) string { return m.Destinations.Databases }, key: "destinations.databases"}},
}

func always(s ...string) func(Map) []string { return func(Map) []string { return s } }

func yes(Map) bool { return true }

type privateEndpoint struct {
	src, group, name string
	subnet           string // group/network/subnet, lower case
	conns            []peConn
	losses           []Loss
}

type peConn struct {
	typ, target string // the service's ARM type (lower case) and group/name
	groups      []string
	manual      bool
}

func (privateAccess) translate(objs []snapshot.Object, o *out) {
	pes := map[string]*privateEndpoint{}
	var children []snapshot.Object
	for _, obj := range objs {
		switch k := strings.ToLower(obj.Kind()); k {
		case azPE:
			pe := readPrivateEndpoint(obj)
			pes[strings.ToLower(pe.group+"/"+pe.name)] = pe
		case azPEDNS:
			children = append(children, obj)
		default:
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
		}
	}
	for _, obj := range children {
		parent, _, _ := strings.Cut(obj.Name(), "/")
		if pes[strings.ToLower(obj.Namespace()+"/"+parent)] == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its private endpoint is not in the snapshot"})
			continue
		}
		o.entries = append(o.entries, Entry{Source: source(obj), State: Mapped,
			Reason: "read with its private endpoint: the zones it fills are Azure's names for the service, which the target answers privately by its own (" + serviceZoneHow[o.m.To] + ")"})
	}
	keys := make([]string, 0, len(pes))
	for k := range pes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var aws awsEndpoints
	gcpNets := map[string][]*privateEndpoint{}
	for _, k := range keys {
		pe := pes[k]
		e := Entry{Source: pe.src, State: Mapped, Losses: pe.losses}
		sub := o.subnets[pe.subnet]
		if sub == nil {
			o.entries = append(o.entries, Entry{Source: pe.src, State: Refused, Reason: "its subnet " + pe.subnet + " is not a subnet of a network in the snapshot"})
			continue
		}
		var services []string
		inVPC, google := false, false
		refuse := ""
		for _, c := range pe.conns {
			for _, g := range c.groups {
				t, ok := peTargets[c.typ][strings.ToLower(g)]
				switch {
				case !ok:
					refuse = fmt.Sprintf("a private endpoint to %s (%s), which is not translated", c.target, g)
				case t.dest(o.m) == "":
					refuse = fmt.Sprintf("its %s goes nowhere: the map chooses no destination for it (%s)", t.what, t.key)
				case t.inVPC != "":
					inVPC = true
					e.Reason = t.what + ": " + t.inVPC + ", so there is no endpoint to write"
				case o.m.To == "aws":
					s := t.aws(o.m)
					if s == nil {
						e.Reason = t.what + " goes to " + t.dest(o.m) + ", in the cluster: the cluster reaches it on its own network"
						continue
					}
					services = append(services, s...)
				case o.m.To == "gcp" && t.gcp(o.m):
					google = true
				case o.m.To == "gcp":
					e.Reason = t.what + " goes to " + t.dest(o.m) + ", in the cluster: the cluster reaches it on its own network"
				}
			}
		}
		if refuse != "" {
			o.entries = append(o.entries, Entry{Source: pe.src, State: Refused, Reason: refuse})
			continue
		}
		switch {
		case len(services) > 0:
			if why := aws.add(pe, sub, services, o); why != "" {
				o.entries = append(o.entries, Entry{Source: pe.src, State: Refused, Reason: why})
				continue
			}
			e.Reason = "an interface VPC endpoint per service in " + awsNet{o.m}.vpcName(sub.vnet) + " (" + strings.Join(uniqueSorted(services), ", ") + "), with private DNS: the AWS services' own names answer with the endpoints' addresses inside the VPC"
		case google:
			if ns := o.netSubs[pe.subnet]; ns == nil || ns.spec == nil {
				o.entries = append(o.entries, Entry{Source: pe.src, State: Refused, Reason: "its network " + sub.vnet.src + " is not translated, so there is no subnetwork to reach Google's APIs from"})
				continue
			}
			gcpNets[sub.vnet.key] = append(gcpNets[sub.vnet.key], pe)
			e.Reason = "Private Google Access on network " + gcpNet{o.m}.netName(sub.vnet) + "'s subnetworks: its machines reach Google's APIs by their own names without leaving Google's network"
		case inVPC:
		}
		o.entries = append(o.entries, e)
	}
	aws.write(o)
	if len(gcpNets) > 0 {
		for vk := range gcpNets {
			for _, ns := range o.netSubs {
				if ns.vnet == vk && ns.spec != nil {
					ns.spec["privateIpGoogleAccess"] = true
				}
			}
		}
		o.require("Private Google Access reaches Google's APIs privately from machines with no external IP; a machine with one reaches them over the internet. As on Azure, the services still answer on the internet to principals allowed to call them, until VPC Service Controls (not translated) close that")
	}
	if len(aws.byVPC) > 0 {
		o.require("Interface VPC endpoints are billed per endpoint and zone by the hour, and per gigabyte: the translation writes one per service and VPC that had a private endpoint")
	}
}

func uniqueSorted(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// awsEndpoints gathers, per VPC, the services private endpoints need and
// the subnets they sit in.
type awsEndpoints struct {
	byVPC map[string]*vpcEndpoints
}

type vpcEndpoints struct {
	v        *vnet
	vpc      string
	services map[string]bool
	subnets  map[string]string // zone -> subnet logical name: one per zone
}

func (a *awsEndpoints) add(pe *privateEndpoint, sub *subnet, services []string, o *out) string {
	ns := o.netSubs[pe.subnet]
	if ns == nil {
		return "its network " + sub.vnet.src + " is not translated, so there is no VPC to put an endpoint in"
	}
	if a.byVPC == nil {
		a.byVPC = map[string]*vpcEndpoints{}
	}
	ve := a.byVPC[sub.vnet.key]
	if ve == nil {
		ve = &vpcEndpoints{v: sub.vnet, vpc: awsNet{o.m}.vpcName(sub.vnet), services: map[string]bool{}, subnets: map[string]string{}}
		a.byVPC[sub.vnet.key] = ve
	}
	for _, s := range services {
		ve.services[s] = true
	}
	// An endpoint takes one subnet per zone; a private endpoint in another
	// subnet of a zone already taken shares that one, which the whole VPC
	// reaches.
	if _, ok := ve.subnets[ns.zone]; !ok {
		ve.subnets[ns.zone] = ns.awsName
	}
	return ""
}

func (a *awsEndpoints) write(o *out) {
	keys := make([]string, 0, len(a.byVPC))
	for k := range a.byVPC {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ve := a.byVPC[k]
		src := ve.v.src
		// The endpoints take HTTPS from the network, as a private
		// endpoint does from its network when no NSG applies to it.
		sg := ve.vpc + "-endpoints"
		var in []any
		for _, p := range ve.v.prefixes {
			in = append(in, sgRule(box{"tcp", 443, 443, nil}, p))
		}
		tags, _ := awsTags(sg, nil)
		o.add("aws", src, awsObject(awsSG, sg, map[string]any{
			"GroupDescription":     "HTTPS from the network to its interface endpoints, for its Azure private endpoints",
			"VpcId":                awsRef(awsVPC, ve.vpc, "VpcId"),
			"SecurityGroupIngress": in,
			"SecurityGroupEgress":  []any{sgRule(box{"all", 0, 65535, nil}, anyV4)},
			"Tags":                 tags,
		}))
		zones := make([]string, 0, len(ve.subnets))
		for z := range ve.subnets {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		var subnets []any
		for _, z := range zones {
			subnets = append(subnets, awsRef(awsSN, ve.subnets[z], "SubnetId"))
		}
		services := make([]string, 0, len(ve.services))
		for s := range ve.services {
			services = append(services, s)
		}
		sort.Strings(services)
		for _, s := range services {
			name := ve.vpc + "-" + strings.ReplaceAll(s, ".", "-")
			t, _ := awsTags(name, nil)
			spec := map[string]any{
				"VpcId": awsRef(awsVPC, ve.vpc, "VpcId"), "ServiceName": "com.amazonaws." + o.m.Region + "." + s,
				"VpcEndpointType": "Interface", "PrivateDnsEnabled": true, "SubnetIds": subnets,
				"SecurityGroupIds": []any{awsRef(awsSG, sg, "GroupId")}, "Tags": t,
			}
			if s == "s3" {
				// S3's private DNS otherwise answers only on-premises
				// lookups, and needs a gateway endpoint for the VPC's.
				spec["DnsOptions"] = map[string]any{"PrivateDnsOnlyForInboundResolverEndpoint": "AllResolvers"}
			}
			o.add("aws", src, awsObject(awsEndpoint, name, spec))
		}
		if len(zones) < 2 {
			o.require(fmt.Sprintf("The interface endpoints in VPC %s are in one availability zone (%s), as Azure's private endpoints were in one subnet: add a subnet in another zone for them to survive the loss of that one", ve.vpc, strings.Join(zones, ", ")))
		}
	}
}

func readPrivateEndpoint(o snapshot.Object) *privateEndpoint {
	pe := &privateEndpoint{src: source(o), group: o.Namespace(), name: o.Name()}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag")
	if t := stringTags(top.m["tags"]); len(t) > 0 {
		top.lose("tags", "an endpoint on the target is the target's own; the private endpoint's tags are not carried over", false)
	}
	top.quiet("tags")
	if el, _ := top.take("extendedLocation"); len(obj(el)) > 0 {
		top.lose("extendedLocation", "an edge zone has no equivalent here", false)
	}
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "networkInterfaces", "customDnsConfigs", "ipVersionType", "billingSku")
	sn, _ := obj(p.m["subnet"])["id"].(string)
	pe.subnet = subnetKey(sn)
	p.quiet("subnet")
	for _, k := range []string{"privateLinkServiceConnections", "manualPrivateLinkServiceConnections"} {
		for _, x := range list(p.m[k]) {
			cp := obj(obj(x)["properties"])
			id, _ := cp["privateLinkServiceId"].(string)
			c := peConn{manual: k == "manualPrivateLinkServiceConnections"}
			if m := azRefRE.FindStringSubmatch(id); m != nil {
				c.typ, c.target = strings.ToLower(m[1]), m[2]+"/"+m[3]
			} else if t, g, n := armID(id); t != "" {
				c.typ, c.target = t, g+"/"+n
			}
			for _, g := range list(cp["groupIds"]) {
				c.groups = append(c.groups, fmt.Sprint(g))
			}
			if c.manual {
				p.lose(k, "a connection the service's owner approves by hand: the target's endpoint connects to a service in the same account or project, with no approval", false)
			}
			pe.conns = append(pe.conns, c)
		}
		p.quiet(k)
	}
	if len(list(p.m["ipConfigurations"])) > 0 {
		var ips []string
		for _, x := range list(p.m["ipConfigurations"]) {
			if a, err := netip.ParseAddr(fmt.Sprint(obj(obj(x)["properties"])["privateIPAddress"])); err == nil {
				ips = append(ips, a.String())
			}
		}
		p.lose("ipConfigurations", fmt.Sprintf("its addresses were fixed (%s); the target picks its endpoints' addresses, and names them by DNS", strings.Join(ips, ", ")), false)
	}
	p.quiet("ipConfigurations")
	if len(list(p.m["applicationSecurityGroups"])) > 0 {
		p.lose("applicationSecurityGroups", "application security groups are not translated: the endpoints take HTTPS from the whole network", false)
	}
	p.quiet("applicationSecurityGroups")
	p.unlessDefault("customNetworkInterfaceName", "", "the endpoint's network interface name is the target's own")
	pe.losses = append(top.rest(), p.rest()...)
	return pe
}

// armID reads a resource ID's type, group and name, lower case.
func armID(id string) (typ, group, name string) {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") && i+4 < len(parts) && strings.EqualFold(parts[i+2], "providers") {
			return strings.ToLower(parts[i+3] + "/" + parts[i+4]), parts[i+1], strings.Join(parts[i+5:], "/")
		}
	}
	return "", "", ""
}
