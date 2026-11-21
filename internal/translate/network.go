package translate

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Azure virtual networks and network security groups, read into a model
// the AWS and GCP writers share.
//
// A virtual network becomes a VPC (AWS) or a VPC network (GCP), its
// subnets the target's subnets. A network security group becomes a
// security group per network it is used in (AWS) or firewall rules on that
// network (GCP). Azure evaluates an NSG's rules by priority, the first
// match deciding, with allow and deny rules both. GCP firewalls work the
// same way, so a rule set is carried over rule for rule. AWS security
// groups only allow: what an NSG allows is worked out as sets of
// addresses, ports and protocols (netset.go) with each deny of higher
// priority taken out, and only that is written. Where a deny cannot be
// taken out exactly, the allow it cuts into is dropped and named: a
// translation may let through less than the source did, never more.

const (
	azVNet    = "microsoft.network/virtualnetworks"
	azSubnet  = azVNet + "/subnets"
	azPeering = azVNet + "/virtualnetworkpeerings"
	azNSG     = "microsoft.network/networksecuritygroups"
	azNSGRule = azNSG + "/securityrules"
)

type network struct{}

func (network) claims(kind string) bool {
	return kind == azVNet || strings.HasPrefix(kind, azVNet+"/") || kind == azNSG || strings.HasPrefix(kind, azNSG+"/")
}

type vnet struct {
	src, group, name string
	key              string // group/name, lower case
	prefixes         []netip.Prefix
	subnets          []*subnet
	tags             map[string]string
	encryption       string // "", AllowUnencrypted, DropUnencrypted
	losses           []Loss
}

type subnet struct {
	vnet   *vnet
	name   string
	prefix netip.Prefix
	nsg    string // group/name of its NSG, lower case
	field  string // where the report names its settings
}

type nsg struct {
	src, group, name string
	key              string
	rules            []nsgRule
	tags             map[string]string
	losses           []Loss
	refuse           string
	subnets          []*subnet
}

// addrs is one side of a rule: what Azure wrote, before it is resolved
// against the network the rule is used in.
type addrs struct {
	any, vnet, internet bool
	prefixes            []netip.Prefix
	other               []string // service tags and application security groups
}

type nsgRule struct {
	name       string
	allow      bool
	inbound    bool
	priority   int
	protos     []string // all, tcp, udp, icmp, esp, ah
	ports      [][2]int // destination ports; tcp and udp only
	peer, self addrs    // inbound: source, destination; outbound: the reverse
	srcPorts   bool     // a source port is named
	builtin    bool     // one of Azure's own rules every NSG has
}

func (r nsgRule) dir() string {
	if r.inbound {
		return "inbound"
	}
	return "outbound"
}

func (r nsgRule) String() string {
	a := "deny"
	if r.allow {
		a = "allow"
	}
	return fmt.Sprintf("%s %s rule %s (priority %d)", r.dir(), a, r.name, r.priority)
}

// azureDefaults are the rules Azure puts at the end of every NSG; a
// capture holds none of them, since no one can write them.
var azureDefaults = []nsgRule{
	{name: "AllowVnetInBound", allow: true, inbound: true, priority: 65000, protos: []string{"all"}, peer: addrs{vnet: true}, self: addrs{vnet: true}, builtin: true},
	{name: "AllowAzureLoadBalancerInBound", allow: true, inbound: true, priority: 65001, protos: []string{"all"}, peer: addrs{other: []string{"AzureLoadBalancer"}}, self: addrs{any: true}, builtin: true},
	{name: "DenyAllInBound", inbound: true, priority: 65500, protos: []string{"all"}, peer: addrs{any: true}, self: addrs{any: true}, builtin: true},
	{name: "AllowVnetOutBound", allow: true, priority: 65000, protos: []string{"all"}, peer: addrs{vnet: true}, self: addrs{vnet: true}, builtin: true},
	{name: "AllowInternetOutBound", allow: true, priority: 65001, protos: []string{"all"}, peer: addrs{internet: true}, self: addrs{any: true}, builtin: true},
	{name: "DenyAllOutBound", priority: 65500, protos: []string{"all"}, peer: addrs{any: true}, self: addrs{any: true}, builtin: true},
}

func (network) translate(objs []snapshot.Object, o *out) {
	vnets := map[string]*vnet{}
	nsgs := map[string]*nsg{}
	var subnetObjs, ruleObjs []snapshot.Object
	for _, obj := range objs {
		switch k := strings.ToLower(obj.Kind()); k {
		case azVNet:
			v := readVNet(obj)
			vnets[v.key] = v
		case azNSG:
			n := readNSG(obj)
			nsgs[n.key] = n
		case azSubnet:
			subnetObjs = append(subnetObjs, obj)
		case azNSGRule:
			ruleObjs = append(ruleObjs, obj)
		case azNSG + "/defaultsecurityrules":
			o.entries = append(o.entries, Entry{Source: source(obj), State: Mapped,
				Reason: "one of Azure's own rules, which every NSG has; its effect is written with its NSG's"})
		default:
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
		}
	}
	// Children a capture keeps as objects of their own are read with their
	// parent, as if inline.
	for _, obj := range subnetObjs {
		parent, name, _ := strings.Cut(obj.Name(), "/")
		v := vnets[strings.ToLower(obj.Namespace()+"/"+parent)]
		if v == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its virtual network is not in the snapshot"})
			continue
		}
		s, losses := readSubnet(v, name, spec(obj), "")
		v.subnets = append(v.subnets, s)
		v.losses = append(v.losses, prefixed(losses, "subnets/"+name+": ")...)
		o.entries = append(o.entries, Entry{Source: source(obj), State: Mapped, Reason: "read with its network " + v.src})
	}
	for _, obj := range ruleObjs {
		parent, name, _ := strings.Cut(obj.Name(), "/")
		n := nsgs[strings.ToLower(obj.Namespace()+"/"+parent)]
		if n == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its network security group is not in the snapshot"})
			continue
		}
		r, losses := readSecurityRule(name, spec(obj), "")
		n.addRule(r, prefixed(losses, "securityRules/"+name+": "))
		o.entries = append(o.entries, Entry{Source: source(obj), State: Mapped, Reason: "read with its network security group " + n.src})
	}
	for _, v := range sortedVNets(vnets) {
		for _, s := range v.subnets {
			o.subnets[v.key+"/"+strings.ToLower(s.name)] = s
			if s.nsg == "" {
				continue
			}
			if n := nsgs[s.nsg]; n != nil {
				n.subnets = append(n.subnets, s)
			} else {
				v.losses = append(v.losses, Loss{Field: s.field + "networkSecurityGroup", Widens: true,
					Why: "its network security group is not in the snapshot, so nothing on the target filters this subnet's traffic as it did"})
			}
		}
	}
	var w netWriter
	switch {
	case o.m.Destinations.Network == "":
		why := "the map chooses no destination for networks (destinations.network)"
		for _, v := range sortedVNets(vnets) {
			o.entries = append(o.entries, Entry{Source: v.src, State: Refused, Reason: why})
		}
		for _, n := range sortedNSGs(nsgs) {
			o.entries = append(o.entries, Entry{Source: n.src, State: Refused, Reason: why})
		}
		return
	case o.m.To == "aws":
		w = awsNet{m: o.m}
	case o.m.To == "gcp":
		w = gcpNet{m: o.m}
	}
	written := map[string]bool{}
	for _, v := range sortedVNets(vnets) {
		written[v.key] = w.vnet(v, o)
	}
	for _, n := range sortedNSGs(nsgs) {
		if n.refuse == "" && len(n.subnets) == 0 {
			n.refuse = "no subnet in the snapshot uses it (one on a network interface is not translated yet), so there is no network to put it in"
		}
		for _, s := range n.subnets {
			if !written[s.vnet.key] && n.refuse == "" {
				n.refuse = "its network " + s.vnet.src + " is refused"
			}
		}
		if n.refuse != "" {
			o.entries = append(o.entries, Entry{Source: n.src, State: Refused, Reason: n.refuse})
			continue
		}
		w.nsg(n, o)
	}
}

// netWriter writes the model for one target.
type netWriter interface {
	vnet(v *vnet, o *out) bool // false: refused
	nsg(n *nsg, o *out)
}

func prefixed(ls []Loss, p string) []Loss {
	for i := range ls {
		ls[i].Field = p + ls[i].Field
	}
	return ls
}

func sortedVNets(m map[string]*vnet) []*vnet {
	out := make([]*vnet, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

func sortedNSGs(m map[string]*nsg) []*nsg {
	out := make([]*nsg, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

func stringTags(v any) map[string]string {
	m, _ := v.(map[string]any)
	if len(m) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, x := range m {
		out[k] = fmt.Sprint(x)
	}
	return out
}

func list(v any) []any { l, _ := v.([]any); return l }

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }

// azRefKey is the group/name of what an Azure reference names, lower case:
// a captured reference is a token, {{truthform|ref|type|group|name|path}};
// a raw resource ID is read too.
func azRefKey(v any, typ string) string {
	s, _ := obj(v)["id"].(string)
	if m := azRefRE.FindStringSubmatch(s); m != nil && strings.EqualFold(m[1], typ) {
		return strings.ToLower(m[2] + "/" + m[3])
	}
	parts := strings.Split(s, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			for j := i + 2; j+2 < len(parts); j++ {
				if strings.EqualFold(parts[j]+"/"+parts[j+1], typ) {
					return strings.ToLower(parts[i+1] + "/" + parts[j+2])
				}
			}
		}
	}
	return ""
}

var azRefRE = regexp.MustCompile(`^\{\{truthform\|ref\|([^|{}]+)\|([^|{}]*)\|([^|{}]+)\|[^|{}]*\}\}$`)

const typVNet, typNSG = "Microsoft.Network/virtualNetworks", "Microsoft.Network/networkSecurityGroups"

func readVNet(o snapshot.Object) *vnet {
	v := &vnet{src: source(o), group: o.Namespace(), name: o.Name(), key: strings.ToLower(o.Namespace() + "/" + o.Name())}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name")
	v.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	if el, _ := top.take("extendedLocation"); len(obj(el)) > 0 {
		top.lose("extendedLocation", "an edge zone has no equivalent here: the network is written to the map's region", false)
	}
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "resourceGuid")
	if as := obj(p.m["addressSpace"]); as != nil {
		a := newProps(as, "properties.addressSpace.")
		for _, x := range list(a.m["addressPrefixes"]) {
			pf, err := netip.ParsePrefix(fmt.Sprint(x))
			switch {
			case err != nil:
				a.lose("addressPrefixes", fmt.Sprintf("%v is not an address prefix", x), false)
			case !pf.Addr().Is4():
				a.lose("addressPrefixes", pf.String()+": IPv6 ranges are not translated yet; the target network is IPv4 only", false)
			default:
				v.prefixes = append(v.prefixes, pf.Masked())
			}
		}
		a.quiet("addressPrefixes")
		if l := list(a.m["ipamPoolPrefixAllocations"]); len(l) > 0 {
			a.lose("ipamPoolPrefixAllocations", "ranges allocated from an IP address manager pool are written as the prefixes they are", false)
		}
		a.quiet("ipamPoolPrefixAllocations")
		v.losses = append(v.losses, a.rest()...)
	}
	p.quiet("addressSpace")
	if d := obj(p.m["dhcpOptions"]); len(list(d["dnsServers"])) > 0 {
		p.lose("dhcpOptions", fmt.Sprintf("its machines resolve names with %v; the target's use the cloud's resolver until DHCP options (AWS) or a DNS server policy (GCP) name these (not translated yet)", list(d["dnsServers"])), false)
	}
	p.quiet("dhcpOptions")
	p.unlessDefault("flowTimeoutInMinutes", nil, "an idle-flow timeout for the network has no equivalent here")
	for _, x := range list(p.m["subnets"]) {
		sm := obj(x)
		name, _ := sm["name"].(string)
		s, losses := readSubnet(v, name, sm, fmt.Sprintf("properties.subnets[%s].", name))
		v.subnets = append(v.subnets, s)
		v.losses = append(v.losses, losses...)
	}
	p.quiet("subnets")
	if l := list(p.m["virtualNetworkPeerings"]); len(l) > 0 {
		p.lose("virtualNetworkPeerings", fmt.Sprintf("%d peering(s) to other networks are not translated yet: the target network reaches no other", len(l)), false)
	}
	p.quiet("virtualNetworkPeerings")
	ddos := p.boolean("enableDdosProtection")
	if dp := obj(p.m["ddosProtectionPlan"]); len(dp) > 0 || ddos {
		p.lose("enableDdosProtection", "it has DDoS Network Protection; the target has only the cloud's default protection until its own (AWS Shield Advanced, Google Cloud Armor) is set up (not translated)", true)
	}
	p.quiet("ddosProtectionPlan")
	p.unlessDefault("enableVmProtection", false, "a retired setting with no equivalent")
	if bc := obj(p.m["bgpCommunities"]); len(bc) > 0 {
		p.lose("bgpCommunities", "BGP communities for ExpressRoute have no equivalent here", false)
	}
	p.quiet("bgpCommunities")
	if e := obj(p.m["encryption"]); e != nil {
		if on, _ := e["enabled"].(bool); on {
			v.encryption, _ = e["enforcement"].(string)
			if v.encryption == "" {
				v.encryption = "AllowUnencrypted"
			}
		}
	}
	p.quiet("encryption")
	if l := list(p.m["ipAllocations"]); len(l) > 0 {
		p.lose("ipAllocations", "IP allocations have no equivalent here", false)
	}
	p.quiet("ipAllocations")
	p.unlessDefault("privateEndpointVNetPolicies", "Disabled", "private endpoint policies for the network have no equivalent here")
	if sg := obj(p.m["summarizedGatewayPrefixes"]); len(sg) > 0 {
		p.lose("summarizedGatewayPrefixes", "gateway prefixes are not translated: no gateway is", false)
	}
	p.quiet("summarizedGatewayPrefixes")
	v.losses = append(append(top.rest(), p.rest()...), v.losses...)
	return v
}

// readSubnet reads a subnet, inline in its network or an object of its
// own. field is where the report names its settings.
func readSubnet(v *vnet, name string, m map[string]any, field string) (*subnet, []Loss) {
	s := &subnet{vnet: v, name: name, field: field}
	top := newProps(m, field)
	top.quiet("name", "id", "properties", "type", "etag")
	p := newProps(obj(m["properties"]), field+"properties.")
	p.quiet("provisioningState", "ipConfigurations", "ipConfigurationProfiles", "privateEndpoints", "resourceNavigationLinks", "serviceAssociationLinks", "purpose")
	var pfs []string
	if a := p.str("addressPrefix"); a != "" {
		pfs = append(pfs, a)
	}
	for _, x := range list(p.m["addressPrefixes"]) {
		pfs = append(pfs, fmt.Sprint(x))
	}
	p.quiet("addressPrefixes")
	for i, a := range pfs {
		pf, err := netip.ParsePrefix(a)
		switch {
		case err != nil || !pf.Addr().Is4():
			p.lose("addressPrefix", a+": only an IPv4 prefix is translated", false)
		case i == 0 || !s.prefix.IsValid():
			s.prefix = pf.Masked()
		default:
			p.lose("addressPrefixes", a+": a subnet on the target has one range; this one is not carried over", false)
		}
	}
	s.nsg = azRefKey(p.m["networkSecurityGroup"], typNSG)
	if p.has("networkSecurityGroup") && s.nsg == "" {
		p.lose("networkSecurityGroup", "its network security group could not be read from the reference", true)
	}
	p.quiet("networkSecurityGroup")
	if len(obj(p.m["routeTable"])) > 0 {
		p.lose("routeTable", "its traffic follows a route table, which is not translated yet: if it sent traffic through a firewall appliance, the target does not", true)
	}
	p.quiet("routeTable")
	if len(obj(p.m["natGateway"])) > 0 {
		p.lose("natGateway", "it reached the internet through a NAT gateway; the target subnet has no internet egress until one is added (not translated yet)", false)
	}
	p.quiet("natGateway")
	if len(list(p.m["serviceEndpoints"])) > 0 {
		p.lose("serviceEndpoints", "service endpoints are not translated: the target reaches those services by its own endpoints", false)
	}
	p.quiet("serviceEndpoints")
	if len(list(p.m["serviceEndpointPolicies"])) > 0 {
		p.lose("serviceEndpointPolicies", "service endpoint policies limited which storage accounts it could reach; the target does not limit this", true)
	}
	p.quiet("serviceEndpointPolicies")
	for _, k := range []string{"ipAllocations", "applicationGatewayIPConfigurations", "ipamPoolPrefixAllocations"} {
		if len(list(p.m[k])) > 0 {
			p.lose(k, "has no equivalent here", false)
		}
		p.quiet(k)
	}
	if d := list(p.m["delegations"]); len(d) > 0 {
		var svc []string
		for _, x := range d {
			svc = append(svc, fmt.Sprint(obj(obj(x)["properties"])["serviceName"]))
		}
		p.lose("delegations", fmt.Sprintf("delegated to %s; a subnet on the target is not delegated: the service that used it is translated, if at all, by its own rules", strings.Join(svc, ", ")), false)
	}
	p.quiet("delegations")
	p.unlessDefault("privateEndpointNetworkPolicies", "Disabled", "network policies on private endpoints have no equivalent here")
	p.unlessDefault("privateLinkServiceNetworkPolicies", "Enabled", "network policies on Private Link services have no equivalent here")
	p.unlessDefault("sharingScope", "", "a subnet shared with other tenants has no equivalent here")
	if p.boolean("defaultOutboundAccess") {
		p.lose("defaultOutboundAccess", "it reached the internet through Azure's default outbound access; on the target it has no internet egress until a NAT gateway (AWS) or Cloud NAT (GCP) is added", false)
	}
	if len(obj(p.m["serviceGateway"])) > 0 {
		p.lose("serviceGateway", "has no equivalent here", false)
	}
	p.quiet("serviceGateway")
	return s, append(top.rest(), p.rest()...)
}

func readNSG(o snapshot.Object) *nsg {
	n := &nsg{src: source(o), group: o.Namespace(), name: o.Name(), key: strings.ToLower(o.Namespace() + "/" + o.Name())}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name")
	n.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "resourceGuid", "defaultSecurityRules", "subnets", "networkInterfaces", "flowLogs")
	p.unlessDefault("flushConnection", false, "flushing connections when rules change has no equivalent here")
	for _, x := range list(p.m["securityRules"]) {
		m := obj(x)
		name, _ := m["name"].(string)
		r, ls := readSecurityRule(name, m, fmt.Sprintf("properties.securityRules[%s].", name))
		n.addRule(r, ls)
	}
	p.quiet("securityRules")
	n.losses = append(append(top.rest(), p.rest()...), n.losses...)
	return n
}

func (n *nsg) addRule(r *nsgRule, losses []Loss) {
	if r == nil {
		if n.refuse == "" {
			for _, l := range losses {
				if strings.HasPrefix(l.Why, "cannot read") {
					n.refuse = l.Field + ": " + l.Why
					break
				}
			}
		}
		n.losses = append(n.losses, losses...)
		return
	}
	n.rules = append(n.rules, *r)
	n.losses = append(n.losses, losses...)
}

// readSecurityRule reads a security rule. A rule it cannot read makes no rule, and
// the NSG is refused: a rule left out could be a deny.
func readSecurityRule(name string, m map[string]any, field string) (*nsgRule, []Loss) {
	top := newProps(m, field)
	top.quiet("name", "id", "properties", "type", "etag")
	p := newProps(obj(m["properties"]), field+"properties.")
	p.quiet("provisioningState", "description")
	r := &nsgRule{name: name}
	bad := func(k, why string) (*nsgRule, []Loss) {
		return nil, []Loss{{Field: field + "properties." + k, Why: "cannot read the rule: " + why, Widens: true}}
	}
	switch a := strings.ToLower(p.str("access")); a {
	case "allow":
		r.allow = true
	case "deny":
	default:
		return bad("access", fmt.Sprintf("%q is not Allow or Deny", a))
	}
	switch d := strings.ToLower(p.str("direction")); d {
	case "inbound":
		r.inbound = true
	case "outbound":
	default:
		return bad("direction", fmt.Sprintf("%q is not Inbound or Outbound", d))
	}
	if pr := p.integer("priority"); pr != nil {
		r.priority = *pr
	} else {
		return bad("priority", "it is missing")
	}
	ports, err := portRanges(p.str("destinationPortRange"), list(p.m["destinationPortRanges"]))
	p.quiet("destinationPortRanges")
	if err != nil {
		return bad("destinationPortRange", err.Error())
	}
	srcPorts, err := portRanges(p.str("sourcePortRange"), list(p.m["sourcePortRanges"]))
	p.quiet("sourcePortRanges")
	if err != nil {
		return bad("sourcePortRange", err.Error())
	}
	r.srcPorts = !(len(srcPorts) == 1 && srcPorts[0] == [2]int{0, 65535})
	switch pr := strings.ToLower(p.str("protocol")); pr {
	case "tcp", "udp":
		r.protos, r.ports = []string{pr}, ports
	case "icmp", "esp", "ah":
		r.protos = []string{pr}
	case "*", "any":
		if len(ports) == 1 && ports[0] == [2]int{0, 65535} {
			r.protos = []string{"all"}
		} else {
			// A port matches only TCP and UDP.
			r.protos, r.ports = []string{"tcp", "udp"}, ports
		}
	default:
		return bad("protocol", fmt.Sprintf("%q is not a protocol Azure takes", pr))
	}
	src := readAddrs(p.str("sourceAddressPrefix"), list(p.m["sourceAddressPrefixes"]), list(p.m["sourceApplicationSecurityGroups"]))
	dst := readAddrs(p.str("destinationAddressPrefix"), list(p.m["destinationAddressPrefixes"]), list(p.m["destinationApplicationSecurityGroups"]))
	p.quiet("sourceAddressPrefixes", "destinationAddressPrefixes", "sourceApplicationSecurityGroups", "destinationApplicationSecurityGroups")
	if r.inbound {
		r.peer, r.self = src, dst
	} else {
		r.peer, r.self = dst, src
	}
	return r, append(top.rest(), p.rest()...)
}

func portRanges(one string, many []any) ([][2]int, error) {
	var specs []string
	if one != "" {
		specs = append(specs, one)
	}
	for _, x := range many {
		specs = append(specs, fmt.Sprint(x))
	}
	if len(specs) == 0 {
		return [][2]int{{0, 65535}}, nil
	}
	var out [][2]int
	for _, s := range specs {
		if s == "*" {
			return [][2]int{{0, 65535}}, nil
		}
		lo, hi, isRange := strings.Cut(s, "-")
		a, err1 := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err1 != nil || err2 != nil || a < 0 || b > 65535 || a > b {
			return nil, fmt.Errorf("%q is not a port or port range", s)
		}
		out = append(out, [2]int{a, b})
	}
	return out, nil
}

func readAddrs(one string, many, asgs []any) addrs {
	var a addrs
	vals := []string{}
	if one != "" {
		vals = append(vals, one)
	}
	for _, x := range many {
		vals = append(vals, fmt.Sprint(x))
	}
	for _, v := range vals {
		switch strings.ToLower(v) {
		case "*", "any", "0.0.0.0/0":
			a.any = true
		case "virtualnetwork":
			a.vnet = true
		case "internet":
			a.internet = true
		default:
			if pf, err := netip.ParsePrefix(v); err == nil {
				if pf.Addr().Is4() {
					a.prefixes = append(a.prefixes, pf.Masked())
				} else {
					a.other = append(a.other, v)
				}
			} else if ad, err := netip.ParseAddr(v); err == nil && ad.Is4() {
				a.prefixes = append(a.prefixes, netip.PrefixFrom(ad, 32))
			} else {
				a.other = append(a.other, v)
			}
		}
	}
	for _, x := range asgs {
		a.other = append(a.other, "application security group "+fmt.Sprint(obj(x)["id"]))
	}
	return a
}

// resolve is what a side of a rule means in one network: Internet is all
// the addresses outside it, as Azure's service tag is. exact is false when
// something in it (a service tag, an application security group, an IPv6
// range) has no addresses here.
func (a addrs) resolve(v *vnet) (ps []netip.Prefix, exact bool) {
	if a.any {
		return []netip.Prefix{anyV4}, len(a.other) == 0
	}
	if a.internet {
		ps = append(ps, prefixMinus([]netip.Prefix{anyV4}, v.prefixes)...)
	}
	if a.vnet {
		ps = append(ps, v.prefixes...)
	}
	ps = append(ps, a.prefixes...)
	return aggregate(ps), len(a.other) == 0
}

// subnetsIn are the prefixes of the subnets in v that use the NSG.
func (n *nsg) subnetsIn(v *vnet) []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range n.subnets {
		if s.vnet == v && s.prefix.IsValid() {
			ps = append(ps, s.prefix)
		}
	}
	return ps
}

// vnets are the networks the NSG is used in, in order.
func (n *nsg) vnets() []*vnet {
	seen := map[*vnet]bool{}
	var out []*vnet
	for _, s := range n.subnets {
		if !seen[s.vnet] {
			seen[s.vnet] = true
			out = append(out, s.vnet)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

// ordered is the NSG's rules and Azure's own, in the order Azure
// evaluates them.
func (n *nsg) ordered() []nsgRule {
	rs := append(append([]nsgRule(nil), n.rules...), azureDefaults...)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].priority < rs[j].priority })
	return rs
}

// boxes is what a rule matches in a network, as boxes; peers holds the
// resolved peer side.
func (r nsgRule) boxes(peers []netip.Prefix) []box {
	var out []box
	for _, p := range r.protos {
		if p == "tcp" || p == "udp" {
			for _, pr := range r.ports {
				out = append(out, box{p, pr[0], pr[1], peers})
			}
			continue
		}
		out = append(out, box{p, 0, 65535, peers})
	}
	return out
}

// tagLosses names, once per NSG, the tags the target cannot hold.
func tagLosses(tags map[string]string, what string) []Loss {
	if len(tags) == 0 {
		return nil
	}
	return []Loss{{Field: "tags", Why: fmt.Sprintf("%d tag(s): %s has no tags or labels to hold them", len(tags), what)}}
}

var rfc1035Bad = regexp.MustCompile(`[^a-z0-9-]+`)

// gcpName makes a Compute resource name ([a-z]([-a-z0-9]*[a-z0-9])?, at
// most 63) from the parts.
func gcpName(parts ...string) string {
	n := rfc1035Bad.ReplaceAllString(strings.ToLower(strings.Join(parts, "-")), "-")
	n = strings.Trim(n, "-")
	if n == "" || n[0] < 'a' || n[0] > 'z' {
		n = "n-" + n
	}
	if len(n) > 63 {
		n = strings.TrimRight(n[:63], "-")
	}
	return n
}
