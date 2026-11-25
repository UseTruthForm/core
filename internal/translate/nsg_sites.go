package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Where a network security group filters: a subnet, a network interface,
// or both at once, and who is in the application security groups its rules
// name.
//
// Azure evaluates the two NSGs on one path one after the other, and both
// must allow: "Azure first processes the rules in a network security group
// associated with a subnet if one exists. Azure then processes the rules in
// a network security group associated with the network interface if one
// exists. This same order of evaluation applies to intra-subnet traffic",
// and outbound the interface's NSG first, then the subnet's
// (learn.microsoft.com/azure/virtual-network/network-security-group-how-it-works).
// Each NSG is a list of its own, the first match by priority deciding: an
// allow at 100 in one does not answer a deny at 200 in the other.
//
// An application security group (ASG) is a set of network interfaces, all
// in one virtual network
// (learn.microsoft.com/azure/virtual-network/application-security-groups).
// A rule that names one as its peer matches traffic from or to its
// members; a rule that names one on its own side applies only to members.
// Who is a member is read from the interfaces, private endpoints and scale
// sets in the snapshot.

const (
	azNIC     = "microsoft.network/networkinterfaces"
	azASG     = "microsoft.network/applicationsecuritygroups"
	azFlowLog = "microsoft.network/networkwatchers/flowlogs"
	azVMSS    = "microsoft.compute/virtualmachinescalesets"

	typNIC = "Microsoft.Network/networkInterfaces"
	typASG = "Microsoft.Network/applicationSecurityGroups"

	// nsgMaxGroups is how many security groups (AWS) or combined rule sets
	// (GCP) one NSG is written as before it is refused: each set of ASGs
	// its interfaces are in, with each NSG it shares a path with, is one.
	nsgMaxGroups = 16
)

// nsgClaims are the types read here beside NSGs themselves: network
// interfaces, application security groups and flow logs.
func nsgClaims(kind string) bool {
	return kind == azNIC || strings.HasPrefix(kind, azNIC+"/") || kind == azASG || strings.HasPrefix(kind, azASG+"/") || kind == azFlowLog
}

// nsgASG is an application security group.
type nsgASG struct {
	src, group, name, key string
	tags                  map[string]string
	losses                []Loss
	inSnapshot            bool
	sites                 []*nsgSite // what is known to be in it
}

// nsgSite is one thing NSGs filter the traffic of: what is in the subnets
// an NSG is on (kind subnet), an NSG the map places in a network with
// nothing attached (unattached), a network interface (nic), a scale set's
// interfaces (vmss), or a private endpoint (endpoint).
type nsgSite struct {
	kind  string
	src   string // as the report names it
	name  string // for a target name
	owner string // what the interface belongs to, in words
	v     *vnet
	sub   *subnet
	// subnetNSG and nicNSG are the NSGs on its path; either may be nil.
	subnetNSG, nicNSG *nsg
	// applied holds its addresses: the subnet's range, or the interface's
	// own when they are fixed.
	applied []netip.Prefix
	// member are the ASGs every one of its addresses is in, maybe those
	// any of them is in.
	member, maybe map[string]bool
}

// nsgs are the NSGs on the site's path, the subnet's first.
func (s *nsgSite) nsgs() []*nsg {
	var out []*nsg
	if s.subnetNSG != nil {
		out = append(out, s.subnetNSG)
	}
	if s.nicNSG != nil && s.nicNSG != s.subnetNSG {
		out = append(out, s.nicNSG)
	}
	return out
}

// asgs are the ASGs the site is in, sorted.
func (s *nsgSite) asgs() []string {
	return sortedMapKeys(s.maybe)
}

// nsgNIC is a network interface as read.
type nsgNIC struct {
	src, group, name string
	nsg              string // group/name of its NSG, lower case
	subnets          []string
	asgs             [][]string // per IP configuration
	fixed            []netip.Prefix
	allFixed         bool
	vm, endpoint     string
	losses           []Loss
}

// nsgState is what the network family knows about NSGs once everything is
// read; the families that come after it attach what it wrote.
type nsgState struct {
	vnets map[string]*vnet
	nsgs  map[string]*nsg
	asgs  map[string]*nsgASG
	// sites are the interfaces, scale sets and private endpoints, in
	// order; endpoints holds the private endpoints by group/name.
	sites     []*nsgSite
	endpoints map[string]*nsgSite
	// placed are the networks the map puts an unattached NSG in.
	placed map[string][]*vnet
	// groups are the security groups (AWS) or tags (GCP) written, by site,
	// and subnetGroup the one for an NSG's subnets, by NSG and network.
	carries     map[*nsgSite][]string
	subnetGroup map[string]string
	markers     map[string]string // ASG key | network key -> marker group
	w           nsgHooks
}

// nsgHooks are what a target's writer does for the families that come
// after the network family.
type nsgHooks interface {
	// endpointGroups gives an AWS VPC's interface endpoints their inbound
	// rules and marker groups; filtered is false where no NSG applied to
	// any of the private endpoints.
	endpointGroups(st *nsgState, o *out, v *vnet, pes []string, group string) (ingress []any, markers []any, filtered bool)
	// privateAccess reports which of a network's subnets may be given
	// Private Google Access for the private endpoints.
	privateAccess(st *nsgState, o *out, v *vnet, pes []string) map[string]bool
}

func (st *nsgState) asg(key string) *nsgASG {
	a := st.asgs[key]
	if a == nil {
		g, n, _ := strings.Cut(key, "/")
		a = &nsgASG{src: typASG + " " + key, group: g, name: n, key: key}
		st.asgs[key] = a
	}
	return a
}

// bound holds every address a member of the ASG can have, as far as the
// snapshot shows: the subnets its members are in. Members are not named by
// their own addresses: what takes a member's place on the target is in the
// subnet's range, and may not keep its address. An ASG no member of is in
// the snapshot is bounded by the network and its peers.
func (st *nsgState) bound(key string, v *vnet) []netip.Prefix {
	var ps []netip.Prefix
	if a := st.asgs[key]; a != nil {
		for _, s := range a.sites {
			if s.sub != nil && s.sub.prefix.IsValid() {
				ps = append(ps, s.sub.prefix)
			}
		}
	}
	if len(ps) == 0 {
		return v.tagPrefixes()
	}
	return aggregate(ps)
}

// disjoint reports whether nothing in the snapshot is in both ASGs. One
// with no known member could hold anything.
func (st *nsgState) disjoint(x, y string) bool {
	a, b := st.asgs[x], st.asgs[y]
	if a == nil || b == nil || len(a.sites) == 0 || len(b.sites) == 0 {
		return false
	}
	for _, s := range a.sites {
		if s.maybe[y] {
			return false
		}
	}
	return true
}

func nsgASGKeys(v any) []string {
	var out []string
	for _, x := range list(v) {
		if k := azRefKey(x, typASG); k != "" {
			out = append(out, k)
		}
	}
	return out
}

func readASG(o snapshot.Object) *nsgASG {
	a := &nsgASG{src: source(o), group: o.Namespace(), name: o.Name(), key: strings.ToLower(o.Namespace() + "/" + o.Name()), inSnapshot: true}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag")
	a.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "resourceGuid")
	a.losses = append(top.rest(), p.rest()...)
	return a
}

// readNIC reads what of a network interface decides how its traffic is
// filtered. The interface itself is its machine's, and machines are not
// translated: its other settings are named once, not one by one.
func readNIC(o snapshot.Object) *nsgNIC {
	n := &nsgNIC{src: source(o), group: o.Namespace(), name: o.Name(), allFixed: true}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag", "tags", "extendedLocation", "kind", "managedBy")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "resourceGuid", "macAddress", "primary", "tapConfigurations", "hostedWorkloads", "dscpConfiguration",
		"vnetEncryptionSupported", "defaultOutboundConnectivityEnabled",
		// The machine's own: how its interface performs and resolves names.
		"dnsSettings", "enableAcceleratedNetworking", "disableTcpStateTracking", "workloadType", "nicType", "migrationPhase", "auxiliaryMode", "auxiliarySku", "privateLinkService")
	n.nsg = azRefKey(p.m["networkSecurityGroup"], typNSG)
	if len(obj(p.m["networkSecurityGroup"])) > 0 && n.nsg == "" {
		p.lose("networkSecurityGroup", "its network security group could not be read from the reference, so what filtered it is not written", true)
	}
	p.quiet("networkSecurityGroup")
	if id, _ := obj(p.m["virtualMachine"])["id"].(string); id != "" {
		n.vm = nsgRefName(id)
	}
	if id, _ := obj(p.m["privateEndpoint"])["id"].(string); id != "" {
		n.endpoint = nsgRefName(id)
	}
	p.quiet("virtualMachine", "privateEndpoint")
	if p.boolean("enableIPForwarding") {
		p.lose("enableIPForwarding", "it forwarded traffic for other addresses (a router or firewall appliance); what takes its place needs the target's own setting for that (source/destination check off on AWS, canIpForward on GCP)", false)
	}
	for _, x := range list(p.m["ipConfigurations"]) {
		m := obj(x)
		name, _ := m["name"].(string)
		ip := newProps(obj(m["properties"]), fmt.Sprintf("properties.ipConfigurations[%s].properties.", name))
		ip.quiet("provisioningState", "privateLinkConnectionProperties", "primary", "privateIPAddressPrefixLength",
			// What the machine is reached through is the machine's.
			"gatewayLoadBalancer", "virtualNetworkTaps", "applicationGatewayBackendAddressPools", "loadBalancerBackendAddressPools", "loadBalancerInboundNatRules")
		sn, _ := obj(ip.m["subnet"])["id"].(string)
		ip.quiet("subnet")
		if k := subnetKey(sn); k != "" {
			n.subnets = append(n.subnets, k)
		} else {
			ip.lose("subnet", "its subnet could not be read from the reference", false)
		}
		n.asgs = append(n.asgs, nsgASGKeys(ip.m["applicationSecurityGroups"]))
		if len(list(ip.m["applicationSecurityGroups"])) != len(n.asgs[len(n.asgs)-1]) {
			ip.lose("applicationSecurityGroups", "an application security group could not be read from its reference; rules that apply to its members are not written for this interface", false)
		}
		ip.quiet("applicationSecurityGroups")
		ver := ip.str("privateIPAddressVersion")
		addr, err := netip.ParseAddr(ip.str("privateIPAddress"))
		switch {
		case strings.EqualFold(ver, "IPv6"):
			ip.lose("privateIPAddressVersion", "IPv6 addresses are not translated", false)
		case strings.EqualFold(ip.str("privateIPAllocationMethod"), "Static") && err == nil && addr.Is4():
			n.fixed = append(n.fixed, netip.PrefixFrom(addr, 32))
		default:
			n.allFixed = false
		}
		if len(obj(ip.m["publicIPAddress"])) > 0 {
			ip.lose("publicIPAddress", "it had a public address; what takes its place has none unless one is given to it", false)
		}
		ip.quiet("publicIPAddress")
		n.losses = append(n.losses, ip.rest()...)
	}
	p.quiet("ipConfigurations")
	n.losses = append(append(top.rest(), p.rest()...), n.losses...)
	return n
}

// nsgRefName is the name a reference or resource ID ends in.
func nsgRefName(id string) string {
	if m := azRefRE.FindStringSubmatch(id); m != nil {
		return m[3]
	}
	parts := strings.Split(strings.TrimRight(id, "/"), "/")
	return parts[len(parts)-1]
}

// newNSGState links what was read: each interface, scale set and private
// endpoint to its subnet, its NSGs and its ASGs.
func newNSGState(vnets map[string]*vnet, nsgs map[string]*nsg, asgObjs, nicObjs []snapshot.Object, o *out) *nsgState {
	st := &nsgState{vnets: vnets, nsgs: nsgs, asgs: map[string]*nsgASG{}, endpoints: map[string]*nsgSite{}, placed: map[string][]*vnet{},
		carries: map[*nsgSite][]string{}, subnetGroup: map[string]string{}, markers: map[string]string{}}
	for _, obj := range asgObjs {
		a := readASG(obj)
		st.asgs[a.key] = a
	}
	// site makes a site in a subnet of the snapshot; nil when the subnet is
	// not in it.
	site := func(kind, src, name, subnet, nicNSG string, asgs [][]string) *nsgSite {
		sub := o.subnets[subnet]
		if sub == nil {
			return nil
		}
		s := &nsgSite{kind: kind, src: src, name: name, v: sub.vnet, sub: sub, member: map[string]bool{}, maybe: map[string]bool{}}
		if sub.prefix.IsValid() {
			s.applied = []netip.Prefix{sub.prefix}
		}
		s.subnetNSG, s.nicNSG = nsgs[sub.nsg], nsgs[nicNSG]
		count := map[string]int{}
		for _, l := range asgs {
			for _, a := range dedupe(l) {
				count[a]++
			}
		}
		for a, c := range count {
			s.maybe[a] = true
			if c == len(asgs) {
				s.member[a] = true
			}
			st.asg(a).sites = append(st.asg(a).sites, s)
		}
		st.sites = append(st.sites, s)
		return s
	}
	sort.Slice(nicObjs, func(i, j int) bool { return source(nicObjs[i]) < source(nicObjs[j]) })
	for _, obj := range nicObjs {
		n := readNIC(obj)
		e := Entry{Source: n.src, State: Mapped, Losses: n.losses}
		switch {
		case n.endpoint != "":
			e.Reason = "the interface of private endpoint " + n.endpoint + ": what filtered it is written with the endpoint"
		case len(n.subnets) == 0:
			e.State, e.Reason = Refused, "it names no subnet that can be read, so what filtered it cannot be placed"
		case len(dedupe(n.subnets)) > 1:
			e.State, e.Reason = Refused, "its IP configurations are in different subnets ("+strings.Join(dedupe(n.subnets), ", ")+"), which Azure does not allow"
		case o.subnets[n.subnets[0]] == nil:
			e.State, e.Reason = Refused, "its subnet "+n.subnets[0]+" is not a subnet of a network in the snapshot, so what filtered it cannot be placed"
		case n.nsg != "" && nsgs[n.nsg] == nil:
			e.State, e.Reason = Refused, "its network security group "+n.nsg+" is not in the snapshot, so nothing on the target filters it as it did"
		default:
			s := site("nic", n.src, n.name, n.subnets[0], n.nsg, n.asgs)
			s.owner = "nothing (it is attached to no machine)"
			if n.vm != "" {
				s.owner = "virtual machine " + n.vm
			}
			if n.allFixed && len(n.fixed) > 0 {
				s.applied = aggregate(n.fixed)
			}
			e.Reason = "an interface is its machine's, and machines are not translated: what filtered it is written, ready for what takes the place of " + s.owner + " (see attachments)"
		}
		o.entries = append(o.entries, e)
	}
	// Scale sets and private endpoints belong to other families (or to
	// none yet); only where they sit and what they are members of is read.
	for _, x := range o.src {
		switch strings.ToLower(x.Kind()) {
		case azVMSS:
			net := obj(obj(obj(spec(x)["properties"])["virtualMachineProfile"])["networkProfile"])
			for _, c := range list(net["networkInterfaceConfigurations"]) {
				cp := obj(obj(c)["properties"])
				cname, _ := obj(c)["name"].(string)
				var subnets []string
				var asgs [][]string
				for _, ipc := range list(cp["ipConfigurations"]) {
					ip := obj(obj(ipc)["properties"])
					sn, _ := obj(ip["subnet"])["id"].(string)
					subnets = append(subnets, subnetKey(sn))
					asgs = append(asgs, nsgASGKeys(ip["applicationSecurityGroups"]))
				}
				if len(dedupe(subnets)) != 1 {
					continue
				}
				if s := site("vmss", source(x)+" interface "+cname, x.Name()+"-"+cname, subnets[0], azRefKey(cp["networkSecurityGroup"], typNSG), asgs); s != nil {
					s.owner = "the instances of scale set " + x.Name()
				}
			}
		case azPE:
			p := obj(spec(x)["properties"])
			sn, _ := obj(p["subnet"])["id"].(string)
			s := site("endpoint", source(x), x.Name(), subnetKey(sn), "", [][]string{nsgASGKeys(p["applicationSecurityGroups"])})
			if s == nil {
				continue
			}
			s.owner = "private endpoint " + x.Name()
			// An NSG applies to a private endpoint only where its subnet
			// says so (learn.microsoft.com/azure/private-link/disable-private-endpoint-network-policy).
			if !s.sub.endpointNSG {
				s.subnetNSG = nil
			}
			var fixed []netip.Prefix
			for _, ipc := range list(p["ipConfigurations"]) {
				if a, err := netip.ParseAddr(fmt.Sprint(obj(obj(ipc)["properties"])["privateIPAddress"])); err == nil && a.Is4() {
					fixed = append(fixed, netip.PrefixFrom(a, 32))
				}
			}
			if len(fixed) > 0 {
				s.applied = aggregate(fixed)
			}
			st.endpoints[strings.ToLower(x.Namespace()+"/"+x.Name())] = s
		}
	}
	for _, a := range st.asgs {
		sort.SliceStable(a.sites, func(i, j int) bool { return a.sites[i].src < a.sites[j].src })
	}
	sort.SliceStable(st.sites, func(i, j int) bool { return st.sites[i].src < st.sites[j].src })
	return st
}

// place finds where an NSG no subnet uses is written: in the networks of
// the interfaces it is on, or the one the map names. An NSG says nothing
// of a network itself, so one attached to nothing is refused until the map
// names its network; "" when it is placed.
func (st *nsgState) place(n *nsg, written map[string]bool, m Map) string {
	refused := ""
	for _, s := range st.sites {
		if s.nicNSG != n || s.kind == "endpoint" {
			continue
		}
		if written[s.v.key] {
			return ""
		}
		refused = "its network " + s.v.src + " is refused"
	}
	if refused != "" {
		return refused
	}
	key := m.nsgNetwork(n.group + "/" + n.name)
	if key == "" {
		return "no subnet or network interface in the snapshot uses it, and an NSG names no network: the map says which network it is written in (network.nsgs, by group/nsg), or it is left out"
	}
	v := st.vnets[strings.ToLower(key)]
	switch {
	case v == nil:
		return "the map puts it in network " + key + " (network.nsgs), which is not in the snapshot"
	case !written[v.key]:
		return "the map puts it in network " + v.src + " (network.nsgs), which is refused"
	}
	st.placed[n.key] = []*vnet{v}
	n.losses = append(n.losses, Loss{Field: "properties", Why: "not attached to anything on the source either; written unattached in " + v.src + ", as the map says (network.nsgs)"})
	return ""
}

// subnetSites are the sites an NSG is written for by itself: its subnets
// in each network, or the network the map places it in.
func (st *nsgState) subnetSites(n *nsg) []*nsgSite {
	var out []*nsgSite
	for _, v := range n.vnets() {
		out = append(out, &nsgSite{kind: "subnet", src: n.src, name: n.name, v: v, subnetNSG: n, applied: n.subnetsIn(v)})
	}
	for _, v := range st.placed[n.key] {
		out = append(out, &nsgSite{kind: "unattached", src: n.src, name: n.name, v: v, subnetNSG: n, applied: v.prefixes})
	}
	return out
}

// selfASGs are the ASGs an NSG's rules name on their own side.
func nsgSelfASGs(ns ...*nsg) map[string]bool {
	out := map[string]bool{}
	for _, n := range ns {
		for _, r := range n.rules {
			for _, a := range r.self.asgs {
				out[a] = true
			}
		}
	}
	return out
}

// peerASGs are the ASGs an NSG's rules name as the peer.
func nsgPeerASGs(n *nsg) []string {
	var out []string
	for _, r := range n.rules {
		out = append(out, r.peer.asgs...)
	}
	return uniqueSorted(out)
}

// entry is the report entry already written for a source.
func (o *out) entry(src string) *Entry {
	for i := range o.entries {
		if o.entries[i].Source == src {
			return &o.entries[i]
		}
	}
	return nil
}

// nsgWrite is one security group (AWS) or one tag's rule set (GCP) to
// write: an NSG's own for its subnets, or what the NSGs on a path let
// through together for the interfaces that share it.
type nsgWrite struct {
	name   string
	key    string
	v      *vnet
	res    *nsgResult
	sites  []*nsgSite
	nsgs   []*nsg
	subnet bool
}

// plan decides which groups are written. name gives a group its name from
// its parts; pairsOnly leaves an interface with one NSG to the writer (GCP
// writes an NSG rule for rule, whatever it is on).
func (st *nsgState) plan(o *out, pairsOnly bool, name func(src string, parts ...string) string) []*nsgWrite {
	for {
		st.carries, st.subnetGroup = map[*nsgSite][]string{}, map[string]string{}
		groups, unfiltered, over := st.planOnce(o, pairsOnly, name)
		if over != nil {
			over.refuse = fmt.Sprintf("the interfaces it is on are in more than %d different sets of application security groups and other NSGs, each of which is a security group of its own: it is not written until they are fewer", nsgMaxGroups)
			continue
		}
		for _, s := range unfiltered {
			why := "a network security group on its path is refused, so nothing is written to filter what takes its place"
			if e := o.entry(s.src); e != nil {
				e.Losses = append(e.Losses, Loss{Field: "properties.networkSecurityGroup", Why: why, Widens: true})
			} else {
				o.require(s.src + ": " + why)
			}
		}
		return groups
	}
}

func (st *nsgState) planOnce(o *out, pairsOnly bool, name func(src string, parts ...string) string) (groups []*nsgWrite, unfiltered []*nsgSite, over *nsg) {
	names := map[string]string{}
	canon := map[string]string{}
	count := map[*nsg]int{}
	for _, n := range sortedNSGs(st.nsgs) {
		if n.refuse != "" {
			continue
		}
		sites := st.subnetSites(n)
		for _, s := range sites {
			gn := name(n.src, n.name)
			if len(sites) > 1 {
				gn = name(n.src+"@"+s.v.src, n.name, s.v.name)
			}
			g := &nsgWrite{name: gn, key: "subnet|" + n.key + "|" + s.v.key, v: s.v, res: st.result(s), sites: []*nsgSite{s}, nsgs: []*nsg{n}, subnet: true}
			groups = append(groups, g)
			names[gn] = g.key
			st.subnetGroup[n.key+"|"+s.v.key] = gn
			canon[n.key+"|"+s.v.key] = g.res.canon()
			count[n]++
		}
	}
	byKey := map[string]*nsgWrite{}
	for _, s := range st.sites {
		ns := s.nsgs()
		if s.kind == "endpoint" || len(ns) == 0 {
			continue
		}
		bad := false
		for _, n := range ns {
			bad = bad || n.refuse != ""
		}
		if bad {
			unfiltered = append(unfiltered, s)
			continue
		}
		if pairsOnly && len(ns) == 1 {
			continue
		}
		res := st.result(s)
		if own := ns[0].key + "|" + s.v.key; len(ns) == 1 && ns[0] == s.subnetNSG && canon[own] == res.canon() {
			// It is filtered as the rest of its subnet is.
			st.carries[s] = []string{st.subnetGroup[own]}
			continue
		}
		key := s.v.key
		var parts []string
		for _, n := range ns {
			key += "|" + n.key
			parts = append(parts, n.name)
		}
		self := nsgSelfASGs(ns...)
		var in []string
		for _, a := range s.asgs() {
			if self[a] && s.member[a] {
				in = append(in, st.asg(a).name)
			}
		}
		if len(in) > 0 {
			parts = append(append(parts, "as"), in...)
		}
		key += "|" + res.canon()
		g := byKey[key]
		if g == nil {
			gn := name("security group "+strings.Join(parts, "-"), parts...)
			if names[gn] != "" {
				gn = name("security group "+strings.Join(append(parts, s.name), "-"), append(parts, s.name)...)
			}
			if names[gn] != "" && o.err == nil {
				o.err = fmt.Errorf("%s: its security group would be named %s, as another is: name it in the map's names (security group %s)", s.src, gn, strings.Join(append(parts, s.name), "-"))
			}
			names[gn] = key
			g = &nsgWrite{name: gn, key: key, v: s.v, res: res, nsgs: ns}
			byKey[key] = g
			groups = append(groups, g)
			for _, n := range ns {
				if count[n]++; count[n] > nsgMaxGroups {
					return nil, nil, n
				}
			}
		}
		g.sites = append(g.sites, s)
		st.carries[s] = []string{g.name}
	}
	return groups, unfiltered, nil
}

// entries starts the report entry of each NSG that is written, and
// reports the refused ones.
func (st *nsgState) entries(o *out) map[string]*Entry {
	ents := map[string]*Entry{}
	for _, n := range sortedNSGs(st.nsgs) {
		if n.refuse != "" {
			o.entries = append(o.entries, Entry{Source: n.src, State: Refused, Reason: n.refuse})
			continue
		}
		ents[n.key] = &Entry{Source: n.src, State: Mapped, Losses: append([]Loss(nil), n.losses...)}
	}
	return ents
}

func (st *nsgState) flush(o *out, ents map[string]*Entry) {
	for _, k := range sortedMapKeys(ents) {
		e := ents[k]
		e.Losses = dedupeLosses(e.Losses)
		e.Targets = uniqueSorted(e.Targets)
		nsgSortEvidence(e.Evidence)
		o.entries = append(o.entries, *e)
	}
}

func nsgSortEvidence(ev []RuleEvidence) {
	sort.SliceStable(ev, func(i, j int) bool {
		a, b := ev[i], ev[j]
		switch {
		case a.Where != b.Where:
			return a.Where < b.Where
		case a.Direction != b.Direction:
			return a.Direction < b.Direction
		}
		return a.Priority < b.Priority
	})
}

// attach reports what a site carries on the target.
func (st *nsgState) attach(o *out, s *nsgSite, carries []string, attached, to string) {
	a := Attachment{Source: s.src, Carries: carries, Attached: attached, To: to}
	for _, n := range s.nsgs() {
		a.NSGs = append(a.NSGs, n.group+"/"+n.name)
	}
	for _, k := range s.asgs() {
		a.ASGs = append(a.ASGs, st.asgName(k))
	}
	o.attachments = append(o.attachments, a)
}
