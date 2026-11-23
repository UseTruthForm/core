package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Routing: where a subnet's traffic can go. Azure's route tables, NAT
// gateways, default outbound access and peerings are read into what each
// subnet's traffic does by destination (delivered in the network, to a
// peer, to the internet, or not at all), and the writers give the target
// subnet the same, or less where the target cannot say it. Objects are not
// copied one for one: an AWS route table and a GCP route do not mean what
// an Azure route table does.
//
// Azure picks a route by longest prefix, and among equal prefixes a
// user-defined route before a system one
// (learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview,
// "How Azure selects routes"). System routes are the network's own ranges
// (Virtual network), each peer's ranges (Virtual network peering) and
// 0.0.0.0/0 (Internet). Azure's own None routes for unused private ranges
// (10.0.0.0/8 and the like) are not modelled: an address in them is not
// reachable on the internet either.

const (
	azRouteTable   = "microsoft.network/routetables"
	azRoute        = azRouteTable + "/routes"
	azNAT          = "microsoft.network/natgateways"
	azPublicIP     = "microsoft.network/publicipaddresses"
	azPublicPrefix = "microsoft.network/publicipprefixes"

	typRouteTable   = "Microsoft.Network/routeTables"
	typNAT          = "Microsoft.Network/natGateways"
	typPublicIP     = "Microsoft.Network/publicIPAddresses"
	typPublicPrefix = "Microsoft.Network/publicIPPrefixes"

	// azNATIdleMinutes is a NAT gateway's TCP idle timeout where none is
	// set (learn.microsoft.com/azure/nat-gateway/nat-overview: "defaults to
	// 4 minutes"): the source's own behaviour, not a choice made here.
	azNATIdleMinutes  = 4
	azNATMaxAddresses = 16
)

func routingClaims(kind string) bool {
	for _, k := range []string{azRouteTable, azNAT, azPublicIP, azPublicPrefix} {
		if kind == k || strings.HasPrefix(kind, k+"/") {
			return true
		}
	}
	return false
}

// The kinds of next hop a destination can have.
const (
	hopLocal     = "vnetlocal"
	hopPeer      = "peering"
	hopInternet  = "internet"
	hopNone      = "none"
	hopAppliance = "virtualappliance"
	hopGateway   = "virtualnetworkgateway"
)

// routingUDR is one user-defined route.
type routingUDR struct {
	name   string
	prefix netip.Prefix
	tag    string // a service tag, where the destination is not a prefix
	hop    string
	ip     string
}

func (r routingUDR) String() string {
	dst := r.tag
	if r.prefix.IsValid() {
		dst = r.prefix.String()
	}
	switch r.hop {
	case hopAppliance:
		return fmt.Sprintf("route %s (%s to virtual appliance %s)", r.name, dst, r.ip)
	case hopGateway:
		return fmt.Sprintf("route %s (%s to the virtual network gateway)", r.name, dst)
	case hopNone:
		return fmt.Sprintf("route %s (%s dropped)", r.name, dst)
	case hopLocal:
		return fmt.Sprintf("route %s (%s kept in the network)", r.name, dst)
	}
	return fmt.Sprintf("route %s (%s to the internet)", r.name, dst)
}

type routingTable struct {
	src, key string
	routes   []routingUDR
	// noPeerRoutes is disablePeeringRoute All: its subnets do not use the
	// peerings' system routes.
	noPeerRoutes bool
	losses       []Loss
	subnets      []*subnet
	targets      []string
}

type routingNAT struct {
	src, group, name, key string
	ips, prefixes         []string // group/name of its public addresses and prefixes
	idle                  int      // minutes
	tags                  map[string]string
	losses                []Loss
	subnets               []*subnet
	addrs                 int // how many addresses it sends from
	refuse                string
	targets               []string
}

type routingPublic struct {
	src     string
	length  int // a prefix's length; 32 for an address
	losses  []Loss
	v6      bool
	nat     *routingNAT
	natSeen bool // it names a NAT gateway
}

type routingPeering struct {
	src, name    string
	local        string // its network, group/name, lower case
	remote       string // the peer, group/name, lower case; "" when not in the snapshot
	remoteID     string
	access       bool
	losses       []Loss
	refuse, idle string // refused, or carrying nothing, and why
	entered      bool   // an object of its own (not inline)
	targets      []string
	reason       string
}

type routing struct {
	tables   map[string]*routingTable
	nats     map[string]*routingNAT
	ips      map[string]*routingPublic
	prefixes map[string]*routingPublic
	peerings []*routingPeering
	routes   []snapshot.Object
	// subnetLosses are what each network's entry gains once its subnets'
	// routes are decided, by the network's source.
	subnetLosses map[string][]Loss
	netTargets   map[string][]string
	// live are the peerings that carry traffic on the target, as
	// "network|peer" by group/name.
	live map[string]bool
}

func newRouting() *routing {
	return &routing{tables: map[string]*routingTable{}, nats: map[string]*routingNAT{}, ips: map[string]*routingPublic{},
		prefixes: map[string]*routingPublic{}, subnetLosses: map[string][]Loss{}, netTargets: map[string][]string{}, live: map[string]bool{}}
}

func routingKey(o snapshot.Object) string { return strings.ToLower(o.Namespace() + "/" + o.Name()) }

// read takes an object the routing rules read; false when it is not one.
func (rt *routing) read(kind string, o snapshot.Object) bool {
	switch kind {
	case azRouteTable:
		rt.tables[routingKey(o)] = readRouteTable(o)
	case azRoute:
		rt.routes = append(rt.routes, o)
	case azNAT:
		rt.nats[routingKey(o)] = readNATGateway(o)
	case azPublicIP:
		rt.ips[routingKey(o)] = readPublicIP(o)
	case azPublicPrefix:
		rt.prefixes[routingKey(o)] = readPublicPrefix(o)
	case azPeering:
		parent, name, _ := strings.Cut(o.Name(), "/")
		p := readPeering(source(o), name, strings.ToLower(o.Namespace()+"/"+parent), spec(o), "")
		p.entered = true
		rt.peerings = append(rt.peerings, p)
	default:
		return false
	}
	return true
}

func readRouteTable(o snapshot.Object) *routingTable {
	t := &routingTable{src: source(o), key: routingKey(o)}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag")
	if len(stringTags(top.m["tags"])) > 0 {
		top.lose("tags", "a route table's routes are written into each subnet's own routes on the target; its tags are not carried over", false)
	}
	top.quiet("tags")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "resourceGuid", "subnets")
	// No gateway is translated, so no route is learned from one on the
	// target whichever way this is set.
	p.quiet("disableBgpRoutePropagation")
	switch d := p.str("disablePeeringRoute"); strings.ToLower(d) {
	case "", "none":
	case "all":
		t.noPeerRoutes = true
		p.lose("disablePeeringRoute", "All: its subnets did not use the peerings' routes, and are given none to the peers on the target", false)
	default:
		t.noPeerRoutes = true
		p.lose("disablePeeringRoute", d+" is not a value this reads; its subnets are given no routes to the peers", false)
	}
	for _, x := range list(p.m["routes"]) {
		m := obj(x)
		name, _ := m["name"].(string)
		r, ls := readUDR(name, m, fmt.Sprintf("properties.routes[%s].", name))
		t.add(r, ls)
	}
	p.quiet("routes")
	t.losses = append(append(top.rest(), p.rest()...), t.losses...)
	return t
}

func (t *routingTable) add(r *routingUDR, ls []Loss) {
	t.losses = append(t.losses, ls...)
	if r == nil {
		return
	}
	for _, x := range t.routes {
		if strings.EqualFold(x.name, r.name) {
			return
		}
	}
	t.routes = append(t.routes, *r)
}

// readUDR reads a route, inline or an object of its own. One whose next
// hop it cannot read makes no route, and that is named as widening: what
// the route kept from its destination is not known.
func readUDR(name string, m map[string]any, field string) (*routingUDR, []Loss) {
	top := newProps(m, field)
	top.quiet("name", "id", "properties", "type", "etag")
	p := newProps(obj(m["properties"]), field+"properties.")
	p.quiet("provisioningState", "hasBgpOverride")
	r := &routingUDR{name: name, ip: p.str("nextHopIpAddress")}
	switch h := strings.ToLower(p.str("nextHopType")); h {
	case hopLocal, hopInternet, hopNone, hopAppliance, hopGateway:
		r.hop = h
	case "virtualapplianceecmp":
		r.hop = hopAppliance
		var ips []string
		for _, x := range list(obj(p.m["nextHop"])["ipAddresses"]) {
			ips = append(ips, fmt.Sprint(x))
		}
		r.ip = strings.Join(ips, ", ")
	default:
		p.quiet("addressPrefix", "nextHop")
		return nil, append(append(top.rest(), p.rest()...), Loss{Field: field + "properties.nextHopType", Widens: true,
			Why: fmt.Sprintf("%q is not a next hop type this reads: the route is not carried over, and what it kept from its destination is not kept on the target", h)})
	}
	p.quiet("nextHop")
	a := p.str("addressPrefix")
	if pf, err := netip.ParsePrefix(a); err == nil {
		if !pf.Addr().Is4() {
			p.lose("addressPrefix", a+": IPv6 routes are not translated; the target network is IPv4 only", false)
			return nil, append(top.rest(), p.rest()...)
		}
		r.prefix = pf.Masked()
	} else {
		r.tag = a
	}
	return r, append(top.rest(), p.rest()...)
}

func readNATGateway(o snapshot.Object) *routingNAT {
	n := &routingNAT{src: source(o), group: o.Namespace(), name: o.Name(), key: routingKey(o), idle: azNATIdleMinutes}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag")
	n.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	if len(list(top.m["zones"])) > 0 {
		top.lose("zones", fmt.Sprintf("it was in zone %v; the target's NAT is in the zone of the map's egress subnet (AWS) or regional (GCP)", list(top.m["zones"])), false)
	}
	top.quiet("zones")
	if sku := obj(top.m["sku"]); strings.EqualFold(fmt.Sprint(sku["name"]), "StandardV2") {
		top.lose("sku", "StandardV2 is zone redundant; an AWS NAT gateway is in one availability zone (a Cloud NAT gateway is regional)", false)
	}
	top.quiet("sku")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "resourceGuid", "subnets")
	if m := p.integer("idleTimeoutInMinutes"); m != nil {
		n.idle = *m
	}
	for _, x := range list(p.m["publicIpAddresses"]) {
		if k := azRefKey(x, typPublicIP); k != "" {
			n.ips = append(n.ips, k)
		} else {
			n.ips = append(n.ips, "?"+fmt.Sprint(obj(x)["id"]))
		}
	}
	for _, x := range list(p.m["publicIpPrefixes"]) {
		if k := azRefKey(x, typPublicPrefix); k != "" {
			n.prefixes = append(n.prefixes, k)
		} else {
			n.prefixes = append(n.prefixes, "?"+fmt.Sprint(obj(x)["id"]))
		}
	}
	p.quiet("publicIpAddresses", "publicIpPrefixes")
	for _, k := range []string{"publicIpAddressesV6", "publicIpPrefixesV6"} {
		if len(list(p.m[k])) > 0 {
			p.lose(k, "IPv6 egress is not translated; the target network is IPv4 only", false)
		}
		p.quiet(k)
	}
	p.unlessDefault("nat64", "None", "NAT64 is not translated")
	for _, k := range []string{"serviceGateway", "sourceVirtualNetwork"} {
		if len(obj(p.m[k])) > 0 {
			p.lose(k, "has no equivalent here: the NAT serves the subnets that name it", false)
		}
		p.quiet(k)
	}
	n.losses = append(top.rest(), p.rest()...)
	return n
}

func readPublicIP(o snapshot.Object) *routingPublic {
	a := &routingPublic{src: source(o), length: 32}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag", "sku", "zones")
	if len(stringTags(top.m["tags"])) > 0 {
		top.lose("tags", "the target's address is a new one; the tags are not carried over", false)
	}
	top.quiet("tags")
	if el, _ := top.take("extendedLocation"); len(obj(el)) > 0 {
		top.lose("extendedLocation", "an edge zone has no equivalent here", false)
	}
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "resourceGuid", "ipConfiguration", "upgradedToV2", "publicIPAllocationMethod", "publicIPPrefix",
		"deleteOption", "migrationPhase", "linkedPublicIPAddress", "servicePublicIPAddress", "idleTimeoutInMinutes")
	a.v6 = strings.EqualFold(p.str("publicIPAddressVersion"), "IPv6")
	a.natSeen = len(obj(p.m["natGateway"])) > 0
	p.quiet("natGateway")
	if ip := p.str("ipAddress"); ip != "" {
		p.lose("ipAddress", ip+" is Azure's: the target sends from an address of its own", false)
	}
	if d := obj(p.m["dnsSettings"]); len(d) > 0 {
		p.lose("dnsSettings", fmt.Sprintf("its name in Azure's DNS (%v) is not carried over", d["domainNameLabel"]), false)
	}
	p.quiet("dnsSettings")
	if d := obj(p.m["ddosSettings"]); len(d) > 0 && !strings.EqualFold(fmt.Sprint(d["protectionMode"]), "Disabled") {
		p.lose("ddosSettings", "DDoS protection settings of the address are not carried over: the target has its own default protection", false)
	}
	p.quiet("ddosSettings")
	if len(list(p.m["ipTags"])) > 0 {
		p.lose("ipTags", "IP tags (routing preference and the like) have no equivalent here", false)
	}
	p.quiet("ipTags")
	a.losses = append(top.rest(), p.rest()...)
	return a
}

func readPublicPrefix(o snapshot.Object) *routingPublic {
	a := &routingPublic{src: source(o), length: 32}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag", "sku", "zones")
	if len(stringTags(top.m["tags"])) > 0 {
		top.lose("tags", "the target's addresses are new ones; the tags are not carried over", false)
	}
	top.quiet("tags")
	if el, _ := top.take("extendedLocation"); len(obj(el)) > 0 {
		top.lose("extendedLocation", "an edge zone has no equivalent here", false)
	}
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "resourceGuid", "ipPrefix", "loadBalancerFrontendIpConfiguration", "publicIPAddresses", "upgradedToV2")
	a.v6 = strings.EqualFold(p.str("publicIPAddressVersion"), "IPv6")
	a.natSeen = len(obj(p.m["natGateway"])) > 0
	p.quiet("natGateway")
	if l := p.integer("prefixLength"); l != nil && *l >= 0 && *l <= 32 {
		a.length = *l
	}
	if len(obj(p.m["customIPPrefix"])) > 0 {
		p.lose("customIPPrefix", "addresses the customer brought to Azure are not moved: the target sends from addresses of its own until they are brought there too", false)
	}
	p.quiet("customIPPrefix")
	if len(list(p.m["ipTags"])) > 0 {
		p.lose("ipTags", "IP tags have no equivalent here", false)
	}
	p.quiet("ipTags")
	a.losses = append(top.rest(), p.rest()...)
	return a
}

// readPeering reads one side of a peering.
func readPeering(src, name, local string, m map[string]any, field string) *routingPeering {
	pe := &routingPeering{src: src, name: name, local: local}
	top := newProps(m, field)
	top.quiet("name", "id", "properties", "type", "etag")
	p := newProps(obj(m["properties"]), field+"properties.")
	p.quiet("provisioningState", "resourceGuid", "remoteVirtualNetworkEncryption", "doNotVerifyRemoteGateways",
		"localAddressSpace", "localVirtualNetworkAddressSpace", "remoteAddressSpace", "remoteVirtualNetworkAddressSpace")
	pe.remoteID, _ = obj(p.m["remoteVirtualNetwork"])["id"].(string)
	// A capture writes a reference to what it holds as a token; an ID left
	// as it was names a network outside the snapshot.
	if azRefRE.MatchString(pe.remoteID) {
		pe.remote = azRefKey(p.m["remoteVirtualNetwork"], typVNet)
	}
	p.quiet("remoteVirtualNetwork")
	// Unset, Azure allows access (the portal's and the API's default).
	pe.access = true
	if v, ok := p.take("allowVirtualNetworkAccess"); ok && v == false {
		pe.access = false
	}
	if st := p.str("peeringState"); st != "" && !strings.EqualFold(st, "Connected") {
		pe.idle = "its state is " + st + ": it carried no traffic, so nothing is written for it"
	}
	if lv := p.str("peeringSyncLevel"); lv != "" && !strings.EqualFold(lv, "FullyInSync") {
		pe.refuse = "its address ranges are not in sync with the peer's (peeringSyncLevel " + lv + "): which ranges it carried is not known here; sync the peering in Azure and capture again"
	}
	if v, ok := p.take("peerCompleteVnets"); ok && v == false {
		pe.refuse = "it peers only some subnets (peerCompleteVnets false), which is not translated yet: a peering written here would join the whole networks"
	}
	p.quiet("localSubnetNames", "remoteSubnetNames")
	if p.boolean("enableOnlyIPv6Peering") {
		pe.refuse = "it carries IPv6 only, which is not translated: the target network is IPv4 only"
	}
	if p.boolean("allowForwardedTraffic") {
		p.lose("allowForwardedTraffic", "it accepted traffic the peer forwarded from elsewhere (an appliance or gateway in a hub); a peering on the target carries only traffic between the two networks' own ranges, so nothing reaches this network through the peer from a third (AWS: a transit gateway; GCP: Network Connectivity Center; neither is translated)", false)
	}
	if p.boolean("allowGatewayTransit") {
		p.lose("allowGatewayTransit", "the peer could use this network's gateway to reach on-premises; no gateway is translated, and a peering on the target gives no transit through one", false)
	}
	if p.boolean("useRemoteGateways") {
		p.lose("useRemoteGateways", "this network reached on-premises through the peer's gateway; no gateway is translated, and a peering on the target gives no transit through one", false)
	}
	if len(obj(p.m["remoteBgpCommunities"])) > 0 {
		p.lose("remoteBgpCommunities", "BGP communities for ExpressRoute have no equivalent here", false)
	}
	p.quiet("remoteBgpCommunities")
	pe.losses = append(top.rest(), p.rest()...)
	return pe
}

// refuseAll refuses everything read, where no network is written.
func (rt *routing) refuseAll(why string, o *out) {
	for _, s := range rt.sources() {
		o.entries = append(o.entries, Entry{Source: s, State: Refused, Reason: why})
	}
}

// sources names every object read, in order.
func (rt *routing) sources() []string {
	var out []string
	for _, t := range rt.tables {
		out = append(out, t.src)
	}
	for _, n := range rt.nats {
		out = append(out, n.src)
	}
	for _, a := range rt.ips {
		out = append(out, a.src)
	}
	for _, a := range rt.prefixes {
		out = append(out, a.src)
	}
	for _, p := range rt.peerings {
		if p.entered {
			out = append(out, p.src)
		}
	}
	for _, r := range rt.routes {
		out = append(out, source(r))
	}
	sort.Strings(out)
	return out
}

// link joins what was read: routes to their tables, tables and NAT
// gateways to the subnets that name them, addresses to their NAT gateways,
// and the two sides of each peering. It decides which peerings carry
// traffic, which the networks' security rules then read (tagPrefixes).
func (rt *routing) link(vnets map[string]*vnet, o *out) {
	for _, r := range rt.routes {
		parent, name, _ := strings.Cut(r.Name(), "/")
		t := rt.tables[strings.ToLower(r.Namespace()+"/"+parent)]
		if t == nil {
			o.entries = append(o.entries, Entry{Source: source(r), State: Refused, Reason: "its route table is not in the snapshot"})
			continue
		}
		u, ls := readUDR(name, spec(r), "")
		t.add(u, prefixed(ls, "routes/"+name+": "))
		o.entries = append(o.entries, Entry{Source: source(r), State: Mapped, Reason: "read with its route table " + t.src})
	}
	rt.routes = nil
	for _, v := range sortedVNets(vnets) {
		for _, m := range v.inlinePeerings {
			name, _ := m["name"].(string)
			dup := false
			for _, p := range rt.peerings {
				dup = dup || (p.local == v.key && strings.EqualFold(p.name, name))
			}
			if !dup {
				p := readPeering(v.src, name, v.key, m, fmt.Sprintf("properties.virtualNetworkPeerings[%s].", name))
				rt.peerings = append(rt.peerings, p)
			}
		}
		for _, s := range v.subnets {
			if t := rt.tables[s.routeTable]; t != nil {
				t.subnets = append(t.subnets, s)
			}
			if n := rt.nats[s.nat]; n != nil {
				n.subnets = append(n.subnets, s)
			}
		}
	}
	for _, n := range sortedMapKeys(rt.nats) {
		rt.countAddresses(rt.nats[n])
	}
	sort.Slice(rt.peerings, func(i, j int) bool {
		return rt.peerings[i].src+"/"+rt.peerings[i].name < rt.peerings[j].src+"/"+rt.peerings[j].name
	})
	for _, p := range rt.peerings {
		a, b := vnets[p.local], vnets[p.remote]
		switch {
		case p.refuse != "":
		case a == nil:
			p.refuse = "its virtual network is not in the snapshot"
		case b == nil:
			p.refuse = fmt.Sprintf("it peers with %s, which is not in the snapshot (a network in another subscription, or one the capture left out): the target network would not reach it. A peering to a network that is not translated is not written (a map entry naming an existing VPC or network on the target for it does not exist yet)", orDefault(p.remoteID, "a network it does not name"))
		case prefixesOverlap(a.prefixes, b.prefixes):
			p.refuse = fmt.Sprintf("its networks' ranges overlap (%v and %v): neither target peers networks whose ranges overlap", a.prefixes, b.prefixes)
		case p.idle != "":
		case rt.reverse(p) == nil:
			p.idle = "its peer " + b.src + " has no peering back to this network: Azure carries traffic only when both sides exist, so nothing is written for it"
		}
	}
	for _, p := range rt.peerings {
		if p.refuse != "" || p.idle != "" {
			continue
		}
		back := rt.reverse(p)
		switch {
		case back.refuse != "":
			p.refuse = "the other side of it, " + back.src + ", is refused: " + back.refuse
		case back.idle != "":
			p.idle = "the other side of it, " + back.src + ", carried no traffic"
		case !p.access || !back.access:
			// Narrower: rules that named the peer's ranges themselves may
			// have let some traffic through on Azure.
			p.idle = "access between the two networks is not allowed (allowVirtualNetworkAccess false on a side): no peering is written, and the networks do not reach each other"
		}
	}
	for _, p := range rt.peerings {
		if p.active() {
			vnets[p.local].peers = append(vnets[p.local].peers, vnets[p.remote])
		}
	}
}

func (p *routingPeering) active() bool { return p.refuse == "" && p.idle == "" }

// reverse is the peering from p's peer back to p's network.
func (rt *routing) reverse(p *routingPeering) *routingPeering {
	for _, q := range rt.peerings {
		if q != p && q.local == p.remote && q.remote == p.local {
			return q
		}
	}
	return nil
}

// countAddresses works out how many addresses a NAT gateway sends from,
// and marks the addresses it uses.
func (rt *routing) countAddresses(n *routingNAT) {
	for _, k := range n.ips {
		a := rt.ips[k]
		switch {
		case a == nil:
			n.addrs++
			n.losses = append(n.losses, Loss{Field: "properties.publicIpAddresses", Why: "a public address it names is not in the snapshot; it is counted as one IPv4 address"})
		case a.v6:
			a.nat = n
		default:
			a.nat = n
			n.addrs++
		}
	}
	for _, k := range n.prefixes {
		a := rt.prefixes[k]
		switch {
		case a == nil:
			n.addrs++
			n.losses = append(n.losses, Loss{Field: "properties.publicIpPrefixes", Why: "a public prefix it names is not in the snapshot; it is counted as one address"})
		case a.v6:
			a.nat = n
		default:
			a.nat = n
			n.addrs += 1 << (32 - a.length)
		}
	}
	// learn.microsoft.com/azure/nat-gateway/nat-overview: "A Standard NAT
	// gateway resource can use up to 16 IPv4 public IP addresses."
	if n.addrs > azNATMaxAddresses {
		n.addrs = azNATMaxAddresses
	}
	if n.addrs == 0 {
		n.refuse = "it has no public IPv4 address, so nothing left through it: its subnets are given no internet egress"
	}
}

// routingReach is what a subnet's traffic does in Azure, by destination.
// The sets do not overlap, and together they are every IPv4 address.
type routingReach struct {
	local    []netip.Prefix
	internet []netip.Prefix
	peers    map[string][]netip.Prefix // by the peer's group/name
	blocked  []routingBlocked
	tagged   []routingUDR // routes to a service tag, which has no addresses here
}

// routingBlocked is a set of destinations a user-defined route keeps from
// going where the system routes would send them.
type routingBlocked struct {
	ps  []netip.Prefix
	udr routingUDR
}

// reach works out a subnet's effective routes: longest prefix first, a
// user-defined route before a system one of the same prefix.
func (rt *routing) reach(s *subnet) routingReach {
	type route struct {
		prefix netip.Prefix
		hop    string
		peer   string
		udr    *routingUDR
	}
	var routes []route
	t := rt.tables[s.routeTable]
	if t != nil {
		for i := range t.routes {
			if u := &t.routes[i]; u.prefix.IsValid() {
				routes = append(routes, route{prefix: u.prefix, hop: u.hop, udr: u})
			}
		}
	}
	for _, p := range s.vnet.prefixes {
		routes = append(routes, route{prefix: p, hop: hopLocal})
	}
	if t == nil || !t.noPeerRoutes {
		for _, pv := range s.vnet.peers {
			if !rt.live[s.vnet.key+"|"+pv.key] {
				continue
			}
			for _, p := range pv.prefixes {
				routes = append(routes, route{prefix: p, hop: hopPeer, peer: pv.key})
			}
		}
	}
	routes = append(routes, route{prefix: anyV4, hop: hopInternet})
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].prefix.Bits() != routes[j].prefix.Bits() {
			return routes[i].prefix.Bits() > routes[j].prefix.Bits()
		}
		return routes[i].udr != nil && routes[j].udr == nil
	})
	r := routingReach{peers: map[string][]netip.Prefix{}}
	var covered []netip.Prefix
	for _, x := range routes {
		region := prefixMinus([]netip.Prefix{x.prefix}, covered)
		covered = append(covered, x.prefix)
		if len(region) == 0 {
			continue
		}
		switch x.hop {
		case hopLocal:
			// Kept in the network: outside its ranges there is nothing to
			// deliver to.
			in := routingIntersect(region, s.vnet.prefixes)
			r.local = append(r.local, in...)
			if out := prefixMinus(region, s.vnet.prefixes); len(out) > 0 && x.udr != nil {
				r.blocked = append(r.blocked, routingBlocked{ps: out, udr: *x.udr})
			}
		case hopPeer:
			r.peers[x.peer] = append(r.peers[x.peer], region...)
		case hopInternet:
			r.internet = append(r.internet, region...)
		default:
			r.blocked = append(r.blocked, routingBlocked{ps: region, udr: *x.udr})
		}
	}
	if t != nil {
		for _, u := range t.routes {
			if !u.prefix.IsValid() {
				r.tagged = append(r.tagged, u)
			}
		}
	}
	r.local, r.internet = aggregate(r.local), aggregate(r.internet)
	for k := range r.peers {
		r.peers[k] = aggregate(r.peers[k])
	}
	return r
}

// blockedAll is every destination the subnet's routes block.
func (r routingReach) blockedAll() []netip.Prefix {
	var ps []netip.Prefix
	for _, b := range r.blocked {
		ps = append(ps, b.ps...)
	}
	return aggregate(ps)
}

func routingIntersect(a, b []netip.Prefix) []netip.Prefix {
	return prefixMinus(a, prefixMinus(a, b))
}

// routingEgress is how a subnet's traffic to the internet leaves.
type routingEgress struct {
	nat     *routingNAT // its NAT gateway
	implied bool        // Azure's default outbound access, which the map made a NAT
}

func (e routingEgress) any() bool { return e.nat != nil || e.implied }

// routingPlan is what one subnet is given on the target.
type routingPlan struct {
	s      *subnet
	reach  routingReach
	egress routingEgress
	losses []Loss
}

func (p *routingPlan) lose(k, why string, widens bool) {
	p.losses = append(p.losses, Loss{Field: p.s.field + "properties." + k, Why: why, Widens: widens})
}

// plan decides a subnet's egress as Azure does. A user-defined route for
// the internet's addresses to an appliance or gateway comes before a NAT
// gateway, which comes before default outbound access
// (learn.microsoft.com/azure/nat-gateway/nat-overview: "UDR to next hop
// virtual appliance or virtual network gateway >> NAT gateway >> ... >>
// default system route to the internet"), so a subnet whose routes leave
// no destination on the internet route is given no NAT, whatever it names.
func (rt *routing) plan(s *subnet, o *out) *routingPlan {
	p := &routingPlan{s: s, reach: rt.reach(s)}
	if s.routeTable != "" && rt.tables[s.routeTable] == nil {
		p.lose("routeTable", "its route table is not in the snapshot: if it sent traffic through a firewall appliance or dropped it, the target does not", true)
	}
	nat := rt.nats[s.nat]
	direct := len(p.reach.internet) > 0
	switch {
	case s.nat != "" && nat == nil:
		p.lose("natGateway", "its NAT gateway is not in the snapshot; the target subnet has no internet egress", false)
	case nat != nil && nat.refuse != "":
		p.lose("natGateway", "its NAT gateway "+nat.src+" is not translated; the target subnet has no internet egress", false)
	case nat != nil && !direct:
		p.lose("natGateway", "its route table sends every destination elsewhere, which comes before its NAT gateway on Azure too: the subnet is given no route to the target's NAT", false)
	case nat != nil:
		p.egress.nat = nat
	case s.outbound == "false" || !direct:
	case o.m.Network != nil && o.m.Network.DefaultOutbound == "nat":
		p.egress.implied = true
	case s.outbound == "true":
		p.lose("defaultOutboundAccess", "it reached the internet through Azure's default outbound access; on the target it has no internet egress unless the map makes that a NAT (network.defaultOutbound: nat), which is billed", false)
	default:
		// Unset is Azure's older default, which allows it ("null, which
		// implicitly allows outbound access",
		// learn.microsoft.com/azure/virtual-network/ip-services/default-outbound-access).
		p.lose("defaultOutboundAccess", "it is not set, which on Azure leaves default outbound access on: its machines reached the internet with no address of their own. On the target the subnet has no internet egress unless the map makes that a NAT (network.defaultOutbound: nat), which is billed", false)
	}
	return p
}

// entries reports what was read, once the writers are done.
func (rt *routing) entries(o *out) {
	for _, k := range sortedMapKeys(rt.tables) {
		t := rt.tables[k]
		e := Entry{Source: t.src, State: Mapped, Losses: dedupeLosses(t.losses), Targets: uniqueSorted(t.targets)}
		if len(t.subnets) == 0 {
			e = Entry{Source: t.src, State: Refused, Reason: "no subnet in the snapshot uses it, so there is no subnet to give its routes to"}
		} else if len(e.Targets) == 0 {
			e.Reason = "its routes are read into what each subnet that uses it can reach: see the subnets' routeTable on their network"
		}
		o.entries = append(o.entries, e)
	}
	for _, k := range sortedMapKeys(rt.nats) {
		n := rt.nats[k]
		switch {
		case n.refuse == "" && len(n.subnets) == 0:
			n.refuse = "no subnet in the snapshot uses it, so there is no network to put it in"
		case n.refuse == "" && len(n.targets) == 0:
			n.refuse = "none of its subnets is given a route to it: their networks are refused, or their route tables send every destination elsewhere"
		}
		if n.refuse != "" {
			o.entries = append(o.entries, Entry{Source: n.src, State: Refused, Reason: n.refuse})
			continue
		}
		o.entries = append(o.entries, Entry{Source: n.src, State: Mapped, Losses: n.losses, Targets: uniqueSorted(n.targets)})
		o.require(fmt.Sprintf("Traffic that left through NAT gateway %s now leaves from the target's own addresses: whoever allows the old ones by address (a partner's firewall, an allowlist) must be given the new ones", n.name))
	}
	public := func(m map[string]*routingPublic, what string) {
		for _, k := range sortedMapKeys(m) {
			a := m[k]
			switch {
			case a.nat == nil && a.natSeen:
				o.entries = append(o.entries, Entry{Source: a.src, State: Refused, Reason: "the NAT gateway it belongs to is not in the snapshot"})
			case a.nat == nil:
				o.entries = append(o.entries, Entry{Source: a.src, State: NotLooked, Reason: "no descriptor yet for a public " + what + " that no NAT gateway in the snapshot uses (one of a load balancer, a gateway or a machine)"})
			case a.nat.refuse != "":
				o.entries = append(o.entries, Entry{Source: a.src, State: Refused, Reason: "its NAT gateway " + a.nat.src + " is refused"})
			case a.v6:
				o.entries = append(o.entries, Entry{Source: a.src, State: Mapped, Reason: "read with its NAT gateway " + a.nat.src,
					Losses: append(a.losses, Loss{Field: "properties.publicIPAddressVersion", Why: "IPv6 egress is not translated; the target network is IPv4 only"})})
			default:
				o.entries = append(o.entries, Entry{Source: a.src, State: Mapped, Losses: a.losses,
					Reason: "read with its NAT gateway " + a.nat.src + ": the target's NAT sends from as many addresses of its own"})
			}
		}
	}
	public(rt.ips, "address")
	public(rt.prefixes, "prefix")
	for _, p := range rt.peerings {
		if !p.entered {
			continue
		}
		e := Entry{Source: p.src, State: Mapped, Losses: p.losses, Targets: uniqueSorted(p.targets), Reason: p.reason}
		switch {
		case p.refuse != "":
			e = Entry{Source: p.src, State: Refused, Reason: p.refuse}
		case p.idle != "":
			e.Reason = p.idle
		}
		o.entries = append(o.entries, e)
	}
}

// write gives each written network's subnets their routes, and reports
// everything read.
func (rt *routing) write(vnets map[string]*vnet, written map[string]bool, o *out) {
	for _, p := range rt.peerings {
		if p.active() && (!written[p.local] || !written[p.remote]) {
			p.refuse = "one of its networks is refused, so there is nothing to peer"
		}
		if p.active() {
			rt.live[p.local+"|"+p.remote] = true
		}
	}
	for _, v := range sortedVNets(vnets) {
		// A peering a network held inline is reported with the network.
		for _, p := range rt.peerings {
			if p.entered || p.local != v.key {
				continue
			}
			switch {
			case p.refuse != "":
				rt.subnetLosses[v.src] = append(rt.subnetLosses[v.src], Loss{Field: "properties.virtualNetworkPeerings[" + p.name + "]", Why: "not translated: " + p.refuse})
			case p.idle != "":
				rt.subnetLosses[v.src] = append(rt.subnetLosses[v.src], Loss{Field: "properties.virtualNetworkPeerings[" + p.name + "]", Why: p.idle})
			}
			rt.subnetLosses[v.src] = append(rt.subnetLosses[v.src], p.losses...)
		}
		if !written[v.key] {
			continue
		}
		var plans []*routingPlan
		for _, s := range v.subnets {
			plans = append(plans, rt.plan(s, o))
		}
		switch o.m.To {
		case "aws":
			rt.aws(v, plans, o)
		case "gcp":
			rt.gcp(v, plans, o)
		}
		for _, p := range plans {
			rt.subnetLosses[v.src] = append(rt.subnetLosses[v.src], p.losses...)
		}
	}
	switch o.m.To {
	case "aws":
		rt.awsPeerings(vnets, o)
	case "gcp":
		rt.gcpPeerings(vnets, o)
	}
	for i := range o.entries {
		if ls := rt.subnetLosses[o.entries[i].Source]; len(ls) > 0 && o.entries[i].State != Refused {
			o.entries[i].Losses = append(o.entries[i].Losses, dedupeLosses(ls)...)
			delete(rt.subnetLosses, o.entries[i].Source)
		}
		if ts := rt.netTargets[o.entries[i].Source]; len(ts) > 0 {
			o.entries[i].Targets = append(o.entries[i].Targets, ts...)
			delete(rt.netTargets, o.entries[i].Source)
		}
	}
	rt.entries(o)
}

// blockedLosses names, for one subnet, what its user-defined routes come
// to on the target. local says what the target does with a destination in
// the network's own ranges that a route kept from being delivered there.
func (p *routingPlan) blockedLosses(v *vnet, how map[string]string, localWidens bool, localWhy string) {
	for _, b := range p.reach.blocked {
		inside := routingIntersect(b.ps, v.prefixes)
		outside := prefixMinus(b.ps, v.prefixes)
		if len(inside) > 0 && localWhy != "" {
			p.lose("routeTable", fmt.Sprintf("%s covers %s of the network's own range; %s", b.udr, routingList(inside), localWhy), localWidens)
		}
		if len(outside) > 0 && how[b.udr.hop] != "" {
			p.lose("routeTable", fmt.Sprintf("%s: %s", b.udr, how[b.udr.hop]), false)
		}
	}
	for _, u := range p.reach.tagged {
		// A service tag has no addresses here, so its traffic follows the
		// subnet's other routes. That is wider only where the route kept
		// it from the internet and the subnet reaches the internet.
		kept := u.hop != hopInternet && u.hop != hopLocal
		wider := kept && p.egress.any()
		why := "its traffic follows the subnet's other routes"
		if wider {
			why = "its traffic leaves with the rest of the subnet's internet traffic, where the route sent it elsewhere or dropped it"
		}
		p.lose("routeTable", fmt.Sprintf("%s names a service tag, which has no addresses here: %s", u, why), wider)
	}
}

func routingList(ps []netip.Prefix) string {
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	if len(s) > 4 {
		s = append(s[:4], fmt.Sprintf("and %d more", len(s)-4))
	}
	return strings.Join(s, ", ")
}
