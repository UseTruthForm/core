package translate

import (
	"fmt"
	"net/netip"
	"strings"
)

// Routing on GCP. Routes belong to a network, not a subnet, and a network
// has a default route to the internet from the start ("When you create a
// VPC network, Google Cloud adds a system-generated IPv4 default route",
// docs.cloud.google.com/vpc/docs/routes). What decides whether a subnet's
// machines reach the internet is Cloud NAT, which is set per subnetwork: so
// a subnet Azure gave egress is listed in a Cloud NAT gateway, and one it
// did not is not.
//
// A static route cannot drop, cannot override a subnet's own route, and
// takes only a machine, a load balancer, a tunnel or the internet gateway
// as its next hop (docs.cloud.google.com/vpc/docs/static-routes). So what
// an Azure route kept from its destination (dropped, or sent to an
// appliance or gateway that is not translated) is kept from it by an
// egress deny firewall rule for the subnet's range, above every rule
// written from an NSG: the traffic goes nowhere, where a missing route
// would have let it follow the network's default route.

const (
	gcpRouter  = "compute.googleapis.com/Router"
	gcpAddress = "compute.googleapis.com/Address"
	gcpRoute   = "compute.googleapis.com/Route"

	// gcpRoutePriority comes before any rule written from an NSG, whose
	// priorities start at 100: a route decides before a security rule does.
	gcpRoutePriority = 50
	gcpMaxRanges     = 256 // ranges in one firewall rule
)

// gcpGoogleAPIs are private.googleapis.com and restricted.googleapis.com,
// the addresses Private Google Access can be pointed at
// (docs.cloud.google.com/vpc/docs/configure-private-google-access).
var gcpGoogleAPIs = []netip.Prefix{netip.MustParsePrefix("199.36.153.8/30"), netip.MustParsePrefix("199.36.153.4/30")}

func (rt *routing) gcp(v *vnet, plans []*routingPlan, o *out) {
	d := gcpNet{o.m}
	net := d.netName(v)
	region := gcpProject + "/regions/" + o.m.Region
	add := func(t string) { rt.netTargets[v.src] = append(rt.netTargets[v.src], t) }
	sub := func(s *subnet) *netSub { return o.netSubs[strings.ToLower(v.group+"/"+v.name+"/"+s.name)] }

	// One Cloud NAT gateway per Azure NAT gateway, and one for default
	// outbound access, all on one Cloud Router: a subnet's range is in one
	// gateway only.
	var nats []any
	var order []*routingNAT
	members := map[*routingNAT][]any{}
	var implied []any
	for _, p := range plans {
		if !p.egress.any() {
			continue
		}
		m := map[string]any{"name": computeBase + sub(p.s).subnetwork, "sourceIpRangesToNat": []any{"ALL_IP_RANGES"}}
		if n := p.egress.nat; n != nil {
			if members[n] == nil {
				order = append(order, n)
			}
			members[n] = append(members[n], m)
		} else {
			implied = append(implied, m)
		}
	}
	router := gcpName(net, "nat")
	for _, n := range order {
		name := o.m.name(n.src, gcpName(n.name))
		var ips []any
		for i := 1; i <= n.addrs; i++ {
			an := gcpName(name, fmt.Sprint(i))
			n.targets = append(n.targets, o.add("gcp", n.src, computeObject(gcpAddress, "Address", "addresses", region, an, map[string]any{"addressType": "EXTERNAL"})))
			ips = append(ips, computeBase+region+"/addresses/"+an)
		}
		nats = append(nats, map[string]any{
			"name": name, "sourceSubnetworkIpRangesToNat": "LIST_OF_SUBNETWORKS", "subnetworks": members[n],
			"natIpAllocateOption": "MANUAL_ONLY", "natIps": ips, "tcpEstablishedIdleTimeoutSec": n.idle * 60,
		})
		n.losses = append(n.losses, tagLosses(n.tags, "a Cloud NAT gateway")...)
		n.targets = append(n.targets, gcpRouter+" "+region+"/routers/"+router)
	}
	if len(implied) > 0 {
		// Azure's default outbound access has no fixed address; nor has a
		// gateway whose addresses Google allocates.
		nats = append(nats, map[string]any{
			"name": awsDefaultOutboundID, "sourceSubnetworkIpRangesToNat": "LIST_OF_SUBNETWORKS", "subnetworks": implied,
			"natIpAllocateOption": "AUTO_ONLY",
		})
		o.require(fmt.Sprintf("Cloud NAT gateway %s on router %s stands for Azure's default outbound access in network %s, as the map chose (network.defaultOutbound): it is billed by the hour and the gigabyte", awsDefaultOutboundID, router, v.group+"/"+v.name))
	}
	if len(nats) > 0 {
		add(o.add("gcp", v.src, computeObject(gcpRouter, "Router", "routers", region, router, map[string]any{"network": d.netURL(v), "nats": nats})))
		// Cloud NAT applies only to packets on a route to the default
		// internet gateway ("Public NAT relies on local static routes whose
		// next hops are the default internet gateway",
		// docs.cloud.google.com/nat/docs/public-nat). The network's own
		// default route can be removed; this one says what the NAT needs.
		add(o.add("gcp", v.src, computeObject(gcpRoute, "Route", "routes", gcpProject+"/global", gcpName(net, "internet"), map[string]any{
			"network": d.netURL(v), "destRange": anyV4.String(), "priority": 1000,
			"nextHopGateway": computeBase + gcpProject + "/global/gateways/default-internet-gateway",
		})))
		o.require("Cloud NAT serves machines with no external address; one given an external address leaves by it instead (docs.cloud.google.com/nat/docs/public-nat), as a machine with a public IP did on Azure only where no NAT gateway or route came first")
	}

	for _, p := range plans {
		s := p.s
		name := gcpName(net, s.name, "no-route")
		inspected := false
		for _, b := range p.reach.blocked {
			inspected = inspected || b.udr.hop == hopAppliance || b.udr.hop == hopGateway
		}
		p.blockedLosses(v, map[string]string{
			hopAppliance: "the appliance is a machine, which is not translated, and a GCP route's next hop must be one in the network: egress deny rule " + name + " keeps these destinations off the network's default route, so that traffic goes nowhere until a route through an inspection appliance on the target is added",
			hopGateway:   "no gateway is translated: egress deny rule " + name + " keeps these destinations off the network's default route, so that traffic goes nowhere",
		}, false, "a subnet's own route cannot be overridden on GCP, so egress deny rule "+name+" drops that traffic, where Azure dropped it or sent it through the appliance")
		dst := p.reach.blockedAll()
		if len(dst) == 0 {
			continue
		}
		if inspected {
			// Private Google Access leaves by the default internet gateway
			// too. Its two fixed ranges are left open, so that a subnet
			// behind a firewall still reaches the services its network has
			// private access to; Google's public ranges are not.
			if open := routingIntersect(gcpGoogleAPIs, dst); len(open) > 0 {
				dst = prefixMinus(dst, gcpGoogleAPIs)
				p.lose("routeTable", fmt.Sprintf("egress deny rule %s leaves %s open (private.googleapis.com and restricted.googleapis.com): Private Google Access reaches Google's APIs through them, and they are not on the internet", name, routingList(gcpGoogleAPIs)), false)
				o.require(fmt.Sprintf("Subnetwork %s sent its traffic through a firewall on Azure, and reaches nothing outside its network on GCP but %s: where its network has Private Google Access, point googleapis.com at private.googleapis.com in a private DNS zone (not translated) for its machines to reach Google's APIs", gcpName(v.name, s.name), routingList(gcpGoogleAPIs)))
			}
		}
		t := rt.tables[s.routeTable]
		for i := 0; len(dst) > 0; i++ {
			n := min(len(dst), gcpMaxRanges)
			rule := name
			if i > 0 {
				rule = gcpName(name, fmt.Sprint(i+1))
			}
			target := o.add("gcp", v.src, computeObject(gcpFirewall, "Firewall", "firewalls", gcpProject+"/global", rule, map[string]any{
				"network": d.netURL(v), "direction": "EGRESS", "priority": gcpRoutePriority,
				"sourceRanges": prefixStrings([]netip.Prefix{s.prefix}), "destinationRanges": prefixStrings(dst[:n]),
				"denied": []any{map[string]any{"IPProtocol": "all"}},
			}))
			dst = dst[n:]
			if t != nil {
				t.targets = append(t.targets, target)
			} else {
				add(target)
			}
		}
	}
}

// gcpPeerings refuses each peering Azure carried traffic over. GCP makes
// one with networks.addPeering on each network: a method, not a resource
// (a network's peerings are "Output only",
// docs.cloud.google.com/compute/docs/reference/rest/v1/networks), and a
// restore creates resources. Written into a snapshot it would be dropped
// by the restore and read as done.
func (rt *routing) gcpPeerings(vnets map[string]*vnet, o *out) {
	d := gcpNet{o.m}
	for _, p := range rt.peerings {
		if !p.active() {
			continue
		}
		a, b := d.netName(vnets[p.local]), d.netName(vnets[p.remote])
		cmd := fmt.Sprintf("gcloud compute networks peerings create %s --network=%s --peer-network=%s", gcpName(p.name), a, b)
		p.refuse = "a GCP peering is made by a call on each network (networks.addPeering), not by creating a resource, and a restore only creates resources: it is not written. Make it once the networks exist: " + cmd
		o.require(fmt.Sprintf("Peer network %s with %s by hand, on both sides, once they are restored (%s): the firewall rules written from the NSGs already take the peer's ranges as part of the network, as Azure's VirtualNetwork tag did, and the subnets' routes leave the peer's ranges alone. GCP peering gives no transit to a third network (docs.cloud.google.com/vpc/docs/vpc-peering)", a, b, cmd))
	}
}
