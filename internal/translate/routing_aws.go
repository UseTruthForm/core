package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/awscc"
)

// Routing on AWS. A subnet with no route table of its own uses the VPC's
// main one, which holds only the local route: it reaches the VPC and
// nothing else. So a subnet is given a route table only for what it must
// reach beyond the VPC: the internet through a NAT gateway, and its
// network's peers.
//
// A NAT gateway sits in a public subnet, one that routes to an internet
// gateway ("You create a public NAT gateway in a public subnet and must
// associate an Elastic IP address with the NAT gateway at creation",
// docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html). Azure's
// sits in none, so the map gives that subnet's range and zone.
//
// A route table has no route that drops ("blackhole" is the state of a
// route whose target is gone, docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Route.html),
// so a destination Azure dropped, or sent through an appliance that is not
// translated, is left without a route: the internet route is then written
// as the ranges Azure sent to the internet rather than as 0.0.0.0/0, which
// would take those destinations in. The local route cannot be dropped, and
// can be pointed only at a network interface, NAT gateway or Gateway Load
// Balancer endpoint for a whole subnet
// (docs.aws.amazon.com/vpc/latest/userguide/subnet-route-tables.html).

const (
	awsIGW       = "AWS::EC2::InternetGateway"
	awsIGWAttach = "AWS::EC2::VPCGatewayAttachment"
	awsEIP       = "AWS::EC2::EIP"
	awsNATGW     = "AWS::EC2::NatGateway"
	awsRT        = "AWS::EC2::RouteTable"
	awsRoute     = "AWS::EC2::Route"
	awsRTAssoc   = "AWS::EC2::SubnetRouteTableAssociation"
	awsPeering   = "AWS::EC2::VPCPeeringConnection"

	// docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-basics.html: "up
	// to 8 IPv4 addresses ... (1 primary IPv4 address and 7 secondary IPv4
	// addresses)"; the default quota is 2.
	awsNATMaxAddresses   = 8
	awsNATAddressQuota   = 2
	awsRouteQuota        = 50  // routes per route table, AWS's default quota
	awsNATIdleSeconds    = 350 // nat-gateway-troubleshooting.html; it cannot be set
	awsDefaultOutboundID = "default-outbound"
)

// awsNamed makes an object whose only name is its Name tag.
func (rt *routing) awsNamed(o *out, src, kind, name string, spec map[string]any) string {
	tags, _ := awsTags(name, nil)
	spec["Tags"] = tags
	return o.add("aws", src, awsObject(kind, name, spec))
}

// awsUnnamed makes an object AWS gives no name or tags (a route, an
// association, a gateway attachment): it is named as a capture names it,
// by its spec, so a second restore finds the first one's.
func (rt *routing) awsUnnamed(o *out, src, kind string, spec map[string]any) string {
	return o.add("aws", src, awsObject(kind, awscc.SpecName(kind, spec), spec))
}

// awsEgressSubnet checks the map's public subnet for a network.
func (rt *routing) awsEgressSubnet(v *vnet, o *out) (cidr netip.Prefix, zone, why string) {
	key := v.group + "/" + v.name
	need := fmt.Sprintf("the map gives network %s no public subnet for a NAT gateway (network.egress.%s: {subnet: a free /28 or wider of %s, zone: ...}): an AWS NAT gateway sits in a subnet that routes to an internet gateway, and an Azure one in none", key, key, prefixList(v.prefixes))
	e, ok := o.m.egressFor(key)
	if !ok {
		return cidr, "", need
	}
	cidr = netip.MustParsePrefix(e.Subnet)
	zone = e.Zone
	if zone == "" && o.m.Network != nil {
		zone = o.m.Network.Zone
	}
	switch {
	case zone == "":
		return cidr, "", fmt.Sprintf("the map names no availability zone for network %s's public subnet (network.egress.%s.zone, or network.zone)", key, key)
	case cidr.Bits() > minRange || cidr.Bits() < maxVPC || !within([]netip.Prefix{cidr}, v.prefixes):
		return cidr, "", fmt.Sprintf("network.egress.%s.subnet %s is not a /%d to /%d inside %s", key, cidr, maxVPC, minRange, prefixList(v.prefixes))
	}
	for _, s := range v.subnets {
		if s.prefix.Overlaps(cidr) {
			return cidr, "", fmt.Sprintf("network.egress.%s.subnet %s overlaps subnet %s (%s)", key, cidr, s.name, s.prefix)
		}
	}
	return cidr, zone, ""
}

func (rt *routing) aws(v *vnet, plans []*routingPlan, o *out) {
	vpc := awsNet{o.m}.vpcName(v)
	vpcRef := awsRef(awsVPC, vpc, "VpcId")
	add := func(t string) { rt.netTargets[v.src] = append(rt.netTargets[v.src], t) }
	egress := false
	for _, p := range plans {
		egress = egress || p.egress.any()
	}
	natName := map[*routingNAT]string{}
	implied := ""
	if egress {
		cidr, zone, why := rt.awsEgressSubnet(v, o)
		if why != "" {
			for _, p := range plans {
				switch {
				case p.egress.nat != nil:
					p.lose("natGateway", "the target subnet has no internet egress: "+why, false)
					if p.egress.nat.refuse == "" {
						p.egress.nat.refuse = why
					}
				case p.egress.implied:
					p.lose("defaultOutboundAccess", "the target subnet has no internet egress: "+why, false)
				}
				p.egress = routingEgress{}
			}
			egress = false
		} else {
			igw, pub := vpc+"-igw", vpc+"-egress"
			add(rt.awsNamed(o, v.src, awsIGW, igw, map[string]any{}))
			add(rt.awsUnnamed(o, v.src, awsIGWAttach, map[string]any{"VpcId": vpcRef, "InternetGatewayId": awsRef(awsIGW, igw, "InternetGatewayId")}))
			add(rt.awsNamed(o, v.src, awsSN, pub, map[string]any{"VpcId": vpcRef, "CidrBlock": cidr.String(), "AvailabilityZone": zone}))
			add(rt.awsNamed(o, v.src, awsRT, pub, map[string]any{"VpcId": vpcRef}))
			add(rt.awsUnnamed(o, v.src, awsRTAssoc, map[string]any{"RouteTableId": awsRef(awsRT, pub, "RouteTableId"), "SubnetId": awsRef(awsSN, pub, "SubnetId")}))
			add(rt.awsUnnamed(o, v.src, awsRoute, map[string]any{"RouteTableId": awsRef(awsRT, pub, "RouteTableId"),
				"DestinationCidrBlock": anyV4.String(), "GatewayId": awsRef(awsIGW, igw, "InternetGatewayId")}))
			gateway := func(src, name string, count int, tags map[string]string) (string, []Loss) {
				t, losses := awsTags(name, tags)
				var allocs []any
				for i := 1; i <= count; i++ {
					ip := fmt.Sprintf("%s-%d", name, i)
					rt.awsNamed(o, src, awsEIP, ip, map[string]any{"Domain": "vpc"})
					allocs = append(allocs, awsRef(awsEIP, ip, "AllocationId"))
				}
				spec := map[string]any{"SubnetId": awsRef(awsSN, pub, "SubnetId"), "AllocationId": allocs[0], "Tags": t}
				if len(allocs) > 1 {
					spec["SecondaryAllocationIds"] = allocs[1:]
				}
				return o.add("aws", src, awsObject(awsNATGW, name, spec)), losses
			}
			for _, p := range plans {
				n := p.egress.nat
				if n == nil || natName[n] != "" {
					continue
				}
				name := o.m.name(n.src, n.name)
				count := n.addrs
				if count > awsNATMaxAddresses {
					n.losses = append(n.losses, Loss{Field: "properties.publicIpAddresses", Why: fmt.Sprintf("it sent from %d addresses; an AWS NAT gateway takes %d at most, so fewer connections to one destination fit at once", count, awsNATMaxAddresses)})
					count = awsNATMaxAddresses
				}
				if count > awsNATAddressQuota {
					o.require(fmt.Sprintf("NAT gateway %s has %d Elastic IP addresses; AWS's default quota is %d per NAT gateway, so raise it before a restore", name, count, awsNATAddressQuota))
				}
				target, losses := gateway(n.src, name, count, n.tags)
				n.losses = append(append(n.losses, losses...), Loss{Field: "properties.idleTimeoutInMinutes",
					Why: fmt.Sprintf("an idle connection was dropped after %d minutes; an AWS NAT gateway drops one after %d seconds, and that cannot be set", n.idle, awsNATIdleSeconds)})
				n.targets = append(n.targets, target)
				natName[n] = name
				o.require(fmt.Sprintf("NAT gateway %s is in one availability zone (%s), in public subnet %s: add one per zone, with a route table per zone, for egress to survive the loss of that zone", name, zone, pub))
			}
			for _, p := range plans {
				if p.egress.implied && implied == "" {
					implied = vpc + "-" + awsDefaultOutboundID
					t, _ := gateway(v.src, implied, 1, nil)
					add(t)
					o.require(fmt.Sprintf("NAT gateway %s stands for Azure's default outbound access in network %s, as the map chose (network.defaultOutbound): it is billed by the hour and the gigabyte, and its address is fixed where Azure's was not", implied, v.group+"/"+v.name))
				}
			}
			o.require("A NAT gateway's public subnet and internet gateway take nothing in from the internet by themselves: only a machine put in that subnet with a public address would be reachable, and the translation puts none there")
		}
	}
	for _, p := range plans {
		s := p.s
		p.blockedLosses(v, map[string]string{
			hopAppliance: "the appliance is a machine, which is not translated: the subnet is given no route for these destinations, so that traffic goes nowhere until a route to an inspection appliance on the target is added",
			hopGateway:   "no gateway is translated: the subnet is given no route for these destinations, so that traffic goes nowhere",
		}, true, "an AWS route table always delivers the VPC's own range directly (its local route cannot be dropped, and can be pointed only at an interface or endpoint that is not translated), so that traffic is delivered where Azure dropped it or sent it through the appliance")
		type route struct {
			dst netip.Prefix
			key string
			to  string
		}
		var routes []route
		if p.egress.any() {
			name := implied
			if p.egress.nat != nil {
				name = natName[p.egress.nat]
			}
			// 0.0.0.0/0 where the routes keep nothing from the internet;
			// otherwise only the ranges Azure sent there.
			dsts := []netip.Prefix{anyV4}
			if len(p.reach.blocked) > 0 {
				dsts = p.reach.internet
			}
			for _, d := range dsts {
				routes = append(routes, route{d, "NatGatewayId", awsRef(awsNATGW, name, "NatGatewayId")})
			}
		}
		for _, pk := range sortedMapKeys(p.reach.peers) {
			pcx := rt.awsPeeringName(v.key, pk, o)
			for _, d := range p.reach.peers[pk] {
				routes = append(routes, route{d, "VpcPeeringConnectionId", awsRef(awsPeering, pcx, "Id")})
			}
		}
		if len(routes) == 0 {
			continue
		}
		table := vpc + "-" + s.name
		sn := o.netSubs[strings.ToLower(v.group+"/"+v.name+"/"+s.name)]
		targets := []string{rt.awsNamed(o, v.src, awsRT, table, map[string]any{"VpcId": vpcRef})}
		tref := awsRef(awsRT, table, "RouteTableId")
		targets = append(targets, rt.awsUnnamed(o, v.src, awsRTAssoc, map[string]any{"RouteTableId": tref, "SubnetId": awsRef(awsSN, sn.awsName, "SubnetId")}))
		sort.SliceStable(routes, func(i, j int) bool { return routes[i].dst.String() < routes[j].dst.String() })
		for _, r := range routes {
			targets = append(targets, rt.awsUnnamed(o, v.src, awsRoute, map[string]any{"RouteTableId": tref, "DestinationCidrBlock": r.dst.String(), r.key: r.to}))
		}
		if len(routes) > awsRouteQuota {
			o.require(fmt.Sprintf("Route table %s has %d routes; AWS's default quota is %d per route table, so raise it before a restore", table, len(routes), awsRouteQuota))
		}
		if t := rt.tables[s.routeTable]; t != nil {
			t.targets = append(t.targets, targets...)
		} else {
			for _, t := range targets {
				add(t)
			}
		}
	}
}

// awsPeeringName is the peering connection between two networks: one for
// both of Azure's sides, named from the side whose network sorts first.
func (rt *routing) awsPeeringName(a, b string, o *out) string {
	if b < a {
		a, b = b, a
	}
	for _, p := range rt.peerings {
		if p.local == a && p.remote == b {
			return o.m.name(p.src, strings.ReplaceAll(a+"-"+b, "/", "-"))
		}
	}
	return ""
}

// awsPeerings writes a VPC peering connection for each pair of networks
// Azure peered. Between two VPCs of one account it is accepted as it is
// made ("If the requester and acceptor VPCs are in the same account, the
// peering request is accepted without a peering role",
// docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcpeeringconnection.html).
// The subnets' routes to it are written with their route tables.
func (rt *routing) awsPeerings(vnets map[string]*vnet, o *out) {
	for _, p := range rt.peerings {
		if !p.active() {
			continue
		}
		name := rt.awsPeeringName(p.local, p.remote, o)
		if p.local > p.remote {
			p.reason = "written once for both sides, as VPC peering connection " + name
			p.targets = append(p.targets, awsPeering+" "+name)
			continue
		}
		a, b := vnets[p.local], vnets[p.remote]
		tags, _ := awsTags(name, nil)
		p.targets = append(p.targets, o.add("aws", p.src, awsObject(awsPeering, name, map[string]any{
			"VpcId": awsRef(awsVPC, awsNet{o.m}.vpcName(a), "VpcId"), "PeerVpcId": awsRef(awsVPC, awsNet{o.m}.vpcName(b), "VpcId"), "Tags": tags,
		})))
		p.reason = "a VPC peering connection, with a route to the peer's range in the route table of each subnet that reached it"
		o.require(fmt.Sprintf("VPC peering connection %s joins %s and %s for their own ranges only: AWS peering gives no transit to a third network, a gateway or a NAT in the peer (docs.aws.amazon.com/vpc/latest/peering/vpc-peering-basics.html)", name, a.src, b.src))
	}
}
