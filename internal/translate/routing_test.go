package translate

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

func azRef(typ, group, name string) map[string]any {
	return map[string]any{"id": "{{truthform|ref|" + typ + "|" + group + "|" + name + "|id}}"}
}

func udr(name, prefix, hop, ip string) map[string]any {
	p := map[string]any{"addressPrefix": prefix, "nextHopType": hop}
	if ip != "" {
		p["nextHopIpAddress"] = ip
	}
	return map[string]any{"name": name, "properties": p}
}

// routingFixture is a made-up hub and spoke. The hub holds a firewall
// appliance and a NAT gateway; the spoke's subnets are each a pattern
// people write: forced through the hub's firewall, out through a NAT
// gateway with some destinations dropped, Azure's default outbound access
// (said and unsaid), and inspection of traffic inside the network. A third
// network peers with one the snapshot does not hold.
func routingFixture() snapshot.Snapshot {
	sub := func(name, prefix string, more map[string]any) map[string]any {
		p := map[string]any{"addressPrefix": prefix}
		for k, v := range more {
			p[k] = v
		}
		return map[string]any{"name": name, "properties": p}
	}
	rtRef := func(n string) map[string]any { return azRef(typRouteTable, "net", n) }
	natRef := func(n string) map[string]any { return azRef(typNAT, "net", n) }
	ipRef := func(n string) map[string]any { return azRef(typPublicIP, "net", n) }
	peer := func(remote map[string]any, more map[string]any) map[string]any {
		p := map[string]any{"remoteVirtualNetwork": remote, "allowVirtualNetworkAccess": true, "peeringState": "Connected", "peeringSyncLevel": "FullyInSync"}
		for k, v := range more {
			p[k] = v
		}
		return pr(p)
	}
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az(typVNet, "net", "hub", map[string]any{"location": "westeurope", "properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.10.0.0/16"}},
			"subnets": []any{
				sub("firewall", "10.10.0.0/26", map[string]any{"defaultOutboundAccess": false, "natGateway": natRef("hub-nat")}),
				sub("shared", "10.10.1.0/24", map[string]any{"defaultOutboundAccess": false}),
			}}}),
		az(typVNet, "net", "spoke", map[string]any{"location": "westeurope", "properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.20.0.0/16"}},
			"subnets": []any{
				// Everything out goes through the hub's firewall; the NAT
				// gateway it also names never sees a packet.
				sub("app", "10.20.1.0/24", map[string]any{"defaultOutboundAccess": false, "routeTable": rtRef("to-firewall"),
					"natGateway": natRef("spoke-nat"), "networkSecurityGroup": nsgRef("net", "web")}),
				// Out through the NAT gateway, but for a partner's range
				// and the hub's shared subnet, which are dropped.
				sub("data", "10.20.2.0/24", map[string]any{"defaultOutboundAccess": false, "routeTable": rtRef("data-rt"), "natGateway": natRef("spoke-nat")}),
				sub("jobs", "10.20.3.0/24", map[string]any{"defaultOutboundAccess": true}),
				sub("batch", "10.20.4.0/24", nil),
				// Traffic to the rest of the network is inspected.
				sub("east", "10.20.5.0/24", map[string]any{"defaultOutboundAccess": false, "routeTable": rtRef("east-west")}),
			}}}),
		az(typVNet, "net", "lone", map[string]any{"location": "westeurope", "properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.30.0.0/16"}},
			"subnets":      []any{sub("only", "10.30.1.0/24", map[string]any{"defaultOutboundAccess": false})}}}),
		az(typVNet+"/virtualNetworkPeerings", "net", "hub/to-spoke", peer(azRef(typVNet, "net", "spoke"), map[string]any{"allowGatewayTransit": true})),
		az(typVNet+"/virtualNetworkPeerings", "net", "spoke/to-hub", peer(azRef(typVNet, "net", "hub"), map[string]any{"allowForwardedTraffic": true, "useRemoteGateways": true})),
		az(typVNet+"/virtualNetworkPeerings", "net", "lone/to-central", peer(map[string]any{
			"id": "/subscriptions/00000000-0000-0000-0000-00000000c0de/resourceGroups/central/providers/Microsoft.Network/virtualNetworks/central-hub"}, nil)),
		az(typNSG, "net", "web", map[string]any{"location": "westeurope", "properties": map[string]any{"securityRules": []any{
			rule("allow-https-vnet", "Allow", "Inbound", 100, "Tcp", "VirtualNetwork", "*", "443"),
			rule("allow-8080-internet", "Allow", "Inbound", 150, "Tcp", "Internet", "*", "8080"),
			rule("deny-rest", "Deny", "Inbound", 200, "*", "*", "*", "*"),
		}}}),
		az(typRouteTable, "net", "to-firewall", map[string]any{"location": "westeurope", "tags": map[string]any{"team": "net"}, "properties": map[string]any{
			"disableBgpRoutePropagation": true,
			"routes":                     []any{udr("default", "0.0.0.0/0", "VirtualAppliance", "10.10.0.4")}}}),
		az(typRouteTable, "net", "data-rt", map[string]any{"location": "westeurope", "properties": map[string]any{
			"routes": []any{udr("drop-partner", "203.0.113.0/24", "None", ""), udr("storage-direct", "Storage", "Internet", "")}}}),
		az(typRouteTable+"/routes", "net", "data-rt/drop-shared", pr(map[string]any{"addressPrefix": "10.10.1.0/24", "nextHopType": "None"})),
		az(typRouteTable, "net", "east-west", map[string]any{"location": "westeurope", "properties": map[string]any{
			"routes": []any{udr("inspect", "10.20.0.0/16", "VirtualAppliance", "10.20.9.4"), udr("own", "10.20.5.0/24", "VnetLocal", "")}}}),
		az(typRouteTable, "net", "spare", map[string]any{"location": "westeurope", "properties": map[string]any{}}),
		az(typNAT, "net", "hub-nat", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard"}, "zones": []any{"1"},
			"properties": map[string]any{"idleTimeoutInMinutes": 10, "publicIpAddresses": []any{ipRef("hub-ip")}}}),
		az(typNAT, "net", "spoke-nat", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard"}, "tags": map[string]any{"env": "dev"},
			"properties": map[string]any{"publicIpAddresses": []any{ipRef("spoke-ip")}, "publicIpPrefixes": []any{azRef(typPublicPrefix, "net", "spoke-prefix")}}}),
		az(typPublicIP, "net", "hub-ip", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard"},
			"properties": map[string]any{"publicIPAllocationMethod": "Static", "publicIPAddressVersion": "IPv4", "ipAddress": "198.51.100.7", "idleTimeoutInMinutes": 4}}),
		az(typPublicIP, "net", "spoke-ip", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard"},
			"properties": map[string]any{"publicIPAllocationMethod": "Static", "publicIPAddressVersion": "IPv4", "ipAddress": "198.51.100.8"}}),
		az(typPublicIP, "net", "lb-ip", map[string]any{"location": "westeurope", "properties": map[string]any{"publicIPAllocationMethod": "Static"}}),
		az(typPublicPrefix, "net", "spoke-prefix", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard"},
			"properties": map[string]any{"prefixLength": 31, "publicIPAddressVersion": "IPv4"}}),
	}}
}

func routingMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Zone: "eu-west-1a", DefaultOutbound: "nat", Egress: map[string]EgressMap{
		"net/hub": {Subnet: "10.10.255.0/28"}, "net/spoke": {Subnet: "10.20.255.0/28", Zone: "eu-west-1b"}}}}
	a.Destinations.Network = "vpc"
	g := Map{To: "gcp", Region: "europe-west1", Network: &NetworkMap{DefaultOutbound: "nat"}}
	g.Destinations.Network = "vpc"
	return map[string]Map{"aws": a, "gcp": g}
}

func runRouting(t *testing.T, s snapshot.Snapshot, m Map) Result {
	t.Helper()
	r, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRoutingGolden(t *testing.T) {
	for name, m := range routingMaps() {
		r := runRouting(t, routingFixture(), m)
		golden(t, "routing-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
		}
		for _, o := range routingFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
	}
}

// awsHop is where an AWS subnet's traffic to dst goes, read from the
// snapshot as AWS routes it: the subnet's route table (the VPC's main one,
// which holds only the local route, when none is associated), longest
// prefix first.
func awsHop(t *testing.T, r Result, vpcCIDR, subnet, dst string) string {
	t.Helper()
	d := netip.MustParseAddr(dst)
	best, hop := netip.MustParsePrefix(vpcCIDR), "local"
	if !best.Contains(d) {
		best, hop = netip.Prefix{}, "none"
	}
	table := ""
	for _, o := range r.Snapshots["aws"].Objects {
		if s := obj(o.Body["spec"]); o.Kind() == awsRTAssoc && s["SubnetId"] == awsRef(awsSN, subnet, "SubnetId") {
			table = fmt.Sprint(s["RouteTableId"])
		}
	}
	for _, o := range r.Snapshots["aws"].Objects {
		s := obj(o.Body["spec"])
		if o.Kind() != awsRoute || s["RouteTableId"] != table {
			continue
		}
		p := netip.MustParsePrefix(fmt.Sprint(s["DestinationCidrBlock"]))
		if !p.Contains(d) || (best.IsValid() && p.Bits() <= best.Bits()) {
			continue
		}
		best = p
		for _, k := range []string{"NatGatewayId", "VpcPeeringConnectionId", "GatewayId"} {
			if v, ok := s[k].(string); ok {
				hop = strings.Split(v, "|")[1] + " " + strings.Split(v, "|")[2]
			}
		}
	}
	return hop
}

// What each subnet reaches on AWS is what it reached on Azure, or less.
func TestRoutingOnAWS(t *testing.T) {
	r := runRouting(t, routingFixture(), routingMaps()["aws"])
	nat, pcx := awsNATGW+" spoke-nat", awsPeering+" net-hub-net-spoke"
	for _, c := range []struct{ vpc, subnet, dst, want, why string }{
		{"10.20.0.0/16", "spoke-app", "10.20.2.9", "local", "its own network"},
		{"10.20.0.0/16", "spoke-app", "10.10.0.4", pcx, "the hub, where the firewall is"},
		{"10.20.0.0/16", "spoke-app", "93.184.216.34", "none", "the internet went through the appliance, which is not translated: no route, and no NAT"},
		{"10.20.0.0/16", "spoke-data", "93.184.216.34", nat, "the internet, through its NAT gateway"},
		{"10.20.0.0/16", "spoke-data", "203.0.113.9", "none", "a range its route table dropped"},
		{"10.20.0.0/16", "spoke-data", "10.10.0.9", pcx, "the hub"},
		{"10.20.0.0/16", "spoke-data", "10.10.1.9", "none", "the hub's shared subnet, which its route table dropped"},
		// Azure drops an unused private range itself; here it leaves with
		// the internet's, and is on no internet: no peering carries it.
		{"10.20.0.0/16", "spoke-data", "10.30.1.9", nat, "a network it is not peered with"},
		{"10.20.0.0/16", "spoke-jobs", "93.184.216.34", awsNATGW + " spoke-default-outbound", "default outbound access, which the map made a NAT"},
		{"10.20.0.0/16", "spoke-batch", "93.184.216.34", awsNATGW + " spoke-default-outbound", "default outbound access left unset"},
		{"10.20.0.0/16", "spoke-east", "93.184.216.34", "none", "a private subnet"},
		{"10.20.0.0/16", "spoke-east", "10.10.1.9", pcx, "the hub"},
		{"10.10.0.0/16", "hub-firewall", "93.184.216.34", awsNATGW + " hub-nat", "the internet"},
		{"10.10.0.0/16", "hub-firewall", "10.20.1.9", pcx, "the spoke"},
		{"10.10.0.0/16", "hub-shared", "93.184.216.34", "none", "a private subnet"},
		{"10.10.0.0/16", "hub-shared", "10.20.1.9", pcx, "the spoke"},
		{"10.10.0.0/16", "hub-egress", "93.184.216.34", awsIGW + " hub-igw", "the NAT gateway's own subnet"},
		{"10.30.0.0/16", "lone-only", "10.10.0.9", "none", "a network whose peering is refused"},
	} {
		if got := awsHop(t, r, c.vpc, c.subnet, c.dst); got != c.want {
			t.Errorf("%s to %s (%s): %s, want %s", c.subnet, c.dst, c.why, got, c.want)
		}
	}
	v := entry(t, r, typVNet+" net/spoke")
	// Inspection inside the network cannot be kept: AWS always delivers
	// the VPC's own range.
	if l := lossAbout(v, "route inspect"); l == nil || !l.Widens || l.Field != "properties.subnets[east].properties.routeTable" {
		t.Errorf("in-network inspection: %+v", v.Losses)
	}
	for _, about := range []string{"route default (0.0.0.0/0 to virtual appliance 10.10.0.4)", "comes before its NAT gateway", "route storage-direct"} {
		if l := lossAbout(v, about); l == nil || l.Widens {
			t.Errorf("%s: %+v", about, l)
		}
	}
	// A dropped range needs no loss: with no route it is dropped.
	if l := lossAbout(v, "drop-partner"); l != nil {
		t.Errorf("a drop that is kept is named as a loss: %+v", l)
	}
	for _, l := range v.Losses {
		if l.Widens && !strings.Contains(l.Why, "route inspect") {
			t.Errorf("widens: %+v", l)
		}
	}
	// The NAT gateways: as many addresses as Azure's, in the map's subnet.
	sn := object(t, r, "aws", awsNATGW, "spoke-nat")
	if sn["SubnetId"] != awsRef(awsSN, "spoke-egress", "SubnetId") || sn["AllocationId"] != awsRef(awsEIP, "spoke-nat-1", "AllocationId") || len(list(sn["SecondaryAllocationIds"])) != 2 {
		t.Errorf("spoke-nat: %v", sn)
	}
	if pub := object(t, r, "aws", awsSN, "spoke-egress"); pub["CidrBlock"] != "10.20.255.0/28" || pub["AvailabilityZone"] != "eu-west-1b" {
		t.Errorf("public subnet: %v", pub)
	}
	if pub := object(t, r, "aws", awsSN, "hub-egress"); pub["AvailabilityZone"] != "eu-west-1a" {
		t.Errorf("hub public subnet: %v", pub)
	}
	n := entry(t, r, typNAT+" net/spoke-nat")
	if l := hasLoss(n, "properties.idleTimeoutInMinutes"); l == nil || !strings.Contains(l.Why, "after 4 minutes") {
		t.Errorf("idle timeout: %+v", n.Losses)
	}
	if !anyRequirement(r, "must be given the new ones") || !anyRequirement(r, "NAT gateway spoke-nat has 3 Elastic IP addresses") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
	for src, want := range map[string]State{
		typPublicIP + " net/hub-ip": WithLosses, typPublicIP + " net/lb-ip": NotLooked, typPublicPrefix + " net/spoke-prefix": Mapped,
		typRouteTable + " net/spare": Refused, typRouteTable + " net/to-firewall": WithLosses, typRouteTable + "/routes net/data-rt/drop-shared": Mapped,
		typVNet + "/virtualNetworkPeerings net/hub/to-spoke": WithLosses, typVNet + "/virtualNetworkPeerings net/spoke/to-hub": WithLosses,
		typVNet + "/virtualNetworkPeerings net/lone/to-central": Refused,
	} {
		if e := entry(t, r, src); e.State != want {
			t.Errorf("%s: %s (%s), want %s", src, e.State, e.Reason, want)
		}
	}
	if e := entry(t, r, typVNet+"/virtualNetworkPeerings net/lone/to-central"); !strings.Contains(e.Reason, "central-hub") || !strings.Contains(e.Reason, "not in the snapshot") {
		t.Errorf("peering out of the snapshot: %s", e.Reason)
	}
	p := entry(t, r, typVNet+"/virtualNetworkPeerings net/spoke/to-hub")
	for _, f := range []string{"properties.allowForwardedTraffic", "properties.useRemoteGateways"} {
		if l := hasLoss(p, f); l == nil || l.Widens {
			t.Errorf("%s: %+v", f, p.Losses)
		}
	}
	if l := hasLoss(entry(t, r, typVNet+"/virtualNetworkPeerings net/hub/to-spoke"), "properties.allowGatewayTransit"); l == nil {
		t.Error("gateway transit is not named")
	}
}

// gcpEgress is what a GCP subnet's traffic to dst meets: the egress deny
// written for its routes, a Cloud NAT gateway, or neither.
func gcpEgress(t *testing.T, r Result, subnetCIDR, subnetwork, dst string) string {
	t.Helper()
	d := netip.MustParseAddr(dst)
	for _, o := range r.Snapshots["gcp"].Objects {
		s := obj(o.Body["spec"])
		if o.Kind() != gcpFirewall || s["direction"] != "EGRESS" || s["priority"] != gcpRoutePriority || fmt.Sprint(s["sourceRanges"]) != "["+subnetCIDR+"]" {
			continue
		}
		for _, x := range list(s["destinationRanges"]) {
			if netip.MustParsePrefix(fmt.Sprint(x)).Contains(d) {
				return "denied"
			}
		}
	}
	for _, o := range r.Snapshots["gcp"].Objects {
		if o.Kind() != gcpRouter {
			continue
		}
		for _, n := range list(obj(o.Body["spec"])["nats"]) {
			for _, s := range list(obj(n)["subnetworks"]) {
				if strings.HasSuffix(fmt.Sprint(obj(s)["name"]), "/subnetworks/"+subnetwork) {
					return "nat " + fmt.Sprint(obj(n)["name"])
				}
			}
		}
	}
	return "no nat"
}

func TestRoutingOnGCP(t *testing.T) {
	r := runRouting(t, routingFixture(), routingMaps()["gcp"])
	for _, c := range []struct{ cidr, subnet, dst, want, why string }{
		{"10.20.1.0/24", "spoke-app", "93.184.216.34", "denied", "the internet went through the appliance, which is not translated"},
		{"10.20.1.0/24", "spoke-app", "10.10.0.4", "no nat", "the hub is left to the peering"},
		{"10.20.1.0/24", "spoke-app", "10.20.2.9", "no nat", "its own network"},
		{"10.20.1.0/24", "spoke-app", "199.36.153.9", "no nat", "private.googleapis.com, for Private Google Access"},
		{"10.20.2.0/24", "spoke-data", "93.184.216.34", "nat spoke-nat", "the internet, through its NAT gateway"},
		{"10.20.2.0/24", "spoke-data", "203.0.113.9", "denied", "a range its route table dropped"},
		{"10.20.2.0/24", "spoke-data", "10.10.1.9", "denied", "the hub's shared subnet, which its route table dropped"},
		{"10.20.2.0/24", "spoke-data", "199.36.153.9", "nat spoke-nat", "nothing is left open where no route sent traffic to a firewall"},
		{"10.20.3.0/24", "spoke-jobs", "93.184.216.34", "nat default-outbound", "default outbound access, which the map made a NAT"},
		{"10.20.4.0/24", "spoke-batch", "93.184.216.34", "nat default-outbound", "default outbound access left unset"},
		{"10.20.5.0/24", "spoke-east", "10.20.2.9", "denied", "the rest of the network, which went through an appliance"},
		{"10.20.5.0/24", "spoke-east", "10.20.5.9", "no nat", "its own subnet"},
		{"10.20.5.0/24", "spoke-east", "93.184.216.34", "no nat", "a private subnet"},
		{"10.10.0.0/26", "hub-firewall", "93.184.216.34", "nat hub-nat", "the internet"},
		{"10.10.1.0/24", "hub-shared", "93.184.216.34", "no nat", "a private subnet"},
	} {
		if got := gcpEgress(t, r, c.cidr, c.subnet, c.dst); got != c.want {
			t.Errorf("%s to %s (%s): %s, want %s", c.subnet, c.dst, c.why, got, c.want)
		}
	}
	region := gcpProject + "/regions/europe-west1"
	router := object(t, r, "gcp", gcpRouter, region+"/routers/spoke-nat")
	var spoke map[string]any
	for _, n := range list(router["nats"]) {
		if obj(n)["name"] == "spoke-nat" {
			spoke = obj(n)
		}
	}
	if spoke["natIpAllocateOption"] != "MANUAL_ONLY" || len(list(spoke["natIps"])) != 3 || spoke["tcpEstablishedIdleTimeoutSec"] != 240 || spoke["sourceSubnetworkIpRangesToNat"] != "LIST_OF_SUBNETWORKS" {
		t.Errorf("spoke-nat: %v", spoke)
	}
	hub := obj(list(object(t, r, "gcp", gcpRouter, region+"/routers/hub-nat")["nats"])[0])
	if hub["tcpEstablishedIdleTimeoutSec"] != 600 || len(list(hub["natIps"])) != 1 {
		t.Errorf("hub-nat: %v", hub)
	}
	if rt := object(t, r, "gcp", gcpRoute, gcpProject+"/global/routes/spoke-internet"); !strings.HasSuffix(fmt.Sprint(rt["nextHopGateway"]), "/global/gateways/default-internet-gateway") || rt["destRange"] != "0.0.0.0/0" {
		t.Errorf("default route: %v", rt)
	}
	// Nothing widens on GCP: what a route kept from its destination is
	// denied.
	for _, e := range r.Report.Entries {
		for _, l := range e.Losses {
			if l.Widens {
				t.Errorf("%s %s widens: %s", e.Source, l.Field, l.Why)
			}
		}
	}
	v := entry(t, r, typVNet+" net/spoke")
	for _, about := range []string{"route inspect", "route default (0.0.0.0/0 to virtual appliance 10.10.0.4)", "leaves 199.36.153.8/30"} {
		if l := lossAbout(v, about); l == nil {
			t.Errorf("%s is not named: %+v", about, v.Losses)
		}
	}
	// A peering is refused, with the call that makes it.
	for _, side := range []string{"net/hub/to-spoke", "net/spoke/to-hub"} {
		if e := entry(t, r, typVNet+"/virtualNetworkPeerings "+side); e.State != Refused || !strings.Contains(e.Reason, "gcloud compute networks peerings create") {
			t.Errorf("%s: %s %s", side, e.State, e.Reason)
		}
	}
	if !anyRequirement(r, "gcloud compute networks peerings create to-hub --network=spoke --peer-network=hub") {
		t.Errorf("requirements: %v", r.Report.Requirements)
	}
}

// Azure's VirtualNetwork tag holds a peer's ranges while the peering
// allows access, and not otherwise.
func TestVirtualNetworkTagHoldsPeers(t *testing.T) {
	blocked := routingFixture()
	for _, o := range blocked.Objects {
		if o.Name() == "hub/to-spoke" {
			obj(spec(o)["properties"])["allowVirtualNetworkAccess"] = false
		}
	}
	for name, m := range routingMaps() {
		for _, c := range []struct {
			s    snapshot.Snapshot
			want string
		}{{routingFixture(), "[10.10.0.0/16 10.20.0.0/16]"}, {blocked, "[10.20.0.0/16]"}} {
			r := runRouting(t, c.s, m)
			var got []any
			if name == "aws" {
				for _, x := range list(object(t, r, "aws", awsSG, "web")["SecurityGroupIngress"]) {
					if obj(x)["FromPort"] == 443 {
						got = append(got, obj(x)["CidrIp"])
					} else if ip := netip.MustParsePrefix(fmt.Sprint(obj(x)["CidrIp"])); ip.Overlaps(netip.MustParsePrefix("10.20.0.0/16")) ||
						(ip.Overlaps(netip.MustParsePrefix("10.10.0.0/16")) && c.want != "[10.20.0.0/16]") {
						// Internet is what is outside the network and its peers.
						t.Errorf("%s: Internet takes in %s", name, ip)
					}
				}
			} else {
				got = list(object(t, r, "gcp", gcpFirewall, gcpProject+"/global/firewalls/web-allow-https-vnet")["sourceRanges"])
			}
			if fmt.Sprint(got) != c.want {
				t.Errorf("%s: VirtualNetwork is %v, want %s", name, got, c.want)
			}
		}
		// With access off no peering is written, and neither side reaches
		// the other.
		r := runRouting(t, blocked, m)
		for _, o := range r.Snapshots[name].Objects {
			if o.Kind() == awsPeering || strings.Contains(canonJSON(o.Body), awsPeering) {
				t.Errorf("%s: a peering is written with access off: %s", name, o.Key())
			}
		}
		if e := entry(t, r, typVNet+"/virtualNetworkPeerings net/spoke/to-hub"); e.State == Refused || !strings.Contains(e.Reason, "carried no traffic") {
			t.Errorf("%s: the other side: %s %s", name, e.State, e.Reason)
		}
		if name == "gcp" {
			// The spoke's forced tunnel then covers the hub's range too.
			if got := gcpEgress(t, r, "10.20.1.0/24", "spoke-app", "10.10.0.4"); got != "denied" {
				t.Errorf("gcp: the hub without a peering: %s", got)
			}
		}
	}
}

// What the map does not choose is not filled in, and what cannot be read
// never opens a path.
func TestRoutingNeedsItsChoices(t *testing.T) {
	m := routingMaps()["aws"]
	nw := *m.Network
	nw.Egress = map[string]EgressMap{"net/hub": {Subnet: "10.10.255.0/28"}}
	nw.DefaultOutbound = ""
	m.Network = &nw
	r := runRouting(t, routingFixture(), m)
	if e := entry(t, r, typNAT+" net/spoke-nat"); e.State != Refused || !strings.Contains(e.Reason, "network.egress.net/spoke") {
		t.Errorf("no public subnet: %s %s", e.State, e.Reason)
	}
	if e := entry(t, r, typPublicIP+" net/spoke-ip"); e.State != Refused {
		t.Errorf("the refused NAT gateway's address: %s", e.State)
	}
	v := entry(t, r, typVNet+" net/spoke")
	for f, about := range map[string]string{
		"properties.subnets[data].properties.natGateway":             "network.egress.net/spoke",
		"properties.subnets[jobs].properties.defaultOutboundAccess":  "network.defaultOutbound: nat",
		"properties.subnets[batch].properties.defaultOutboundAccess": "it is not set",
	} {
		if l := hasLoss(v, f); l == nil || l.Widens || !strings.Contains(l.Why, about) {
			t.Errorf("%s: %+v", f, l)
		}
	}
	for _, sn := range []string{"spoke-data", "spoke-jobs", "spoke-batch"} {
		if got := awsHop(t, r, "10.20.0.0/16", sn, "93.184.216.34"); got != "none" {
			t.Errorf("%s reaches the internet by %s with nothing chosen", sn, got)
		}
	}
	for _, o := range r.Snapshots["aws"].Objects {
		if strings.HasPrefix(o.Name(), "spoke-egress") || strings.HasPrefix(o.Name(), "spoke-igw") {
			t.Errorf("a guessed public subnet: %s", o.Key())
		}
	}
	// A public subnet that overlaps one of the network's, or lies outside
	// it, is refused.
	for _, bad := range []string{"10.20.2.0/28", "10.99.0.0/28", "10.20.255.0/29"} {
		nw.Egress = map[string]EgressMap{"net/hub": {Subnet: "10.10.255.0/28"}, "net/spoke": {Subnet: bad}}
		if e := entry(t, runRouting(t, routingFixture(), m), typNAT+" net/spoke-nat"); e.State != Refused || !strings.Contains(e.Reason, bad) {
			t.Errorf("public subnet %s: %s %s", bad, e.State, e.Reason)
		}
	}
	for _, bad := range []Map{
		{To: "gcp", Network: &NetworkMap{Egress: map[string]EgressMap{"net/hub": {Subnet: "10.10.255.0/28"}}}},
		{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Egress: map[string]EgressMap{"net/hub": {Subnet: "10.10.255.9/28"}}}},
		{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Egress: map[string]EgressMap{"hub": {Subnet: "10.10.255.0/28"}}}},
		{To: "aws", Region: "eu-west-1", Network: &NetworkMap{DefaultOutbound: "internet"}},
	} {
		bad.Destinations.Network = "vpc"
		if err := bad.validate(); err == nil {
			t.Errorf("map accepted: %+v", bad.Network)
		}
	}
	// A next hop no rule reads, a route table that is not in the snapshot,
	// and a route to a service tag that kept traffic from the internet all
	// widen; a peering out of sync, of some subnets only, or one-sided is
	// refused or carries nothing.
	s := routingFixture()
	for _, o := range s.Objects {
		p := obj(spec(o)["properties"])
		switch o.Name() {
		case "to-firewall":
			p["routes"] = []any{udr("default", "0.0.0.0/0", "Teleport", "")}
		case "data-rt":
			p["routes"] = append(list(p["routes"]), udr("inspect-storage", "Storage", "VirtualAppliance", "10.10.0.4"))
		case "hub/to-spoke":
			p["peeringSyncLevel"] = "RemoteNotInSync"
		}
	}
	for name, m := range routingMaps() {
		r := runRouting(t, s, m)
		if l := hasLoss(entry(t, r, typRouteTable+" net/to-firewall"), "properties.routes[default].properties.nextHopType"); l == nil || !l.Widens {
			t.Errorf("%s: unread next hop: %+v", name, l)
		}
		if l := lossAbout(entry(t, r, typVNet+" net/spoke"), "route inspect-storage"); l == nil || !l.Widens {
			t.Errorf("%s: service tag to an appliance: %+v", name, l)
		}
		if e := entry(t, r, typVNet+"/virtualNetworkPeerings net/hub/to-spoke"); e.State != Refused || !strings.Contains(e.Reason, "RemoteNotInSync") {
			t.Errorf("%s: out of sync: %s %s", name, e.State, e.Reason)
		}
		if e := entry(t, r, typVNet+"/virtualNetworkPeerings net/spoke/to-hub"); e.State != Refused {
			t.Errorf("%s: the other side of a refused peering: %s", name, e.State)
		}
	}
	// An ID left as it was names a network outside the snapshot, even one
	// with the group and name of a network inside it.
	far := routingFixture()
	for _, o := range far.Objects {
		if o.Name() == "lone/to-central" {
			obj(spec(o)["properties"])["remoteVirtualNetwork"] = map[string]any{
				"id": "/subscriptions/00000000-0000-0000-0000-00000000c0de/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/hub"}
		}
	}
	if e := entry(t, runRouting(t, far, routingMaps()["aws"]), typVNet+"/virtualNetworkPeerings net/lone/to-central"); e.State != Refused || !strings.Contains(e.Reason, "not in the snapshot") {
		t.Errorf("a namesake in another subscription: %s %s", e.State, e.Reason)
	}
	one := routingFixture()
	var kept []snapshot.Object
	for _, o := range one.Objects {
		if o.Name() != "hub/to-spoke" {
			kept = append(kept, o)
		}
	}
	one.Objects = kept
	r = runRouting(t, one, routingMaps()["aws"])
	if e := entry(t, r, typVNet+"/virtualNetworkPeerings net/spoke/to-hub"); e.State == Refused || !strings.Contains(e.Reason, "no peering back") {
		t.Errorf("one-sided peering: %s %s", e.State, e.Reason)
	}
	if got := awsHop(t, r, "10.20.0.0/16", "spoke-data", "10.10.0.9"); strings.Contains(got, awsPeering) || len(r.Snapshots["aws"].Objects) == 0 || strings.Contains(canonJSON(r.Snapshots["aws"].Objects), awsPeering) {
		t.Errorf("a one-sided peering carries traffic: %s", got)
	}
	none := Map{To: "aws", Region: "eu-west-1"}
	for _, e := range runRouting(t, routingFixture(), none).Report.Entries {
		if e.State != Refused || !strings.Contains(e.Reason, "destinations.network") {
			t.Errorf("no destination: %s %s %s", e.Source, e.State, e.Reason)
		}
	}
}

// Both translations restore, and a second restore finds everything as the
// first left it. AWS refuses what leaves through an internet gateway
// before the gateway is attached, as the real one does.
func TestRoutingRestores(t *testing.T) {
	tg := targets(t)
	s := runRouting(t, routingFixture(), routingMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	var attached atomic.Int32
	f.AfterCreate = func(typeName string, _ map[string]any) {
		if typeName == awsIGWAttach {
			attached.Add(1)
		}
	}
	f.Validate = func(typeName string, desired map[string]any) error {
		if typeName != awsNATGW && typeName != awsEIP && !(typeName == awsRoute && desired["GatewayId"] != nil) {
			return nil
		}
		if attached.Load() != 2 {
			return fmt.Errorf("%s: the VPC has no internet gateway attached", typeName)
		}
		return nil
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	if c := f.Count(); c[awsNATGW] != 3 || c[awsEIP] != 5 || c[awsPeering] != 1 || c[awsIGW] != 2 || c[awsSN] != 10 {
		t.Errorf("aws created %v", c)
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runRouting(t, routingFixture(), routingMaps()["gcp"]).Snapshots["gcp"]
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

// The effective routes of a subnet, as Azure works them out.
func TestRoutingReach(t *testing.T) {
	p := netip.MustParsePrefix
	hub := &vnet{key: "net/hub", prefixes: []netip.Prefix{p("10.10.0.0/16")}}
	v := &vnet{key: "net/spoke", prefixes: []netip.Prefix{p("10.20.0.0/16")}, peers: []*vnet{hub}}
	rt := newRouting()
	rt.live["net/spoke|net/hub"] = true
	rt.tables["net/t"] = &routingTable{routes: []routingUDR{
		{name: "default", prefix: anyV4, hop: hopAppliance, ip: "10.10.0.4"},
		{name: "direct", prefix: p("192.0.2.0/24"), hop: hopInternet},
		{name: "drop", prefix: p("10.10.1.0/24"), hop: hopNone},
		{name: "wide-local", prefix: p("10.0.0.0/8"), hop: hopLocal},
	}}
	r := rt.reach(&subnet{vnet: v, routeTable: "net/t"})
	if fmt.Sprint(r.internet) != "[192.0.2.0/24]" || fmt.Sprint(r.local) != "[10.20.0.0/16]" {
		t.Errorf("internet %v, local %v", r.internet, r.local)
	}
	if got := r.peers["net/hub"]; within([]netip.Prefix{p("10.10.1.0/24")}, got) || !within([]netip.Prefix{p("10.10.0.0/24"), p("10.10.2.0/23")}, got) {
		t.Errorf("peer: %v", got)
	}
	all := append(append(append([]netip.Prefix(nil), r.internet...), r.local...), r.peers["net/hub"]...)
	if prefixesOverlap(all, r.blockedAll()) || len(prefixMinus([]netip.Prefix{anyV4}, append(all, r.blockedAll()...))) != 0 {
		t.Errorf("the sets overlap or leave addresses out: %v / %v", all, r.blockedAll())
	}
	// A route kept in the network for more than the network holds delivers
	// nothing outside it, and the default route takes the rest.
	if !within([]netip.Prefix{p("10.99.0.0/16"), p("8.8.8.0/24"), p("10.10.1.0/24")}, r.blockedAll()) {
		t.Errorf("blocked: %v", r.blockedAll())
	}
	// A route table's route comes before Azure's own of the same prefix.
	rt.tables["net/t"] = &routingTable{routes: []routingUDR{{name: "no-hub", prefix: p("10.10.0.0/16"), hop: hopNone}}}
	if r = rt.reach(&subnet{vnet: v, routeTable: "net/t"}); len(r.peers["net/hub"]) != 0 || fmt.Sprint(r.blockedAll()) != "[10.10.0.0/16]" {
		t.Errorf("a route over the peering's: %+v", r)
	}
	// With no route table: the network, its peers, and the internet.
	r = rt.reach(&subnet{vnet: v})
	if len(r.blocked) != 0 || fmt.Sprint(r.peers["net/hub"]) != "[10.10.0.0/16]" || within([]netip.Prefix{p("10.10.0.0/16")}, r.internet) {
		t.Errorf("no table: %+v", r)
	}
	// A table that turns the peerings' routes off.
	rt.tables["net/t"] = &routingTable{noPeerRoutes: true}
	if r = rt.reach(&subnet{vnet: v, routeTable: "net/t"}); len(r.peers) != 0 || !within([]netip.Prefix{p("10.10.0.0/16")}, r.internet) {
		t.Errorf("no peer routes: %+v", r)
	}
}

func init() {
	moreReaders = append(moreReaders, func(rd map[string]reflected) {
		rd[typRouteTable] = reflected{version: netVersion, name: "rt", read: func(o snapshot.Object) []Loss { return readRouteTable(o).losses }}
		rd[typRouteTable+"/routes"] = reflected{version: netVersion, name: "rt/r", set: map[string]any{"nextHopType": "None", "addressPrefix": "10.0.0.0/8"},
			read: func(o snapshot.Object) []Loss { _, ls := readUDR("r", spec(o), ""); return ls }}
		rd[typNAT] = reflected{version: netVersion, name: "nat", read: func(o snapshot.Object) []Loss { return readNATGateway(o).losses }}
		rd[typPublicIP] = reflected{version: netVersion, name: "ip", read: func(o snapshot.Object) []Loss { return readPublicIP(o).losses }}
		rd[typPublicPrefix] = reflected{version: netVersion, name: "pfx", read: func(o snapshot.Object) []Loss { return readPublicPrefix(o).losses }}
		rd[typVNet+"/virtualNetworkPeerings"] = reflected{version: netVersion, name: "vn/p", read: func(o snapshot.Object) []Loss {
			return readPeering("p", "p", "rg/vn", spec(o), "").losses
		}}
	})
}

// Every route table, NAT gateway and public address type Azure defines is
// read, or named here.
func TestEveryRoutingTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	// Alone in a snapshot, each has nothing to belong to.
	decided := map[string]State{azRouteTable: Refused, azRoute: Refused, azNAT: Refused, azPublicIP: NotLooked, azPublicPrefix: NotLooked}
	for _, n := range reg.Names() {
		if l := strings.ToLower(n); routingClaims(l) {
			if _, ok := decided[l]; !ok {
				t.Errorf("%s has a definition and no decision", n)
			}
		}
	}
	for k, want := range decided {
		r := runRouting(t, snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", "x/y", nil)}}, routingMaps()["aws"])
		if e := r.Report.Entries[0]; e.State != want {
			t.Errorf("%s: %s, want %s", k, e.State, want)
		}
	}
}
