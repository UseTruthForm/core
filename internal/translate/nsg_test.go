package translate

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

func asgRef(name string) map[string]any {
	return map[string]any{"id": "{{truthform|ref|Microsoft.Network/applicationSecurityGroups|sec|" + name + "|id}}"}
}

func secRef(typ, name string) map[string]any {
	return map[string]any{"id": "{{truthform|ref|" + typ + "|sec|" + name + "|id}}"}
}

// asgRule is a rule whose source, destination or both are application
// security groups: src and dst are an address prefix, or "asg:name".
func asgRule(name, access, dir string, prio int, proto, src, dst, ports string) map[string]any {
	p := map[string]any{"access": access, "direction": dir, "priority": prio, "protocol": proto, "sourcePortRange": "*", "destinationPortRange": ports}
	for side, v := range map[string]string{"source": src, "destination": dst} {
		if n, ok := strings.CutPrefix(v, "asg:"); ok {
			p[side+"ApplicationSecurityGroups"] = []any{asgRef(n)}
		} else {
			p[side+"AddressPrefix"] = v
		}
	}
	return map[string]any{"name": name, "properties": p}
}

func nic(name, subnet, nsg, vm, ip string, static bool, asgs ...string) snapshot.Object {
	ipc := map[string]any{"subnet": secRef("Microsoft.Network/virtualNetworks/subnets", "core/"+subnet), "privateIPAddress": ip,
		"privateIPAllocationMethod": "Dynamic", "privateIPAddressVersion": "IPv4", "primary": true}
	if static {
		ipc["privateIPAllocationMethod"] = "Static"
	}
	var l []any
	for _, a := range asgs {
		l = append(l, asgRef(a))
	}
	if l != nil {
		ipc["applicationSecurityGroups"] = l
	}
	p := map[string]any{"ipConfigurations": []any{map[string]any{"name": "ipconfig1", "properties": ipc}}, "enableIPForwarding": false}
	if nsg != "" {
		p["networkSecurityGroup"] = secRef("Microsoft.Network/networkSecurityGroups", nsg)
	}
	if vm != "" {
		p["virtualMachine"] = map[string]any{"id": "{{truthform|ref|Microsoft.Compute/virtualMachines|sec|" + vm + "|id}}"}
	}
	return az("Microsoft.Network/networkInterfaces", "sec", name, map[string]any{"location": "westeurope", "properties": p})
}

func secSubnet(name, prefix, nsg, policies string) map[string]any {
	p := map[string]any{"addressPrefix": prefix, "defaultOutboundAccess": false}
	if nsg != "" {
		p["networkSecurityGroup"] = secRef("Microsoft.Network/networkSecurityGroups", nsg)
	}
	if policies != "" {
		p["privateEndpointNetworkPolicies"] = policies
	}
	return map[string]any{"name": name, "properties": p}
}

func secNSG(name string, rules ...any) snapshot.Object {
	return az("Microsoft.Network/networkSecurityGroups", "sec", name, map[string]any{"location": "westeurope", "properties": map[string]any{"securityRules": rules}})
}

func secPE(name, subnet, typ, target, group, ip string, asgs ...string) snapshot.Object {
	p := map[string]any{
		"subnet": secRef("Microsoft.Network/virtualNetworks/subnets", "core/"+subnet),
		"privateLinkServiceConnections": []any{map[string]any{"name": name, "properties": map[string]any{
			"privateLinkServiceId": peRef(typ, "shop", target), "groupIds": []any{group}}}},
		"customDnsConfigs": []any{map[string]any{"ipAddresses": []any{ip}}},
	}
	var l []any
	for _, a := range asgs {
		l = append(l, asgRef(a))
	}
	if l != nil {
		p["applicationSecurityGroups"] = l
	}
	return az("Microsoft.Network/privateEndpoints", "sec", name, map[string]any{"location": "westeurope", "properties": p})
}

func flowLogObj(name, typ, target string, enabled bool, more map[string]any) snapshot.Object {
	p := map[string]any{"targetResourceId": "{{truthform|ref|" + typ + "|sec|" + target + "|id}}", "enabled": enabled,
		"storageId": "{{truthform|ref|Microsoft.Storage/storageAccounts|shop|shoplogs|id}}", "format": map[string]any{"type": "JSON", "version": 2}}
	for k, v := range more {
		p[k] = v
	}
	return az("Microsoft.Network/networkWatchers/flowLogs", "NetworkWatcherRG", "NetworkWatcher_westeurope/"+name, map[string]any{"location": "westeurope", "properties": p})
}

// nsgFixture is a made-up network as a security team writes one: NSGs on
// subnets and on interfaces, on the same path and apart, rules that name
// application security groups as source, as destination, in allows and in
// denies, private endpoints an NSG does and does not apply to, an NSG
// nothing uses, and flow logs.
func nsgFixture() snapshot.Snapshot {
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.Network/virtualNetworks", "sec", "core", map[string]any{"location": "westeurope", "properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.30.0.0/16"}},
			"subnets": []any{
				secSubnet("app", "10.30.1.0/24", "app-nsg", ""),
				secSubnet("data", "10.30.2.0/24", "data-nsg", ""),
				secSubnet("pe", "10.30.3.0/24", "pe-nsg", "NetworkSecurityGroupEnabled"),
				secSubnet("legacy", "10.30.4.0/24", "pe-nsg", "Disabled"),
				secSubnet("aks", "10.30.5.0/24", "aks-nsg", ""),
				secSubnet("bare", "10.30.6.0/24", "", ""),
			}}}),
		secNSG("app-nsg",
			rule("allow-https", "Allow", "Inbound", 100, "Tcp", "Internet", "*", "443"),
			rule("deny-ssh", "Deny", "Inbound", 200, "Tcp", "*", "*", "22"),
			// Both sides a group: the web tier to the API tier.
			asgRule("allow-web-to-api", "Allow", "Inbound", 300, "Tcp", "asg:web", "asg:api", "8080"),
			// A deny of a group's members, before an allow of the whole
			// network.
			asgRule("deny-batch", "Deny", "Inbound", 310, "Tcp", "asg:batch", "*", "9000-9100"),
			rule("allow-9000", "Allow", "Inbound", 320, "Tcp", "VirtualNetwork", "*", "9000-9100"),
			rule("deny-vnet-in", "Deny", "Inbound", 4000, "*", "VirtualNetwork", "*", "*"),
			// Out: Postgres to the database group, then nothing else to it.
			asgRule("allow-out-db", "Allow", "Outbound", 300, "Tcp", "*", "asg:db", "5432"),
			asgRule("deny-out-db", "Deny", "Outbound", 400, "*", "*", "asg:db", "*"),
		),
		secNSG("data-nsg",
			asgRule("allow-pg-from-web", "Allow", "Inbound", 100, "Tcp", "asg:web", "*", "5432"),
			// A deny of half the subnet the web group's members are in,
			// before an allow of the group on the same port.
			rule("deny-half", "Deny", "Inbound", 105, "Tcp", "10.30.1.128/25", "*", "8443"),
			asgRule("allow-admin-from-web", "Allow", "Inbound", 110, "Tcp", "asg:web", "*", "8443"),
			rule("deny-app", "Deny", "Inbound", 200, "*", "10.30.1.0/24", "*", "*"),
			rule("deny-internet-out", "Deny", "Outbound", 4000, "*", "*", "Internet", "*"),
		),
		// On an interface, under the app subnet's NSG: its allow of SSH at
		// 100 must not answer the subnet's deny at 200.
		secNSG("vm-nsg",
			rule("allow-ssh", "Allow", "Inbound", 100, "Tcp", "*", "*", "22"),
			rule("allow-https-corp", "Allow", "Inbound", 110, "Tcp", "10.0.0.0/8", "*", "443"),
			rule("allow-9050", "Allow", "Inbound", 120, "Tcp", "10.30.0.0/16", "*", "9050"),
			rule("deny-rest", "Deny", "Inbound", 4000, "*", "*", "*", "*"),
			rule("deny-internet", "Deny", "Outbound", 100, "*", "*", "Internet", "*"),
		),
		secNSG("pe-nsg",
			rule("allow-app", "Allow", "Inbound", 100, "Tcp", "10.30.1.0/24", "*", "443"),
			rule("deny-rest", "Deny", "Inbound", 200, "*", "VirtualNetwork", "*", "*"),
		),
		secNSG("aks-nsg", rule("allow-https", "Allow", "Inbound", 100, "Tcp", "Internet", "*", "443")),
		secNSG("spare-nsg", rule("allow-http", "Allow", "Inbound", 100, "Tcp", "*", "*", "80")),
		az("Microsoft.Network/applicationSecurityGroups", "sec", "web", map[string]any{"location": "westeurope", "properties": map[string]any{}}),
		az("Microsoft.Network/applicationSecurityGroups", "sec", "api", map[string]any{"location": "westeurope", "properties": map[string]any{}}),
		az("Microsoft.Network/applicationSecurityGroups", "sec", "batch", map[string]any{"location": "westeurope", "properties": map[string]any{}}),
		az("Microsoft.Network/applicationSecurityGroups", "sec", "db", map[string]any{"location": "westeurope", "properties": map[string]any{}}),
		nic("vm1-nic", "app", "vm-nsg", "vm1", "10.30.1.10", true, "web"),
		nic("vm2-nic", "app", "", "vm2", "10.30.1.20", false, "api"),
		nic("vm3-nic", "data", "", "vm3", "10.30.2.10", true, "web", "db"),
		nic("vm4-nic", "bare", "vm-nsg", "vm4", "10.30.6.10", true, "batch"),
		nic("vm5-nic", "app", "", "vm5", "10.30.1.30", false),
		secPE("pe-store", "pe", "Microsoft.Storage/storageAccounts", "shopfiles", "blob", "10.30.3.4"),
		secPE("pe-vault", "legacy", "Microsoft.KeyVault/vaults", "shopkv", "vault", "10.30.4.4"),
		flowLogObj("fl-core", "Microsoft.Network/virtualNetworks", "core", true, map[string]any{
			"retentionPolicy":            map[string]any{"enabled": true, "days": 30},
			"flowAnalyticsConfiguration": map[string]any{"networkWatcherFlowAnalyticsConfiguration": map[string]any{"enabled": true, "workspaceResourceId": "w", "trafficAnalyticsInterval": 10}},
			"enabledFilteringCriteria":   "dstip=10.30.2.10",
		}),
		flowLogObj("fl-app-nsg", "Microsoft.Network/networkSecurityGroups", "app-nsg", true, nil),
		flowLogObj("fl-data", "Microsoft.Network/virtualNetworks/subnets", "core/data", true, nil),
		flowLogObj("fl-off", "Microsoft.Network/virtualNetworks/subnets", "core/app", false, nil),
	}}
}

func nsgMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Zone: "eu-west-1a", NSGs: map[string]string{"sec/spare-nsg": "sec/core"},
		FlowLogs: &FlowLogsMap{Destination: "arn:aws:s3:::shop-flow-logs/azure/"}}}
	g := Map{To: "gcp", Region: "europe-west1", Network: &NetworkMap{NSGs: map[string]string{"sec/spare-nsg": "sec/core"}},
		Secrets: &SecretsMap{Replication: "automatic"}}
	for _, m := range []*Map{&a, &g} {
		m.Destinations.Network, m.Destinations.Storage, m.Destinations.Secrets = "vpc", "buckets", "secret-manager"
	}
	return map[string]Map{"aws": a, "gcp": g}
}

func runNSG(t *testing.T, s snapshot.Snapshot, m Map) Result {
	t.Helper()
	r, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// --- The packet oracle -------------------------------------------------
//
// The same packets are put to Azure's rules, read from the fixture and
// evaluated as Azure does, and to the translation's output, read from the
// target snapshot and evaluated as that cloud does. Nothing the target
// lets through may be something Azure did not.

// orEnd is one address on the network: what filters it on Azure and what
// it is in. src is how the report's attachments name it.
type orEnd struct {
	name      string
	addr      netip.Addr
	subnet    string // the subnet it is in; "" outside the network
	subnetNSG string
	nicNSG    string
	asgs      []string
	src       string
	endpoint  bool
}

func orEnds() []orEnd {
	a := netip.MustParseAddr
	n := "Microsoft.Network/networkInterfaces sec/"
	return []orEnd{
		{name: "vm1", addr: a("10.30.1.10"), subnet: "app", subnetNSG: "app-nsg", nicNSG: "vm-nsg", asgs: []string{"web"}, src: n + "vm1-nic"},
		{name: "vm2", addr: a("10.30.1.20"), subnet: "app", subnetNSG: "app-nsg", asgs: []string{"api"}, src: n + "vm2-nic"},
		{name: "vm5", addr: a("10.30.1.30"), subnet: "app", subnetNSG: "app-nsg", src: n + "vm5-nic"},
		{name: "app-other", addr: a("10.30.1.200"), subnet: "app", subnetNSG: "app-nsg", src: "subnet sec/core/app"},
		{name: "vm3", addr: a("10.30.2.10"), subnet: "data", subnetNSG: "data-nsg", asgs: []string{"web", "db"}, src: n + "vm3-nic"},
		{name: "data-other", addr: a("10.30.2.200"), subnet: "data", subnetNSG: "data-nsg", src: "subnet sec/core/data"},
		{name: "vm4", addr: a("10.30.6.10"), subnet: "bare", nicNSG: "vm-nsg", asgs: []string{"batch"}, src: n + "vm4-nic"},
		{name: "pe-store", addr: a("10.30.3.4"), subnet: "pe", subnetNSG: "pe-nsg", src: "Microsoft.Network/privateEndpoints sec/pe-store", endpoint: true},
		{name: "pe-vault", addr: a("10.30.4.4"), subnet: "legacy", src: "Microsoft.Network/privateEndpoints sec/pe-vault", endpoint: true},
		{name: "node", addr: a("10.30.5.10"), subnet: "aks", subnetNSG: "aks-nsg", src: "subnet sec/core/aks"},
		{name: "internet", addr: a("8.8.8.8")},
		{name: "corp", addr: a("10.1.2.3")},
		{name: "partner", addr: a("192.0.2.1")},
	}
}

type orPacket struct {
	self, peer orEnd
	inbound    bool
	proto      string
	port       int
}

func (p orPacket) String() string {
	d := "to"
	if p.inbound {
		d = "from"
	}
	return fmt.Sprintf("%s %s %s %s/%d", p.self.name, d, p.peer.name, p.proto, p.port)
}

func orGrid() []orPacket {
	var out []orPacket
	ends := orEnds()
	for _, self := range ends {
		if self.subnet == "" {
			continue
		}
		for _, peer := range ends {
			if peer.name == self.name {
				continue
			}
			for _, inbound := range []bool{true, false} {
				for _, port := range []int{22, 80, 443, 5432, 8080, 8443, 9000, 9050, 12345} {
					for _, proto := range []string{"tcp", "udp"} {
						out = append(out, orPacket{self, peer, inbound, proto, port})
					}
				}
				for _, proto := range []string{"icmp", "esp", "gre"} {
					out = append(out, orPacket{self, peer, inbound, proto, 0})
				}
			}
		}
	}
	return out
}

var orVNet = netip.MustParsePrefix("10.30.0.0/16")

func orRuleMatches(r nsgRule, p orPacket) bool {
	proto := false
	for _, x := range r.protos {
		proto = proto || x == "all" || x == p.proto
	}
	if !proto {
		return false
	}
	if p.proto == "tcp" || p.proto == "udp" {
		in := len(r.ports) == 0
		for _, pr := range r.ports {
			in = in || (pr[0] <= p.port && p.port <= pr[1])
		}
		if !in {
			return false
		}
	}
	side := func(a addrs, e orEnd) bool {
		if a.any {
			return true
		}
		if a.vnet && orVNet.Contains(e.addr) {
			return true
		}
		if a.internet && !orVNet.Contains(e.addr) {
			return true
		}
		for _, pf := range a.prefixes {
			if pf.Contains(e.addr) {
				return true
			}
		}
		for _, g := range a.asgs {
			for _, m := range e.asgs {
				if g == "sec/"+m {
					return true
				}
			}
		}
		return false
	}
	return side(r.peer, p.peer) && side(r.self, p.self)
}

// orAzure asks each NSG on the packet's path in turn, the first rule that
// matches deciding, and lets it through only when all of them do. deciding
// are the rules that decided, by NSG.
func orAzure(nsgs map[string]*nsg, p orPacket) (allowed bool, deciding map[string]string) {
	deciding = map[string]string{}
	allowed = true
	for _, name := range []string{p.self.subnetNSG, p.self.nicNSG} {
		if name == "" {
			continue
		}
		n := nsgs[name]
		for _, r := range n.ordered() {
			if r.inbound == p.inbound && orRuleMatches(r, p) {
				deciding[name] = r.name
				allowed = allowed && r.allow
				break
			}
		}
	}
	return allowed, deciding
}

func orFixtureNSGs(s snapshot.Snapshot) map[string]*nsg {
	out := map[string]*nsg{}
	for _, o := range s.Objects {
		if o.Kind() == "Microsoft.Network/networkSecurityGroups" {
			out[o.Name()] = readNSG(o)
		}
	}
	return out
}

// orCarries is what each end carries on the target, from the report.
func orCarries(r Result) map[string][]string {
	out := map[string][]string{}
	for _, a := range r.Report.Attachments {
		out[a.Source] = a.Carries
	}
	return out
}

func orRefName(v any) string {
	parts := strings.Split(strings.Trim(fmt.Sprint(v), "{}"), "|")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// orAWS evaluates the packet as AWS does: it is let through when any rule
// of any security group its end carries matches.
func orAWS(t *testing.T, r Result, carries map[string][]string, p orPacket) bool {
	key := "SecurityGroupEgress"
	if p.inbound {
		key = "SecurityGroupIngress"
	}
	for _, g := range carries[p.self.src] {
		for _, x := range list(object(t, r, "aws", awsSG, g)[key]) {
			m := obj(x)
			switch proto := fmt.Sprint(m["IpProtocol"]); {
			case proto == "-1":
			case proto == p.proto && (proto == "tcp" || proto == "udp"):
				from, to := fmt.Sprint(m["FromPort"]), fmt.Sprint(m["ToPort"])
				if fmt.Sprint(p.port) != from && !(atoi(from) <= p.port && p.port <= atoi(to)) {
					continue
				}
			case proto == p.proto, proto == "50" && p.proto == "esp", proto == "51" && p.proto == "ah":
			default:
				continue
			}
			if c, ok := m["CidrIp"]; ok {
				if netip.MustParsePrefix(fmt.Sprint(c)).Contains(p.peer.addr) {
					return true
				}
				continue
			}
			ref := m["SourceSecurityGroupId"]
			if !p.inbound {
				ref = m["DestinationSecurityGroupId"]
			}
			for _, pg := range carries[p.peer.src] {
				if p.peer.subnet != "" && pg == orRefName(ref) {
					return true
				}
			}
		}
	}
	return false
}

func atoi(s string) int {
	n := 0
	fmt.Sscan(s, &n)
	return n
}

// orGCP evaluates the packet as GCP does: of the rules that apply to the
// instance and match, the lowest priority number decides, a deny before an
// allow of the same priority; with none, ingress is denied and egress
// allowed.
func orGCP(r Result, carries map[string][]string, p orPacket) bool {
	in := func(l any, a netip.Addr) bool {
		for _, x := range list(l) {
			if netip.MustParsePrefix(fmt.Sprint(x)).Contains(a) {
				return true
			}
		}
		return false
	}
	has := func(l any, tags []string) bool {
		for _, x := range list(l) {
			for _, t := range tags {
				if fmt.Sprint(x) == t {
					return true
				}
			}
		}
		return false
	}
	best, allow := 1<<30, !p.inbound
	for _, o := range objectByKind(r, "gcp", gcpFirewall) {
		s := obj(o.Body["spec"])
		if (s["direction"] == "INGRESS") != p.inbound {
			continue
		}
		if s["targetTags"] != nil && !has(s["targetTags"], carries[p.self.src]) {
			continue
		}
		if p.inbound {
			fromTag := p.peer.subnet != "" && has(s["sourceTags"], carries[p.peer.src])
			if !in(s["sourceRanges"], p.peer.addr) && !fromTag {
				continue
			}
			if s["destinationRanges"] != nil && !in(s["destinationRanges"], p.self.addr) {
				continue
			}
		} else {
			if !in(s["destinationRanges"], p.peer.addr) || (s["sourceRanges"] != nil && !in(s["sourceRanges"], p.self.addr)) {
				continue
			}
		}
		rules, isAllow := s["allowed"], true
		if rules == nil {
			rules, isAllow = s["denied"], false
		}
		match := false
		for _, x := range list(rules) {
			m := obj(x)
			if proto := fmt.Sprint(m["IPProtocol"]); proto != "all" && proto != p.proto {
				continue
			}
			if m["ports"] == nil {
				match = true
			}
			for _, pr := range list(m["ports"]) {
				lo, hi, isRange := strings.Cut(fmt.Sprint(pr), "-")
				if !isRange {
					hi = lo
				}
				match = match || (atoi(lo) <= p.port && p.port <= atoi(hi))
			}
		}
		prio := atoi(fmt.Sprint(s["priority"]))
		if match && (prio < best || (prio == best && !isAllow)) {
			best, allow = prio, isAllow
		}
	}
	return allow
}

// orGCPEndpoint is whether a peer reaches Google's APIs privately, which
// is what a private endpoint became: its subnetwork has Private Google
// Access, and the traffic is HTTPS.
func orGCPEndpoint(t *testing.T, r Result, p orPacket) bool {
	if !p.inbound || p.proto != "tcp" || p.port != 443 || p.peer.subnet == "" {
		return false
	}
	sn := object(t, r, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/core-"+p.peer.subnet)
	return sn["privateIpGoogleAccess"] == true
}

// orExplained reports whether the evidence names a rule, on the packet's
// path and of its kind of traffic, that the target enforces more strictly
// or does not carry.
func orExplained(r Result, nsgs map[string]*nsg, p orPacket) bool {
	for _, name := range []string{p.self.subnetNSG, p.self.nicNSG} {
		if name == "" {
			continue
		}
		for _, e := range r.Report.Entries {
			if e.Source != "Microsoft.Network/networkSecurityGroups sec/"+name {
				continue
			}
			for _, ev := range e.Evidence {
				if ev.Status != nsgStricter && ev.Status != nsgNotCarried {
					continue
				}
				for _, rule := range nsgs[name].ordered() {
					q := p
					q.peer, q.self = orEnd{addr: p.peer.addr}, orEnd{addr: p.self.addr}
					anyPeer := rule
					anyPeer.peer, anyPeer.self = addrs{any: true}, addrs{any: true}
					if rule.name == ev.Rule && rule.dir() == ev.Direction && orRuleMatches(anyPeer, q) {
						return true
					}
				}
			}
		}
	}
	return false
}

// The oracle: over a grid of packets, on both targets, nothing is let
// through that Azure did not let through, and wherever less is, the
// evidence names a rule that explains it.
func TestNSGPacketOracle(t *testing.T) {
	s := nsgFixture()
	nsgs := orFixtureNSGs(s)
	grid := orGrid()
	for _, target := range []string{"aws", "gcp"} {
		r := runNSG(t, s, nsgMaps()[target])
		carries := orCarries(r)
		allowedBoth, stricter, wider := 0, map[string]int{}, 0
		for _, p := range grid {
			if p.self.subnetNSG == "" && p.self.nicNSG == "" {
				continue // nothing filtered it on Azure, and nothing is written for it
			}
			if p.self.endpoint && !p.inbound {
				continue // a private endpoint starts no traffic
			}
			az, deciding := orAzure(nsgs, p)
			var got bool
			switch {
			case target == "aws":
				got = orAWS(t, r, carries, p)
			case p.self.endpoint:
				got = orGCPEndpoint(t, r, p)
			default:
				got = orGCP(r, carries, p)
			}
			switch {
			case got && !az:
				wider++
				t.Errorf("%s: %s is let through, and Azure denied it (%v)", target, p, deciding)
			case got:
				allowedBoth++
			case az:
				if p.self.endpoint && !(p.proto == "tcp" && p.port == 443) {
					stricter["a private endpoint's target answers HTTPS only"]++
					continue
				}
				var by []string
				for _, k := range sortedMapKeys(deciding) {
					by = append(by, k+"/"+deciding[k])
				}
				stricter[strings.Join(by, " + ")]++
				if !orExplained(r, nsgs, p) {
					t.Errorf("%s: %s is denied, Azure let it through (%v), and no evidence row says why", target, p, deciding)
				}
			}
		}
		var lines []string
		n := 0
		for _, k := range sortedMapKeys(stricter) {
			lines = append(lines, fmt.Sprintf("  %4d  %s", stricter[k], k))
			n += stricter[k]
		}
		t.Logf("%s: %d packets; %d let through by both, %d by neither, %d wider, %d stricter (by the Azure rule that allowed them):\n%s",
			target, len(grid), allowedBoth, len(grid)-allowedBoth-n-wider, wider, n, strings.Join(lines, "\n"))
		if allowedBoth < 200 {
			t.Errorf("%s: only %d packets are let through by both: the oracle is not looking at the rules", target, allowedBoth)
		}
	}
}

// What the oracle must have seen, packet by packet.
func TestNSGPackets(t *testing.T) {
	s := nsgFixture()
	nsgs := orFixtureNSGs(s)
	ends := map[string]orEnd{}
	for _, e := range orEnds() {
		ends[e.name] = e
	}
	cases := []struct {
		self, peer string
		inbound    bool
		port       int
		azure      bool
		aws, gcp   bool
	}{
		// The interface NSG's SSH allow at 100 does not answer the
		// subnet NSG's deny at 200.
		{"vm1", "corp", true, 22, false, false, false},
		// HTTPS: the subnet allows the internet, the interface only 10/8.
		{"vm1", "corp", true, 443, true, true, true},
		{"vm1", "internet", true, 443, false, false, false},
		{"vm5", "internet", true, 443, true, true, true},
		// The web tier reaches the API tier's members, and only them.
		{"vm2", "vm1", true, 8080, true, true, true},
		{"vm5", "vm1", true, 8080, false, false, false},
		{"vm2", "vm5", true, 8080, false, false, false},
		// A member of batch is denied what the rest of the network is
		// allowed; on AWS the subnet it is in goes whole, on GCP its tag.
		{"vm5", "vm4", true, 9000, false, false, false},
		{"vm5", "vm3", true, 9000, true, true, true},
		// The web group reaches Postgres, from either subnet.
		{"data-other", "vm1", true, 5432, true, true, true},
		{"data-other", "vm5", true, 5432, false, false, false},
		// 8443: half the app subnet is denied before the group is
		// allowed. vm1 is in the other half: Azure allows it; the target
		// cannot say which members, and allows none (AWS); GCP keeps the
		// deny and the allow in order, so it is exact.
		{"data-other", "vm1", true, 8443, true, false, true},
		// Out to the database group's members only.
		{"vm5", "vm3", false, 5432, true, true, false},
		{"vm5", "vm3", false, 80, false, false, false},
		// vm1 under both NSGs: nothing out to the internet.
		{"vm1", "internet", false, 443, false, false, false},
		{"vm5", "internet", false, 443, true, true, true},
		// The private endpoint an NSG applies to takes HTTPS from the app
		// subnet only; the one in a subnet with policies off shares its
		// interface endpoints on AWS, which let in what both did.
		{"pe-store", "vm5", true, 443, true, true, true},
		{"pe-store", "vm3", true, 443, false, false, false},
		{"pe-vault", "vm3", true, 443, true, false, false},
	}
	res := map[string]Result{}
	for _, target := range []string{"aws", "gcp"} {
		res[target] = runNSG(t, s, nsgMaps()[target])
	}
	for _, c := range cases {
		p := orPacket{ends[c.self], ends[c.peer], c.inbound, "tcp", c.port}
		if az, by := orAzure(nsgs, p); az != c.azure {
			t.Errorf("Azure: %s: %v (%v), want %v", p, az, by, c.azure)
		}
		if got := orAWS(t, res["aws"], orCarries(res["aws"]), p); got != c.aws {
			t.Errorf("aws: %s: %v, want %v", p, got, c.aws)
		}
		got := orGCP(res["gcp"], orCarries(res["gcp"]), p)
		if p.self.endpoint {
			got = orGCPEndpoint(t, res["gcp"], p)
		}
		if got != c.gcp {
			t.Errorf("gcp: %s: %v, want %v", p, got, c.gcp)
		}
	}
}

// The whole translation is pinned, and each source is reported once.
func TestNSGGolden(t *testing.T) {
	for name, m := range nsgMaps() {
		r := runNSG(t, nsgFixture(), m)
		golden(t, "nsg-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
		}
		for _, o := range nsgFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
	}
}

func sgStrings(t *testing.T, r Result, sg, key string) []string {
	t.Helper()
	var got []string
	for _, x := range list(object(t, r, "aws", awsSG, sg)[key]) {
		got = append(got, sgRuleString(obj(x), key == "SecurityGroupIngress"))
	}
	return got
}

func evidenceFor(t *testing.T, r Result, nsg, where, rule string) RuleEvidence {
	t.Helper()
	for _, ev := range entry(t, r, "Microsoft.Network/networkSecurityGroups sec/"+nsg).Evidence {
		if ev.Rule == rule && strings.HasSuffix(ev.Where, where) {
			return ev
		}
	}
	t.Fatalf("no evidence for %s of %s in %s", rule, nsg, where)
	return RuleEvidence{}
}

// On AWS two NSGs on one path are one security group holding what both
// allow, an application security group is a group with no rules, and
// every interface is told exactly what to carry.
func TestNSGsOnInterfacesAWS(t *testing.T) {
	r := runNSG(t, nsgFixture(), nsgMaps()["aws"])
	both := sgStrings(t, r, "app-nsg-vm-nsg", "SecurityGroupIngress")
	for _, s := range both {
		if strings.HasPrefix(s, "tcp/22-") || strings.HasPrefix(s, "-1") || strings.Contains(s, "0.0.0.0/0") {
			t.Errorf("the two NSGs together allow %s, which one of them denies", s)
		}
	}
	if !contains(both, "tcp/443-443 from 10.0.0.0/12") || len(both) < 6 {
		t.Errorf("what both allow: %v", both)
	}
	// Each NSG alone is still written for where it is alone.
	if alone := sgStrings(t, r, "vm-nsg", "SecurityGroupIngress"); !contains(alone, "tcp/22-22 from 0.0.0.0/0") {
		t.Errorf("vm-nsg by itself: %v", alone)
	}
	carries := orCarries(r)
	want := map[string]string{
		"Microsoft.Network/networkInterfaces sec/vm1-nic": "app-nsg-vm-nsg web",
		"Microsoft.Network/networkInterfaces sec/vm2-nic": "app-nsg-as-api api",
		"Microsoft.Network/networkInterfaces sec/vm3-nic": "data-nsg db web",
		"Microsoft.Network/networkInterfaces sec/vm4-nic": "vm-nsg batch",
		"Microsoft.Network/networkInterfaces sec/vm5-nic": "app-nsg",
		"Microsoft.Network/privateEndpoints sec/pe-store": "core-endpoints",
		"Microsoft.Network/privateEndpoints sec/pe-vault": "core-endpoints",
		"subnet sec/core/app":                             "app-nsg",
	}
	for src, w := range want {
		if got := strings.Join(carries[src], " "); got != w {
			t.Errorf("%s carries %q, want %q", src, got, w)
		}
	}
	for _, a := range r.Report.Attachments {
		wantHow := "requirement"
		if strings.Contains(a.Source, "privateEndpoints") {
			wantHow = "written"
		}
		if a.Attached != wantHow {
			t.Errorf("%s: attached %s", a.Source, a.Attached)
		}
	}
	// A marker lets nothing through: no inbound rule, and no way out but
	// to itself, where AWS would otherwise allow everything.
	for _, m := range []string{"web", "api", "batch", "db"} {
		sg := object(t, r, "aws", awsSG, m)
		if sg["SecurityGroupIngress"] != nil || strings.Join(sgStrings(t, r, m, "SecurityGroupEgress"), ",") != "-1 to 127.0.0.1/32" {
			t.Errorf("marker %s has rules: %v", m, sg)
		}
	}
	// Rules name the groups: the web tier to the API tier's own group,
	// Postgres out to the database group.
	if api := sgStrings(t, r, "app-nsg-as-api", "SecurityGroupIngress"); !contains(api, "tcp/8080-8080 from {{truthform|AWS::EC2::SecurityGroup|web|GroupId}}") {
		t.Errorf("the API tier's group: %v", api)
	}
	for _, g := range []string{"app-nsg", "app-nsg-vm-nsg"} {
		for _, s := range sgStrings(t, r, g, "SecurityGroupIngress") {
			if strings.Contains(s, "8080") {
				t.Errorf("%s, which is not the API tier's, allows %s", g, s)
			}
		}
	}
	out := sgStrings(t, r, "app-nsg", "SecurityGroupEgress")
	if !contains(out, "tcp/5432-5432 to {{truthform|AWS::EC2::SecurityGroup|db|GroupId}}") {
		t.Errorf("app-nsg egress: %v", out)
	}
	for _, s := range out {
		if p, err := netip.ParsePrefix(s[strings.LastIndex(s, " ")+1:]); err == nil && p.Overlaps(netip.MustParsePrefix("10.30.2.0/24")) {
			t.Errorf("app-nsg lets traffic out to the subnet the denied group's members are in: %s", s)
		}
	}
	// The deny of the batch group takes its members' subnet out of the
	// allow that follows.
	for _, s := range sgStrings(t, r, "app-nsg", "SecurityGroupIngress") {
		if p, err := netip.ParsePrefix(s[strings.LastIndex(s, " ")+1:]); err == nil && strings.HasPrefix(s, "tcp/9000") && p.Overlaps(netip.MustParsePrefix("10.30.6.0/24")) {
			t.Errorf("app-nsg lets the batch group's subnet in on 9000: %s", s)
		}
	}
	// The interface endpoints let in what every private endpoint behind
	// them did: HTTPS from the app subnet.
	if in := sgStrings(t, r, "core-endpoints", "SecurityGroupIngress"); strings.Join(in, ",") != "tcp/443-443 from 10.30.1.0/24" {
		t.Errorf("the endpoints' group: %v", in)
	}
	e := entry(t, r, "Microsoft.Network/networkSecurityGroups sec/pe-nsg")
	if !contains(e.Targets, awsSG+" core-endpoints") || lossAbout(e, "only its inbound rules for HTTPS") == nil {
		t.Errorf("pe-nsg: %v %v", e.Targets, e.Losses)
	}
	// Evidence, rule by rule.
	for _, c := range []struct{ nsg, where, rule, status string }{
		{"app-nsg", " app-nsg", "deny-ssh", nsgExact},
		{"app-nsg", " app-nsg", "allow-https", nsgExact},
		{"app-nsg", " app-nsg", "allow-web-to-api", nsgNoEffect},
		{"app-nsg", " app-nsg-as-api", "allow-web-to-api", nsgExact},
		{"app-nsg", " app-nsg", "allow-9000", nsgStricter},
		{"app-nsg", " app-nsg", "AllowAzureLoadBalancerInBound", nsgNotCarried},
		{"vm-nsg", " app-nsg-vm-nsg", "allow-ssh", nsgExact},
		{"data-nsg", " data-nsg", "allow-admin-from-web", nsgStricter},
		{"data-nsg", " data-nsg", "allow-pg-from-web", nsgExact},
		{"pe-nsg", " core-endpoints", "allow-app", nsgExact},
	} {
		if ev := evidenceFor(t, r, c.nsg, c.where, c.rule); ev.Status != c.status {
			t.Errorf("%s in%s: %s is %s (%s), want %s", c.nsg, c.where, c.rule, ev.Status, ev.Why, c.status)
		}
	}
	if ev := evidenceFor(t, r, "app-nsg", " app-nsg", "allow-https"); len(ev.EnforcedBy) == 0 || !strings.Contains(ev.EnforcedBy[0], "AWS::EC2::SecurityGroup app-nsg ingress tcp/443-443 from ") {
		t.Errorf("allow-https is enforced by %v", ev.EnforcedBy)
	}
	if ev := evidenceFor(t, r, "vm-nsg", " app-nsg-vm-nsg", "allow-ssh"); !strings.Contains(ev.Why, "nothing it allows is left") {
		t.Errorf("allow-ssh under the subnet's deny: %+v", ev)
	}
	// Every rule of every NSG has a row wherever the NSG is written,
	// Azure's own six among them.
	for _, e := range r.Report.Entries {
		if !strings.HasPrefix(e.Source, "Microsoft.Network/networkSecurityGroups ") {
			continue
		}
		rows := map[string]int{}
		for _, ev := range e.Evidence {
			rows[ev.Where]++
			if ev.Status == "" || (ev.Status != nsgExact && ev.Status != nsgNoEffect && ev.Why == "") {
				t.Errorf("%s: %+v says nothing", e.Source, ev)
			}
		}
		n := len(orFixtureNSGs(nsgFixture())[strings.TrimPrefix(e.Source, "Microsoft.Network/networkSecurityGroups sec/")].ordered())
		for where, c := range rows {
			if c != n && !strings.HasSuffix(where, "core-endpoints") {
				t.Errorf("%s in %s: %d rows for %d rules", e.Source, where, c, n)
			}
		}
		if len(rows) == 0 {
			t.Errorf("%s has no evidence", e.Source)
		}
	}
	for _, e := range r.Report.Entries {
		for _, l := range e.Losses {
			if l.Widens || l.Unread {
				t.Errorf("%s: %s: %s", e.Source, l.Field, l.Why)
			}
		}
		if e.State == Refused || e.State == NotLooked {
			t.Errorf("%s is %s: %s", e.Source, e.State, e.Reason)
		}
	}
}

// On GCP an NSG by itself is rule for rule under its tag, a group is a
// tag, and two NSGs on a path are one tag of allows closed by a deny.
func TestNSGsOnInterfacesGCP(t *testing.T) {
	r := runNSG(t, nsgFixture(), nsgMaps()["gcp"])
	fw := func(name string) map[string]any {
		return object(t, r, "gcp", gcpFirewall, gcpProject+"/global/firewalls/"+name)
	}
	if f := fw("app-nsg-allow-web-to-api"); fmt.Sprint(f["targetTags"]) != "[app-nsg-as-api]" || fmt.Sprint(f["sourceTags"]) != "[asg-web]" || f["sourceRanges"] != nil {
		t.Errorf("group to group: %v", f)
	}
	if f := fw("app-nsg-deny-batch"); f["denied"] == nil || fmt.Sprint(f["sourceTags"]) != "[asg-batch]" || f["priority"] != 310 {
		t.Errorf("deny of a group: %v", f)
	}
	if f := fw("app-nsg-deny-out-db"); f["denied"] == nil || fmt.Sprint(f["destinationRanges"]) != "[10.30.2.0/24]" {
		t.Errorf("deny out to a group: %v", f)
	}
	for _, o := range objectByKind(r, "gcp", gcpFirewall) {
		s := obj(o.Body["spec"])
		if strings.Contains(o.Name(), "allow-out-db") {
			t.Errorf("an allow out to a group's members is written: %v", s)
		}
		if fmt.Sprint(s["targetTags"]) == "[app-nsg-vm-nsg]" {
			switch {
			case s["denied"] != nil && (s["priority"] != gcpPairPriority+1 || s["direction"] != "EGRESS"):
				t.Errorf("a deny under the pair's tag: %v", s)
			case s["allowed"] != nil && s["priority"] != gcpPairPriority:
				t.Errorf("an allow under the pair's tag: %v", s)
			case strings.Contains(canonJSON(s["allowed"]), `"22"`):
				t.Errorf("the pair allows SSH: %v", s)
			}
		}
	}
	if f := fw("app-nsg-vm-nsg-out-deny"); fmt.Sprint(f["destinationRanges"]) != "[0.0.0.0/0]" || canonJSON(f["denied"]) != `[{"IPProtocol":"all"}]` {
		t.Errorf("the pair's closing deny: %v", f)
	}
	carries := orCarries(r)
	for src, w := range map[string]string{
		"Microsoft.Network/networkInterfaces sec/vm1-nic": "app-nsg-vm-nsg asg-web",
		"Microsoft.Network/networkInterfaces sec/vm2-nic": "app-nsg app-nsg-as-api asg-api",
		"Microsoft.Network/networkInterfaces sec/vm4-nic": "vm-nsg asg-batch",
	} {
		if got := strings.Join(carries[src], " "); got != w {
			t.Errorf("%s carries %q, want %q", src, got, w)
		}
	}
	// Private Google Access only where the NSG let the whole subnetwork
	// reach the private endpoint.
	for sn, want := range map[string]bool{"app": true, "data": false, "bare": false, "pe": false} {
		got := object(t, r, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/core-"+sn)["privateIpGoogleAccess"] == true
		if got != want {
			t.Errorf("Private Google Access on core-%s: %v", sn, got)
		}
	}
	if l := lossAbout(entry(t, r, "Microsoft.Network/networkSecurityGroups sec/pe-nsg"), "are not given Private Google Access"); l == nil || l.Widens {
		t.Errorf("pe-nsg: %+v", l)
	}
	for _, c := range []struct{ nsg, where, rule, status string }{
		{"app-nsg", "tag app-nsg", "deny-batch", nsgExact},
		{"app-nsg", "tag app-nsg", "allow-out-db", nsgNotCarried},
		{"app-nsg", "tag app-nsg", "deny-out-db", nsgStricter},
		{"app-nsg", "tag app-nsg", "DenyAllInBound", nsgExact},
		{"data-nsg", "tag data-nsg", "allow-admin-from-web", nsgExact},
		{"vm-nsg", "tag app-nsg-vm-nsg", "allow-ssh", nsgExact},
		{"vm-nsg", "tag vm-nsg", "allow-ssh", nsgExact},
	} {
		if ev := evidenceFor(t, r, c.nsg, c.where, c.rule); ev.Status != c.status {
			t.Errorf("%s in %s: %s is %s (%s), want %s", c.nsg, c.where, c.rule, ev.Status, ev.Why, c.status)
		}
	}
	if ev := evidenceFor(t, r, "app-nsg", "tag app-nsg", "deny-ssh"); len(ev.EnforcedBy) != 1 || !strings.HasSuffix(ev.EnforcedBy[0], "/firewalls/app-nsg-deny-ssh") {
		t.Errorf("deny-ssh is enforced by %v", ev.EnforcedBy)
	}
	for _, e := range r.Report.Entries {
		for _, l := range e.Losses {
			if l.Widens || l.Unread {
				t.Errorf("%s: %s: %s", e.Source, l.Field, l.Why)
			}
		}
		if e.State == Refused || e.State == NotLooked {
			t.Errorf("%s is %s: %s", e.Source, e.State, e.Reason)
		}
	}
}

// An NSG nothing uses names no network: the map does, or it is refused.
// One whose interface cannot be placed is not written for it.
func TestNSGPlacement(t *testing.T) {
	for name, m := range nsgMaps() {
		m.Network = &NetworkMap{Zone: m.Network.Zone, FlowLogs: m.Network.FlowLogs}
		r := runNSG(t, nsgFixture(), m)
		if e := entry(t, r, "Microsoft.Network/networkSecurityGroups sec/spare-nsg"); e.State != Refused || !strings.Contains(e.Reason, "network.nsgs") {
			t.Errorf("%s: an NSG nothing uses: %s %s", name, e.State, e.Reason)
		}
		m.Network.NSGs = map[string]string{"sec/spare-nsg": "sec/nowhere"}
		if e := entry(t, runNSG(t, nsgFixture(), m), "Microsoft.Network/networkSecurityGroups sec/spare-nsg"); e.State != Refused || !strings.Contains(e.Reason, "not in the snapshot") {
			t.Errorf("%s: placed in a network that is not there: %s %s", name, e.State, e.Reason)
		}
		r = runNSG(t, nsgFixture(), nsgMaps()[name])
		if e := entry(t, r, "Microsoft.Network/networkSecurityGroups sec/spare-nsg"); e.State != WithLosses || lossAbout(e, "not attached to anything on the source either") == nil {
			t.Errorf("%s: placed by the map: %s %v", name, e.State, e.Losses)
		}
		// An interface in a subnet that is not there, and one whose NSG
		// is not.
		s := nsgFixture()
		s.Objects = append(s.Objects, nic("lost-nic", "gone", "vm-nsg", "vm9", "10.30.9.9", true), nic("bare-nic", "app", "missing-nsg", "vm8", "10.30.1.99", true))
		r = runNSG(t, s, nsgMaps()[name])
		if e := entry(t, r, "Microsoft.Network/networkInterfaces sec/lost-nic"); e.State != Refused || !strings.Contains(e.Reason, "is not a subnet of a network in the snapshot") {
			t.Errorf("%s: lost-nic: %s %s", name, e.State, e.Reason)
		}
		if e := entry(t, r, "Microsoft.Network/networkInterfaces sec/bare-nic"); e.State != Refused || !strings.Contains(e.Reason, "missing-nsg is not in the snapshot") {
			t.Errorf("%s: bare-nic: %s %s", name, e.State, e.Reason)
		}
	}
	bad := nsgMaps()["aws"]
	bad.Network.NSGs = map[string]string{"spare-nsg": "core"}
	if _, err := Translate(nsgFixture(), bad, targets(t)); err == nil || !strings.Contains(err.Error(), "network.nsgs") {
		t.Errorf("a map key that is not group/nsg: %v", err)
	}
}

// A scale set's instances are members of a group too: the deny of the
// group takes their subnet out as well.
func TestNSGScaleSetMembers(t *testing.T) {
	s := nsgFixture()
	s.Objects = append(s.Objects, az("Microsoft.Compute/virtualMachineScaleSets", "sec", "workers", map[string]any{"location": "westeurope", "properties": map[string]any{
		"virtualMachineProfile": map[string]any{"networkProfile": map[string]any{"networkInterfaceConfigurations": []any{map[string]any{"name": "nic0", "properties": map[string]any{
			"networkSecurityGroup": secRef("Microsoft.Network/networkSecurityGroups", "vm-nsg"),
			"ipConfigurations": []any{map[string]any{"name": "ip0", "properties": map[string]any{
				"subnet": secRef("Microsoft.Network/virtualNetworks/subnets", "core/data"), "applicationSecurityGroups": []any{asgRef("batch")}}}},
		}}}}}}}))
	r := runNSG(t, s, nsgMaps()["aws"])
	n := 0
	for _, x := range sgStrings(t, r, "app-nsg", "SecurityGroupIngress") {
		p, err := netip.ParsePrefix(x[strings.LastIndex(x, " ")+1:])
		if err != nil || !strings.HasPrefix(x, "tcp/9000") {
			continue
		}
		n++
		for _, sub := range []string{"10.30.2.0/24", "10.30.6.0/24"} {
			if p.Overlaps(netip.MustParsePrefix(sub)) {
				t.Errorf("app-nsg lets %s, where the batch group has members, in on 9000: %s", sub, x)
			}
		}
	}
	if n == 0 {
		t.Error("app-nsg allows nothing on 9000")
	}
	src := "Microsoft.Compute/virtualMachineScaleSets sec/workers interface nic0"
	if got := strings.Join(orCarries(r)[src], " "); got != "data-nsg-vm-nsg batch" {
		t.Errorf("the scale set's interfaces carry %q", got)
	}
	if !anyRequirement(r, "the instances of scale set workers") {
		t.Errorf("no requirement names the scale set: %v", r.Report.Requirements)
	}
	if e := entry(t, r, "Microsoft.Compute/virtualMachineScaleSets sec/workers"); e.State != NotLooked {
		t.Errorf("the scale set itself: %s", e.State)
	}
}

// A private endpoint in a group: the interface endpoints carry the
// group's marker only when every private endpoint behind them was in it.
func TestNSGEndpointGroups(t *testing.T) {
	s := nsgFixture()
	for i, o := range s.Objects {
		if o.Name() == "pe-store" {
			s.Objects[i] = secPE("pe-store", "pe", "Microsoft.Storage/storageAccounts", "shopfiles", "blob", "10.30.3.4", "db")
		}
	}
	r := runNSG(t, s, nsgMaps()["aws"])
	if ids := canonJSON(object(t, r, "aws", awsEndpoint, "core-s3")["SecurityGroupIds"]); strings.Contains(ids, "|db|") {
		t.Errorf("the endpoints carry a marker one private endpoint behind them was not in: %s", ids)
	}
	if !anyRequirement(r, "do not carry the group's marker") {
		t.Errorf("no requirement says so: %v", r.Report.Requirements)
	}
	for i, o := range s.Objects {
		if o.Name() == "pe-vault" {
			s.Objects[i] = secPE("pe-vault", "legacy", "Microsoft.KeyVault/vaults", "shopkv", "vault", "10.30.4.4", "db")
		}
	}
	r = runNSG(t, s, nsgMaps()["aws"])
	if ids := canonJSON(object(t, r, "aws", awsEndpoint, "core-s3")["SecurityGroupIds"]); !strings.Contains(ids, "|db|") || !strings.Contains(ids, "|core-endpoints|") {
		t.Errorf("the endpoints do not carry the marker all were in: %s", ids)
	}
	// Policies off everywhere: the group written without any NSG.
	plain := nsgFixture()
	subs := list(obj(obj(plain.Objects[0].Body["spec"])["properties"])["subnets"])
	obj(obj(subs[2])["properties"])["privateEndpointNetworkPolicies"] = "Disabled"
	r = runNSG(t, plain, nsgMaps()["aws"])
	if in := sgStrings(t, r, "core-endpoints", "SecurityGroupIngress"); strings.Join(in, ",") != "tcp/443-443 from 10.30.0.0/16" {
		t.Errorf("no NSG applies to the endpoints: %v", in)
	}
	if e := entry(t, r, "Microsoft.Network/networkSecurityGroups sec/pe-nsg"); contains(e.Targets, awsSG+" core-endpoints") {
		t.Errorf("pe-nsg is said to filter endpoints it does not apply to: %v", e.Targets)
	}
	g := runNSG(t, plain, nsgMaps()["gcp"])
	for _, sn := range []string{"app", "data", "bare"} {
		if object(t, g, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/core-"+sn)["privateIpGoogleAccess"] != true {
			t.Errorf("no NSG applies to the endpoints, and core-%s has no Private Google Access", sn)
		}
	}
}

// An NSG whose interfaces are in too many sets of groups is refused, not
// written as security groups without end.
func TestNSGTooManyGroups(t *testing.T) {
	s := nsgFixture()
	var rules []any
	for i := 0; i <= nsgMaxGroups; i++ {
		g := fmt.Sprintf("tier%d", i)
		rules = append(rules, asgRule("allow-"+g, "Allow", "Inbound", 100+i, "Tcp", "*", "asg:"+g, fmt.Sprint(7000+i)))
		s.Objects = append(s.Objects, nic(g+"-nic", "aks", "", g, fmt.Sprintf("10.30.5.%d", 20+i), false, g))
	}
	for i, o := range s.Objects {
		if o.Name() == "aks-nsg" {
			s.Objects[i] = secNSG("aks-nsg", rules...)
		}
	}
	r := runNSG(t, s, nsgMaps()["aws"])
	if e := entry(t, r, "Microsoft.Network/networkSecurityGroups sec/aks-nsg"); e.State != Refused || !strings.Contains(e.Reason, "different sets of application security groups") {
		t.Errorf("aks-nsg: %s %s", e.State, e.Reason)
	}
	if e := entry(t, r, "Microsoft.Network/networkInterfaces sec/tier0-nic"); lossAbout(e, "is refused") == nil || !lossAbout(e, "is refused").Widens {
		t.Errorf("an interface under a refused NSG: %+v", e.Losses)
	}
	for _, o := range objectByKind(r, "aws", awsSG) {
		if strings.HasPrefix(o.Name(), "aks-nsg") {
			t.Errorf("a refused NSG is written: %s", o.Name())
		}
	}
}

// The arithmetic two NSGs on a path are combined with.
func TestNetSetIntersections(t *testing.T) {
	p := netip.MustParsePrefix
	ps := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, x := range s {
			out = append(out, p(x))
		}
		return out
	}
	str := func(l []netip.Prefix) string { return routingList(l) }
	for _, c := range []struct {
		a, b []netip.Prefix
		want string
	}{
		{ps("10.0.0.0/8"), ps("10.1.0.0/16"), "10.1.0.0/16"},
		{ps("10.1.0.0/16"), ps("10.0.0.0/8"), "10.1.0.0/16"},
		{ps("10.0.0.0/8"), ps("192.168.0.0/16"), ""},
		{ps("0.0.0.0/0"), ps("10.0.0.0/24", "10.0.1.0/24"), "10.0.0.0/23"},
		{ps("10.0.0.0/24", "10.0.2.0/24"), ps("10.0.0.0/23"), "10.0.0.0/24"},
		{ps("10.0.0.0/16"), ps("10.0.0.0/16"), "10.0.0.0/16"},
		{nil, ps("10.0.0.0/16"), ""},
	} {
		if got := str(prefixIntersect(c.a, c.b)); got != c.want {
			t.Errorf("%v and %v: %q, want %q", c.a, c.b, got, c.want)
		}
		if got := str(prefixIntersect(c.b, c.a)); got != c.want {
			t.Errorf("%v and %v: %q, want %q", c.b, c.a, got, c.want)
		}
	}
	any := ps("0.0.0.0/0")
	for _, c := range []struct {
		a, b box
		want string
	}{
		{box{"tcp", 0, 65535, any}, box{"tcp", 22, 22, ps("10.0.0.0/8")}, "tcp/22 10.0.0.0/8"},
		{box{"all", 0, 65535, ps("10.0.0.0/8")}, box{"tcp", 80, 443, any}, "tcp/80-443 10.0.0.0/8"},
		{box{"tcp", 80, 443, any}, box{"all", 0, 65535, ps("10.0.0.0/8")}, "tcp/80-443 10.0.0.0/8"},
		{box{"all", 0, 65535, any}, box{"all", 0, 65535, ps("10.0.0.0/8")}, "all 10.0.0.0/8"},
		{box{"all", 0, 65535, any}, box{"icmp", 0, 65535, any}, "icmp 0.0.0.0/0"},
		{box{"tcp", 100, 200, any}, box{"tcp", 150, 300, any}, "tcp/150-200 0.0.0.0/0"},
		{box{"tcp", 100, 200, any}, box{"tcp", 201, 300, any}, ""},
		{box{"tcp", 100, 200, any}, box{"udp", 100, 200, any}, ""},
		{box{"tcp", 100, 200, ps("10.0.0.0/8")}, box{"tcp", 100, 200, ps("11.0.0.0/8")}, ""},
		{box{"icmp", 0, 65535, any}, box{"esp", 0, 65535, any}, ""},
	} {
		for _, pair := range [][2]box{{c.a, c.b}, {c.b, c.a}} {
			got, ok := pair[0].intersect(pair[1])
			s := ""
			if ok {
				s = got.String()
			}
			if s != c.want {
				t.Errorf("%s and %s: %q, want %q", pair[0], pair[1], s, c.want)
			}
		}
	}
	// What two boxes share is in both, and what only one holds is not in
	// it: checked address by address and port by port.
	a := box{"tcp", 10, 30, ps("10.0.0.0/23", "10.0.4.0/24")}
	b := box{"all", 0, 65535, ps("10.0.1.0/24", "10.0.4.128/25", "10.9.0.0/16")}
	both, _ := a.intersect(b)
	holds := func(x box, proto string, port int, addr string) bool {
		in := false
		for _, pf := range x.peer {
			in = in || pf.Contains(netip.MustParseAddr(addr))
		}
		return in && protoOverlap(x.proto, proto) && x.lo <= port && port <= x.hi
	}
	for _, addr := range []string{"10.0.0.5", "10.0.1.5", "10.0.4.5", "10.0.4.200", "10.9.0.1", "10.8.0.1"} {
		for _, port := range []int{5, 10, 20, 30, 31} {
			for _, proto := range []string{"tcp", "udp"} {
				if want := holds(a, proto, port, addr) && holds(b, proto, port, addr); holds(both, proto, port, addr) != want {
					t.Errorf("%s %s/%d: in both is %v, want %v", addr, proto, port, !want, want)
				}
			}
		}
	}
}
