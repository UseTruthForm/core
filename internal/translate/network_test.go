package translate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

func nsgRef(group, name string) map[string]any {
	return map[string]any{"id": "{{truthform|ref|Microsoft.Network/networkSecurityGroups|" + group + "|" + name + "|id}}"}
}

func rule(name, access, dir string, prio int, proto, src, dst, ports string) map[string]any {
	return map[string]any{"name": name, "properties": map[string]any{
		"access": access, "direction": dir, "priority": prio, "protocol": proto,
		"sourceAddressPrefix": src, "destinationAddressPrefix": dst,
		"sourcePortRange": "*", "destinationPortRange": ports,
	}}
}

// netFixture is a made-up network: a VNet with two subnets, each behind
// an NSG of the patterns people write, an NSG nothing uses, and a peering.
func netFixture() snapshot.Snapshot {
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.Network/virtualNetworks", "net", "core", map[string]any{"location": "westeurope", "tags": map[string]any{"env": "dev"},
			"properties": map[string]any{
				"addressSpace": map[string]any{"addressPrefixes": []any{"10.20.0.0/16"}},
				"subnets": []any{
					map[string]any{"name": "app", "properties": map[string]any{"addressPrefix": "10.20.1.0/24",
						"networkSecurityGroup": nsgRef("net", "web"), "defaultOutboundAccess": true,
						"privateEndpointNetworkPolicies": "Disabled", "privateLinkServiceNetworkPolicies": "Enabled"}},
					map[string]any{"name": "data", "properties": map[string]any{"addressPrefix": "10.20.2.0/24",
						"networkSecurityGroup": nsgRef("net", "data"), "defaultOutboundAccess": false,
						"routeTable": map[string]any{"id": "{{truthform|ref|Microsoft.Network/routeTables|net|to-firewall|id}}"}}},
				},
				"enableDdosProtection": false, "privateEndpointVNetPolicies": "Disabled",
			}}),
		// The web tier: HTTPS from the internet, SSH denied from anywhere,
		// an SSH allow the deny hides, and one from a service tag.
		az("Microsoft.Network/networkSecurityGroups", "net", "web", map[string]any{"location": "westeurope",
			"properties": map[string]any{"securityRules": []any{
				rule("allow-https", "Allow", "Inbound", 100, "Tcp", "Internet", "*", "443"),
				rule("deny-ssh", "Deny", "Inbound", 200, "Tcp", "*", "*", "22"),
				rule("allow-mgmt-ssh", "Allow", "Inbound", 300, "Tcp", "10.0.0.0/8", "*", "22"),
				rule("allow-frontdoor", "Allow", "Inbound", 400, "Tcp", "AzureFrontDoor.Backend", "*", "443"),
				// Any protocol on one port is TCP and UDP on it.
				rule("allow-dns", "Allow", "Inbound", 500, "*", "192.0.2.0/24", "*", "53"),
				// A source port, and one host of the subnet: neither can
				// a security group say.
				srcPort(rule("allow-ephemeral", "Allow", "Inbound", 510, "Tcp", "198.51.100.0/24", "*", "8000"), "1024-65535"),
				rule("allow-one-host", "Allow", "Inbound", 520, "Tcp", "203.0.113.0/24", "10.20.1.10", "9000"),
				// A deny of a service tag, before an allow it cuts into.
				rule("deny-azurecloud", "Deny", "Inbound", 150, "Tcp", "AzureCloud", "*", "8443"),
				rule("allow-8443", "Allow", "Inbound", 600, "Tcp", "Internet", "*", "8443"),
			}}}),
		// The data tier: nothing from the app subnet but Postgres, nothing
		// out to the internet.
		az("Microsoft.Network/networkSecurityGroups", "net", "data", map[string]any{"location": "westeurope",
			"properties": map[string]any{"securityRules": []any{
				rule("allow-pg-from-app", "Allow", "Inbound", 100, "Tcp", "10.20.1.0/24", "*", "5432"),
				rule("deny-app", "Deny", "Inbound", 110, "*", "10.20.1.0/24", "*", "*"),
				rule("deny-internet-out", "Deny", "Outbound", 4000, "*", "*", "Internet", "*"),
				// The internet in, and after it the network denied the
				// same port: Internet is not the network's own addresses.
				rule("allow-8443-internet", "Allow", "Inbound", 130, "Tcp", "Internet", "*", "8443"),
				rule("deny-vnet-8443", "Deny", "Inbound", 140, "Tcp", "VirtualNetwork", "*", "8443"),
			}}}),
		az("Microsoft.Network/networkSecurityGroups", "net", "unused", map[string]any{"location": "westeurope", "properties": map[string]any{}}),
		az("Microsoft.Network/virtualNetworks/virtualNetworkPeerings", "net", "core/to-hub", pr(map[string]any{"allowForwardedTraffic": true})),
	}}
}

func srcPort(r map[string]any, ports string) map[string]any {
	r["properties"].(map[string]any)["sourcePortRange"] = ports
	return r
}

func netMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Zone: "eu-west-1a"}}
	a.Destinations.Network = "vpc"
	g := Map{To: "gcp", Region: "europe-west1"}
	g.Destinations.Network = "vpc"
	return map[string]Map{"aws": a, "gcp": g}
}

func runNet(t *testing.T, m Map) Result {
	t.Helper()
	r, err := Translate(netFixture(), m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func ingress(t *testing.T, r Result, sg string, key string) []string {
	t.Helper()
	var got []string
	for _, x := range list(object(t, r, "aws", awsSG, sg)[key]) {
		m := obj(x)
		s := fmt.Sprint(m["IpProtocol"])
		if m["FromPort"] != nil {
			s += fmt.Sprintf("/%v-%v", m["FromPort"], m["ToPort"])
		}
		got = append(got, s+" "+fmt.Sprint(m["CidrIp"]))
	}
	sort.Strings(got)
	return got
}

// The whole network translation is pinned, and each source is reported
// once.
func TestNetworkGolden(t *testing.T) {
	for name, m := range netMaps() {
		r := runNet(t, m)
		golden(t, "network-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
		}
		for _, o := range netFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
	}
}

// On AWS, what each NSG allows is written with its denies taken out:
// computed, rule by rule, against Azure's own default rules.
func TestNSGsBecomeSecurityGroups(t *testing.T) {
	r := runNet(t, netMaps()["aws"])
	web := ingress(t, r, "web", "SecurityGroupIngress")
	// HTTPS from the internet and the network joins into all addresses;
	// SSH is gone from the network's own allow-all, and the hidden SSH
	// allow writes nothing.
	// The service tag deny on 8443 is taken out for every address, the
	// network's included: less than the source allowed, never more.
	want := []string{
		"tcp/0-21 10.20.0.0/16", "tcp/23-8442 10.20.0.0/16", "tcp/8444-65535 10.20.0.0/16", "tcp/443-443 0.0.0.0/0",
		"udp/0-65535 10.20.0.0/16", "icmp/-1--1 10.20.0.0/16", "50 10.20.0.0/16", "51 10.20.0.0/16",
		"tcp/53-53 192.0.2.0/24", "udp/53-53 192.0.2.0/24",
	}
	sort.Strings(want)
	if strings.Join(web, "\n") != strings.Join(want, "\n") {
		t.Errorf("web ingress:\n%s\nwant\n%s", strings.Join(web, "\n"), strings.Join(want, "\n"))
	}
	for _, s := range web {
		if strings.HasPrefix(s, "tcp/22-22") || strings.Contains(s, "10.0.0.0/8") {
			t.Errorf("SSH the deny hides is allowed: %s", s)
		}
	}
	// Postgres from the app subnet, nothing else from it, the rest of the
	// network as before.
	data := ingress(t, r, "data", "SecurityGroupIngress")
	if !contains(data, "tcp/5432-5432 10.20.1.0/24") {
		t.Errorf("data: no Postgres from app: %v", data)
	}
	for _, s := range data {
		if strings.HasSuffix(s, " 10.20.1.0/24") && s != "tcp/5432-5432 10.20.1.0/24" {
			t.Errorf("data: the denied app subnet gets %s", s)
		}
		if strings.HasSuffix(s, " 10.20.0.0/16") {
			t.Errorf("data: the whole network, app subnet included, gets %s", s)
		}
	}
	// No internet out: only the network.
	if out := ingress(t, r, "data", "SecurityGroupEgress"); strings.Join(out, ",") != "-1 10.20.0.0/16" {
		t.Errorf("data egress: %v", out)
	}
	if out := ingress(t, r, "web", "SecurityGroupEgress"); strings.Join(out, ",") != "-1 0.0.0.0/0" {
		t.Errorf("web egress: %v", out)
	}
	if !contains(web, "tcp/53-53 192.0.2.0/24") || !contains(web, "udp/53-53 192.0.2.0/24") {
		t.Errorf("any protocol on port 53 is not TCP and UDP: %v", web)
	}
	for _, s := range web {
		for _, bad := range []string{"198.51.100.0/24", "203.0.113.0/24", "-1 192.0.2.0/24", "8443"} {
			if strings.Contains(s, bad) {
				t.Errorf("web ingress has %s, which the security group cannot say exactly: %s", bad, s)
			}
		}
	}
	e := entry(t, r, "Microsoft.Network/networkSecurityGroups net/web")
	for _, about := range []string{"allow-ephemeral", "allow-one-host", "deny-azurecloud"} {
		if l := lossAbout(e, about); l == nil || l.Widens {
			t.Errorf("%s: %+v", about, l)
		}
	}
	if l := lossAbout(e, "AzureFrontDoor.Backend"); l == nil || l.Widens {
		t.Errorf("the service tag allow: %+v", l)
	}
	if l := lossAbout(e, "every protocol but one"); l == nil || l.Widens {
		t.Errorf("the split allow-all: %+v", e.Losses)
	}
	if e := entry(t, r, "Microsoft.Network/networkSecurityGroups net/unused"); e.State != Refused {
		t.Errorf("unused NSG: %s", e.State)
	}
	if e := entry(t, r, "Microsoft.Network/virtualNetworks/virtualNetworkPeerings"); e.State != Refused {
		t.Errorf("peering: %s", e.State)
	}
	v := entry(t, r, "Microsoft.Network/virtualNetworks net/core")
	if l := hasLoss(v, "properties.subnets[data].properties.routeTable"); l == nil || !l.Widens {
		t.Errorf("route table: %+v", v.Losses)
	}
	if l := hasLoss(v, "properties.subnets[app].properties.defaultOutboundAccess"); l == nil || l.Widens {
		t.Errorf("default outbound: %+v", v.Losses)
	}
	if sn := object(t, r, "aws", awsSN, "core-app"); sn["AvailabilityZone"] != "eu-west-1a" || sn["CidrBlock"] != "10.20.1.0/24" {
		t.Errorf("subnet: %v", sn)
	}
}

// On GCP the rules keep their priorities and denies, applied by a tag per
// NSG; the network's own allow is the one Azure default written.
func TestNSGsBecomeFirewalls(t *testing.T) {
	r := runNet(t, netMaps()["gcp"])
	fw := func(name string) map[string]any {
		return object(t, r, "gcp", gcpFirewall, gcpProject+"/global/firewalls/"+name)
	}
	https := fw("web-allow-https")
	if fmt.Sprint(https["sourceRanges"]) != "[0.0.0.0/0]" || https["priority"] != 100 || fmt.Sprint(https["targetTags"]) != "[web]" {
		t.Errorf("https: %v", https)
	}
	deny := fw("web-deny-ssh")
	if deny["denied"] == nil || deny["priority"] != 200 {
		t.Errorf("deny-ssh: %v", deny)
	}
	if fw("web-allowvnetinbound")["priority"] != 65000 {
		t.Error("the network's own allow is not at 65000")
	}
	out := fw("data-deny-internet-out")
	if out["direction"] != "EGRESS" || out["denied"] == nil {
		t.Errorf("deny-internet-out: %v", out)
	}
	// Internet here is every address outside the network, as Azure's tag.
	for _, x := range list(out["destinationRanges"]) {
		p := netip.MustParsePrefix(fmt.Sprint(x))
		if p.Overlaps(netip.MustParsePrefix("10.20.0.0/16")) {
			t.Errorf("the internet deny takes in the network: %s", p)
		}
	}
	if one := fw("web-allow-one-host"); fmt.Sprint(one["destinationRanges"]) != "[10.20.1.10/32]" {
		t.Errorf("one host: %v", one)
	}
	for _, x := range list(fw("data-allow-8443-internet")["sourceRanges"]) {
		if netip.MustParsePrefix(fmt.Sprint(x)).Overlaps(netip.MustParsePrefix("10.20.0.0/16")) {
			t.Errorf("the internet allow takes in the network a later deny shuts out: %s", x)
		}
	}
	if net := object(t, r, "gcp", gcpNetwork, gcpProject+"/global/networks/core"); net["autoCreateSubnetworks"] != false {
		t.Errorf("network: %v", net)
	}
	if !anyRequirement(r, "network tag web") {
		t.Errorf("no tag requirement: %v", r.Report.Requirements)
	}
}

// What the map does not choose is refused, never filled in.
func TestNetworksNeedTheirChoices(t *testing.T) {
	m := netMaps()["aws"]
	m.Network = nil
	r := runNet(t, m)
	if e := entry(t, r, "Microsoft.Network/virtualNetworks net/core"); e.State != Refused || !strings.Contains(e.Reason, "availability zone") {
		t.Errorf("no zone: %s %s", e.State, e.Reason)
	}
	if e := entry(t, r, "Microsoft.Network/networkSecurityGroups net/web"); e.State != Refused || !strings.Contains(e.Reason, "is refused") {
		t.Errorf("NSG on a refused network: %s %s", e.State, e.Reason)
	}
	g := netMaps()["gcp"]
	g.Region = ""
	if e := entry(t, runNet(t, g), "Microsoft.Network/virtualNetworks net/core"); e.State != Refused || !strings.Contains(e.Reason, "region") {
		t.Errorf("no region: %s %s", e.State, e.Reason)
	}
	none := Map{To: "aws", Region: "eu-west-1"}
	if e := entry(t, runNet(t, none), "Microsoft.Network/virtualNetworks net/core"); e.State != Refused || !strings.Contains(e.Reason, "destinations.network") {
		t.Errorf("no destination: %s %s", e.State, e.Reason)
	}
}

// An allow that can be written only partly, or a deny that cannot be
// written as it is, always errs toward letting less through.
func TestNetworkRulesNeverWiden(t *testing.T) {
	for name, m := range netMaps() {
		r := runNet(t, m)
		for _, e := range r.Report.Entries {
			for _, l := range e.Losses {
				if l.Widens && !strings.Contains(l.Field, "routeTable") {
					t.Errorf("%s: %s %s widens: %s", name, e.Source, l.Field, l.Why)
				}
			}
		}
	}
	// An ASG as the destination of an allow: the rule applies to its
	// members only, so it is not in what the subnet's instances carry.
	s := netFixture()
	web := obj(s.Objects[1].Body["spec"])["properties"].(map[string]any)
	web["securityRules"] = append(list(web["securityRules"]), map[string]any{"name": "allow-asg", "properties": map[string]any{
		"access": "Allow", "direction": "Inbound", "priority": 500, "protocol": "Tcp", "sourceAddressPrefix": "*",
		"destinationApplicationSecurityGroups": []any{map[string]any{"id": "{{truthform|ref|Microsoft.Network/applicationSecurityGroups|net|web-vms|id}}"}},
		"sourcePortRange":                      "*", "destinationPortRange": "8080"}})
	for name, m := range netMaps() {
		r, err := Translate(s, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, ev := range entry(t, r, "Microsoft.Network/networkSecurityGroups net/web").Evidence {
			if ev.Rule == "allow-asg" {
				found = true
				if name == "aws" && ev.Status != nsgNoEffect {
					t.Errorf("aws: the ASG allow in the subnet's group: %+v", ev)
				}
			}
		}
		if !found {
			t.Errorf("%s: no evidence for the ASG allow", name)
		}
		for _, o := range r.Snapshots[m.To].Objects {
			if strings.Contains(canonJSON(o.Body), "8080") && !strings.Contains(canonJSON(obj(o.Body["spec"])["targetTags"]), "web-as-web-vms") {
				t.Errorf("%s: port 8080 is open to what is not in the group: %s", name, o.Key())
			}
		}
	}
}

func TestNetworksRestore(t *testing.T) {
	tg := targets(t)
	s := runNet(t, netMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	if c := f.Count(); c[awsVPC] != 1 || c[awsSN] != 2 || c[awsSG] != 2 {
		t.Errorf("aws created %v", c)
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runNet(t, netMaps()["gcp"]).Snapshots["gcp"]
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

// The prefix and box arithmetic the AWS writer stands on.
func TestNetSets(t *testing.T) {
	p := netip.MustParsePrefix
	got := prefixMinus([]netip.Prefix{p("10.0.0.0/16")}, []netip.Prefix{p("10.0.1.0/24")})
	if len(got) != 8 || within([]netip.Prefix{p("10.0.1.5/32")}, got) || !within([]netip.Prefix{p("10.0.2.0/24")}, got) {
		t.Errorf("minus: %v", got)
	}
	if a := aggregate(append(got, p("10.0.1.0/24"))); len(a) != 1 || a[0] != p("10.0.0.0/16") {
		t.Errorf("aggregate: %v", a)
	}
	b := box{"tcp", 0, 65535, []netip.Prefix{p("10.0.0.0/8")}}
	parts, _ := b.minus(box{"tcp", 22, 22, []netip.Prefix{anyV4}})
	if len(parts) != 2 || parts[0].hi != 21 || parts[1].lo != 23 {
		t.Errorf("port split: %v", parts)
	}
	parts, _ = b.minus(box{"all", 0, 65535, []netip.Prefix{p("10.1.0.0/16")}})
	if len(parts) != 1 || within([]netip.Prefix{p("10.1.0.0/16")}, parts[0].peer) {
		t.Errorf("peer split: %v", parts)
	}
	if parts, _ := b.minus(box{"tcp", 0, 65535, []netip.Prefix{anyV4}}); len(parts) != 0 {
		t.Errorf("covered: %v", parts)
	}
	if parts, narrowed := (box{"all", 0, 65535, []netip.Prefix{anyV4}}).minus(box{"udp", 53, 53, []netip.Prefix{anyV4}}); !narrowed || len(parts) != 6 {
		t.Errorf("all minus udp/53: %v %v", parts, narrowed)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func lossAbout(e Entry, s string) *Loss {
	for i := range e.Losses {
		if strings.Contains(e.Losses[i].Why, s) || strings.Contains(e.Losses[i].Field, s) {
			return &e.Losses[i]
		}
	}
	return nil
}

func anyRequirement(r Result, s string) bool {
	for _, q := range r.Report.Requirements {
		if strings.Contains(q, s) {
			return true
		}
	}
	return false
}

func canonJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// A resource group needs no destination, and what #32 puts out of scope is
// refused with its reason, not left "not looked at".
func TestDecidedTypes(t *testing.T) {
	s := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{
		az("Microsoft.Resources/resourceGroups", "", "shop-rg", map[string]any{"location": "westeurope", "tags": map[string]any{"team": "shop"}}),
		az("Microsoft.Authorization/roleAssignments", "shop-rg", "a1", pr(map[string]any{"principalId": "p"})),
		az("Microsoft.ManagedIdentity/userAssignedIdentities", "shop-rg", "shop-id", map[string]any{"location": "westeurope"}),
		az("Microsoft.Web/sites", "shop-rg", "shop-web", map[string]any{"location": "westeurope"}),
		az("Microsoft.Insights/diagnosticSettings", "shop-rg", "to-storage", pr(nil)),
		az("Microsoft.Authorization/policyAssignments", "shop-rg", "tags", pr(nil)),
		az("Microsoft.Compute/virtualMachines", "shop-rg", "vm", pr(nil)),
		az("Microsoft.RecoveryServices/vaults", "shop-rg", "vault", pr(nil)),
		az("Microsoft.RecoveryServices/vaults/backupPolicies", "shop-rg", "vault/daily", pr(nil)),
		az("Microsoft.DataProtection/backupVaults", "shop-rg", "bv", pr(nil)),
		az("Microsoft.CognitiveServices/accounts", "shop-rg", "ai", pr(nil)),
		az("Microsoft.CognitiveServices/accounts/deployments", "shop-rg", "ai/chat", pr(nil)),
		az("Microsoft.SignalRService/WebPubSub", "shop-rg", "push", pr(nil)),
		az("microsoft.monitor/accounts", "shop-rg", "metrics", pr(nil)),
	}}
	want := map[string]State{
		"Microsoft.Resources/resourceGroups shop-rg":                           WithLosses,
		"Microsoft.Authorization/roleAssignments shop-rg/a1":                   Refused,
		"Microsoft.ManagedIdentity/userAssignedIdentities shop-rg/shop-id":     Refused,
		"Microsoft.Web/sites shop-rg/shop-web":                                 Refused,
		"Microsoft.Insights/diagnosticSettings shop-rg/to-storage":             Refused,
		"Microsoft.Authorization/policyAssignments shop-rg/tags":               Refused,
		"Microsoft.Compute/virtualMachines shop-rg/vm":                         NotLooked,
		"Microsoft.RecoveryServices/vaults shop-rg/vault":                      Refused,
		"Microsoft.RecoveryServices/vaults/backupPolicies shop-rg/vault/daily": Refused,
		"Microsoft.DataProtection/backupVaults shop-rg/bv":                     Refused,
		"Microsoft.CognitiveServices/accounts shop-rg/ai":                      Refused,
		"Microsoft.CognitiveServices/accounts/deployments shop-rg/ai/chat":     Refused,
		"Microsoft.SignalRService/WebPubSub shop-rg/push":                      Refused,
		"microsoft.monitor/accounts shop-rg/metrics":                           Refused,
	}
	for name, m := range netMaps() {
		r, err := Translate(s, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range r.Report.Entries {
			if want[e.Source] != e.State {
				t.Errorf("%s: %s is %s, want %s (%s)", name, e.Source, e.State, want[e.Source], e.Reason)
			}
			// The identity family's refusals say their own reasons (identity_test.go).
			if e.State == Refused && !strings.Contains(e.Reason, "#32") && !strings.Contains(e.Reason, "not a resource") && !(identity{}).claims(strings.ToLower(strings.Fields(e.Source)[0])) {
				t.Errorf("%s: %s refused without its reason: %s", name, e.Source, e.Reason)
			}
		}
		if len(r.Report.Entries) != len(want) {
			t.Errorf("%s: %d entries for %d sources", name, len(r.Report.Entries), len(want))
		}
	}
}
