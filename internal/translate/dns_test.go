package translate

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

func vnetRef(group, name string) map[string]any {
	return map[string]any{"id": "{{truthform|ref|Microsoft.Network/virtualNetworks|" + group + "|" + name + "|id}}"}
}

func rec(typ, zone, name string, p map[string]any) snapshot.Object {
	return az("Microsoft.Network/dnsZones/"+typ, "dns", zone+"/"+name, pr(p))
}

func prec(typ, zone, name string, p map[string]any) snapshot.Object {
	return az("Microsoft.Network/privateDnsZones/"+typ, "dns", zone+"/"+name, pr(p))
}

func link(zone, name string, vn map[string]any, registration bool) snapshot.Object {
	return az("Microsoft.Network/privateDnsZones/virtualNetworkLinks", "dns", zone+"/"+name, map[string]any{"location": "global",
		"properties": map[string]any{"virtualNetwork": vn, "registrationEnabled": registration, "resolutionPolicy": "Default"}})
}

var longTXT = strings.Repeat("k", 300)

// dnsFixture is a made-up estate: a signed public zone with the record
// types people write, an alias, a delegation and its DS; a private zone
// linked to a translated network, a missing one and a refused one; a
// private zone linked only to a missing network; a legacy private zone;
// and the networks.
func dnsFixture() snapshot.Snapshot {
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.Network/virtualNetworks", "net", "core", map[string]any{"location": "westeurope", "properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.20.0.0/16"}},
			"subnets":      []any{map[string]any{"name": "app", "properties": map[string]any{"addressPrefix": "10.20.1.0/24"}}},
		}}),
		az("Microsoft.Network/virtualNetworks", "net", "empty", map[string]any{"location": "westeurope", "properties": map[string]any{}}),

		az("Microsoft.Network/dnsZones", "dns", "shop.example", map[string]any{"location": "global",
			"tags": map[string]any{"env": "dev", "Cost Center": "42"}, "properties": map[string]any{"zoneType": "Public"}}),
		rec("A", "shop.example", "@", map[string]any{"TTL": 300, "ARecords": []any{map[string]any{"ipv4Address": "203.0.113.10"}, map[string]any{"ipv4Address": "203.0.113.11"}}}),
		rec("AAAA", "shop.example", "@", map[string]any{"TTL": 300, "AAAARecords": []any{map[string]any{"ipv6Address": "2001:db8::10"}}}),
		rec("MX", "shop.example", "@", map[string]any{"TTL": 3600, "MXRecords": []any{
			map[string]any{"preference": 10, "exchange": "mail1.shop.example"}, map[string]any{"preference": 20, "exchange": "mail2.shop.example."}}}),
		rec("TXT", "shop.example", "@", map[string]any{"TTL": 3600, "metadata": map[string]any{"owner": "mail"}, "TXTRecords": []any{
			map[string]any{"value": []any{`v=spf1 include:_spf.example.net -all`}},
			map[string]any{"value": []any{longTXT}},
			map[string]any{"value": []any{`say "hi"`}}}}),
		rec("CAA", "shop.example", "@", map[string]any{"TTL": 3600, "caaRecords": []any{map[string]any{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}}}),
		rec("NS", "shop.example", "@", map[string]any{"TTL": 172800, "NSRecords": []any{map[string]any{"nsdname": "ns1-01.azure-dns.com."}}}),
		rec("SOA", "shop.example", "@", map[string]any{"TTL": 3600, "SOARecord": map[string]any{"host": "ns1-01.azure-dns.com.", "email": "azuredns-hostmaster.microsoft.com",
			"refreshTime": 3600, "retryTime": 300, "expireTime": 2419200, "minimumTTL": 300}}),
		// An alias to an Azure public IP: refused.
		rec("A", "shop.example", "www", map[string]any{"TTL": 60, "targetResource": map[string]any{"id": "{{truthform|ref|Microsoft.Network/publicIPAddresses|net|web-ip|id}}"}}),
		rec("TXT", "shop.example", "www", map[string]any{"TTL": 60, "TXTRecords": []any{map[string]any{"value": []any{"verify=1"}}}}),
		rec("CNAME", "shop.example", "app", map[string]any{"TTL": 300, "CNAMERecord": map[string]any{"cname": "shop-app.azurewebsites.net"}}),
		rec("SRV", "shop.example", "_sip._tcp", map[string]any{"TTL": 300, "SRVRecords": []any{map[string]any{"priority": 10, "weight": 60, "port": 5060, "target": "sip.shop.example"}}}),
		// A delegation, with its DS.
		rec("NS", "shop.example", "dev", map[string]any{"TTL": 3600, "NSRecords": []any{map[string]any{"nsdname": "ns1.dev-dns.example.net"}}}),
		az("Microsoft.Network/dnsZones/DS", "dns", "shop.example/dev", pr(map[string]any{"TTL": 3600, "DSRecords": []any{
			map[string]any{"keyTag": 12345, "algorithm": 13, "digest": map[string]any{"algorithmType": 2, "value": "ABCDEF0123"}}}})),
		az("Microsoft.Network/dnsZones/dnssecConfigs", "dns", "shop.example/default", map[string]any{}),

		az("Microsoft.Network/privateDnsZones", "dns", "core.internal", map[string]any{"location": "global", "tags": map[string]any{"env": "dev"}}),
		prec("A", "core.internal", "db", map[string]any{"ttl": 10, "aRecords": []any{map[string]any{"ipv4Address": "10.20.1.4"}}}),
		prec("CNAME", "core.internal", "api", map[string]any{"ttl": 10, "cnameRecord": map[string]any{"cname": "db.core.internal"}}),
		prec("PTR", "core.internal", "4.1", map[string]any{"ttl": 10, "ptrRecords": []any{map[string]any{"ptrdname": "db.core.internal"}}}),
		prec("A", "core.internal", "web", map[string]any{"ttl": 10, "aRecords": []any{}}),
		prec("SOA", "core.internal", "@", map[string]any{"ttl": 3600, "soaRecord": map[string]any{"email": "azureprivatedns-host.microsoft.com", "minimumTtl": 10}}),
		link("core.internal", "core-link", vnetRef("net", "core"), true),
		link("core.internal", "gone-link", vnetRef("net", "gone"), false),
		link("core.internal", "empty-link", vnetRef("net", "empty"), false),

		az("Microsoft.Network/privateDnsZones", "dns", "orphan.internal", map[string]any{"location": "global"}),
		prec("A", "orphan.internal", "x", map[string]any{"ttl": 10, "aRecords": []any{map[string]any{"ipv4Address": "10.9.0.1"}}}),
		link("orphan.internal", "gone", vnetRef("net", "gone"), false),

		// Azure's private zones before private DNS zones.
		az("Microsoft.Network/dnsZones", "dns", "old.internal", map[string]any{"location": "global", "properties": map[string]any{
			"zoneType": "Private", "resolutionVirtualNetworks": []any{vnetRef("net", "core")}, "registrationVirtualNetworks": []any{vnetRef("net", "core")}}}),
		rec("A", "old.internal", "legacy", map[string]any{"TTL": 60, "ARecords": []any{map[string]any{"ipv4Address": "10.20.1.9"}}}),
		// A record set with no zone.
		rec("A", "missing.example", "x", map[string]any{"TTL": 60, "ARecords": []any{map[string]any{"ipv4Address": "192.0.2.1"}}}),
	}}
}

func dnsMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Zone: "eu-west-1a"}}
	a.Destinations.Network, a.Destinations.DNS = "vpc", "route53"
	g := Map{To: "gcp", Region: "europe-west1"}
	g.Destinations.Network, g.Destinations.DNS = "vpc", "cloud-dns"
	return map[string]Map{"aws": a, "gcp": g}
}

func runDNS(t *testing.T, s snapshot.Snapshot, m Map) Result {
	t.Helper()
	r, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func objectByKind(r Result, platform, kind string) []snapshot.Object {
	var out []snapshot.Object
	for _, o := range r.Snapshots[platform].Objects {
		if o.Kind() == kind {
			out = append(out, o)
		}
	}
	return out
}

// awsRecordSet is the record set of a name and type.
func awsRecordSet(t *testing.T, r Result, name, typ string) map[string]any {
	t.Helper()
	for _, o := range objectByKind(r, "aws", awsRecord) {
		s := obj(o.Body["spec"])
		if s["Name"] == name && s["Type"] == typ {
			return s
		}
	}
	t.Fatalf("no record set %s %s", name, typ)
	return nil
}

func TestDNSGolden(t *testing.T) {
	for name, m := range dnsMaps() {
		r := runDNS(t, dnsFixture(), m)
		golden(t, "dns-"+name, r)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
		}
		for _, o := range dnsFixture().Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
	}
}

func TestDNSZonesBecomeHostedZones(t *testing.T) {
	r := runDNS(t, dnsFixture(), dnsMaps()["aws"])
	zone := object(t, r, "aws", awsZone, "shop.example.")
	if zone["Name"] != "shop.example." || zone["VPCs"] != nil {
		t.Errorf("public zone: %v", zone)
	}
	if fmt.Sprint(zone["HostedZoneTags"]) != "[map[Key:Cost Center Value:42] map[Key:env Value:dev]]" {
		t.Errorf("tags: %v", zone["HostedZoneTags"])
	}
	want := map[[2]string]string{
		{"shop.example.", "A"}:             "[203.0.113.10 203.0.113.11]",
		{"shop.example.", "AAAA"}:          "[2001:db8::10]",
		{"shop.example.", "MX"}:            "[10 mail1.shop.example. 20 mail2.shop.example.]",
		{"shop.example.", "CAA"}:           `[0 issue "letsencrypt.org"]`,
		{"app.shop.example.", "CNAME"}:     "[shop-app.azurewebsites.net.]",
		{"_sip._tcp.shop.example.", "SRV"}: "[10 60 5060 sip.shop.example.]",
		{"dev.shop.example.", "NS"}:        "[ns1.dev-dns.example.net.]",
		{"dev.shop.example.", "DS"}:        "[12345 13 2 ABCDEF0123]",
		{"www.shop.example.", "TXT"}:       `["verify=1"]`,
		{"db.core.internal.", "A"}:         "[10.20.1.4]",
		{"api.core.internal.", "CNAME"}:    "[db.core.internal.]",
		{"4.1.core.internal.", "PTR"}:      "[db.core.internal.]",
		{"legacy.old.internal.", "A"}:      "[10.20.1.9]",
	}
	for k, v := range want {
		rs := awsRecordSet(t, r, k[0], k[1])
		if fmt.Sprint(rs["ResourceRecords"]) != v {
			t.Errorf("%s %s: %v, want %s", k[0], k[1], rs["ResourceRecords"], v)
		}
		if !strings.HasPrefix(fmt.Sprint(rs["HostedZoneId"]), "{{truthform|AWS::Route53::HostedZone|") {
			t.Errorf("%s %s: zone %v", k[0], k[1], rs["HostedZoneId"])
		}
	}
	if rs := awsRecordSet(t, r, "shop.example.", "A"); rs["TTL"] != "300" || rs["HostedZoneId"] != "{{truthform|AWS::Route53::HostedZone|shop.example.|Id}}" {
		t.Errorf("apex A: %v", rs)
	}
	// TXT strings are quoted, a long one split at 255, quotes escaped.
	txt := list(awsRecordSet(t, r, "shop.example.", "TXT")["ResourceRecords"])
	if len(txt) != 3 || txt[0] != `"v=spf1 include:_spf.example.net -all"` || txt[1] != `"`+longTXT[:255]+`" "`+longTXT[255:]+`"` || txt[2] != `"say \"hi\""` {
		t.Errorf("TXT: %q", txt)
	}
	e := entry(t, r, "Microsoft.Network/dnsZones/TXT dns/shop.example/@")
	if l := lossAbout(e, "255"); l == nil || l.Widens {
		t.Errorf("long TXT: %+v", e.Losses)
	}
	if l := hasLoss(e, "properties.metadata"); l == nil || l.Widens {
		t.Errorf("metadata: %+v", e.Losses)
	}
	// What the target makes itself is not written.
	for _, o := range objectByKind(r, "aws", awsRecord) {
		s := obj(o.Body["spec"])
		if s["Type"] == "SOA" || (s["Type"] == "NS" && s["Name"] == "shop.example.") {
			t.Errorf("wrote %s %s", s["Name"], s["Type"])
		}
	}
	for _, src := range []string{"Microsoft.Network/dnsZones/SOA dns/shop.example/@", "Microsoft.Network/dnsZones/NS dns/shop.example/@", "Microsoft.Network/privateDnsZones/SOA dns/core.internal/@"} {
		if e := entry(t, r, src); e.State == Refused || len(e.Targets) > 0 || e.Reason == "" {
			t.Errorf("%s: %s %q %v", src, e.State, e.Reason, e.Targets)
		}
	}
	if l := lossAbout(entry(t, r, "Microsoft.Network/dnsZones/SOA dns/shop.example/@"), "negative-caching"); l == nil || l.Widens {
		t.Error("the SOA's timers are not named")
	}
	if !anyRequirement(r, "Delegation of shop.example.") || !anyRequirement(r, "moves traffic") {
		t.Errorf("no delegation requirement: %v", r.Report.Requirements)
	}
	if !anyRequirement(r, "shop-app.azurewebsites.net.") {
		t.Errorf("a CNAME to Azure is not named: %v", r.Report.Requirements)
	}
	// The private zone is associated with the network family's VPC.
	pz := object(t, r, "aws", awsZone, "core.internal.")
	if fmt.Sprint(pz["VPCs"]) != "[map[VPCId:{{truthform|AWS::EC2::VPC|core|VpcId}} VPCRegion:eu-west-1]]" {
		t.Errorf("private zone VPCs: %v", pz["VPCs"])
	}
	if old := object(t, r, "aws", awsZone, "old.internal."); old["VPCs"] == nil {
		t.Errorf("legacy private zone: %v", old)
	}
	ze := entry(t, r, "Microsoft.Network/privateDnsZones dns/core.internal")
	if l := lossAbout(ze, "registered"); l == nil || l.Widens || !strings.Contains(l.Field, "core-link") {
		t.Errorf("registration: %+v", ze.Losses)
	}
	if l := lossAbout(entry(t, r, "Microsoft.Network/dnsZones dns/old.internal"), "registered"); l == nil || l.Widens {
		t.Error("legacy registration is not named")
	}
	// DNSSEC: Route 53 cannot sign without a key, so the zone widens.
	pub := entry(t, r, "Microsoft.Network/dnsZones dns/shop.example")
	if l := hasLoss(pub, "dnssecConfigs"); l == nil || !l.Widens {
		t.Errorf("DNSSEC on AWS: %+v", pub.Losses)
	}
	if !anyRequirement(r, "take the DS record out") {
		t.Errorf("no DS requirement: %v", r.Report.Requirements)
	}
	if e := entry(t, r, "Microsoft.Network/dnsZones/dnssecConfigs"); e.State != Mapped {
		t.Errorf("dnssecConfigs: %s", e.State)
	}
}

func TestDNSZonesBecomeManagedZones(t *testing.T) {
	r := runDNS(t, dnsFixture(), dnsMaps()["gcp"])
	zone := object(t, r, "gcp", gcpZone, gcpProject+"/managedZones/shop-example")
	if zone["dnsName"] != "shop.example." || zone["visibility"] != "public" || zone["name"] != "shop-example" {
		t.Errorf("public zone: %v", zone)
	}
	if fmt.Sprint(zone["dnssecConfig"]) != "map[state:on]" {
		t.Errorf("DNSSEC on GCP: %v", zone["dnssecConfig"])
	}
	if fmt.Sprint(zone["labels"]) != "map[env:dev]" {
		t.Errorf("labels: %v", zone["labels"])
	}
	pub := entry(t, r, "Microsoft.Network/dnsZones dns/shop.example")
	if l := hasLoss(pub, "tags.Cost Center"); l == nil || l.Widens {
		t.Errorf("a tag that is no label: %+v", pub.Losses)
	}
	if l := hasLoss(pub, "dnssecConfigs"); l != nil {
		t.Errorf("DNSSEC lost on GCP: %+v", l)
	}
	if !anyRequirement(r, "replace the DS record") {
		t.Errorf("no DS requirement: %v", r.Report.Requirements)
	}
	rs := object(t, r, "gcp", gcpRRSet, gcpProject+"/managedZones/shop-example/rrsets/shop.example./MX")
	if rs["ttl"] != 3600 || fmt.Sprint(rs["rrdatas"]) != "[10 mail1.shop.example. 20 mail2.shop.example.]" || rs["type"] != "MX" || rs["name"] != "shop.example." {
		t.Errorf("MX: %v", rs)
	}
	pz := object(t, r, "gcp", gcpZone, gcpProject+"/managedZones/core-internal")
	if pz["visibility"] != "private" || fmt.Sprint(pz["privateVisibilityConfig"]) != "map[networks:[map[networkUrl:"+computeBase+gcpProject+"/global/networks/core]]]" {
		t.Errorf("private zone: %v", pz)
	}
	if !anyRequirement(r, "Delegation of shop.example.") {
		t.Errorf("no delegation requirement: %v", r.Report.Requirements)
	}
}

// What cannot be carried over as it is, is refused, on both targets.
func TestDNSRefusals(t *testing.T) {
	for name, m := range dnsMaps() {
		r := runDNS(t, dnsFixture(), m)
		for src, about := range map[string]string{
			"Microsoft.Network/dnsZones/A dns/shop.example/www":                                  "alias",
			"Microsoft.Network/privateDnsZones/virtualNetworkLinks dns/core.internal/gone-link":  "not in the snapshot",
			"Microsoft.Network/privateDnsZones/virtualNetworkLinks dns/core.internal/empty-link": "is refused",
			"Microsoft.Network/privateDnsZones dns/orphan.internal":                              "every network",
			"Microsoft.Network/privateDnsZones/A dns/orphan.internal/x":                          "its zone",
			"Microsoft.Network/privateDnsZones/virtualNetworkLinks dns/orphan.internal/gone":     "its zone",
			"Microsoft.Network/privateDnsZones/A dns/core.internal/web":                          "no records",
			"Microsoft.Network/dnsZones/A dns/missing.example/x":                                 "not in the snapshot",
		} {
			if e := entry(t, r, src); e.State != Refused || !strings.Contains(e.Reason, about) {
				t.Errorf("%s: %s: %s %q", name, src, e.State, e.Reason)
			}
		}
		if e := entry(t, r, "Microsoft.Network/privateDnsZones/virtualNetworkLinks dns/core.internal/core-link"); e.State != Mapped {
			t.Errorf("%s: core-link: %s %q", name, e.State, e.Reason)
		}
		// The alias's name is written for its other type, and not for A.
		for _, o := range r.Snapshots[m.To].Objects {
			b := canonJSON(o.Body)
			if strings.Contains(b, "www.shop.example.") && strings.Contains(b, `"A"`) {
				t.Errorf("%s: the alias is written: %s", name, o.Key())
			}
			if strings.Contains(b, "orphan.internal") {
				t.Errorf("%s: the refused zone is written: %s", name, o.Key())
			}
		}
		// Every widening is DNSSEC on AWS, and nothing else.
		for _, e := range r.Report.Entries {
			for _, l := range e.Losses {
				if l.Widens && !(name == "aws" && l.Field == "dnssecConfigs") {
					t.Errorf("%s: %s %s widens: %s", name, e.Source, l.Field, l.Why)
				}
				if l.Unread {
					t.Errorf("%s: %s %s unread", name, e.Source, l.Field)
				}
			}
		}
	}
}

// What the map does not choose is refused, never filled in.
func TestDNSNeedsItsChoices(t *testing.T) {
	m := dnsMaps()["aws"]
	m.Destinations.DNS = ""
	r := runDNS(t, dnsFixture(), m)
	for _, src := range []string{"Microsoft.Network/dnsZones dns/shop.example", "Microsoft.Network/privateDnsZones dns/core.internal"} {
		if e := entry(t, r, src); e.State != Refused || !strings.Contains(e.Reason, "destinations.dns") {
			t.Errorf("%s: %s %q", src, e.State, e.Reason)
		}
	}
	if e := entry(t, r, "Microsoft.Network/dnsZones/MX dns/shop.example/@"); e.State != Refused {
		t.Errorf("a record of a refused zone: %s", e.State)
	}
	if e := entry(t, r, "Microsoft.Network/dnsZones/dnssecConfigs"); e.State != Refused {
		t.Errorf("DNSSEC of a refused zone: %s", e.State)
	}
	if len(objectByKind(r, "aws", awsZone)) != 0 {
		t.Error("zones written with no destination")
	}
	// Without the network, a private zone has nothing to answer in.
	m = dnsMaps()["gcp"]
	m.Destinations.Network = ""
	r = runDNS(t, dnsFixture(), m)
	if e := entry(t, r, "Microsoft.Network/privateDnsZones dns/core.internal"); e.State != Refused {
		t.Errorf("private zone with no network: %s %q", e.State, e.Reason)
	}
	if e := entry(t, r, "Microsoft.Network/dnsZones dns/old.internal"); e.State != Refused || !strings.Contains(e.Reason, "is refused") {
		t.Errorf("legacy private zone with no network: %s %q", e.State, e.Reason)
	}
	if e := entry(t, r, "Microsoft.Network/dnsZones dns/shop.example"); e.State == Refused {
		t.Errorf("a public zone needs no network: %s %q", e.State, e.Reason)
	}
	for name, bad := range map[string]Map{
		"route53 on gcp":   {To: "gcp", Destinations: dnsMaps()["gcp"].Destinations},
		"cloud-dns on aws": {To: "aws", Region: "r", Destinations: dnsMaps()["gcp"].Destinations},
		"unknown":          {To: "aws", Region: "r"},
	} {
		switch name {
		case "route53 on gcp":
			bad.Destinations.DNS = "route53"
		case "unknown":
			bad.Destinations.DNS = "bind"
		}
		bad.Destinations.Network = ""
		if _, err := Translate(dnsFixture(), bad, targets(t)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !dnsMaps()["aws"].NeedsAWS() || !dnsMaps()["gcp"].NeedsGCP() {
		t.Error("the DNS destinations do not load their definitions")
	}
	dm := Map{To: "aws", Region: "r"}
	dm.Destinations.DNS = "route53"
	if !dm.NeedsAWS() {
		t.Error("route53 alone does not load the AWS registry")
	}
	gm := Map{To: "gcp"}
	gm.Destinations.DNS = "cloud-dns"
	if !gm.NeedsGCP() || !contains(gm.destinationList(), "dns: cloud-dns") {
		t.Error("cloud-dns alone does not load the Discovery documents")
	}
}

// A zone name Cloud DNS does not take is refused, naming the map key.
func TestDNSZoneNamesFollowCloudDNS(t *testing.T) {
	m := dnsMaps()["gcp"]
	m.Names = map[string]string{"Microsoft.Network/dnsZones dns/shop.example": "Shop_Zone"}
	r := runDNS(t, dnsFixture(), m)
	if e := entry(t, r, "Microsoft.Network/dnsZones dns/shop.example"); e.State != Refused || !strings.Contains(e.Reason, "names") {
		t.Errorf("bad name: %s %q", e.State, e.Reason)
	}
	m.Names["Microsoft.Network/dnsZones dns/shop.example"] = "storefront"
	r = runDNS(t, dnsFixture(), m)
	object(t, r, "gcp", gcpZone, gcpProject+"/managedZones/storefront")
	object(t, r, "gcp", gcpRRSet, gcpProject+"/managedZones/storefront/rrsets/shop.example./A")
}

// A setting no rule reads fails the translation; a record it cannot read
// refuses its set.
func TestDNSUnknownSettings(t *testing.T) {
	s := dnsFixture()
	s.Objects = append(s.Objects,
		rec("A", "shop.example", "new", map[string]any{"TTL": 60, "ARecords": []any{map[string]any{"ipv4Address": "192.0.2.7"}}, "someNewSetting": "x"}),
		rec("A", "shop.example", "bad", map[string]any{"TTL": 60, "ARecords": []any{map[string]any{"ipv4Address": "2001:db8::1"}}}),
		rec("MX", "shop.example", "nottl", map[string]any{"MXRecords": []any{map[string]any{"preference": 1, "exchange": "m.example"}}}),
		rec("A", "shop.example", "mixed", map[string]any{"TTL": 60, "ARecords": []any{map[string]any{"ipv4Address": "192.0.2.8"}}, "MXRecords": []any{map[string]any{"preference": 1, "exchange": "m.example"}}}),
	)
	for name, m := range dnsMaps() {
		r := runDNS(t, s, m)
		if l := hasLoss(entry(t, r, "Microsoft.Network/dnsZones/A dns/shop.example/new"), "properties.someNewSetting"); l == nil || !l.Unread {
			t.Errorf("%s: an unknown setting: %+v", name, l)
		}
		if e := entry(t, r, "Microsoft.Network/dnsZones/A dns/shop.example/bad"); e.State != Refused || !strings.Contains(e.Reason, "IPv4") {
			t.Errorf("%s: an IPv6 address in an A set: %s %q", name, e.State, e.Reason)
		}
		if e := entry(t, r, "Microsoft.Network/dnsZones/MX dns/shop.example/nottl"); e.State != Refused || !strings.Contains(e.Reason, "TTL") {
			t.Errorf("%s: no TTL: %s %q", name, e.State, e.Reason)
		}
		if l := lossAbout(entry(t, r, "Microsoft.Network/dnsZones/A dns/shop.example/mixed"), "MX records on a record set of type A"); l == nil || l.Widens {
			t.Errorf("%s: another type's records: %+v", name, l)
		}
		if !r.Report.Failed() {
			t.Errorf("%s: not failed", name)
		}
	}
}

// AWS names follow a capture's: by DNS name, then -2, -3 for the next
// sets of a name. Each name is unique, and the same every run.
func TestDNSAWSNames(t *testing.T) {
	r := runDNS(t, dnsFixture(), dnsMaps()["aws"])
	seen := map[string]bool{}
	apex := 0
	for _, o := range objectByKind(r, "aws", awsRecord) {
		if seen[o.Name()] {
			t.Errorf("two record sets named %s", o.Name())
		}
		seen[o.Name()] = true
		if strings.HasPrefix(o.Name(), "shop.example.") {
			apex++
		}
	}
	if apex != 5 || !seen["shop.example."] || !seen["shop.example.-5"] || seen["shop.example.-6"] {
		t.Errorf("apex names: %v", seen)
	}
	again := runDNS(t, dnsFixture(), dnsMaps()["aws"])
	for i, o := range objectByKind(again, "aws", awsRecord) {
		if objectByKind(r, "aws", awsRecord)[i].Name() != o.Name() {
			t.Errorf("names differ between runs: %s", o.Name())
		}
	}
}

func TestDNSRestores(t *testing.T) {
	tg := targets(t)
	s := runDNS(t, dnsFixture(), dnsMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	if c := f.Count(); c[awsZone] != 3 || c[awsRecord] != 14 {
		t.Errorf("aws created %v", c)
	}
	for _, id := range f.IDs(awsRecord) {
		if z := fmt.Sprint(f.Stored(awsRecord, id)["HostedZoneId"]); strings.Contains(z, "{{") || z == "" {
			t.Errorf("record set %s: zone %q", id, z)
		}
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runDNS(t, dnsFixture(), dnsMaps()["gcp"]).Snapshots["gcp"]
	gf := gcp.NewWorld(tg.GCP).Project("target-project", "123456789")
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK {
			t.Errorf("gcp %s: %s", res.Key, res.Detail)
		}
	}
	got, err := gf.Call(context.Background(), "GET", "https://dns.googleapis.com/dns/v1/projects/target-project/managedZones/shop-example/rrsets/shop.example./TXT", nil)
	if err != nil || len(list(got["rrdatas"])) != 3 {
		t.Errorf("TXT in the project: %v %v", got, err)
	}
	pz, err := gf.Call(context.Background(), "GET", "https://dns.googleapis.com/dns/v1/projects/target-project/managedZones/core-internal", nil)
	if err != nil || !strings.Contains(canonJSON(pz), "projects/target-project/global/networks/core") {
		t.Errorf("private zone in the project: %v %v", pz, err)
	}
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("gcp again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}

// The text forms the targets take.
func TestDNSText(t *testing.T) {
	if q := quoteDNS("a\"b\\c\x01é"); q != `"a\"b\\c\001\195\169"` {
		t.Errorf("quote: %s", q)
	}
	if dnsHost("x.example") != "x.example." || dnsHost("x.example.") != "x.example." {
		t.Error("host")
	}
	data, _, why := recordData("NAPTR", "NAPTRRecords", []any{map[string]any{"order": 100, "preference": 10, "flags": "U", "services": "E2U+sip", "regexp": "!^.*$!sip:info@shop.example!", "replacement": ""}})
	if why != "" || len(data) != 1 || data[0] != `100 10 "U" "E2U+sip" "!^.*$!sip:info@shop.example!" .` {
		t.Errorf("NAPTR: %v %s", data, why)
	}
	data, _, why = recordData("TLSA", "TLSARecords", []any{map[string]any{"usage": 3, "selector": 1, "matchingType": 1, "certAssociationData": "ABCD"}})
	if why != "" || data[0] != "3 1 1 ABCD" {
		t.Errorf("TLSA: %v %s", data, why)
	}
	if _, _, why := recordData("SRV", "SRVRecords", []any{map[string]any{"priority": 1, "weight": 1, "target": "x"}}); !strings.Contains(why, "port") {
		t.Errorf("SRV without a port: %q", why)
	}
}

// A name with a public and a private zone (split horizon): on AWS both are
// written, named as a capture names them, the public one first since it
// references nothing, and a second restore finds both and their records.
func TestDNSSplitHorizonOnAWS(t *testing.T) {
	s := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{
		dnsFixture().Objects[0],
		az("Microsoft.Network/dnsZones", "dns", "shop.example", map[string]any{"location": "global", "properties": map[string]any{}}),
		rec("A", "shop.example", "www", map[string]any{"TTL": 60, "ARecords": []any{map[string]any{"ipv4Address": "203.0.113.20"}}}),
		az("Microsoft.Network/privateDnsZones", "dns", "shop.example", map[string]any{"location": "global"}),
		prec("A", "shop.example", "www", map[string]any{"ttl": 60, "aRecords": []any{map[string]any{"ipv4Address": "10.20.1.20"}}}),
		link("shop.example", "core", vnetRef("net", "core"), false),
	}}
	r := runDNS(t, s, dnsMaps()["aws"])
	if z := object(t, r, "aws", awsZone, "shop.example."); z["VPCs"] != nil {
		t.Errorf("the public zone is not shop.example.: %v", z)
	}
	if z := object(t, r, "aws", awsZone, "shop.example.-2"); z["VPCs"] == nil {
		t.Errorf("the private zone is not shop.example.-2: %v", z)
	}
	if a := object(t, r, "aws", awsRecord, "www.shop.example."); a["HostedZoneId"] != awsRef(awsZone, "shop.example.", "Id") {
		t.Errorf("the public www: %v", a)
	}
	tg := targets(t)
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, r.Snapshots["aws"], awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("%s: %s", res.Key, res.Detail)
		}
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, r.Snapshots["aws"], awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}
