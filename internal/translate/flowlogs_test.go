package translate

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

func init() {
	moreReaders = append(moreReaders, func(rd map[string]reflected) {
		rd[typNIC] = reflected{version: netVersion, name: "nic", read: func(o snapshot.Object) []Loss { return readNIC(o).losses }}
		rd[typASG] = reflected{version: netVersion, name: "asg", read: func(o snapshot.Object) []Loss { return readASG(o).losses }}
		rd["Microsoft.Network/networkWatchers/flowLogs"] = reflected{version: netVersion, name: "w/fl", read: func(o snapshot.Object) []Loss { return readFlowLog(o).losses }}
	})
}

// Every network interface, application security group and flow log type
// Azure defines is read, or named here.
func TestEveryNSGTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	// Alone in a snapshot: an interface has no subnet to be placed in, a
	// flow log nothing to log.
	decided := map[string]State{
		azNIC: Refused, azASG: Mapped, azFlowLog: Refused,
		azNIC + "/tapconfigurations": NotLooked, azNIC + "/ipconfigurations": NotLooked,
		azASG + "/addressprefixsets": NotLooked,
	}
	for _, n := range reg.Names() {
		if l := strings.ToLower(n); nsgClaims(l) {
			if _, ok := decided[l]; !ok {
				t.Errorf("%s has a definition and no decision", n)
			}
		}
	}
	for k, want := range decided {
		props := map[string]any{}
		if k == azFlowLog {
			props = pr(map[string]any{"enabled": true})
		}
		for name, m := range nsgMaps() {
			r := runNSG(t, snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", "x/y", props)}}, m)
			if e := r.Report.Entries[0]; e.State != want {
				t.Errorf("%s: %s: %s (%s), want %s", name, k, e.State, e.Reason, want)
			}
		}
	}
	// With no destination for networks, each is refused for that.
	for _, k := range []string{azNIC, azASG, azFlowLog} {
		r := runNSG(t, snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", "x/y", nil)}}, Map{To: "aws", Region: "eu-west-1"})
		if e := r.Report.Entries[0]; e.State != Refused || !strings.Contains(e.Reason, "destinations.network") {
			t.Errorf("%s with no destination: %s %s", k, e.State, e.Reason)
		}
	}
	// The watcher itself stays Azure's own.
	r := runNSG(t, snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az("Microsoft.Network/networkWatchers", "rg", "w", nil)}}, nsgMaps()["aws"])
	if e := r.Report.Entries[0]; e.State != Refused || !strings.Contains(e.Reason, "Azure creates a network watcher") {
		t.Errorf("a network watcher: %s %s", e.State, e.Reason)
	}
}

func TestNSGsRestore(t *testing.T) {
	tg := targets(t)
	s := runNSG(t, nsgFixture(), nsgMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	// Six NSG groups by themselves, two for interfaces, four markers, the
	// endpoints' own.
	if c := f.Count(); c[awsSG] != 13 || c[awsFlowLog] != 1 || c[awsEndpoint] != 2 {
		t.Errorf("aws created %v", c)
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runNSG(t, nsgFixture(), nsgMaps()["gcp"]).Snapshots["gcp"]
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

// A virtual network flow log becomes a VPC flow log on the VPC or subnet
// (AWS) or VPC Flow Logs on the subnetworks (GCP); an NSG flow log, the
// retiring kind, the same for the networks its NSG is used in.
func TestFlowLogs(t *testing.T) {
	const fl = "Microsoft.Network/networkWatchers/flowLogs NetworkWatcherRG/NetworkWatcher_westeurope/"
	r := runNSG(t, nsgFixture(), nsgMaps()["aws"])
	v := object(t, r, "aws", awsFlowLog, "core-flow-log")
	if v["ResourceType"] != "VPC" || v["ResourceId"] != awsRef(awsVPC, "core", "VpcId") || v["TrafficType"] != "ALL" || v["LogDestinationType"] != "s3" ||
		v["LogDestination"] != "arn:aws:s3:::shop-flow-logs/azure/" || fmt.Sprint(v["MaxAggregationInterval"]) != "60" || v["LogFormat"] != flowLogFormat {
		t.Errorf("the VPC's flow log: %v", v)
	}
	// The format begins with AWS's default fields in their order, and has
	// what lines a record up with Azure's.
	if !strings.HasPrefix(flowLogFormat, "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ") {
		t.Errorf("the format does not begin with the default fields: %s", flowLogFormat)
	}
	for _, f := range []string{"${flow-direction}", "${tcp-flags}", "${pkt-srcaddr}", "${pkt-dstaddr}", "${reject-reason}", "${encryption-status}", "${subnet-id}", "${vpc-id}"} {
		if !strings.Contains(flowLogFormat, f) {
			t.Errorf("the format has no %s", f)
		}
	}
	// The subnet's flow log, the NSG's and the network's are one: the
	// VPC's holds them all.
	if n := len(objectByKind(r, "aws", awsFlowLog)); n != 1 {
		t.Errorf("%d flow logs, want the VPC's alone", n)
	}
	for _, name := range []string{"fl-core", "fl-app-nsg", "fl-data"} {
		if e := entry(t, r, fl+name); e.State != WithLosses || strings.Join(e.Targets, ",") != awsFlowLog+" core-flow-log" {
			t.Errorf("%s: %s %v", name, e.State, e.Targets)
		}
	}
	e := entry(t, r, fl+"fl-core")
	for _, about := range []string{"properties.retentionPolicy", "properties.flowAnalyticsConfiguration", "properties.enabledFilteringCriteria", "properties.format.version", "properties.storageId", "properties.format"} {
		if l := hasLoss(e, about); l == nil || l.Widens {
			t.Errorf("fl-core: %s: %+v", about, l)
		}
	}
	if l := lossAbout(entry(t, r, fl+"fl-app-nsg"), "retires on September 30, 2027"); l == nil || l.Widens {
		t.Errorf("the NSG flow log: %+v", l)
	}
	if e := entry(t, r, fl+"fl-off"); e.State != Mapped || !strings.Contains(e.Reason, "turned off") || len(e.Targets) != 0 {
		t.Errorf("a flow log turned off: %s %s %v", e.State, e.Reason, e.Targets)
	}
	for _, q := range []string{"delivery.logs.amazonaws.com", "expire after 30 day(s)", "fixed format"} {
		if !anyRequirement(r, q) {
			t.Errorf("no requirement about %s", q)
		}
	}
	// Without a bucket, refused: nothing stands for Azure's container.
	m := nsgMaps()["aws"]
	m.Network.FlowLogs = nil
	nr := runNSG(t, nsgFixture(), m)
	if e := entry(t, nr, fl+"fl-core"); e.State != Refused || !strings.Contains(e.Reason, "network.flowLogs.destination") {
		t.Errorf("no destination: %s %s", e.State, e.Reason)
	}
	if n := len(objectByKind(nr, "aws", awsFlowLog)); n != 0 {
		t.Errorf("%d flow logs with nowhere to go", n)
	}
	// A subnet's flow log by itself is the subnet's.
	one := nsgFixture()
	var objs []snapshot.Object
	for _, o := range one.Objects {
		if !strings.HasSuffix(o.Name(), "fl-core") && !strings.HasSuffix(o.Name(), "fl-app-nsg") {
			objs = append(objs, o)
		}
	}
	one.Objects = append(objs, flowLogObj("fl-nic", "Microsoft.Network/networkInterfaces", "vm4-nic", true, nil), flowLogObj("fl-gone", "Microsoft.Network/virtualNetworks", "gone", true, nil),
		flowLogObj("fl-odd", "Microsoft.Compute/virtualMachines", "vm1", true, nil))
	sr := runNSG(t, one, nsgMaps()["aws"])
	if sn := object(t, sr, "aws", awsFlowLog, "core-data-flow-log"); sn["ResourceType"] != "Subnet" || sn["ResourceId"] != awsRef(awsSN, "core-data", "SubnetId") {
		t.Errorf("the subnet's flow log: %v", sn)
	}
	if e := entry(t, sr, fl+"fl-nic"); strings.Join(e.Targets, ",") != awsFlowLog+" core-bare-flow-log" || lossAbout(e, "the whole of its subnet") == nil {
		t.Errorf("an interface's flow log: %v %v", e.Targets, e.Losses)
	}
	if e := entry(t, sr, fl+"fl-gone"); e.State != Refused || !strings.Contains(e.Reason, "not in the snapshot") {
		t.Errorf("a flow log of a network that is not there: %s %s", e.State, e.Reason)
	}
	if e := entry(t, sr, fl+"fl-odd"); e.State != Refused || !strings.Contains(e.Reason, "is not a virtual network") {
		t.Errorf("a flow log of something else: %s %s", e.State, e.Reason)
	}
	if len(objectByKind(sr, "aws", awsFlowLog)) != 2 {
		t.Errorf("flow logs: %v", objectByKind(sr, "aws", awsFlowLog))
	}

	g := runNSG(t, nsgFixture(), nsgMaps()["gcp"])
	for _, sn := range []string{"app", "data", "pe", "legacy", "aks", "bare"} {
		lc := obj(object(t, g, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/core-"+sn)["logConfig"])
		if lc["enable"] != true || lc["aggregationInterval"] != "INTERVAL_1_MIN" || fmt.Sprint(lc["flowSampling"]) != "1" || lc["metadata"] != "INCLUDE_ALL_METADATA" {
			t.Errorf("core-%s: %v", sn, lc)
		}
	}
	if e := entry(t, g, fl+"fl-core"); len(e.Targets) != 6 || lossAbout(e, "Cloud Logging") == nil {
		t.Errorf("gcp fl-core: %v %v", e.Targets, e.Losses)
	}
	for _, q := range []string{"Logging sink", "firewall rule logging", "are kept 30 day(s)"} {
		if !anyRequirement(g, q) {
			t.Errorf("gcp: no requirement about %s", q)
		}
	}
	gs := runNSG(t, one, nsgMaps()["gcp"])
	for sn, want := range map[string]bool{"data": true, "bare": true, "app": false, "pe": false} {
		lc := object(t, gs, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/core-"+sn)["logConfig"]
		if (lc != nil) != want {
			t.Errorf("gcp: core-%s logged: %v", sn, lc)
		}
	}
}

// Flow logs are off where the source had none, unless the map asks for
// them everywhere.
func TestFlowLogsEverywhere(t *testing.T) {
	for name, m := range netMaps() {
		if r := runNet(t, m); strings.Contains(canonJSON(r.Snapshots[m.To].Objects), "FlowLog") || strings.Contains(canonJSON(r.Snapshots[m.To].Objects), "logConfig") {
			t.Errorf("%s: a network the source did not log is logged", name)
		}
		m.Network = &NetworkMap{FlowLogs: &FlowLogsMap{Everywhere: true}}
		if name == "aws" {
			m.Network.Zone = "eu-west-1a"
			if r := runNet(t, m); len(objectByKind(r, "aws", awsFlowLog)) != 0 {
				t.Error("aws: logged everywhere with nowhere to deliver to")
			}
			m.Network.FlowLogs.Destination = "arn:aws:s3:::shop-flow-logs"
		}
		r := runNet(t, m)
		e := entry(t, r, "Microsoft.Network/virtualNetworks net/core")
		if lossAbout(e, "network.flowLogs.everywhere") == nil {
			t.Errorf("%s: %v", name, e.Losses)
		}
		if name == "aws" {
			if v := object(t, r, "aws", awsFlowLog, "core-flow-log"); v["ResourceType"] != "VPC" || !contains(e.Targets, awsFlowLog+" core-flow-log") {
				t.Errorf("aws: %v %v", v, e.Targets)
			}
		} else if obj(object(t, r, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/core-app")["logConfig"])["enable"] != true {
			t.Error("gcp: core-app is not logged")
		}
	}
	for dest, want := range map[string]string{"s3://shop": "is not an S3 bucket's ARN", "arn:aws:s3:::shop-logs/AWSLogs/": "AWSLogs"} {
		m := netMaps()["aws"]
		m.Network.FlowLogs = &FlowLogsMap{Destination: dest}
		if _, err := Translate(netFixture(), m, targets(t)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("destination %s: %v", dest, err)
		}
	}
	g := netMaps()["gcp"]
	g.Network = &NetworkMap{FlowLogs: &FlowLogsMap{Destination: "arn:aws:s3:::shop-logs"}}
	if _, err := Translate(netFixture(), g, targets(t)); err == nil || !strings.Contains(err.Error(), "is for aws") {
		t.Errorf("a destination on gcp: %v", err)
	}
}
