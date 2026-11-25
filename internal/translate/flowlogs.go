package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Flow logs: Azure's networkWatchers/flowLogs, which record the flows
// through a virtual network, a subnet or a network interface (virtual
// network flow logs) or through an NSG (NSG flow logs, which "retire on
// September 30, 2027" and can no longer be created,
// learn.microsoft.com/azure/network-watcher/nsg-flow-logs-overview).
//
// On AWS one becomes a VPC flow log on the VPC or subnet, delivered to the
// S3 bucket the map names, every minute as Azure does ("Logs are collected
// at 1-minute intervals"), in the fixed format flowLogFormat. On GCP it
// turns on VPC Flow Logs on the subnetworks, unsampled, every minute, with
// all metadata; the records go to Cloud Logging. What a record holds on
// each cloud differs: docs/guide.md has the table a parser needs.

const (
	awsFlowLog = "AWS::EC2::FlowLog"
	// flowLogFormat is the record AWS writes: the default fields first, in
	// their order, then what a parser needs to line a record up with
	// Azure's tuple (direction, TCP flags for the flow's state, the packet's
	// own addresses behind a NAT, why it was rejected, whether it was
	// encrypted). docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
	flowLogFormat = "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}" +
		" ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${flow-direction} ${traffic-path} ${reject-reason} ${encryption-status}"
)

var flowLogARN = regexp.MustCompile(`^arn:aws[a-z-]*:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](/.*)?$`)

type flowLog struct {
	src, name      string
	enabled        bool
	typ, target    string // what it logs: the ARM type (lower case) and group/name
	losses         []Loss
	retentionDays  int
	storage        string
	nsgKind        bool
	unreadableWhat string
}

func readFlowLog(o snapshot.Object) *flowLog {
	f := &flowLog{src: source(o), name: o.Name()}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag")
	if t := stringTags(top.m["tags"]); len(t) > 0 {
		top.lose("tags", "the flow log's tags are not carried over: on GCP it is a setting of a subnetwork, and on AWS the flow log is named for what it logs", false)
	}
	top.quiet("tags")
	if id := obj(top.m["identity"]); len(id) > 0 && !strings.EqualFold(fmt.Sprint(id["type"]), "None") {
		top.lose("identity", "the identity it wrote to the storage account with is not translated: AWS's log delivery service writes to the bucket by the bucket's policy, and GCP writes to Cloud Logging itself", false)
	}
	top.quiet("identity")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "targetResourceGuid")
	f.enabled = p.boolean("enabled")
	id := p.str("targetResourceId")
	if m := azRefRE.FindStringSubmatch(id); m != nil {
		f.typ, f.target = strings.ToLower(m[1]), strings.ToLower(m[2]+"/"+m[3])
	} else if k := subnetKey(id); k != "" {
		f.typ, f.target = azSubnet, k
	} else if t, g, n := armID(id); t != "" {
		f.typ, f.target = t, strings.ToLower(g+"/"+n)
	} else {
		f.unreadableWhat = id
	}
	f.nsgKind = f.typ == azNSG
	f.storage = nsgRefName(p.str("storageId"))
	if rp := obj(p.m["retentionPolicy"]); len(rp) > 0 {
		r := newProps(rp, "properties.retentionPolicy.")
		on := r.boolean("enabled")
		if d := r.integer("days"); on && d != nil && *d > 0 {
			f.retentionDays = *d
		}
		f.losses = append(f.losses, r.rest()...)
	}
	p.quiet("retentionPolicy")
	if fm := obj(p.m["format"]); len(fm) > 0 {
		r := newProps(fm, "properties.format.")
		r.quiet("type")
		if v := r.integer("version"); v != nil {
			r.lose("version", fmt.Sprintf("version %d of Azure's record is not what the target writes: a parser reads each cloud's own record (the guide's record-field table lines them up)", *v), false)
		}
		f.losses = append(f.losses, r.rest()...)
	}
	p.quiet("format")
	if a := obj(obj(p.m["flowAnalyticsConfiguration"])["networkWatcherFlowAnalyticsConfiguration"]); len(a) > 0 {
		if on, _ := a["enabled"].(bool); on {
			p.lose("flowAnalyticsConfiguration", "traffic analytics is not translated: the target's records are analysed with its own tools (Athena or CloudWatch Logs Insights; Log Analytics or BigQuery)", false)
		}
	}
	p.quiet("flowAnalyticsConfiguration")
	if c := p.str("enabledFilteringCriteria"); c != "" {
		p.lose("enabledFilteringCriteria", "it recorded only flows matching "+c+"; the target records every flow, which is more: Azure's filter has no equal on AWS, and GCP's filter expressions are written in another language", false)
	}
	if c := p.str("recordTypes"); c != "" {
		p.lose("recordTypes", "it recorded only flow states "+c+"; the target's records do not carry Azure's flow states, and every flow is recorded", false)
	}
	f.losses = append(append(top.rest(), p.rest()...), f.losses...)
	return f
}

// flowScope is one thing logged on the target: a network or one subnet.
type flowScope struct {
	v   *vnet
	sub *subnet
}

func (s flowScope) key() string {
	if s.sub != nil {
		return s.v.key + "/" + strings.ToLower(s.sub.name)
	}
	return s.v.key
}

// flowLogs writes the flow logs once the networks are written.
func flowLogs(objs []snapshot.Object, st *nsgState, written map[string]bool, o *out) {
	// Whole networks first: a subnet of one already logged needs no log of
	// its own.
	var logs []*flowLog
	for _, x := range objs {
		logs = append(logs, readFlowLog(x))
	}
	sort.SliceStable(logs, func(i, j int) bool {
		if a, b := logs[i].typ == azVNet || logs[i].nsgKind, logs[j].typ == azVNet || logs[j].nsgKind; a != b {
			return a
		}
		return logs[i].src < logs[j].src
	})
	fm := &FlowLogsMap{}
	if o.m.Network != nil && o.m.Network.FlowLogs != nil {
		fm = o.m.Network.FlowLogs
	}
	logged := map[string][]string{} // scope -> the targets that log it
	// write turns logging on for a scope; "" when it cannot.
	write := func(src string, sc flowScope) []string {
		if t, ok := logged[sc.key()]; ok {
			return t
		}
		if t, ok := logged[sc.v.key]; ok && o.m.To == "aws" {
			return t // the VPC's flow log holds its subnets' flows
		}
		var targets []string
		if o.m.To == "aws" {
			vpc := awsNet{o.m}.vpcName(sc.v)
			name, typ, id := vpc+"-flow-log", "VPC", awsRef(awsVPC, vpc, "VpcId")
			if sc.sub != nil {
				sn := vpc + "-" + sc.sub.name
				name, typ, id = sn+"-flow-log", "Subnet", awsRef(awsSN, sn, "SubnetId")
			}
			tags, _ := awsTags(name, nil)
			targets = append(targets, o.add("aws", src, awsObject(awsFlowLog, name, map[string]any{
				"ResourceId": id, "ResourceType": typ, "TrafficType": "ALL",
				"LogDestinationType": "s3", "LogDestination": fm.Destination,
				"MaxAggregationInterval": 60, "LogFormat": flowLogFormat,
				"DestinationOptions": map[string]any{"FileFormat": "plain-text", "HiveCompatiblePartitions": false, "PerHourPartition": true},
				"Tags":               tags,
			})))
		} else {
			for _, s := range sc.v.subnets {
				if sc.sub != nil && s != sc.sub {
					continue
				}
				ns := o.netSubs[sc.v.key+"/"+strings.ToLower(s.name)]
				if ns == nil || ns.spec == nil {
					continue
				}
				// Set outright: the two pages of Google's reference give
				// different defaults for metadata, and sampling is half
				// by default (docs.cloud.google.com/compute/docs/reference/rest/v1/subnetworks).
				ns.spec["logConfig"] = map[string]any{"enable": true, "aggregationInterval": "INTERVAL_1_MIN", "flowSampling": 1.0, "metadata": "INCLUDE_ALL_METADATA"}
				targets = append(targets, gcpSubnet+" "+ns.subnetwork)
			}
		}
		if len(targets) > 0 {
			logged[sc.key()] = targets
		}
		return targets
	}
	wrote := false
	for _, f := range logs {
		e := Entry{Source: f.src, State: Mapped, Losses: f.losses}
		refuse := func(why string) {
			o.entries = append(o.entries, Entry{Source: f.src, State: Refused, Reason: why})
		}
		if !f.enabled {
			e.Reason = "it is turned off on the source, so nothing is logged for it on the target"
			e.Losses = nil
			o.entries = append(o.entries, e)
			continue
		}
		var scopes []flowScope
		why := ""
		switch f.typ {
		case azVNet:
			if v := st.vnets[f.target]; v != nil {
				scopes = append(scopes, flowScope{v: v})
			}
		case azSubnet:
			if s := o.subnets[f.target]; s != nil {
				scopes = append(scopes, flowScope{v: s.vnet, sub: s})
			}
		case azNIC:
			for _, s := range st.sites {
				if s.kind == "nic" && strings.EqualFold(s.src, typNIC+" "+f.target) {
					scopes = append(scopes, flowScope{v: s.v, sub: s.sub})
					e.Losses = append(e.Losses, Loss{Field: "properties.targetResourceId", Why: "it logged one network interface, whose machine is not translated: the whole of its subnet " + s.sub.name + " is logged, which is more"})
				}
			}
		case azNSG:
			n := st.nsgs[f.target]
			if n == nil {
				break
			}
			seen := map[*vnet]bool{}
			vs := append(n.vnets(), st.placed[n.key]...)
			for _, s := range st.sites {
				if s.nicNSG == n {
					vs = append(vs, s.v)
				}
			}
			for _, v := range vs {
				if !seen[v] {
					seen[v] = true
					scopes = append(scopes, flowScope{v: v})
				}
			}
			e.Losses = append(e.Losses, Loss{Field: "properties.targetResourceId", Why: "an NSG flow log, the kind Azure retires on September 30, 2027 in favour of virtual network flow logs: the target logs networks, not rule sets, so the whole of each network its NSG is used in is logged, which is more"})
			if len(scopes) == 0 {
				why = "its network security group " + f.target + " is used in no network of the snapshot, so there is nothing to log"
			}
		default:
			why = fmt.Sprintf("it logs %s, which is not a virtual network, subnet, network interface or network security group", orDefault(f.typ+" "+f.target, f.unreadableWhat))
		}
		switch {
		case why != "":
		case len(scopes) == 0:
			why = "what it logs (" + f.typ + " " + f.target + ") is not in the snapshot"
		case o.m.To == "aws" && fm.Destination == "":
			why = "the map names no S3 bucket for flow logs (network.flowLogs.destination): Azure wrote them to a container of its own in storage account " + f.storage + ", which no bucket stands for"
		}
		for _, sc := range scopes {
			if !written[sc.v.key] && why == "" {
				why = "its network " + sc.v.src + " is refused"
			}
		}
		if why != "" {
			refuse(why)
			continue
		}
		for _, sc := range scopes {
			e.Targets = append(e.Targets, write(f.src, sc)...)
		}
		wrote = true
		if o.m.To == "aws" {
			e.Losses = append(e.Losses, Loss{Field: "properties.storageId", Why: "storage account " + f.storage + " held the records in a container Azure made; AWS delivers them to " + fm.Destination + ", the map's choice, under AWSLogs/"})
			if f.retentionDays > 0 {
				e.Losses = append(e.Losses, Loss{Field: "properties.retentionPolicy", Why: fmt.Sprintf("records were deleted after %d day(s); a flow log on AWS has no retention of its own, so the bucket's lifecycle rules must expire them", f.retentionDays)})
				o.require(fmt.Sprintf("Flow log records under %s expire after %d day(s), as on Azure: set that in the bucket's lifecycle rules (not written here)", fm.Destination, f.retentionDays))
			}
		} else {
			e.Losses = append(e.Losses, Loss{Field: "properties.storageId", Why: "storage account " + f.storage + " held the records; GCP writes them to Cloud Logging (log compute.googleapis.com/vpc_flows), and a sink carries them on to a bucket, BigQuery or Pub/Sub"})
			if f.retentionDays > 0 {
				e.Losses = append(e.Losses, Loss{Field: "properties.retentionPolicy", Why: fmt.Sprintf("records were deleted after %d day(s); on GCP that is the retention of the Cloud Logging bucket they are kept in, which is not written here", f.retentionDays)})
				o.require(fmt.Sprintf("Flow log records are kept %d day(s), as on Azure: set that as the retention of the Cloud Logging bucket that holds compute.googleapis.com/vpc_flows (not written here)", f.retentionDays))
			}
		}
		e.Losses = append(e.Losses, Loss{Field: "properties.format", Why: "the target writes its own record, not Azure's: " + map[string]string{
			"aws": "one line per flow and direction in the fixed format the guide gives, with ACCEPT or REJECT and TCP flags where Azure had flow states B, C, E and D",
			"gcp": "one entry per flow and reporting side with bytes and packets one way; packets an ingress rule denied are not recorded at all unless firewall rule logging is turned on",
		}[o.m.To]})
		o.entries = append(o.entries, e)
	}
	if fm.Everywhere {
		for _, v := range sortedVNets(st.vnets) {
			if !written[v.key] || (o.m.To == "aws" && fm.Destination == "") {
				continue
			}
			if _, ok := logged[v.key]; ok {
				continue
			}
			if e := o.entry(v.src); e != nil {
				e.Targets = append(e.Targets, write(v.src, flowScope{v: v})...)
				e.Losses = append(e.Losses, Loss{Field: "properties", Why: "its flows are logged on the target though the source logged none, or only part: the map asks for flow logs everywhere (network.flowLogs.everywhere)"})
				wrote = true
			}
		}
	}
	if !wrote {
		return
	}
	if o.m.To == "aws" {
		o.require("Flow logs are delivered to " + fm.Destination + " by delivery.logs.amazonaws.com: the bucket's policy must let it write (s3:PutObject under AWSLogs/, s3:GetBucketAcl), which AWS adds itself only when whoever creates the flow log owns the bucket and may change its policy (docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-permissions.html)")
		o.require("VPC flow log records are in the fixed format `" + flowLogFormat + "`, one line per flow and direction every minute: a parser relies on that order (the guide's record-field table)")
	} else {
		o.require("VPC Flow Logs go to Cloud Logging (log compute.googleapis.com/vpc_flows, resource type gce_subnetwork): where a security tool reads them from a bucket, BigQuery or Pub/Sub, add a Logging sink for that log (not written here)")
		o.require("VPC Flow Logs do not record packets an ingress firewall rule denied: turn on firewall rule logging (logConfig on the rules) where denied flows must be seen, as Azure's flow logs showed them (state D)")
	}
	o.require("Flow logs are billed by volume on the target: they are written only where the source logged, unless the map asks for them everywhere")
}
