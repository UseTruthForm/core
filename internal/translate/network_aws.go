package translate

import (
	"fmt"
	"github.com/usetruthform/core/internal/awscc"
	"net/netip"
	"sort"
	"strings"
)

// Networks on AWS: a VPC per virtual network, a subnet per subnet in the
// availability zone the map names, and a security group per network an
// NSG is used in, holding what the NSG allows with its denies taken out.

const (
	awsVPC   = "AWS::EC2::VPC"
	awsSN    = "AWS::EC2::Subnet"
	awsSG    = "AWS::EC2::SecurityGroup"
	sgQuota  = 60 // rules per direction, AWS's default quota
	maxVPC   = 16 // widest VPC range, /16
	minRange = 28 // narrowest VPC or subnet range, /28
)

type awsNet struct{ m Map }

func awsTags(name string, tags map[string]string) ([]any, []Loss) {
	out := []any{map[string]any{"Key": "Name", "Value": name}}
	var losses []Loss
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch {
		case strings.EqualFold(k, "Name"):
			losses = append(losses, Loss{Field: "tags.Name", Why: "AWS's Name tag holds the name the translation gives it"})
		case strings.HasPrefix(strings.ToLower(k), "aws:"):
			losses = append(losses, Loss{Field: "tags." + k, Why: "AWS reserves tags that begin aws:"})
		default:
			out = append(out, map[string]any{"Key": k, "Value": tags[k]})
		}
	}
	return out, losses
}

func (d awsNet) vpcName(v *vnet) string { return d.m.name(v.src, v.name) }

func (d awsNet) vnet(v *vnet, o *out) bool {
	refuse := func(why string) bool {
		o.entries = append(o.entries, Entry{Source: v.src, State: Refused, Reason: why})
		return false
	}
	if len(v.prefixes) == 0 {
		return refuse("it has no IPv4 address range")
	}
	blocks, why := vpcBlocks(v.prefixes)
	if why != "" {
		return refuse(why)
	}
	var noZone []string
	for _, s := range v.subnets {
		if d.m.zoneFor(v.group+"/"+v.name+"/"+s.name) == "" {
			noZone = append(noZone, s.name)
		}
	}
	if len(noZone) > 0 {
		return refuse(fmt.Sprintf("the map names no availability zone for subnet(s) %s (network.zone, or network.zones by group/network/subnet): an AWS subnet is in one zone, and an Azure one is not", strings.Join(noZone, ", ")))
	}
	for _, s := range v.subnets {
		if !s.prefix.IsValid() {
			return refuse("subnet " + s.name + " has no IPv4 range")
		}
		if _, ok := vpcBlockOf(blocks, s.prefix); s.prefix.Bits() > minRange || !ok {
			return refuse(fmt.Sprintf("subnet %s's range %s is not a /%d to /%d inside one of the VPC's blocks (%s)", s.name, s.prefix, maxVPC, minRange, prefixList(blocks)))
		}
	}
	name := d.vpcName(v)
	tags, losses := awsTags(name, v.tags)
	spec := map[string]any{"CidrBlock": blocks[0].String(), "EnableDnsSupport": true, "EnableDnsHostnames": true, "Tags": tags}
	switch v.encryption {
	case "DropUnencrypted":
		spec["VpcEncryptionControl"] = map[string]any{"Mode": "enforce"}
	case "AllowUnencrypted":
		spec["VpcEncryptionControl"] = map[string]any{"Mode": "monitor"}
		losses = append(losses, Loss{Field: "properties.encryption", Why: "Azure encrypts traffic between machines that support it and lets the rest through; AWS's monitor mode reports unencrypted traffic, and Nitro instances encrypt between themselves"})
	}
	e := Entry{Source: v.src, State: Mapped, Losses: append(v.losses, losses...)}
	e.Targets = append(e.Targets, o.add("aws", v.src, awsObject(awsVPC, name, spec)))
	// The rest of its addresses, as blocks added to the VPC. A subnet in
	// one is created once it is associated: the restore orders that, as
	// no reference of the subnet's shows it.
	for _, b := range blocks[1:] {
		// It has no name of its own: it is named as a capture names
		// it, by its spec, so a second restore finds the first one's.
		bs := map[string]any{"VpcId": awsRef(awsVPC, name, "VpcId"), "CidrBlock": b.String()}
		e.Targets = append(e.Targets, o.add("aws", v.src, awsObject(awsVPCBlock, awscc.SpecName(awsVPCBlock, bs), bs)))
	}
	if len(blocks) > 1 {
		e.Losses = append(e.Losses, Loss{Field: "properties.addressSpace.addressPrefixes",
			Why: fmt.Sprintf("a VPC is created with one block of /%d to /%d and given the rest: %s are written as blocks %s, the same addresses, which AWS routes to each other as one network", maxVPC, minRange, prefixList(v.prefixes), prefixList(blocks))})
	}
	if len(blocks) > vpcBlockQuota {
		o.require(fmt.Sprintf("VPC %s has %d IPv4 CIDR blocks: raise the account's quota \"IPv4 CIDR blocks per VPC\" (%d by default) to at least that before the restore", name, len(blocks), vpcBlockQuota))
	}
	for _, s := range v.subnets {
		sn := name + "-" + s.name
		st, _ := awsTags(sn, nil)
		zone := d.m.zoneFor(v.group + "/" + v.name + "/" + s.name)
		e.Targets = append(e.Targets, o.add("aws", v.src, awsObject(awsSN, sn, map[string]any{
			"VpcId": awsRef(awsVPC, name, "VpcId"), "CidrBlock": s.prefix.String(),
			"AvailabilityZone": zone, "Tags": st,
		})))
		o.netSubs[strings.ToLower(v.group+"/"+v.name+"/"+s.name)] = &netSub{vnet: v.key, awsName: sn, zone: zone}
	}
	o.entries = append(o.entries, e)
	return true
}

// nsgs writes every NSG's security groups: one for the subnets it is on
// in each network, and one for each set of interfaces that share a path
// through it (with another NSG, or as members of an application security
// group its rules single out). Security groups on one interface are added
// together ("the rules from each security group are aggregated to form a
// single set of rules", docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html),
// so two NSGs on a path are never two groups on an interface: what both
// allow is worked out and written as one.
func (d awsNet) nsgs(st *nsgState, o *out) {
	st.w = d
	groups := st.plan(o, false, func(src string, parts ...string) string { return d.m.name(src, strings.Join(parts, "-")) })
	ents := st.entries(o)
	for _, g := range groups {
		name := g.name
		var in, outR []any
		var written [2][]nsgWritten
		for dir, key := range []string{"ingress", "egress"} {
			for _, f := range g.res.final[dir] {
				for _, r := range d.sgRulesFor(st, o, f, g.v, dir == 0) {
					label := fmt.Sprintf("%s %s %s %s", awsSG, name, key, sgRuleString(r, dir == 0))
					fw := f
					if f.asg == "" {
						fw.peer = []netip.Prefix{netip.MustParsePrefix(fmt.Sprint(r["CidrIp"]))}
					}
					written[dir] = append(written[dir], nsgWritten{fw, label})
					if dir == 0 {
						in = append(in, r)
					} else {
						outR = append(outR, r)
					}
				}
			}
		}
		if len(outR) == 0 {
			outR = []any{sgLocalhost()}
		}
		if len(in) > sgQuota || len(outR) > sgQuota {
			o.require(fmt.Sprintf("Security group %s has %d inbound and %d outbound rules; AWS's default quota is %d per direction, so raise it before a restore", name, len(in), len(outR), sgQuota))
		}
		var tagsFrom map[string]string
		desc := "From Azure network security group " + g.nsgs[0].group + "/" + g.nsgs[0].name
		if !g.subnet {
			var names []string
			for _, n := range g.nsgs {
				names = append(names, n.group+"/"+n.name)
			}
			desc = "What Azure NSG " + strings.Join(names, " and ") + " let through on the interfaces " + g.sites[0].name + " stood for"
		} else {
			tagsFrom = g.nsgs[0].tags
		}
		tags, tl := awsTags(name, tagsFrom)
		spec := map[string]any{
			"GroupDescription":     desc,
			"VpcId":                awsRef(awsVPC, awsNet{d.m}.vpcName(g.v), "VpcId"),
			"SecurityGroupIngress": in,
			"SecurityGroupEgress":  outR,
			"Tags":                 tags,
		}
		if len(in) == 0 {
			delete(spec, "SecurityGroupIngress")
		}
		target := o.add("aws", g.nsgs[0].src, awsObject(awsSG, name, spec))
		for i, n := range g.nsgs {
			e := ents[n.key]
			e.Targets = append(e.Targets, target)
			e.Losses = append(e.Losses, g.res.lossesFor(i)...)
			if g.subnet {
				e.Losses = append(e.Losses, tl...)
			}
			e.Evidence = append(e.Evidence, g.res.evidence(i, awsSG+" "+name, written, awsSG+" "+name+": security groups only allow, and no rule of it allows what this denies")...)
		}
		if g.subnet {
			var where []string
			n := g.nsgs[0]
			for _, s := range n.subnets {
				if s.vnet == g.v {
					where = append(where, g.v.name+"-"+s.name)
					if ns := o.netSubs[strings.ToLower(g.v.group+"/"+g.v.name+"/"+s.name)]; ns != nil {
						ns.tag = name
					}
					o.attachments = append(o.attachments, Attachment{Source: "subnet " + g.v.group + "/" + g.v.name + "/" + s.name, NSGs: []string{n.group + "/" + n.name},
						Carries: []string{name}, Attached: "requirement", To: "every instance and node group in subnet " + g.v.name + "-" + s.name + " that no other row names"})
				}
			}
			if len(where) > 0 {
				o.require(fmt.Sprintf("Security group %s takes the place of an NSG on subnet(s) %s: an AWS security group applies only to what attaches it, so attach it to the instances (and node groups) in them", name, strings.Join(where, ", ")))
			} else {
				o.require(fmt.Sprintf("Security group %s is written in VPC %s attached to nothing, as its NSG was", name, awsNet{d.m}.vpcName(g.v)))
			}
		}
	}
	// What each interface carries: its group, and a marker group for each
	// application security group it is in.
	for _, s := range st.sites {
		if s.kind == "endpoint" {
			continue
		}
		carries := append([]string(nil), st.carries[s]...)
		for _, a := range s.asgs() {
			if s.member[a] {
				carries = append(carries, d.marker(st, o, a, s.v))
			}
		}
		st.attach(o, s, carries, "requirement", "what takes the place of "+s.owner)
		if len(carries) == 0 {
			continue
		}
		o.require(fmt.Sprintf("What takes the place of %s (%s) carries security group(s) %s and no other translated from an NSG: security groups on one interface add up, so the group of either NSG alone beside it would let through what the other denied", s.owner, s.src, strings.Join(carries, ", ")))
		if len(carries) > sgPerInterface {
			o.require(fmt.Sprintf("What takes the place of %s carries %d security groups; AWS's default quota is %d per network interface, so raise it", s.owner, len(carries), sgPerInterface))
		}
	}
	for _, k := range sortedMapKeys(st.asgs) {
		a := st.asgs[k]
		e := Entry{Source: a.src, State: Mapped, Losses: a.losses}
		if !a.inSnapshot {
			continue
		}
		var members []string
		for _, s := range a.sites {
			members = append(members, s.owner)
		}
		for _, mk := range sortedMapKeys(st.markers) {
			if strings.HasPrefix(mk, k+"|") {
				e.Targets = append(e.Targets, awsSG+" "+st.markers[mk])
				o.require(fmt.Sprintf("Security group %s marks the members of application security group %s/%s and has no rules of its own: what takes the place of each member carries it beside its own group (members on Azure: %s)", st.markers[mk], a.group, a.name, orDefault(strings.Join(uniqueSorted(members), ", "), "none in the snapshot")))
			}
		}
		if len(e.Targets) == 0 {
			e.Reason = "no rule of a translated NSG names it and nothing in the snapshot is in it: there is nothing to write"
		} else {
			e.Reason = "a security group with no rules, which rules name as their source or destination and members carry"
			_, tl := awsTags(a.name, a.tags)
			e.Losses = append(e.Losses, tl...)
		}
		o.entries = append(o.entries, e)
	}
	st.flush(o, ents)
}

// sgPerInterface is AWS's default quota of security groups on one network
// interface (docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html).
const sgPerInterface = 5

// sgLocalhost is the one rule that leaves a security group with no way
// out: "The default rule is removed only when you specify one or more
// egress rules. If you want to remove the default rule and limit egress
// traffic to just the localhost (127.0.0.1/32), use the following example"
// (docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroup.html).
// Without it a group with no outbound rule is given AWS's allow-all.
func sgLocalhost() map[string]any {
	return map[string]any{"IpProtocol": "-1", "CidrIp": "127.0.0.1/32"}
}

// marker is the security group that stands for an ASG in a network,
// written when first asked for. It has no rules: carrying it lets nothing
// through, and only says who its carrier is.
func (d awsNet) marker(st *nsgState, o *out, asg string, v *vnet) string {
	k := asg + "|" + v.key
	if name, ok := st.markers[k]; ok {
		return name
	}
	a := st.asg(asg)
	name := d.m.name(a.src, a.name)
	for mk, other := range st.markers {
		if other == name && strings.HasPrefix(mk, asg+"|") {
			name = d.m.name(a.src+"@"+v.src, a.name+"-"+v.name)
		}
	}
	st.markers[k] = name
	tags, _ := awsTags(name, a.tags)
	o.add("aws", a.src, awsObject(awsSG, name, map[string]any{
		"GroupDescription":    "Members of Azure application security group " + a.group + "/" + a.name,
		"VpcId":               awsRef(awsVPC, d.vpcName(v), "VpcId"),
		"SecurityGroupEgress": []any{sgLocalhost()},
		"Tags":                tags,
	}))
	return name
}

// sgRulesFor writes one tidied part as security group rules: one per
// address range, or one naming the ASG's marker group.
func (d awsNet) sgRulesFor(st *nsgState, o *out, f nsgFinal, v *vnet, inbound bool) []map[string]any {
	if f.asg != "" {
		r := sgRule(f.box, anyV4)
		delete(r, "CidrIp")
		key := "DestinationSecurityGroupId"
		if inbound {
			key = "SourceSecurityGroupId"
		}
		r[key] = awsRef(awsSG, d.marker(st, o, f.asg, v), "GroupId")
		return []map[string]any{r}
	}
	var out []map[string]any
	for _, p := range f.peer {
		out = append(out, sgRule(f.box, p))
	}
	return out
}

func sgRuleString(r map[string]any, inbound bool) string {
	s := fmt.Sprint(r["IpProtocol"])
	if r["FromPort"] != nil {
		s += fmt.Sprintf("/%v-%v", r["FromPort"], r["ToPort"])
	}
	word := " to "
	if inbound {
		word = " from "
	}
	for _, k := range []string{"CidrIp", "SourceSecurityGroupId", "DestinationSecurityGroupId"} {
		if r[k] != nil {
			return s + word + fmt.Sprint(r[k])
		}
	}
	return s
}

const (
	nsgSelfAll = iota
	nsgSelfPart
	nsgSelfNone
)

// selfState says how much of a site a rule's own side holds: all of it,
// none of it, or part. A rule whose own side is an application security
// group applies to its members only.
func (st *nsgState) selfState(r nsgRule, s *nsgSite) int {
	if len(r.self.asgs) > 0 {
		if r.self.any || r.self.vnet || r.self.internet || len(r.self.prefixes) > 0 || len(r.self.other) > 0 {
			return nsgSelfPart
		}
		for _, a := range r.self.asgs {
			if s.member[a] {
				return nsgSelfAll
			}
		}
		for _, a := range r.self.asgs {
			if s.maybe[a] {
				return nsgSelfPart
			}
		}
		return nsgSelfNone
	}
	if coversSelf(r.self, s.v, s.applied) {
		return nsgSelfAll
	}
	if ps, exact := r.self.resolve(s.v); exact && !prefixesOverlap(ps, s.applied) {
		return nsgSelfNone
	}
	return nsgSelfPart
}

// siteRules is what one direction of an NSG allows at a site, as parts:
// each allow with every deny before it taken out. Evidence of what became
// of each rule comes with it.
func (st *nsgState) siteRules(n *nsg, s *nsgSite, inbound bool) ([]nsgPart, []*nsgEv, []Loss) {
	v := s.v
	var denies, allowed []nsgPart
	var losses []Loss
	var evs []*nsgEv
	var ev *nsgEv
	closeEv := func() {
		if ev != nil {
			losses = append(losses[:ev.from], dedupeLosses(losses[ev.from:])...)
			ev.to = len(losses)
		}
	}
	field := func(r nsgRule) string { return "properties.securityRules[" + r.name + "]" }
	for _, r := range n.ordered() {
		if r.inbound != inbound {
			continue
		}
		closeEv()
		ev = &nsgEv{rule: r, from: len(losses)}
		evs = append(evs, ev)
		peers, exact := r.peer.resolve(v)
		self := st.selfState(r, s)
		if self == nsgSelfNone {
			ev.skipped, ev.note = true, "it names addresses none of which are here ("+routingList(s.applied)+")"
			if len(r.self.asgs) > 0 {
				ev.note = "it applies only to members of application security group " + st.asgName(r.self.asgs[0]) + ", and this is written for what is not in it: its members carry a group of their own"
			}
			continue
		}
		selfAll := self == nsgSelfAll
		if !r.allow {
			if !exact {
				peers = []netip.Prefix{anyV4}
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s names %s, which has no addresses here; it is taken out of what is allowed for every address instead", r, strings.Join(r.peer.other, ", "))})
			}
			if !selfAll {
				losses = append(losses, Loss{Field: field(r), Why: r.String() + " applies to part of its subnets' addresses; a security group cannot say which, so it is taken out for all of them"})
			}
			if r.srcPorts {
				losses = append(losses, Loss{Field: field(r), Why: r.String() + " names source ports; a security group cannot, so it is taken out for every source port"})
			}
			for _, b := range r.boxes(peers) {
				denies = append(denies, nsgPart{box: b, rules: [2]string{r.name}})
			}
			for _, a := range r.peer.asgs {
				for _, b := range r.boxes(st.bound(a, v)) {
					denies = append(denies, nsgPart{box: b, asg: a, rules: [2]string{r.name}})
				}
			}
			continue
		}
		if r.builtin && r.name == "AllowAzureLoadBalancerInBound" {
			ev.note = "Azure's load balancer has no addresses on the target, whose load balancers check health from addresses the other rules decide on"
			continue // an AWS load balancer checks health from inside the VPC, which AllowVnetInBound allows
		}
		switch {
		case r.srcPorts:
			losses = append(losses, Loss{Field: field(r), Why: r.String() + " names source ports; a security group cannot, so it is not carried over"})
			continue
		case !selfAll:
			losses = append(losses, Loss{Field: field(r), Why: r.String() + " applies to part of its subnets' addresses; a security group applies to whole instances, so it is not carried over: give those instances a security group of their own"})
			continue
		case !exact && len(peers) == 0 && len(r.peer.asgs) == 0:
			losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s allows %s, which has no addresses here; it is not carried over", r, strings.Join(r.peer.other, ", "))})
			continue
		case !exact:
			losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s also allows %s, which has no addresses here; only its address ranges are carried over", r, strings.Join(r.peer.other, ", "))})
		}
		var bs []nsgPart
		if len(peers) > 0 {
			for _, b := range r.boxes(peers) {
				bs = append(bs, nsgPart{box: b, rules: [2]string{r.name}})
			}
		}
		for _, a := range r.peer.asgs {
			for _, b := range r.boxes(st.bound(a, v)) {
				bs = append(bs, nsgPart{box: b, asg: a, rules: [2]string{r.name}})
			}
		}
		for _, dn := range denies {
			var next []nsgPart
			for _, b := range bs {
				parts, narrowed, why := st.minus(b, dn)
				if narrowed {
					losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s allows every protocol, and a deny before it takes out %s; a security group cannot write every protocol but one, so it allows TCP, UDP, ICMP, ESP and AH, and no other protocol (GRE, SCTP and the like)", r, dn.proto)})
				}
				if why != "" {
					losses = append(losses, Loss{Field: field(r), Why: r.String() + ": " + why})
				}
				next = append(next, parts...)
			}
			bs = next
		}
		ev.kept = true
		allowed = append(allowed, bs...)
	}
	closeEv()
	return allowed, evs, losses
}

func sgRule(b box, p netip.Prefix) map[string]any {
	r := map[string]any{"CidrIp": p.String()}
	switch b.proto {
	case "all":
		r["IpProtocol"] = "-1"
	case "tcp", "udp":
		r["IpProtocol"], r["FromPort"], r["ToPort"] = b.proto, b.lo, b.hi
	case "icmp":
		r["IpProtocol"], r["FromPort"], r["ToPort"] = "icmp", -1, -1
	case "esp":
		r["IpProtocol"] = "50"
	case "ah":
		r["IpProtocol"] = "51"
	}
	return r
}

// coversSelf reports whether a rule's own side holds every address of the
// subnets the NSG is used on in v.
func coversSelf(self addrs, v *vnet, applied []netip.Prefix) bool {
	ps, exact := self.resolve(v)
	return exact && within(applied, ps)
}

func dedupeLosses(ls []Loss) []Loss {
	seen := map[string]bool{}
	var out []Loss
	for _, l := range ls {
		k := l.Field + "\x00" + l.Why
		if !seen[k] {
			seen[k] = true
			out = append(out, l)
		}
	}
	return out
}

// prefixList is ranges as text, in the order given.
func prefixList(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}
