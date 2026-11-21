package translate

import (
	"fmt"
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
	switch {
	case len(v.prefixes) == 0:
		return refuse("it has no IPv4 address range")
	case len(v.prefixes) > 1:
		return refuse(fmt.Sprintf("it has %d address ranges; a VPC with more than one is not translated yet", len(v.prefixes)))
	case v.prefixes[0].Bits() < maxVPC || v.prefixes[0].Bits() > minRange:
		return refuse(fmt.Sprintf("its range %s is outside what a VPC takes (/%d to /%d)", v.prefixes[0], maxVPC, minRange))
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
		if s.prefix.Bits() > minRange || !within([]netip.Prefix{s.prefix}, v.prefixes) {
			return refuse(fmt.Sprintf("subnet %s's range %s is not a /%d or wider inside %s", s.name, s.prefix, minRange, v.prefixes[0]))
		}
	}
	name := d.vpcName(v)
	tags, losses := awsTags(name, v.tags)
	spec := map[string]any{"CidrBlock": v.prefixes[0].String(), "EnableDnsSupport": true, "EnableDnsHostnames": true, "Tags": tags}
	switch v.encryption {
	case "DropUnencrypted":
		spec["VpcEncryptionControl"] = map[string]any{"Mode": "enforce"}
	case "AllowUnencrypted":
		spec["VpcEncryptionControl"] = map[string]any{"Mode": "monitor"}
		losses = append(losses, Loss{Field: "properties.encryption", Why: "Azure encrypts traffic between machines that support it and lets the rest through; AWS's monitor mode reports unencrypted traffic, and Nitro instances encrypt between themselves"})
	}
	e := Entry{Source: v.src, State: Mapped, Losses: append(v.losses, losses...)}
	e.Targets = append(e.Targets, o.add("aws", v.src, awsObject(awsVPC, name, spec)))
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

func (d awsNet) nsg(n *nsg, o *out) {
	e := Entry{Source: n.src, State: Mapped, Losses: append([]Loss(nil), n.losses...)}
	vs := n.vnets()
	for _, v := range vs {
		name := d.m.name(n.src, n.name)
		if len(vs) > 1 {
			name = d.m.name(n.src+"@"+v.src, n.name+"-"+v.name)
		}
		in, inLoss := sgRules(n, v, true)
		outR, outLoss := sgRules(n, v, false)
		e.Losses = append(e.Losses, inLoss...)
		e.Losses = append(e.Losses, outLoss...)
		if len(outR) == 0 {
			e.Losses = append(e.Losses, Loss{Field: "properties.securityRules", Widens: true,
				Why: "it lets no outbound traffic through; a security group with no outbound rule is given AWS's allow-all, so this one cannot be written as it is"})
		}
		if len(in) > sgQuota || len(outR) > sgQuota {
			o.require(fmt.Sprintf("Security group %s has %d inbound and %d outbound rules; AWS's default quota is %d per direction, so raise it before a restore", name, len(in), len(outR), sgQuota))
		}
		tags, tl := awsTags(name, n.tags)
		e.Losses = append(e.Losses, tl...)
		spec := map[string]any{
			"GroupDescription":     "From Azure network security group " + n.group + "/" + n.name,
			"VpcId":                awsRef(awsVPC, awsNet{d.m}.vpcName(v), "VpcId"),
			"SecurityGroupIngress": in,
			"SecurityGroupEgress":  outR,
			"Tags":                 tags,
		}
		if len(in) == 0 {
			delete(spec, "SecurityGroupIngress")
		}
		e.Targets = append(e.Targets, o.add("aws", n.src, awsObject(awsSG, name, spec)))
		var where []string
		for _, s := range n.subnets {
			if s.vnet == v {
				where = append(where, v.name+"-"+s.name)
				if ns := o.netSubs[strings.ToLower(v.group+"/"+v.name+"/"+s.name)]; ns != nil {
					ns.tag = name
				}
			}
		}
		o.require(fmt.Sprintf("Security group %s takes the place of an NSG on subnet(s) %s: an AWS security group applies only to what attaches it, so attach it to the instances (and node groups) in them", name, strings.Join(where, ", ")))
	}
	o.entries = append(o.entries, e)
}

// sgRules is what one direction of an NSG allows in a network, as security
// group rules: each allow with every deny before it taken out.
func sgRules(n *nsg, v *vnet, inbound bool) ([]any, []Loss) {
	applied := n.subnetsIn(v)
	var denies, allowed []box
	var losses []Loss
	field := func(r nsgRule) string { return "properties.securityRules[" + r.name + "]" }
	for _, r := range n.ordered() {
		if r.inbound != inbound {
			continue
		}
		peers, exact := r.peer.resolve(v)
		selfAll := coversSelf(r.self, v, applied)
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
			denies = append(denies, r.boxes(peers)...)
			continue
		}
		if r.builtin && r.name == "AllowAzureLoadBalancerInBound" {
			continue // an AWS load balancer checks health from inside the VPC, which AllowVnetInBound allows
		}
		switch {
		case r.srcPorts:
			losses = append(losses, Loss{Field: field(r), Why: r.String() + " names source ports; a security group cannot, so it is not carried over"})
			continue
		case !selfAll:
			losses = append(losses, Loss{Field: field(r), Why: r.String() + " applies to part of its subnets' addresses; a security group applies to whole instances, so it is not carried over: give those instances a security group of their own"})
			continue
		case !exact && len(peers) == 0:
			losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s allows %s, which has no addresses here; it is not carried over", r, strings.Join(r.peer.other, ", "))})
			continue
		case !exact:
			losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s also allows %s, which has no addresses here; only its address ranges are carried over", r, strings.Join(r.peer.other, ", "))})
		}
		bs := r.boxes(peers)
		for _, dn := range denies {
			var next []box
			for _, b := range bs {
				parts, narrowed := b.minus(dn)
				if narrowed {
					losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s allows every protocol, and a deny before it takes out %s; a security group cannot write every protocol but one, so it allows TCP, UDP, ICMP, ESP and AH, and no other protocol (GRE, SCTP and the like)", r, dn.proto)})
				}
				next = append(next, parts...)
			}
			bs = next
		}
		allowed = append(allowed, bs...)
	}
	var rules []any
	for _, b := range tidy(allowed) {
		for _, p := range b.peer {
			rules = append(rules, sgRule(b, p))
		}
	}
	return rules, dedupeLosses(losses)
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
