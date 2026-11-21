package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Networks on GCP: a VPC network per virtual network, a subnetwork per
// subnet in the map's region, and a firewall rule per NSG rule. Firewall
// rules have priorities and denies, as NSG rules do, so each keeps its
// priority. They apply to instances by network tag, where an NSG applies to
// a subnet, so each NSG's rules carry a tag of their own.

const (
	gcpNetwork  = "compute.googleapis.com/Network"
	gcpSubnet   = "compute.googleapis.com/Subnetwork"
	gcpFirewall = "compute.googleapis.com/Firewall"
	computeBase = "https://www.googleapis.com/compute/v1/"
	gcpMTU      = 1500 // Azure's; GCP's default is 1460
)

// gcpHealthChecks are where Google's load balancers check health from.
var gcpHealthChecks = []string{"35.191.0.0/16", "130.211.0.0/22"}

type gcpNet struct{ m Map }

func computeObject(typ, schema, coll, parent, name string, spec map[string]any) snapshot.Object {
	s := map[string]any{"name": name}
	for k, v := range spec {
		s[k] = v
	}
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": typ,
		"metadata": map[string]any{"name": parent + "/" + coll + "/" + name, "annotations": map[string]any{
			"truthform.org/discovery":  "compute/v1",
			"truthform.org/schema":     schema,
			"truthform.org/collection": coll,
			"truthform.org/parent":     parent,
		}}, "spec": s}}
}

func (d gcpNet) netName(v *vnet) string { return d.m.name(v.src, gcpName(v.name)) }

func (d gcpNet) netURL(v *vnet) string {
	return computeBase + gcpProject + "/global/networks/" + d.netName(v)
}

func (d gcpNet) vnet(v *vnet, o *out) bool {
	refuse := func(why string) bool {
		o.entries = append(o.entries, Entry{Source: v.src, State: Refused, Reason: why})
		return false
	}
	if d.m.Region == "" {
		return refuse("the map names no region (region): a subnetwork is regional")
	}
	if len(v.prefixes) == 0 {
		return refuse("it has no IPv4 address range")
	}
	for _, s := range v.subnets {
		if !s.prefix.IsValid() {
			return refuse("subnet " + s.name + " has no IPv4 range")
		}
		if s.prefix.Bits() > 29 {
			return refuse(fmt.Sprintf("subnet %s's range %s is narrower than a subnetwork takes (/29)", s.name, s.prefix))
		}
	}
	name := d.netName(v)
	e := Entry{Source: v.src, State: Mapped, Losses: append(append([]Loss(nil), v.losses...), tagLosses(v.tags, "a VPC network")...)}
	if v.encryption != "" {
		e.Losses = append(e.Losses, Loss{Field: "properties.encryption", Why: v.encryption + " on the source; Google encrypts traffic between VMs in a VPC network itself, and there is no setting for it"})
	}
	e.Targets = append(e.Targets, o.add("gcp", v.src, computeObject(gcpNetwork, "Network", "networks", gcpProject+"/global", name, map[string]any{
		"autoCreateSubnetworks": false, "routingConfig": map[string]any{"routingMode": "REGIONAL"}, "mtu": gcpMTU,
	})))
	region := gcpProject + "/regions/" + d.m.Region
	for _, s := range v.subnets {
		sn := d.m.name(v.group+"/"+v.name+"/"+s.name, gcpName(v.name, s.name))
		obj := computeObject(gcpSubnet, "Subnetwork", "subnetworks", region, sn, map[string]any{
			"ipCidrRange": s.prefix.String(), "network": d.netURL(v), "region": computeBase + region,
		})
		e.Targets = append(e.Targets, o.add("gcp", v.src, obj))
		o.netSubs[strings.ToLower(v.group+"/"+v.name+"/"+s.name)] = &netSub{vnet: v.key, network: gcpProject + "/global/networks/" + name,
			subnetwork: region + "/subnetworks/" + sn, spec: obj.Body["spec"].(map[string]any)}
	}
	o.entries = append(o.entries, e)
	return true
}

// gcpPairPriority is the priority of the rules written for two NSGs on
// one path; the deny that closes their egress comes right after.
const gcpPairPriority = 1000

// nsgs writes every NSG as firewall rules. An NSG by itself is written
// rule for rule under a tag of its own, whatever it is on: a subnet's
// instances and an interface's machine carry the same tag. A rule that
// applies only to an application security group's members is written under
// a tag those members carry beside it, and one that names a group as its
// source names the group's tag.
//
// Two NSGs on one path cannot be two tags: GCP puts every rule that
// applies to an instance in one list by priority ("The highest priority
// rule applicable to a target for a given type of traffic takes
// precedence", docs.cloud.google.com/firewall/docs/firewalls), where Azure
// asks each NSG in turn, so an allow at 100 from one would answer a deny at
// 200 from the other. What both allow is worked out, as for AWS, and
// written under one tag as allows, with a deny of all other egress after
// them (ingress is denied where nothing allows it).
func (d gcpNet) nsgs(st *nsgState, o *out) {
	st.w = d
	groups := st.plan(o, true, func(src string, parts ...string) string { return gcpName(parts...) })
	ents := st.entries(o)
	tags := map[string]string{} // NSG key | network key -> tag
	for _, n := range sortedNSGs(st.nsgs) {
		if n.refuse != "" {
			continue
		}
		e := ents[n.key]
		e.Losses = append(e.Losses, tagLosses(n.tags, "a firewall rule")...)
		applied := map[*vnet][]netip.Prefix{}
		var vs []*vnet
		use := func(v *vnet, ps []netip.Prefix) {
			if _, ok := applied[v]; !ok {
				vs = append(vs, v)
			}
			applied[v] = append(applied[v], ps...)
		}
		for _, s := range st.subnetSites(n) {
			use(s.v, s.applied)
		}
		for _, s := range st.sites {
			if ns := s.nsgs(); s.kind != "endpoint" && len(ns) == 1 && ns[0] == n {
				use(s.v, s.applied)
			}
		}
		sort.Slice(vs, func(i, j int) bool { return vs[i].src < vs[j].src })
		for _, v := range vs {
			tag := gcpName(n.name)
			if len(vs) > 1 {
				tag = gcpName(n.name, v.name)
			}
			tags[n.key+"|"+v.key] = tag
			rules, losses, evidence := d.firewalls(st, n, v, tag, aggregate(applied[v]))
			e.Losses = append(e.Losses, losses...)
			e.Evidence = append(e.Evidence, evidence...)
			for _, fw := range rules {
				e.Targets = append(e.Targets, o.add("gcp", n.src, fw))
			}
			var where []string
			for _, s := range n.subnets {
				if s.vnet == v {
					where = append(where, gcpName(v.name, s.name))
					if ns := o.netSubs[strings.ToLower(v.group+"/"+v.name+"/"+s.name)]; ns != nil {
						ns.tag = tag
					}
					o.attachments = append(o.attachments, Attachment{Source: "subnet " + v.group + "/" + v.name + "/" + s.name, NSGs: []string{n.group + "/" + n.name},
						Carries: []string{tag}, Attached: "requirement", To: "every instance and GKE node in subnetwork " + gcpName(v.name, s.name) + " that no other row names"})
				}
			}
			if len(where) > 0 {
				o.require(fmt.Sprintf("Instances (and GKE nodes) in subnetwork(s) %s carry the network tag %s: an NSG applied to a whole subnet, a firewall rule applies to instances by tag", strings.Join(where, ", "), tag))
			}
			o.require("Google's load balancers check health from " + strings.Join(gcpHealthChecks, " and ") + ": where one fronts these instances, allow those ranges (Azure's load balancer was allowed by every NSG)")
		}
	}
	for _, g := range groups {
		if g.subnet {
			continue
		}
		d.pair(st, g, ents, o)
	}
	for _, s := range st.sites {
		ns := s.nsgs()
		if s.kind == "endpoint" {
			continue
		}
		carries := append([]string(nil), st.carries[s]...)
		if len(ns) == 1 && ns[0].refuse == "" {
			tag := tags[ns[0].key+"|"+s.v.key]
			carries = []string{tag}
			self := nsgSelfASGs(ns[0])
			for _, a := range s.asgs() {
				switch {
				case !self[a]:
				case s.member[a]:
					carries = append(carries, d.selfTag(st, tag, a))
				default:
					if e := o.entry(s.src); e != nil {
						e.Losses = append(e.Losses, Loss{Field: "properties.ipConfigurations", Widens: true,
							Why: "only some of its IP configurations are in application security group " + st.asgName(a) + ", and a network tag is the whole instance's: the rules of " + ns[0].name + " for that group's members, denies among them, are not applied to it"})
					}
				}
			}
		}
		for _, a := range s.asgs() {
			if s.member[a] {
				carries = append(carries, d.marker(st, a))
			}
		}
		st.attach(o, s, carries, "requirement", "what takes the place of "+s.owner)
		if len(carries) > 0 {
			o.require(fmt.Sprintf("What takes the place of %s (%s) carries network tag(s) %s and no other translated from an NSG: every rule that applies to an instance is in one list on GCP, so another NSG's tag beside them would let through what these deny", s.owner, s.src, strings.Join(carries, ", ")))
		}
	}
	for _, k := range sortedMapKeys(st.asgs) {
		a := st.asgs[k]
		if !a.inSnapshot {
			continue
		}
		var members []string
		for _, s := range a.sites {
			members = append(members, s.owner)
		}
		e := Entry{Source: a.src, State: Mapped, Losses: append(append([]Loss(nil), a.losses...), tagLosses(a.tags, "a network tag")...),
			Reason: "network tag " + d.marker(st, a.key) + ": a tag is not an object, so nothing is written; rules name it as their source and members carry it"}
		o.require(fmt.Sprintf("Network tag %s marks the members of application security group %s/%s: what takes the place of each member carries it (members on Azure: %s)", d.marker(st, a.key), a.group, a.name, orDefault(strings.Join(uniqueSorted(members), ", "), "none in the snapshot")))
		o.entries = append(o.entries, e)
	}
	st.flush(o, ents)
}

// marker is the network tag that stands for an ASG. It begins asg-, which
// no tag of an NSG's rules does, so that carrying it brings no rule.
func (d gcpNet) marker(st *nsgState, asg string) string {
	a := st.asg(asg)
	return d.m.name(a.src, gcpName("asg", a.name))
}

// selfTag is the tag of the rules of an NSG that apply to an ASG's
// members only.
func (d gcpNet) selfTag(st *nsgState, tag, asg string) string {
	return gcpName(tag, "as", st.asg(asg).name)
}

// pair writes what two NSGs on one path let through together, under one
// tag.
func (d gcpNet) pair(st *nsgState, g *nsgWrite, ents map[string]*Entry, o *out) {
	tag := g.name
	// An egress rule names its destinations by address: the members of a
	// group cannot be, so such a part is left out.
	var keep []nsgPart
	for _, p := range g.res.parts[1] {
		if p.asg == "" {
			keep = append(keep, p)
			continue
		}
		why := "allows traffic to the members of application security group " + st.asgName(p.asg) + "; a GCP egress rule names destinations by address, and the subnets its members are in hold more than them, so it is not carried over"
		for i := range g.nsgs {
			for _, ev := range g.res.evs[i] {
				if ev.rule.name == p.rules[i] && !ev.rule.inbound && !nsgHas(ev.more, why) {
					ev.more = append(ev.more, why)
				}
			}
		}
	}
	g.res.parts[1], g.res.final[1] = keep, nsgTidy(keep)
	var written [2][]nsgWritten
	var targets []string
	add := func(name string, spec map[string]any) string {
		spec["network"], spec["targetTags"] = d.netURL(g.v), []any{tag}
		t := o.add("gcp", g.nsgs[0].src, computeObject(gcpFirewall, "Firewall", "firewalls", gcpProject+"/global", name, spec))
		targets = append(targets, t)
		return t
	}
	for dir, word := range []string{"in", "out"} {
		// One rule per set of peers, holding every protocol and port
		// allowed for it.
		type set struct {
			f       []nsgFinal
			peer    []netip.Prefix
			srcTags []any
		}
		var sets []*set
		by := map[string]*set{}
		for _, f := range g.res.final[dir] {
			k := "asg " + f.asg
			if f.asg == "" {
				k = routingList(f.peer)
			}
			s := by[k]
			if s == nil {
				s = &set{peer: f.peer}
				if f.asg != "" {
					s.peer, s.srcTags = nil, []any{d.marker(st, f.asg)}
				}
				by[k] = s
				sets = append(sets, s)
			}
			s.f = append(s.f, f)
		}
		n := 0
		for _, s := range sets {
			var allowed []any
			for _, f := range s.f {
				allowed = append(allowed, gcpAllowed(f.box))
			}
			for first := true; first || len(s.peer) > 0; first = false {
				n++
				spec := map[string]any{"priority": gcpPairPriority, "allowed": allowed}
				c := min(len(s.peer), gcpMaxRanges)
				switch {
				case dir == 1:
					spec["direction"], spec["destinationRanges"] = "EGRESS", prefixStrings(s.peer[:c])
				case s.srcTags != nil:
					spec["direction"], spec["sourceTags"] = "INGRESS", s.srcTags
				default:
					spec["direction"], spec["sourceRanges"] = "INGRESS", prefixStrings(s.peer[:c])
				}
				label := add(gcpName(tag, word, fmt.Sprint(n)), spec)
				for _, f := range s.f {
					fw := f
					if f.asg == "" {
						fw.peer = s.peer[:c]
					}
					written[dir] = append(written[dir], nsgWritten{fw, label})
				}
				s.peer = s.peer[c:]
			}
		}
	}
	closing := add(gcpName(tag, "out", "deny"), map[string]any{"priority": gcpPairPriority + 1, "direction": "EGRESS",
		"destinationRanges": []any{anyV4.String()}, "denied": []any{map[string]any{"IPProtocol": "all"}}})
	where := "network tag " + tag
	for i, n := range g.nsgs {
		e := ents[n.key]
		e.Targets = append(e.Targets, targets...)
		for _, l := range g.res.lossesFor(i) {
			l.Why = strings.ReplaceAll(l.Why, "a security group", "a rule set made of two NSGs, which only allows,")
			e.Losses = append(e.Losses, l)
		}
		rows := g.res.evidence(i, where, written, "no rule under "+where+" allows what this denies: ingress is denied where nothing allows it, and "+closing+" denies all other egress")
		for j := range rows {
			rows[j].Why = strings.ReplaceAll(rows[j].Why, "a security group", "a rule set made of two NSGs, which only allows,")
		}
		e.Evidence = append(e.Evidence, rows...)
	}
}

func gcpAllowed(b box) map[string]any {
	e := map[string]any{"IPProtocol": b.proto}
	if b.ported() && !(b.lo == 0 && b.hi == 65535) {
		e["ports"] = []any{portString(b.lo, b.hi)}
	}
	return e
}

// firewalls writes an NSG's rules as firewall rules on one network, with
// Azure's own rules where GCP's implied ones differ: GCP denies all
// ingress and allows all egress at the lowest priority, so of Azure's
// rules only AllowVnetInBound needs writing. applied holds the addresses
// of what the NSG is on there.
func (d gcpNet) firewalls(st *nsgState, n *nsg, v *vnet, tag string, applied []netip.Prefix) ([]snapshot.Object, []Loss, []RuleEvidence) {
	var objs []snapshot.Object
	var losses []Loss
	var evidence []RuleEvidence
	where := "network tag " + tag
	field := func(r nsgRule) string { return "properties.securityRules[" + r.name + "]" }
	rules := n.ordered()
	for _, r := range rules {
		ev := &nsgEv{rule: r, from: len(losses)}
		row := func(name string) {
			losses = append(losses[:ev.from], dedupeLosses(losses[ev.from:])...)
			ev.to = len(losses)
			x := ev.row(where, losses)
			if name != "" {
				x.EnforcedBy = []string{gcpFirewall + " " + name}
			} else if ev.skipped {
				x.Status, x.EnforcedBy = nsgExact, []string{ev.note}
				x.Why = ""
			}
			evidence = append(evidence, x)
		}
		if r.builtin && r.name != "AllowVnetInBound" {
			switch r.name {
			case "AllowAzureLoadBalancerInBound":
				ev.note = "Azure's load balancer has no addresses on GCP; Google's check health from ranges of their own, which a requirement names"
			case "DenyAllInBound":
				ev.skipped, ev.note = true, "GCP's implied rule, which denies ingress nothing allows"
			default:
				ev.skipped, ev.note = true, "GCP's implied rule, which allows egress nothing denies: Azure's three outbound defaults allow the network, then the internet, which is every address"
			}
			row("")
			continue
		}
		peers, exact := r.peer.resolve(v)
		self, selfExact := r.self.resolve(v)
		selfAll := selfExact && within(applied, self)
		targetTags := []any{tag}
		if len(r.self.asgs) > 0 && selfExact && len(self) == 0 {
			// It applies to a group's members only: they carry a tag for
			// these rules beside the NSG's.
			targetTags, selfAll = nil, true
			for _, a := range r.self.asgs {
				targetTags = append(targetTags, d.selfTag(st, tag, a))
			}
		} else if len(r.self.asgs) > 0 {
			selfExact = false
		}
		var sourceTags []any
		if r.allow {
			switch {
			case r.srcPorts:
				losses = append(losses, Loss{Field: field(r), Why: r.String() + " names source ports; a firewall rule cannot, so it is not carried over"})
				row("")
				continue
			case !selfExact:
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s applies to %s, which has no addresses here; it is not carried over", r, strings.Join(append(r.self.other, r.self.asgs...), ", "))})
				row("")
				continue
			case !exact && len(peers) == 0 && len(r.peer.asgs) == 0:
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s allows %s, which has no addresses here; it is not carried over", r, strings.Join(r.peer.other, ", "))})
				row("")
				continue
			case !exact:
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s also allows %s, which has no addresses here; only its address ranges are carried over", r, strings.Join(r.peer.other, ", "))})
			}
			if !r.inbound && len(r.peer.asgs) > 0 {
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s allows traffic to the members of application security group %s; a GCP egress rule names destinations by address, and the subnets its members are in hold more than them, so that is not carried over", r, st.asgName(r.peer.asgs[0]))})
				if len(peers) == 0 {
					row("")
					continue
				}
			}
			if r.peer.internet && !d.vnetDenied(rules, r, v) {
				// Internet is every address outside the network. Where no
				// deny touches the network's own traffic, AllowVnetInBound
				// allows it anyway, so all addresses says the same in one
				// range.
				peers = aggregate(append(peers, v.tagPrefixes()...))
			}
		} else {
			if !exact {
				peers = []netip.Prefix{anyV4}
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s names %s, which has no addresses here; it denies every address instead", r, strings.Join(r.peer.other, ", "))})
			}
			if !selfExact {
				selfAll = true
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s applies to %s, which has no addresses here; it applies to every instance with the tag instead", r, strings.Join(append(r.self.other, r.self.asgs...), ", "))})
			}
			if r.srcPorts {
				losses = append(losses, Loss{Field: field(r), Why: r.String() + " names source ports; a firewall rule cannot, so it denies every source port"})
			}
			if !r.inbound && len(r.peer.asgs) > 0 {
				// The members cannot be named: the subnets they are in
				// are denied whole.
				for _, a := range r.peer.asgs {
					peers = append(peers, st.bound(a, v)...)
				}
				peers = aggregate(peers)
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s denies traffic to the members of application security group %s; a GCP egress rule names destinations by address, so the subnets its members are in (%s) are denied whole", r, st.asgName(r.peer.asgs[0]), routingList(peers))})
			}
		}
		if r.inbound {
			// "Source tags ... identify network interfaces of VM instances
			// in the same VPC network as the firewall rule"
			// (docs.cloud.google.com/vpc/docs/add-remove-network-tags), as
			// an ASG's members are in one virtual network.
			for _, a := range r.peer.asgs {
				sourceTags = append(sourceTags, d.marker(st, a))
			}
		}
		if len(peers) == 0 && len(sourceTags) == 0 {
			ev.note = "it names no address"
			row("")
			continue
		}
		spec := map[string]any{
			"network": d.netURL(v), "priority": r.priority, "targetTags": targetTags,
		}
		if r.inbound {
			spec["direction"] = "INGRESS"
			if len(peers) > 0 {
				spec["sourceRanges"] = prefixStrings(peers)
			}
			if len(sourceTags) > 0 {
				spec["sourceTags"] = sourceTags
			}
			if !selfAll {
				spec["destinationRanges"] = prefixStrings(self)
			}
		} else {
			spec["direction"], spec["destinationRanges"] = "EGRESS", prefixStrings(peers)
			if !selfAll {
				spec["sourceRanges"] = prefixStrings(self)
			}
		}
		if r.allow {
			spec["allowed"] = gcpProtocols(r)
		} else {
			spec["denied"] = gcpProtocols(r)
		}
		name := d.m.name(n.src+"/"+r.name, gcpName(tag, r.name))
		objs = append(objs, computeObject(gcpFirewall, "Firewall", "firewalls", gcpProject+"/global", name, spec))
		ev.kept = true
		row(gcpProject + "/global/firewalls/" + name)
	}
	return objs, losses, evidence
}

// vnetDenied reports whether any deny in the NSG touches traffic from the
// network itself that rule r would match.
func (d gcpNet) vnetDenied(rules []nsgRule, r nsgRule, v *vnet) bool {
	for _, dn := range rules {
		if dn.allow || dn.builtin || dn.inbound != r.inbound {
			continue
		}
		dp, _ := dn.peer.resolve(v)
		if !dn.peer.any && len(dn.peer.other)+len(dn.peer.asgs) > 0 {
			dp = []netip.Prefix{anyV4}
		}
		for _, a := range r.boxes(v.tagPrefixes()) {
			for _, b := range dn.boxes(dp) {
				if a.overlaps(b) {
					return true
				}
			}
		}
	}
	return false
}

func gcpProtocols(r nsgRule) []any {
	ports := map[string][]string{}
	var protos []string
	for _, p := range r.protos {
		if _, ok := ports[p]; !ok {
			protos = append(protos, p)
			ports[p] = nil
		}
		if p == "tcp" || p == "udp" {
			for _, pr := range r.ports {
				if pr != [2]int{0, 65535} {
					ports[p] = append(ports[p], portString(pr[0], pr[1]))
				}
			}
		}
	}
	sort.Strings(protos)
	var out []any
	for _, p := range protos {
		e := map[string]any{"IPProtocol": p}
		if len(ports[p]) > 0 {
			l := make([]any, len(ports[p]))
			for i, s := range ports[p] {
				l[i] = s
			}
			e["ports"] = l
		}
		out = append(out, e)
	}
	return out
}
