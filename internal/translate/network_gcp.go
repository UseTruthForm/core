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

func (d gcpNet) nsg(n *nsg, o *out) {
	e := Entry{Source: n.src, State: Mapped, Losses: append(append([]Loss(nil), n.losses...), tagLosses(n.tags, "a firewall rule")...)}
	vs := n.vnets()
	for _, v := range vs {
		tag := gcpName(n.name)
		if len(vs) > 1 {
			tag = gcpName(n.name, v.name)
		}
		rules, losses := d.firewalls(n, v, tag)
		e.Losses = append(e.Losses, losses...)
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
			}
		}
		o.require(fmt.Sprintf("Instances (and GKE nodes) in subnetwork(s) %s carry the network tag %s: an NSG applied to a whole subnet, a firewall rule applies to instances by tag", strings.Join(where, ", "), tag))
		o.require("Google's load balancers check health from " + strings.Join(gcpHealthChecks, " and ") + ": where one fronts these instances, allow those ranges (Azure's load balancer was allowed by every NSG)")
	}
	o.entries = append(o.entries, e)
}

// firewalls writes an NSG's rules as firewall rules on one network, with
// Azure's own rules where GCP's implied ones differ: GCP denies all
// ingress and allows all egress at the lowest priority, so of Azure's
// rules only AllowVnetInBound needs writing.
func (d gcpNet) firewalls(n *nsg, v *vnet, tag string) ([]snapshot.Object, []Loss) {
	applied := n.subnetsIn(v)
	var objs []snapshot.Object
	var losses []Loss
	field := func(r nsgRule) string { return "properties.securityRules[" + r.name + "]" }
	rules := n.ordered()
	for _, r := range rules {
		if r.builtin && r.name != "AllowVnetInBound" {
			continue
		}
		peers, exact := r.peer.resolve(v)
		self, selfExact := r.self.resolve(v)
		selfAll := selfExact && within(applied, self)
		if r.allow {
			switch {
			case r.srcPorts:
				losses = append(losses, Loss{Field: field(r), Why: r.String() + " names source ports; a firewall rule cannot, so it is not carried over"})
				continue
			case !selfExact:
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s applies to %s, which has no addresses here; it is not carried over", r, strings.Join(r.self.other, ", "))})
				continue
			case !exact && len(peers) == 0:
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s allows %s, which has no addresses here; it is not carried over", r, strings.Join(r.peer.other, ", "))})
				continue
			case !exact:
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s also allows %s, which has no addresses here; only its address ranges are carried over", r, strings.Join(r.peer.other, ", "))})
			}
			if r.peer.internet && !d.vnetDenied(rules, r, v) {
				// Internet is every address outside the network. Where no
				// deny touches the network's own traffic, AllowVnetInBound
				// allows it anyway, so all addresses says the same in one
				// range.
				peers = aggregate(append(peers, v.prefixes...))
			}
		} else {
			if !exact {
				peers = []netip.Prefix{anyV4}
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s names %s, which has no addresses here; it denies every address instead", r, strings.Join(r.peer.other, ", "))})
			}
			if !selfExact {
				selfAll = true
				losses = append(losses, Loss{Field: field(r), Why: fmt.Sprintf("%s applies to %s, which has no addresses here; it applies to every instance with the tag instead", r, strings.Join(r.self.other, ", "))})
			}
			if r.srcPorts {
				losses = append(losses, Loss{Field: field(r), Why: r.String() + " names source ports; a firewall rule cannot, so it denies every source port"})
			}
		}
		if len(peers) == 0 {
			continue
		}
		spec := map[string]any{
			"network": d.netURL(v), "priority": r.priority, "targetTags": []any{tag},
		}
		if r.inbound {
			spec["direction"], spec["sourceRanges"] = "INGRESS", prefixStrings(peers)
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
	}
	return objs, dedupeLosses(losses)
}

// vnetDenied reports whether any deny in the NSG touches traffic from the
// network itself that rule r would match.
func (d gcpNet) vnetDenied(rules []nsgRule, r nsgRule, v *vnet) bool {
	for _, dn := range rules {
		if dn.allow || dn.builtin || dn.inbound != r.inbound {
			continue
		}
		dp, _ := dn.peer.resolve(v)
		if !dn.peer.any && len(dn.peer.other) > 0 {
			dp = []netip.Prefix{anyV4}
		}
		for _, a := range r.boxes(v.prefixes) {
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
