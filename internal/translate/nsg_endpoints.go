package translate

import (
	"fmt"
	"net/netip"
	"strings"
)

// NSGs and private endpoints. An NSG on a subnet filters the private
// endpoints in it only where the subnet's privateEndpointNetworkPolicies
// says so, and an endpoint's own interface takes none ("A read-only
// network interface is automatically created",
// learn.microsoft.com/azure/private-link/private-endpoint-overview). Only
// inbound rules matter: "Outbound traffic denied from a private endpoint
// isn't a valid scenario, as the service provider can't originate
// traffic".
//
// On AWS several private endpoints share one interface endpoint per
// service and VPC, and so one security group: it lets in what every one
// of them let in, the intersection, since letting in what any of them did
// would open one service to who could reach only another. On GCP there is
// no interface to filter: Private Google Access is a setting of the
// subnetwork the traffic comes from, so it is given only to the
// subnetworks every filtered endpoint took HTTPS from, all of them.

// endpointParts is the HTTPS every one of the private endpoints lets in.
// An endpoint no NSG applies to takes HTTPS from its network, as the
// group written without any NSG does.
func (st *nsgState) endpointParts(v *vnet, pes []string) (parts []nsgPart, results []*nsgResult, whys []string) {
	for i, k := range pes {
		s := st.endpoints[k]
		own := []nsgPart{{box: box{"tcp", 443, 443, v.prefixes}}}
		if s != nil && s.subnetNSG != nil && s.subnetNSG.refuse == "" {
			res := st.result(s)
			results = append(results, res)
			own = nil
			for _, p := range res.parts[0] {
				if z, ok := p.box.intersect(box{"tcp", 443, 443, p.peer}); ok {
					own = append(own, nsgPart{box: z, asg: p.asg, rules: p.rules})
				}
			}
			res.parts[0] = own
		}
		if i == 0 {
			parts = own
			continue
		}
		var bl []nsgBothLoss
		parts, bl = st.both(parts, own)
		for _, l := range bl {
			whys = append(whys, l.why)
		}
	}
	return parts, results, dedupe(whys)
}

func (st *nsgState) endpointNames(pes []string) string {
	var names []string
	for _, k := range pes {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

func (d awsNet) endpointGroups(st *nsgState, o *out, v *vnet, pes []string, group string) (ingress []any, markers []any, filtered bool) {
	parts, results, whys := st.endpointParts(v, pes)
	// The endpoints carry an ASG's marker only when every private endpoint
	// behind them was in it: a rule that allowed traffic to the group's
	// members would otherwise reach a service it did not.
	var common []string
	for i, k := range pes {
		s := st.endpoints[k]
		if s == nil {
			common = nil
			break
		}
		if i == 0 {
			common = sortedMapKeys(s.member)
			continue
		}
		var both []string
		for _, a := range common {
			if s.member[a] {
				both = append(both, a)
			}
		}
		common = both
	}
	carries := []string{group}
	for _, a := range common {
		name := d.marker(st, o, a, v)
		markers = append(markers, awsRef(awsSG, name, "GroupId"))
		carries = append(carries, name)
	}
	to := "the interface endpoints of VPC " + d.vpcName(v)
	for _, k := range pes {
		if s := st.endpoints[k]; s != nil {
			st.attach(o, s, carries, "written", to)
			for _, a := range s.asgs() {
				if !nsgHas(common, a) {
					o.require(fmt.Sprintf("Private endpoint %s was in application security group %s, and shares its interface endpoints with private endpoints that were not: the endpoints do not carry the group's marker, so a rule that allowed traffic to the group's members does not reach them", k, st.asgName(a)))
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, markers, false
	}
	var written [2][]nsgWritten
	for _, f := range nsgTidy(parts) {
		for _, r := range d.sgRulesFor(st, o, f, v, true) {
			fw := f
			if f.asg == "" {
				fw.peer = []netip.Prefix{netip.MustParsePrefix(fmt.Sprint(r["CidrIp"]))}
			}
			written[0] = append(written[0], nsgWritten{fw, fmt.Sprintf("%s %s ingress %s", awsSG, group, sgRuleString(r, true))})
			ingress = append(ingress, r)
		}
	}
	for _, res := range results {
		n := res.site.subnetNSG
		e := o.entry(n.src)
		if e == nil {
			continue
		}
		e.Targets = uniqueSorted(append(e.Targets, awsSG+" "+group))
		ls := res.lossesFor(0)
		ls = append(ls, Loss{Field: "properties.securityRules", Why: "for its private endpoints (" + st.endpointNames(pes) + ") only its inbound rules for HTTPS are written, on the security group of " + to + ": an interface endpoint answers on port 443 and starts no traffic"})
		for _, w := range whys {
			ls = append(ls, Loss{Field: "properties.securityRules", Why: "private endpoints " + st.endpointNames(pes) + " share " + to + ", which let in only what each of them did: " + w})
		}
		e.Losses = dedupeLosses(append(e.Losses, ls...))
		e.Evidence = append(e.Evidence, res.evidence(0, awsSG+" "+group, written, awsSG+" "+group+": security groups only allow, and no rule of it allows what this denies")...)
		nsgSortEvidence(e.Evidence)
	}
	return ingress, markers, true
}

func (d awsNet) privateAccess(*nsgState, *out, *vnet, []string) map[string]bool { return nil }

func (d gcpNet) endpointGroups(*nsgState, *out, *vnet, []string, string) ([]any, []any, bool) {
	return nil, nil, false
}

func (d gcpNet) privateAccess(st *nsgState, o *out, v *vnet, pes []string) map[string]bool {
	parts, results, _ := st.endpointParts(v, pes)
	var from []netip.Prefix
	for _, p := range parts {
		if p.asg == "" {
			from = append(from, p.peer...)
		}
	}
	from = aggregate(from)
	allowed := map[string]bool{}
	var on, off []string
	var written [2][]nsgWritten
	for _, s := range v.subnets {
		key := v.key + "/" + strings.ToLower(s.name)
		name := gcpName(v.name, s.name)
		if len(results) == 0 || (s.prefix.IsValid() && within([]netip.Prefix{s.prefix}, from)) {
			allowed[key] = true
			on = append(on, name)
			written[0] = append(written[0], nsgWritten{nsgFinal{box: box{"tcp", 443, 443, []netip.Prefix{s.prefix}}}, "privateIpGoogleAccess on " + gcpSubnet + " " + name})
		} else {
			off = append(off, name)
		}
	}
	to := "Private Google Access on subnetwork(s) " + orDefault(strings.Join(on, ", "), "none") + " of network " + d.netName(v)
	for _, k := range pes {
		if s := st.endpoints[k]; s != nil {
			st.attach(o, s, nil, "written", to)
		}
	}
	if len(results) == 0 {
		return nil
	}
	where := "Private Google Access in network " + d.netName(v)
	for _, res := range results {
		n := res.site.subnetNSG
		e := o.entry(n.src)
		if e == nil {
			continue
		}
		ls := res.lossesFor(0)
		ls = append(ls, Loss{Field: "properties.securityRules", Why: "GCP has no interface to filter for its private endpoints (" + st.endpointNames(pes) + "): Private Google Access is a setting of the subnetwork traffic comes from, so it is given to the subnetworks all of whose addresses every one of these endpoints took HTTPS from, and to no other"})
		if len(off) > 0 {
			ls = append(ls, Loss{Field: "properties.securityRules", Why: "subnetwork(s) " + strings.Join(off, ", ") + " are not given Private Google Access: the NSG kept some or all of their addresses from a private endpoint, and the setting is the whole subnetwork's. Machines in them it did allow, and members of an application security group it allowed by name, lose the private path"})
		}
		for i := range ls {
			ls[i].Why = strings.ReplaceAll(ls[i].Why, "a security group", "a subnetwork's setting")
		}
		e.Losses = dedupeLosses(append(e.Losses, ls...))
		rows := res.evidence(0, where, written, where+": a subnetwork some address of which this denies is not given it")
		for i := range rows {
			// Whether a subnetwork was let in is decided on whole
			// subnetworks: an allow of part of one is stricter here.
			if rows[i].Access == "allow" && rows[i].Status == nsgExact && len(off) > 0 {
				rows[i].Status, rows[i].Why = nsgStricter, "it counts only where it lets in a whole subnetwork: "+strings.Join(off, ", ")+" are not given Private Google Access"
			}
			rows[i].Why = strings.ReplaceAll(rows[i].Why, "a security group", "a subnetwork's setting")
		}
		e.Evidence = append(e.Evidence, rows...)
		nsgSortEvidence(e.Evidence)
	}
	return allowed
}
