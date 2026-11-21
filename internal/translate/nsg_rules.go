package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// What a set of NSGs lets through at one site, as parts, and the evidence
// of what became of each rule.

// nsgPart is a box whose peer is either address ranges or the members of
// an application security group. For a group, the box's peer holds the
// ranges its members can be in (nsgState.bound): the arithmetic is done on
// those, and a part stays a group's only while it still holds all of them,
// since a target can name a group but not some of its members.
type nsgPart struct {
	box
	asg string
	// rules names the rule each NSG on the path allowed it by.
	rules [2]string
}

const (
	nsgExact      = "exact"
	nsgStricter   = "stricter"
	nsgNotCarried = "not carried"
	nsgNoEffect   = "does not apply"
)

// nsgEv is what became of one rule at one site.
type nsgEv struct {
	rule     nsgRule
	from, to int // its losses, in the list they were added to
	kept     bool
	note     string // why it does not apply, or is left out without loss
	skipped  bool
	more     []string
}

func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (st *nsgState) asgName(key string) string {
	if a := st.asgs[key]; a != nil {
		return a.group + "/" + a.name
	}
	return key
}

// minus takes a deny out of an allowed part. why is set when what is left
// is less than Azure leaves: the target cannot say it exactly.
func (st *nsgState) minus(b, d nsgPart) (out []nsgPart, narrowed bool, why string) {
	wrap := func(bs []box) {
		for _, x := range bs {
			out = append(out, nsgPart{box: x, asg: b.asg, rules: b.rules})
		}
	}
	if !b.box.overlaps(d.box) && !(b.asg != "" && d.asg != "") {
		return []nsgPart{b}, false, ""
	}
	switch {
	case b.asg == "" && d.asg == "":
		parts, n := b.box.minus(d.box)
		wrap(parts)
		return out, n, ""
	case b.asg == "":
		// A deny of a group's members, from an allow of address ranges:
		// the ranges its members are in go whole.
		parts, n := b.box.minus(d.box)
		wrap(parts)
		return out, n, fmt.Sprintf("a deny before it (%s) names application security group %s; single members cannot be taken out of an address range, so the subnets its members are in (%s) are taken out whole", d.rules[0], st.asgName(d.asg), routingList(d.peer))
	case d.asg == "":
		// A deny of address ranges, from an allow of a group's members:
		// exact where it holds none or all of the ranges they are in.
		parts, n := b.box.minus(d.box)
		dropped := false
		for _, x := range parts {
			if samePrefixes(x.peer, b.peer) {
				out = append(out, nsgPart{box: x, asg: b.asg, rules: b.rules})
			} else {
				dropped = true
			}
		}
		if dropped {
			why = fmt.Sprintf("a deny before it (%s) takes out some of the addresses the members of application security group %s can have (%s); a group cannot be allowed in part, so on the ports the deny names none of its members are allowed", d.rules[0], st.asgName(b.asg), routingList(b.peer))
		}
		return out, n, why
	case d.asg != b.asg && st.disjoint(b.asg, d.asg):
		// Nothing is in both groups: the deny takes nothing from it.
		return []nsgPart{b}, false, ""
	}
	// A deny of the group itself, or of one some member is also in.
	all := d.box
	all.peer = []netip.Prefix{anyV4}
	if !b.box.overlaps(all) {
		return []nsgPart{b}, false, ""
	}
	parts, n := b.box.minus(all)
	wrap(parts)
	if d.asg != b.asg {
		why = fmt.Sprintf("a deny before it (%s) names application security group %s, and something may be in both it and %s; a target cannot say every member of one but those of the other, so on the ports the deny names no member is allowed", d.rules[0], st.asgName(d.asg), st.asgName(b.asg))
	}
	return out, n, why
}

// nsgBothLoss is where combining two NSGs' parts could not be written
// exactly: the rules it came from, and why.
type nsgBothLoss struct {
	rules [2]string
	why   string
}

// both is what two NSGs on one path let through together: the traffic
// each allows, part by part. Azure lets a packet through only when both
// allow it.
func (st *nsgState) both(a, b []nsgPart) (out []nsgPart, losses []nsgBothLoss) {
	for _, x := range a {
		for _, y := range b {
			rules := [2]string{x.rules[0], y.rules[0]}
			switch {
			case x.asg == y.asg:
				if x.asg != "" {
					// The same group on both sides: its ranges are the same.
					y.peer = x.peer
				}
				if z, ok := x.box.intersect(y.box); ok {
					out = append(out, nsgPart{box: z, asg: x.asg, rules: rules})
				}
			case x.asg != "" && y.asg != "":
				if st.disjoint(x.asg, y.asg) {
					continue
				}
				any := y.box
				any.peer = x.peer
				if _, ok := x.box.intersect(any); ok {
					losses = append(losses, nsgBothLoss{rules, fmt.Sprintf("the two NSGs on this path allow the members of different application security groups (%s and %s); only what is in both is allowed by both, which a target cannot name, so none is", st.asgName(x.asg), st.asgName(y.asg))})
				}
			default:
				g, p := x, y
				if g.asg == "" {
					g, p = y, x
				}
				z, ok := g.box.intersect(p.box)
				switch {
				case !ok:
				case samePrefixes(z.peer, g.peer):
					out = append(out, nsgPart{box: z, asg: g.asg, rules: rules})
				default:
					losses = append(losses, nsgBothLoss{rules, fmt.Sprintf("one NSG on this path allows the members of application security group %s and the other only some of the addresses they can have (%s of %s); a group cannot be allowed in part, so none of its members are", st.asgName(g.asg), routingList(z.peer), routingList(g.peer))})
				}
			}
		}
	}
	return out, losses
}

// nsgFinal is one rule's worth of what a site lets through, tidied: a
// protocol, ports, and address ranges or a group.
type nsgFinal struct {
	box
	asg string
}

// nsgTidy makes the parts into as few rules as say the same.
func nsgTidy(parts []nsgPart) []nsgFinal {
	var plain []box
	groups := map[string][]box{}
	for _, p := range parts {
		if p.asg == "" {
			plain = append(plain, p.box)
		} else {
			groups[p.asg] = append(groups[p.asg], p.box)
		}
	}
	var out []nsgFinal
	for _, b := range tidy(plain) {
		out = append(out, nsgFinal{box: b})
	}
	for _, k := range sortedMapKeys(groups) {
		for _, b := range tidy(groups[k]) {
			out = append(out, nsgFinal{box: b, asg: k})
		}
	}
	return out
}

// nsgWritten is one rule written on the target, for the evidence: what it
// matches and how the report names it.
type nsgWritten struct {
	nsgFinal
	label string
}

// nsgResult is what one site lets through and what became of each rule of
// each NSG on its path.
type nsgResult struct {
	site   *nsgSite
	parts  [2][]nsgPart // inbound, outbound; before tidying
	final  [2][]nsgFinal
	evs    [][]*nsgEv // per NSG
	losses [][]Loss   // per NSG
}

// canon is the result as text: two sites with the same let through the
// same.
func (r *nsgResult) canon() string {
	var sb strings.Builder
	for d, fs := range r.final {
		for _, f := range fs {
			fmt.Fprintf(&sb, "%d %s %s\n", d, f.asg, f.box.String())
		}
	}
	return sb.String()
}

// result works out what a site lets through: each NSG's rules in order,
// and where there are two, what both allow.
func (st *nsgState) result(s *nsgSite) *nsgResult {
	ns := s.nsgs()
	r := &nsgResult{site: s, evs: make([][]*nsgEv, len(ns)), losses: make([][]Loss, len(ns))}
	for d, inbound := range []bool{true, false} {
		var combined []nsgPart
		for i, n := range ns {
			parts, evs, losses := st.siteRules(n, s, inbound)
			base := len(r.losses[i])
			for _, ev := range evs {
				ev.from, ev.to = ev.from+base, ev.to+base
			}
			r.evs[i] = append(r.evs[i], evs...)
			r.losses[i] = append(r.losses[i], losses...)
			if i == 0 {
				combined = parts
				continue
			}
			var bl []nsgBothLoss
			combined, bl = st.both(combined, parts)
			for _, l := range bl {
				for j := range ns {
					for _, ev := range r.evs[j] {
						if ev.rule.name == l.rules[j] && ev.rule.inbound == inbound && !nsgHas(ev.more, l.why) {
							ev.more = append(ev.more, l.why)
						}
					}
				}
			}
		}
		r.parts[d] = combined
		r.final[d] = nsgTidy(combined)
	}
	return r
}

// lossesFor are the losses of one NSG at the site, with what combining it
// with the other cost.
func (r *nsgResult) lossesFor(i int) []Loss {
	out := append([]Loss(nil), r.losses[i]...)
	for _, ev := range r.evs[i] {
		for _, w := range ev.more {
			out = append(out, Loss{Field: "properties.securityRules[" + ev.rule.name + "]", Why: ev.rule.String() + ": " + w})
		}
	}
	return dedupeLosses(out)
}

// evidence is the report's rows for one NSG at the site: where is the
// security group or tag, written the rules written there, absent how the
// target enforces a deny.
func (r *nsgResult) evidence(i int, where string, written [2][]nsgWritten, absent string) []RuleEvidence {
	var out []RuleEvidence
	for _, ev := range r.evs[i] {
		d := 1
		if ev.rule.inbound {
			d = 0
		}
		row := ev.row(where, r.losses[i])
		if ev.rule.allow && ev.kept {
			seen := map[string]bool{}
			for _, p := range r.parts[d] {
				if p.rules[i] != ev.rule.name {
					continue
				}
				for _, w := range written[d] {
					if w.asg == p.asg && (p.asg != "" || prefixesOverlap(w.peer, p.peer)) && protoOverlap(w.proto, p.proto) && w.lo <= p.hi && p.lo <= w.hi && !seen[w.label] {
						seen[w.label] = true
						row.EnforcedBy = append(row.EnforcedBy, w.label)
					}
				}
			}
			sort.Strings(row.EnforcedBy)
			if len(row.EnforcedBy) == 0 && row.Status == nsgExact {
				row.Why = "nothing it allows is left once the rules before it, and any other NSG on the path, have had their say"
				row.EnforcedBy = []string{absent}
			}
		} else if !ev.rule.allow && !ev.skipped {
			row.EnforcedBy = []string{absent}
		}
		out = append(out, row)
	}
	return out
}

func (ev *nsgEv) row(where string, losses []Loss) RuleEvidence {
	row := RuleEvidence{Where: where, Rule: ev.rule.name, Priority: ev.rule.priority, Direction: ev.rule.dir(), Access: "deny", Default: ev.rule.builtin, Status: nsgExact}
	if ev.rule.allow {
		row.Access = "allow"
	}
	var whys []string
	for _, l := range losses[ev.from:ev.to] {
		whys = append(whys, l.Why)
	}
	whys = append(whys, ev.more...)
	switch {
	case ev.skipped:
		row.Status, whys = nsgNoEffect, []string{ev.note}
	case ev.rule.allow && !ev.kept:
		row.Status = nsgNotCarried
		if ev.note != "" {
			whys = append(whys, ev.note)
		}
	case len(whys) > 0:
		row.Status = nsgStricter
	}
	row.Why = strings.Join(dedupe(whys), "; ")
	return row
}

// RuleEvidence is what became of one rule of a network security group in
// one place it is written: the evidence, rule by rule, that a control was
// carried over. A rule is exact (the target lets through what it did),
// stricter (less, and why), not carried (an allow left out, so nothing it
// allowed is let through) or does not apply (it names addresses or an
// application security group that are not there).
type RuleEvidence struct {
	// Where is the security group (AWS) or network tag (GCP) the row is
	// about: an NSG is written once for its subnets, and once more for each
	// set of interfaces it shares a path with another NSG on.
	Where     string `json:"where"`
	Rule      string `json:"rule"`
	Priority  int    `json:"priority"`
	Direction string `json:"direction"`
	Access    string `json:"access"`
	// Default marks one of the rules Azure gives every NSG.
	Default bool   `json:"default,omitempty"`
	Status  string `json:"status"`
	Why     string `json:"why,omitempty"`
	// EnforcedBy are the target's rules that carry it. A deny on AWS, and
	// in a rule set made of two NSGs on GCP, is enforced by no rule
	// allowing what it denies.
	EnforcedBy []string `json:"enforcedBy,omitempty"`
}

// Attachment is one thing a network security group filtered, and what
// stands for that on the target.
type Attachment struct {
	// Source is the subnet, interface, scale set or private endpoint.
	Source string `json:"source"`
	// NSGs are the network security groups on its path, the subnet's
	// first; ASGs the application security groups it is in.
	NSGs []string `json:"nsgs,omitempty"`
	ASGs []string `json:"asgs,omitempty"`
	// Carries are the security groups (AWS) or network tags (GCP) that
	// stand for them, all of which it must carry and no other of these.
	Carries []string `json:"carries,omitempty"`
	// Attached is "written" when a translated object carries them, or
	// "requirement" when a person attaches them to what takes its place.
	Attached string `json:"attached"`
	// To is what carries them, or must.
	To string `json:"to"`
}

func sortedAttachments(as []Attachment) []Attachment {
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Source != as[j].Source {
			return as[i].Source < as[j].Source
		}
		return as[i].To < as[j].To
	})
	return as
}

func nsgHas(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
