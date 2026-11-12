package saas

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// A subdomain restore puts one zone's DNS records a level down, under a
// name of their own: the source's auth.example.com becomes
// auth.test.example.com in the same zone, so a second environment gets its
// records beside the first's without touching them.

const (
	zoneKind   = "cloudflare/zone"
	recordKind = "cloudflare/dns_record"
)

// Subdomain maps a snapshot's records under one name in their zone.
type Subdomain struct {
	// Name is where the records go (test.example.com). The zone is the
	// snapshot's zone it falls under.
	Name string
	// Addresses replaces a source A or AAAA address with the target's: the
	// same address would send the new names to the source's servers.
	Addresses map[string]string
	// Targets replaces a CNAME's host outside the zone with the target's
	// (a source's app service or load balancer); kept as it is, it would
	// send the new names to the source too. Keys are lower case.
	Targets map[string]string
	zone    string
	// dropped holds where the records left out would have gone: a CNAME
	// moved to one of those names points at nothing.
	dropped map[string]bool
}

// maxComment is the longest record comment Cloudflare's free plan takes.
const maxComment = 100

// Left is a record a subdomain restore leaves out, and why.
type Left struct{ Name, Reason string }

// Mark is the comment on every record a subdomain restore writes. Only a
// record that carries it is TruthForm's to change.
func (d *Subdomain) Mark() string { return "truthform: " + d.Name }

// ours reports whether a record's comment is the mark. A record written
// before the tool was renamed carries the mark under the old name. Without
// this it would read as someone else's: every restore would stop on it as a
// conflict, and --update would refuse to touch a record TruthForm made.
func (d *Subdomain) ours(comment string) bool {
	return comment == d.Mark() || comment == d.legacyMark()
}

func (d *Subdomain) legacyMark() string { return "stackdna: " + d.Name }

// existing reads a record already in the zone as the restore compares it: a
// mark under the old name counts as the mark. Recognising the record as
// ours is not enough: the plan carries the new mark, so the record would
// still differ in its comment, a second run of the same restore would
// report every record as "already exists and differs (comment)" where the
// old build said identical, and diff --subdomain would show each as
// changed. The record itself keeps its comment until something else in it
// changes and --update rewrites it whole.
func (d *Subdomain) existing(kind string, spec map[string]any) map[string]any {
	if kind != recordKind || stringOf(spec["comment"]) != d.legacyMark() {
		return spec
	}
	out := make(map[string]any, len(spec))
	for k, v := range spec {
		out[k] = v
	}
	out["comment"] = d.Mark()
	return out
}

// under reports whether a DNS name is the subdomain or below it.
func under(name, sub string) bool {
	name, sub = strings.ToLower(name), strings.ToLower(sub)
	return name == sub || strings.HasSuffix(name, "."+sub)
}

// move puts a name of the zone under the subdomain: the zone itself
// becomes the subdomain, www.zone becomes www.subdomain.
func (d *Subdomain) move(name string) string {
	if strings.EqualFold(name, d.zone) {
		return d.Name
	}
	return name[:len(name)-len(d.zone)] + d.Name
}

// Map returns the snapshot with the zone's records under the subdomain,
// each carrying the mark, and what it left out. Other zones are left out
// whole; the zone itself stays, for its records to find.
func (d *Subdomain) Map(s snapshot.Snapshot) (snapshot.Snapshot, []Left, error) {
	d.Name = strings.ToLower(strings.TrimSuffix(d.Name, "."))
	if d.Name == "" || strings.Contains(d.Name, "*") {
		return s, nil, fmt.Errorf("--subdomain %q: give a name such as test.example.com", d.Name)
	}
	if len(d.Mark()) > maxComment {
		return s, nil, fmt.Errorf("--subdomain %s: the comment marking its records (%q) is %d characters, over the %d Cloudflare's free plan takes; choose a shorter name", d.Name, d.Mark(), len(d.Mark()), maxComment)
	}
	d.zone, d.dropped = "", map[string]bool{}
	for _, o := range s.Objects {
		if z := strings.ToLower(o.Name()); o.Kind() == zoneKind && strings.HasSuffix(d.Name, "."+z) && len(z) > len(d.zone) {
			d.zone = z
		}
	}
	if d.zone == "" {
		return s, nil, fmt.Errorf("--subdomain %s: no zone in the snapshot holds it (it must be below one, as test.example.com is below example.com)", d.Name)
	}
	out := s
	out.Objects = nil
	var left []Left
	others := map[string]int{}
	for _, o := range s.Objects {
		switch o.Kind() {
		case zoneKind:
			if strings.EqualFold(o.Name(), d.zone) {
				out.Objects = append(out.Objects, o)
			} else {
				others[o.Name()] += 0
			}
			continue
		case recordKind:
		default:
			left = append(left, Left{o.Kind() + " " + o.Name(), "not DNS"})
			continue
		}
		ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		if p, _ := ann[annParent].(string); !strings.EqualFold(p, d.zone) {
			others[p]++
			continue
		}
		spec, _ := o.Body["spec"].(map[string]any)
		typ, name, content := stringOf(spec["type"]), stringOf(spec["name"]), stringOf(spec["content"])
		if why := d.leave(typ, name, content); why != "" {
			left = append(left, Left{typ + " " + name, why})
			if !under(name, d.Name) {
				d.dropped[strings.ToLower(d.move(name))] = true
			}
			continue
		}
		ns := deepCopy(spec)
		ns["name"] = d.move(name)
		switch {
		case strings.EqualFold(typ, "CNAME") && under(content, d.zone) && !under(content, d.Name):
			ns["content"] = d.move(content)
		case strings.EqualFold(typ, "CNAME"):
			if to, ok := d.Targets[strings.ToLower(strings.TrimSuffix(content, "."))]; ok {
				ns["content"] = to
			}
		case strings.EqualFold(typ, "A") || strings.EqualFold(typ, "AAAA"):
			if to, ok := d.Addresses[content]; ok {
				ns["content"] = to
			}
		}
		ns["comment"] = d.Mark()
		body := deepCopy(o.Body)
		body["spec"] = ns
		body["metadata"].(map[string]any)["name"] = d.zone + "/" + typ + " " + stringOf(ns["name"]) + " " + stringOf(ns["content"])
		out.Objects = append(out.Objects, snapshot.Object{Body: body})
	}
	if len(others) > 0 {
		n := 0
		for _, c := range others {
			n += c
		}
		left = append(left, Left{fmt.Sprintf("%d other zones (%d records)", len(others), n), "not the zone " + d.Name + " is in: " + strings.Join(sortedKeys(others), ", ")})
	}
	sort.Slice(out.Objects, func(i, j int) bool { return out.Objects[i].Key() < out.Objects[j].Key() })
	return out, left, nil
}

// mailLabels name records only mail reads: DMARC, DKIM, MTA-STS, TLS
// reporting, BIMI, and mail clients' autodiscovery.
var mailLabels = []string{"_dmarc", "_domainkey", "_mta-sts", "_smtp._tls", "_bimi", "autodiscover", "autoconfig"}

// leave says why a record stays out of a subdomain restore. Mail decides
// where a domain's mail goes and who may send it; a copy one level down
// would only add a second mail domain nobody asked for. A delegation and
// an ACME challenge belong to the servers and clients that answer them.
func (d *Subdomain) leave(typ, name, content string) string {
	lname, lc := strings.ToLower(name), strings.ToLower(strings.Trim(content, `"`))
	switch {
	case under(name, d.Name):
		return "already under " + d.Name
	case strings.EqualFold(typ, "MX"):
		return "mail: left as it is"
	case strings.EqualFold(typ, "TXT") && (strings.HasPrefix(lc, "v=spf1") || strings.HasPrefix(lc, "v=dkim1") || strings.HasPrefix(lc, "v=dmarc1")):
		return "mail (SPF, DKIM or DMARC): left as it is"
	case strings.EqualFold(typ, "NS"):
		return "a delegation: the name servers it names would have to answer for the new name too"
	case strings.HasPrefix(lname, "_acme-challenge."):
		return "ACME: the certificate client manages it"
	}
	for _, l := range mailLabels {
		if strings.HasPrefix(lname, l+".") || strings.Contains(lname, "."+l+".") {
			return "mail: left as it is"
		}
	}
	return ""
}

// Unmapped lists the records that would still reach the source: an A or
// AAAA record with a source address, a CNAME to a host outside the
// subdomain that --target does not name. Each is "TYPE name content".
func (d *Subdomain) Unmapped(planned snapshot.Snapshot) []string {
	var out []string
	for _, o := range planned.Objects {
		spec, _ := o.Body["spec"].(map[string]any)
		t, n, c := strings.ToUpper(stringOf(spec["type"])), stringOf(spec["name"]), stringOf(spec["content"])
		if o.Kind() != recordKind {
			continue
		}
		switch {
		case t == "A" || t == "AAAA":
			if _, mapped := d.Addresses[c]; !mapped && !d.isTarget(c) {
				out = append(out, t+" "+n+" "+c)
			}
		case t == "CNAME" && !under(c, d.Name):
			if _, mapped := d.Targets[strings.ToLower(strings.TrimSuffix(c, "."))]; !mapped && !d.isTargetHost(c) {
				out = append(out, t+" "+n+" "+c)
			}
		}
	}
	return out
}

func (d *Subdomain) isTargetHost(host string) bool {
	for _, to := range d.Targets {
		if strings.EqualFold(to, strings.TrimSuffix(host, ".")) {
			return true
		}
	}
	return false
}

func (d *Subdomain) isTarget(addr string) bool {
	for _, to := range d.Addresses {
		if to == addr {
			return true
		}
	}
	return false
}

// Check compares the planned records with what the target zone holds now.
// A conflict stops the restore before it writes anything: a record at a
// planned name TruthForm did not make, the subdomain delegated or a zone
// of its own, a CNAME beside other records. A warning does not: a
// wildcard above the subdomain that answers for it today, and a record
// TruthForm made earlier that the snapshot no longer has.
func (d *Subdomain) Check(planned, target snapshot.Snapshot) (conflicts, warnings []string) {
	byName := map[string][]map[string]any{}
	keys := map[string]bool{}
	for _, o := range planned.Objects {
		if o.Kind() != recordKind {
			continue
		}
		spec, _ := o.Body["spec"].(map[string]any)
		n := strings.ToLower(stringOf(spec["name"]))
		byName[n] = append(byName[n], spec)
		keys[strings.ToLower(o.Name())] = true
	}
	for _, n := range sortedKeys(byName) {
		for _, r := range byName[n] {
			if strings.EqualFold(stringOf(r["type"]), "CNAME") && len(byName[n]) > 1 {
				conflicts = append(conflicts, n+": the snapshot has a CNAME there beside other records, which DNS does not allow")
				break
			}
		}
	}
	zoneThere := false
	for _, o := range target.Objects {
		if o.Kind() != zoneKind {
			continue
		}
		if strings.EqualFold(o.Name(), d.zone) {
			zoneThere = true
		} else if under(o.Name(), d.Name) {
			conflicts = append(conflicts, o.Name()+" is a zone of its own in the target account; its records belong there, not in "+d.zone)
		}
	}
	if !zoneThere {
		conflicts = append(conflicts, "the zone "+d.zone+" is not in the target account; a subdomain restore writes into a zone that exists")
	}
	shadowed := false
	for _, o := range target.Objects {
		ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		if p, _ := ann[annParent].(string); o.Kind() != recordKind || !strings.EqualFold(p, d.zone) {
			continue
		}
		spec, _ := o.Body["spec"].(map[string]any)
		t, n, c := stringOf(spec["type"]), strings.ToLower(stringOf(spec["name"])), stringOf(spec["content"])
		ours := d.ours(stringOf(spec["comment"]))
		desc := t + " " + n + " " + c
		switch {
		case strings.EqualFold(t, "NS") && (under(d.Name, n) && n != d.zone):
			conflicts = append(conflicts, desc+": "+n+" is delegated to other name servers, so records for it in "+d.zone+" would not be answered")
		case !under(n, d.Name):
			if strings.HasPrefix(n, "*.") && under(d.Name, n[2:]) {
				warnings = append(warnings, fmt.Sprintf("%s answers for %s and every name below it today. Once the restore creates any name at or under %s, it no longer answers for them: a name there the plan does not create stops resolving instead of reaching %s", desc, d.Name, d.Name, c))
				shadowed = true
			}
		case len(byName[n]) > 0 && !ours:
			conflicts = append(conflicts, desc+": already there, and TruthForm did not make it (no "+fmt.Sprintf("%q", d.Mark())+" comment)")
		case ours && !keys[strings.ToLower(d.zone+"/"+t+" "+n+" "+c)] && clashes(t, byName[n]):
			conflicts = append(conflicts, desc+": made by an earlier restore with other content; the restore would put a second record beside it (DNS would answer with both), so delete it first")
		case ours && !keys[strings.ToLower(d.zone+"/"+t+" "+n+" "+c)]:
			warnings = append(warnings, desc+": made by an earlier restore and not in this snapshot; left as it is")
		}
	}
	for _, n := range sortedKeys(byName) {
		for _, r := range byName[n] {
			t, c := strings.ToUpper(stringOf(r["type"])), stringOf(r["content"])
			switch {
			case t == "CNAME" && d.dropped[strings.ToLower(strings.TrimSuffix(c, "."))]:
				warnings = append(warnings, "CNAME "+n+" "+c+": points at a name the restore leaves out, so it will answer with nothing")
			case t == "SRV" || t == "HTTPS" || t == "SVCB":
				warnings = append(warnings, t+" "+n+" "+c+": its target is copied as it is; if it names the source's host, the new name reaches the source")
			}
		}
	}
	if shadowed {
		if _, ok := byName["*."+d.Name]; !ok {
			warnings = append(warnings, "the plan creates no *."+d.Name+", so nothing will answer for the other names under "+d.Name)
		}
	}
	return conflicts, warnings
}

// RestoreUnder restores the mapped snapshot after reading the target and
// checking it. Any conflict, or an address left as the source's, stops
// the restore before it writes: it returns the conflicts and no results.
// A dry run goes on to list its writes.
func (c *Client) RestoreUnder(ctx context.Context, d *Subdomain, mapped snapshot.Snapshot, opt RestoreOptions) (conflicts, warnings []string, results []snapshot.Result, err error) {
	target, err := c.Capture(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading the target zone before the restore: %w", err)
	}
	conflicts, warnings = d.Check(mapped, target)
	for _, a := range d.Unmapped(mapped) {
		how := "--address <source-ip>=<target-ip>"
		if strings.HasPrefix(a, "CNAME ") {
			how = "--target <source-host>=<target-host> (the same host twice keeps it)"
		}
		conflicts = append(conflicts, a+": still points at the source, so the new name would reach the source's servers; give its target with "+how)
	}
	if len(conflicts) > 0 && !opt.DryRun {
		return conflicts, warnings, nil, nil
	}
	opt.Present = map[string]bool{zoneKind: true}
	opt.Allow = d.Allow
	opt.Existing = d.existing
	return conflicts, warnings, c.Restore(ctx, mapped, opt), nil
}

// clashes reports whether a record of type t at a name would answer beside
// the planned ones there: the same type, or a CNAME on either side.
func clashes(t string, planned []map[string]any) bool {
	for _, r := range planned {
		pt := stringOf(r["type"])
		if strings.EqualFold(pt, t) || strings.EqualFold(pt, "CNAME") || strings.EqualFold(t, "CNAME") {
			return true
		}
	}
	return false
}

// Allow refuses every write a subdomain restore must not make: a record
// outside the subdomain, anything but a record, and a change to a record
// that does not carry the mark.
func (d *Subdomain) Allow(o snapshot.Object, existing map[string]any) string {
	spec, _ := o.Body["spec"].(map[string]any)
	switch n := stringOf(spec["name"]); {
	case o.Kind() != recordKind:
		return "a subdomain restore writes DNS records only"
	case !under(n, d.Name):
		return n + " is not under " + d.Name
	case existing != nil && !d.ours(stringOf(existing["comment"])):
		return "TruthForm did not make it (no " + fmt.Sprintf("%q", d.Mark()) + " comment)"
	}
	return ""
}

// Scope keeps what a diff of the subdomain compares: its zone and the
// records under it.
func (d *Subdomain) Scope(s snapshot.Snapshot) snapshot.Snapshot {
	out := s
	out.Objects = nil
	for _, o := range s.Objects {
		spec, _ := o.Body["spec"].(map[string]any)
		ann, _ := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		p, _ := ann[annParent].(string)
		if (o.Kind() == zoneKind && strings.EqualFold(o.Name(), d.zone)) ||
			(o.Kind() == recordKind && strings.EqualFold(p, d.zone) && under(stringOf(spec["name"]), d.Name)) {
			// Compared as the restore compares it (see existing).
			if seen := d.existing(o.Kind(), spec); stringOf(seen["comment"]) != stringOf(spec["comment"]) {
				body := make(map[string]any, len(o.Body))
				for k, v := range o.Body {
					body[k] = v
				}
				body["spec"] = seen
				o = snapshot.Object{Body: body}
			}
			out.Objects = append(out.Objects, o)
		}
	}
	return out
}
