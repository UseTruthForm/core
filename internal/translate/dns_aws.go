package translate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/usetruthform/core/internal/awscc"
)

// DNS zones on AWS: a Route 53 hosted zone per zone, private ones
// associated with the VPCs the network family writes, and a record set
// per record set.
//
// Each object is named as a capture of the rebuilt account names it, so a
// second restore finds what the first made and a capture diffs against
// the translation: a hosted zone by its DNS name, a record set by its own
// (www.shop.example.), and where several share one (a name's A, MX and
// TXT sets), the second and later get -2, -3 in the order a capture takes
// them.

const (
	awsZone   = "AWS::Route53::HostedZone"
	awsRecord = "AWS::Route53::RecordSet"
)

type route53 struct{ m Map }

// pending is an object waiting for its name.
type pending struct {
	kind, base string
	depth      int // how deep its references go: a capture names by levels
	spec       map[string]any
	hash       string
	name       string
}

func (d route53) write(zones []*dnsZone, o *out) {
	var zp []*pending
	var written []*dnsZone
	zoneObj := map[*dnsZone]*pending{}
	entries := map[*dnsZone]*Entry{}
	for _, z := range zones {
		if z.refuse != "" {
			continue
		}
		e := &Entry{Source: z.src, State: Mapped, Losses: append([]Loss(nil), z.losses...)}
		spec := map[string]any{"Name": z.fqdn(), "HostedZoneConfig": map[string]any{"Comment": "From Azure DNS zone " + z.group + "/" + z.name}}
		if tags, losses := hostedZoneTags(z.tags); len(tags) > 0 || len(losses) > 0 {
			if len(tags) > 0 {
				spec["HostedZoneTags"] = tags
			}
			e.Losses = append(e.Losses, losses...)
		}
		depth := 0
		if z.private {
			var vpcs []any
			seen := map[string]bool{}
			for _, l := range z.links {
				if l.refuse != "" || seen[l.vnet] {
					continue
				}
				e.Losses = append(e.Losses, prefixed(append([]Loss(nil), l.losses...), linkField(l))...)
				seen[l.vnet] = true
				vpc := awsNet{d.m}.vpcName(&vnet{src: l.vnetSrc, name: l.vnetName})
				vpcs = append(vpcs, map[string]any{"VPCId": awsRef(awsVPC, vpc, "VpcId"), "VPCRegion": d.m.Region})
				if l.registration {
					o.require(fmt.Sprintf("Instances in VPC %s are not registered in private hosted zone %s, as Azure registered its machines' names: write the records their names need", vpc, z.fqdn()))
				}
			}
			if len(vpcs) == 0 {
				z.refuse = "it is linked to no network: a Route 53 private hosted zone is associated with at least one VPC"
				continue
			}
			spec["VPCs"] = vpcs
			depth = 1
			o.require(fmt.Sprintf("Private hosted zone %s answers only in its VPCs: whatever resolved it through Azure from elsewhere (a DNS forwarder, on-premises conditional forwarding) must forward to a Route 53 Resolver inbound endpoint instead (not translated)", z.fqdn()))
		} else {
			o.require(fmt.Sprintf("Delegation of %s: at its registrar (or in its parent zone), replace Azure's name servers with the hosted zone's NameServers. Until then the internet still resolves the Azure zone; this is the step that moves traffic", z.fqdn()))
		}
		if z.signed {
			e.Losses = append(e.Losses, Loss{Field: "dnssecConfigs", Widens: true,
				Why: "the zone is signed with DNSSEC; Route 53 signs only with a key-signing key backed by a KMS key, and keys are not translated (#32), so the hosted zone is unsigned and its answers can be forged"})
			o.require(fmt.Sprintf("DNSSEC for %s: the hosted zone is not signed; take the DS record out at the registrar before the name servers change, or resolvers that validate fail the whole zone", z.fqdn()))
		}
		p := &pending{kind: awsZone, base: z.fqdn(), depth: depth, spec: spec}
		zp = append(zp, p)
		zoneObj[z] = p
		entries[z] = e
		written = append(written, z)
	}
	captureNames(zp, o)
	var rp []*pending
	recObj := map[*dnsRecord]*pending{}
	for _, z := range written {
		zo := zoneObj[z]
		for _, r := range z.records {
			if r.skip != "" || r.refuse != "" {
				continue
			}
			p := &pending{kind: awsRecord, base: r.fqdn(), depth: zo.depth + 1, spec: map[string]any{
				"HostedZoneId": awsRef(awsZone, zo.name, "Id"), "Name": r.fqdn(), "Type": r.typ,
				"TTL": strconv.Itoa(r.ttl), "ResourceRecords": anyList(r.data),
			}}
			rp = append(rp, p)
			recObj[r] = p
			pointsAtAzure(r, o)
		}
	}
	captureNames(rp, o)
	for _, z := range written {
		e := entries[z]
		e.Targets = append(e.Targets, o.add("aws", z.src, awsObject(awsZone, zoneObj[z].name, zoneObj[z].spec)))
		o.entries = append(o.entries, *e)
		z.written = true
		for _, r := range z.records {
			o.entries = append(o.entries, recordEntry(r, func() string {
				p := recObj[r]
				return o.add("aws", r.src, awsObject(awsRecord, p.name, p.spec))
			}))
		}
	}
}

// recordEntry reports a record set: written by add, or why not.
func recordEntry(r *dnsRecord, add func() string) Entry {
	switch {
	case r.skip != "":
		return Entry{Source: r.src, State: Mapped, Reason: r.skip, Losses: r.losses}
	case r.refuse != "":
		return Entry{Source: r.src, State: Refused, Reason: r.refuse}
	}
	return Entry{Source: r.src, State: Mapped, Losses: r.losses, Targets: []string{add()}}
}

// azureEndpoints are the suffixes of names Azure gives its services.
var azureEndpoints = []string{".azurewebsites.net.", ".azurefd.net.", ".azureedge.net.", ".cloudapp.azure.com.", ".cloudapp.net.",
	".trafficmanager.net.", ".windows.net.", ".azurecr.io.", ".azure-api.net.", ".azurestaticapps.net.", ".azurecontainerapps.io."}

// pointsAtAzure requires, for a record written as it is that names an
// Azure endpoint, that it be pointed at the target's.
func pointsAtAzure(r *dnsRecord, o *out) {
	for _, d := range r.data {
		for _, sfx := range azureEndpoints {
			if strings.HasSuffix(strings.ToLower(d), sfx) {
				o.require(fmt.Sprintf("Record %s %s is written as it is and names %s, an Azure endpoint: it still sends traffic to Azure until it names the target's", r.fqdn(), r.typ, d))
				return
			}
		}
	}
}

func linkField(l *dnsLink) string {
	if l.src == "" {
		return ""
	}
	return "virtualNetworkLinks/" + l.name + ": "
}

// captureNames names objects of one type as awscc's capture names them:
// by level of reference (what references nothing first), then by base
// name, then by the hash of the spec; a base already taken gets -2, -3.
func captureNames(ps []*pending, o *out) {
	for _, p := range ps {
		spec := p.spec
		if built, err := o.tg.AWS.Object(p.kind, "x", deepCopyAny(spec).(map[string]any)); err == nil {
			spec, _ = built.Body["spec"].(map[string]any)
		}
		p.hash = awscc.SpecName(p.kind, spec)
	}
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.depth != b.depth {
			return a.depth < b.depth
		}
		if a.base != b.base {
			return a.base < b.base
		}
		return a.hash < b.hash
	})
	used := map[string]bool{}
	for _, p := range ps {
		base := strings.NewReplacer("|", "_", "{", "_", "}", "_").Replace(p.base)
		n := base
		for i := 2; used[n]; i++ {
			n = fmt.Sprintf("%s-%d", base, i)
		}
		used[n] = true
		p.name = n
	}
}

func deepCopyAny(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, y := range x {
			m[k] = deepCopyAny(y)
		}
		return m
	case []any:
		l := make([]any, len(x))
		for i, y := range x {
			l[i] = deepCopyAny(y)
		}
		return l
	}
	return v
}

func anyList(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// hostedZoneTags are a zone's tags as Route 53 takes them.
func hostedZoneTags(tags map[string]string) ([]any, []Loss) {
	var out []any
	var losses []Loss
	for _, k := range sortedKeys(tags) {
		switch v := tags[k]; {
		case strings.HasPrefix(strings.ToLower(k), "aws:"):
			losses = append(losses, Loss{Field: "tags." + k, Why: "AWS reserves tags that begin aws:"})
		case len(k) > 128 || len(v) > 256:
			losses = append(losses, Loss{Field: "tags." + k, Why: "longer than a Route 53 tag takes (key 128, value 256)"})
		default:
			out = append(out, map[string]any{"Key": k, "Value": v})
		}
	}
	return out, losses
}
