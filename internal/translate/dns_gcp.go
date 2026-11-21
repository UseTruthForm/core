package translate

import (
	"fmt"
	"regexp"

	"github.com/usetruthform/core/internal/snapshot"
)

// DNS zones on GCP: a Cloud DNS managed zone per zone (global, as Cloud
// DNS has no regions), private ones visible to the VPC networks the
// network family writes, and a resource record set per record set, under
// its zone as Cloud DNS names it (managedZones/z/rrsets/www.shop.example./A).

const (
	gcpZone  = "dns.googleapis.com/ManagedZone"
	gcpRRSet = "dns.googleapis.com/ResourceRecordSet"
)

var (
	gcpZoneName = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])?$`)
)

type cloudDNS struct{ m Map }

func dnsObject(typ, schema, coll, parent, rel string, spec map[string]any) snapshot.Object {
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": typ,
		"metadata": map[string]any{"name": rel, "annotations": map[string]any{
			"truthform.org/discovery":  "dns/v1",
			"truthform.org/schema":     schema,
			"truthform.org/collection": coll,
			"truthform.org/parent":     parent,
		}}, "spec": spec}}
}

func (d cloudDNS) write(zones []*dnsZone, o *out) {
	for _, z := range zones {
		if z.refuse != "" {
			continue
		}
		name := d.m.name(z.src, gcpName(z.name))
		if !gcpZoneName.MatchString(name) || len(name) > 63 {
			z.refuse = fmt.Sprintf("%q is not a Cloud DNS zone name ([a-z][-a-z0-9]*, at most 63): name it in the map's names", name)
			continue
		}
		e := Entry{Source: z.src, State: Mapped, Losses: append([]Loss(nil), z.losses...)}
		spec := map[string]any{"name": name, "dnsName": z.fqdn(), "description": "From Azure DNS zone " + z.group + "/" + z.name, "visibility": "public"}
		if labels, losses := gcpLabels(z.tags); len(labels) > 0 || len(losses) > 0 {
			if len(labels) > 0 {
				spec["labels"] = labels
			}
			e.Losses = append(e.Losses, losses...)
		}
		if z.private {
			spec["visibility"] = "private"
			networks := []any{}
			seen := map[string]bool{}
			for _, l := range z.links {
				if l.refuse != "" || seen[l.vnet] {
					continue
				}
				seen[l.vnet] = true
				e.Losses = append(e.Losses, prefixed(append([]Loss(nil), l.losses...), linkField(l))...)
				v := &vnet{src: l.vnetSrc, name: l.vnetName}
				networks = append(networks, map[string]any{"networkUrl": gcpNet{d.m}.netURL(v)})
				if l.registration {
					o.require(fmt.Sprintf("Instances in VPC network %s are not registered in private zone %s, as Azure registered its machines' names: write the records their names need", gcpNet{d.m}.netName(v), z.fqdn()))
				}
			}
			spec["privateVisibilityConfig"] = map[string]any{"networks": networks}
			o.require(fmt.Sprintf("Private zone %s answers only in its VPC networks: whatever resolved it through Azure from elsewhere (a DNS forwarder, on-premises conditional forwarding) must forward to a Cloud DNS inbound server policy instead (not translated)", z.fqdn()))
		} else {
			o.require(fmt.Sprintf("Delegation of %s: at its registrar (or in its parent zone), replace Azure's name servers with the managed zone's nameServers. Until then the internet still resolves the Azure zone; this is the step that moves traffic", z.fqdn()))
		}
		if z.signed {
			// Cloud DNS signs with keys it manages: nothing to translate
			// but that it is on.
			spec["dnssecConfig"] = map[string]any{"state": "on"}
			o.require(fmt.Sprintf("DNSSEC for %s: Cloud DNS signs it with new keys; replace the DS record at the registrar with the managed zone's when the name servers change, or resolvers that validate fail the whole zone", z.fqdn()))
		}
		zoneRel := gcpProject + "/managedZones/" + name
		e.Targets = append(e.Targets, o.add("gcp", z.src, dnsObject(gcpZone, "ManagedZone", "managedZones", gcpProject, zoneRel, spec)))
		o.entries = append(o.entries, e)
		z.written = true
		for _, r := range z.records {
			if r.skip == "" && r.refuse == "" {
				pointsAtAzure(r, o)
			}
			o.entries = append(o.entries, recordEntry(r, func() string {
				return o.add("gcp", r.src, dnsObject(gcpRRSet, "ResourceRecordSet", "resourceRecordSets", zoneRel,
					zoneRel+"/rrsets/"+r.fqdn()+"/"+r.typ, map[string]any{
						"name": r.fqdn(), "type": r.typ, "ttl": r.ttl, "rrdatas": anyList(r.data),
					}))
			}))
		}
	}
}

// gcpLabels are a zone's tags as Cloud DNS labels take them; a tag that is
// not a label as it is, is named rather than rewritten.
