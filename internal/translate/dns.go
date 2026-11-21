package translate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Azure DNS zones, public and private, read into a model the Route 53 and
// Cloud DNS writers share.
//
// A public zone becomes a public hosted zone (AWS) or a public managed zone
// (GCP), and each record set a record set. A private zone becomes a private
// hosted zone associated with the VPCs, or a private managed zone visible to
// the VPC networks, that the network family writes for the virtual networks
// it is linked to. Azure keeps each record set as an object of its own, one
// per name and type (zone/www of type A), and a private zone's links to
// networks the same way: all are read with their zone.
//
// What the target makes itself is not written: a zone's SOA record and its
// own name servers (the NS record at its apex). The target's name servers
// are new, so the delegation at the registrar has to change to them; that
// is the step that moves traffic, and it is a requirement, never done here.

const (
	azDNSZone     = "microsoft.network/dnszones"
	azPrivateZone = "microsoft.network/privatednszones"
	azZoneLink    = azPrivateZone + "/virtualnetworklinks"
	azDNSSEC      = azDNSZone + "/dnssecconfigs"
)

type dnsFamily struct{}

func (dnsFamily) claims(kind string) bool {
	return kind == azDNSZone || strings.HasPrefix(kind, azDNSZone+"/") || kind == azPrivateZone || strings.HasPrefix(kind, azPrivateZone+"/")
}

// dnsRecordKeys holds, per record type, the setting a record set keeps its
// records in. A public zone's record set says ARecords, a private zone's
// aRecords; settings are matched without regard to case, as ARM does.
var dnsRecordKeys = map[string]string{
	"A": "ARecords", "AAAA": "AAAARecords", "CAA": "caaRecords", "CNAME": "CNAMERecord", "MX": "MXRecords",
	"NS": "NSRecords", "PTR": "PTRRecords", "SOA": "SOARecord", "SRV": "SRVRecords", "TXT": "TXTRecords",
	"DS": "DSRecords", "TLSA": "TLSARecords", "NAPTR": "NAPTRRecords",
}

type dnsZone struct {
	src, group string
	name       string // its DNS name, lower case, without the final dot
	key        string // public|group/name or private|group/name by its type, lower case
	private    bool
	inline     bool // a legacy zone of zoneType Private: its networks are in it
	tags       map[string]string
	links      []*dnsLink
	records    []*dnsRecord
	signed     bool // DNSSEC
	losses     []Loss
	refuse     string
	written    bool
}

func (z *dnsZone) fqdn() string { return z.name + "." }

type dnsLink struct {
	src          string // "" for a network named in a legacy zone
	name         string
	vnet         string // group/name of the network, lower case
	vnetSrc      string // the network as the report names it, once found
	vnetName     string
	registration bool
	losses       []Loss
	refuse       string
}

type dnsRecord struct {
	src    string
	zone   *dnsZone
	rel    string // the name in the zone; @ is the zone itself
	typ    string
	ttl    int
	data   []string // each record as both targets write it (RFC 1035's text form)
	losses []Loss
	refuse string
	skip   string // read, and not written: why
}

func (r *dnsRecord) fqdn() string {
	if r.rel == "@" {
		return r.zone.fqdn()
	}
	return strings.ToLower(r.rel) + "." + r.zone.fqdn()
}

func (dnsFamily) translate(objs []snapshot.Object, o *out) {
	zones := map[string]*dnsZone{}
	var recObjs, linkObjs, secObjs []snapshot.Object
	for _, obj := range objs {
		switch k := strings.ToLower(obj.Kind()); {
		case k == azDNSZone:
			z := readZone(obj, false)
			zones[z.key] = z
		case k == azPrivateZone:
			z := readZone(obj, true)
			zones[z.key] = z
		case k == azZoneLink:
			linkObjs = append(linkObjs, obj)
		case k == azDNSSEC:
			secObjs = append(secObjs, obj)
		case recordType(k) != "":
			recObjs = append(recObjs, obj)
		default:
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
		}
	}
	// Children are read with their zone. Each is reported on its own, once
	// its zone is decided.
	type child struct {
		obj  snapshot.Object
		zone *dnsZone
		link *dnsLink
	}
	var children []child
	zoneOf := func(obj snapshot.Object, private bool) *dnsZone {
		parent, _, _ := strings.Cut(obj.Name(), "/")
		flavor := "public|"
		if private {
			flavor = "private|"
		}
		z := zones[strings.ToLower(flavor+obj.Namespace()+"/"+parent)]
		if z == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its zone is not in the snapshot"})
		}
		return z
	}
	for _, obj := range recObjs {
		k := strings.ToLower(obj.Kind())
		z := zoneOf(obj, strings.HasPrefix(k, azPrivateZone+"/"))
		if z == nil {
			continue
		}
		r := readRecord(obj, recordType(k))
		r.zone = z
		switch {
		case r.typ == "SOA":
			r.skip = "the target makes the zone's SOA record itself"
		case r.typ == "NS" && r.rel == "@":
			r.skip = "the zone's own name servers: the target makes this record itself, naming its own, and the registrar's delegation has to change to them"
		}
		z.records = append(z.records, r)
	}
	for _, obj := range linkObjs {
		z := zoneOf(obj, true)
		if z == nil {
			continue
		}
		l := readLink(obj)
		z.links = append(z.links, l)
		children = append(children, child{obj: obj, zone: z, link: l})
	}
	for _, obj := range secObjs {
		z := zoneOf(obj, false)
		if z == nil {
			continue
		}
		z.signed = true
		children = append(children, child{obj: obj, zone: z})
	}
	sorted := make([]*dnsZone, 0, len(zones))
	for _, z := range zones {
		sorted = append(sorted, z)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].src < sorted[j].src })

	if o.m.Destinations.DNS == "" {
		for _, z := range sorted {
			z.refuse = "the map chooses no destination for DNS zones (destinations.dns)"
		}
	}
	for _, z := range sorted {
		dnsLinkNetworks(z, o)
	}
	var w dnsWriter
	switch o.m.To {
	case "aws":
		w = route53{m: o.m}
	case "gcp":
		w = cloudDNS{m: o.m}
	}
	if o.m.Destinations.DNS != "" {
		w.write(sorted, o)
	}
	for _, z := range sorted {
		if !z.written {
			if z.refuse == "" {
				z.refuse = "refused by its writer"
			}
			o.entries = append(o.entries, Entry{Source: z.src, State: Refused, Reason: z.refuse})
			for _, r := range z.records {
				o.entries = append(o.entries, Entry{Source: r.src, State: Refused, Reason: "its zone " + z.src + " is refused"})
			}
		}
	}
	for _, c := range children {
		e := Entry{Source: source(c.obj), State: Mapped, Reason: "read with its zone " + c.zone.src}
		switch {
		case !c.zone.written:
			e = Entry{Source: source(c.obj), State: Refused, Reason: "its zone " + c.zone.src + " is refused"}
		case c.link != nil && c.link.refuse != "":
			e = Entry{Source: source(c.obj), State: Refused, Reason: c.link.refuse}
		}
		o.entries = append(o.entries, e)
	}
}

// dnsLinkNetworks finds, for each network a private zone is linked to,
// what the network family made of it. A link to a network not translated
// is refused: the zone would answer in a network that is not there. A zone
// left with no network is refused; so is a legacy zone, whose networks are
// in it, when any of them is not translated.
func dnsLinkNetworks(z *dnsZone, o *out) {
	if !z.private || z.refuse != "" {
		return
	}
	live := 0
	for _, l := range z.links {
		if l.refuse != "" {
			continue
		}
		e := o.entryFor(vnetSource(l.vnet))
		switch {
		case e == nil:
			l.refuse = "the network it links, " + l.vnet + ", is not in the snapshot"
		case e.State != Mapped:
			l.refuse = "the network it links, " + e.Source + ", is refused"
		default:
			l.vnetSrc = e.Source
			_, l.vnetName, _ = strings.Cut(e.Source[strings.Index(e.Source, " ")+1:], "/")
			live++
			continue
		}
		if z.inline {
			z.refuse = "properties: " + l.refuse
			return
		}
	}
	if len(z.links) > 0 && live == 0 {
		z.refuse = "every network it is linked to is refused or missing, so it would answer nowhere"
	}
}

func vnetSource(key string) string { return "microsoft.network/virtualnetworks " + key }

// entryFor is the report entry for a source so far, matched without regard
// to case: what an earlier family made of it.
func (o *out) entryFor(src string) *Entry {
	for i := range o.entries {
		if strings.EqualFold(o.entries[i].Source, src) {
			return &o.entries[i]
		}
	}
	return nil
}

// dnsWriter writes the zones for one target, reporting each zone it writes
// and its records, and marking it written.
type dnsWriter interface {
	write(zones []*dnsZone, o *out)
}

// recordType is the record type of a record set's kind, or "".
func recordType(kind string) string {
	for _, p := range []string{azDNSZone + "/", azPrivateZone + "/"} {
		if t, ok := strings.CutPrefix(kind, p); ok {
			t = strings.ToUpper(t)
			if _, known := dnsRecordKeys[t]; known {
				return t
			}
		}
	}
	return ""
}

// ciKey is the key m has for k, matched without regard to case; k when it
// has none.
func ciKey(m map[string]any, k string) string {
	if _, ok := m[k]; ok {
		return k
	}
	for x := range m {
		if strings.EqualFold(x, k) {
			return x
		}
	}
	return k
}

func readZone(o snapshot.Object, private bool) *dnsZone {
	flavor := "public|"
	if private {
		flavor = "private|"
	}
	z := &dnsZone{src: source(o), group: o.Namespace(), name: strings.ToLower(strings.TrimSuffix(o.Name(), ".")), private: private}
	z.key = strings.ToLower(flavor + o.Namespace() + "/" + z.name)
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag")
	z.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("maxNumberOfRecordSets", "maxNumberOfRecordsPerRecordSet", "numberOfRecordSets", "nameServers", "signingKeys",
		"maxNumberOfVirtualNetworkLinks", "numberOfVirtualNetworkLinks", "maxNumberOfVirtualNetworkLinksWithRegistration",
		"numberOfVirtualNetworkLinksWithRegistration", "provisioningState", "internalId")
	if !private {
		zt := p.str("zoneType")
		reg, res := list(p.m["registrationVirtualNetworks"]), list(p.m["resolutionVirtualNetworks"])
		p.quiet("registrationVirtualNetworks", "resolutionVirtualNetworks")
		switch strings.ToLower(zt) {
		case "", "public":
			if len(reg)+len(res) > 0 {
				p.lose("resolutionVirtualNetworks", "networks named on a Public zone, which Azure uses only for a Private one", false)
			}
		case "private":
			// The zones Azure had before private DNS zones: the networks
			// are in the zone, not links of their own.
			z.private, z.inline = true, true
			seen := map[string]*dnsLink{}
			add := func(x any, field string, registration bool) {
				k := azRefKey(x, typVNet)
				if k == "" {
					z.refuse = "properties." + field + ": a network could not be read from the reference"
					return
				}
				l := seen[k]
				if l == nil {
					_, name, _ := strings.Cut(k, "/")
					l = &dnsLink{name: name, vnet: k}
					seen[k] = l
					z.links = append(z.links, l)
				}
				l.registration = l.registration || registration
			}
			for _, x := range res {
				add(x, "resolutionVirtualNetworks", false)
			}
			for _, x := range reg {
				add(x, "registrationVirtualNetworks", true)
			}
			for _, l := range z.links {
				if l.registration {
					l.losses = append(l.losses, registrationLoss("properties.registrationVirtualNetworks["+l.vnet+"]"))
				}
			}
		default:
			z.refuse = fmt.Sprintf("properties.zoneType: %q is not Public or Private", zt)
		}
	}
	z.losses = append(top.rest(), p.rest()...)
	return z
}

func registrationLoss(field string) Loss {
	return Loss{Field: field, Why: "Azure registered the names of the network's machines in the zone itself; neither Route 53 nor Cloud DNS does, so those names answer only once records are written for them (instances keep the target's own internal names)"}
}

func readLink(o snapshot.Object) *dnsLink {
	_, name, _ := strings.Cut(o.Name(), "/")
	l := &dnsLink{src: source(o), name: name}
	top := newProps(spec(o), "")
	top.quiet("location", "properties", "name", "etag")
	if t := stringTags(top.m["tags"]); len(t) > 0 {
		top.lose("tags", fmt.Sprintf("%d tag(s): a zone's association with a network has no tags or labels on the target", len(t)), false)
	}
	top.quiet("tags")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("virtualNetworkLinkState", "provisioningState")
	l.vnet = azRefKey(p.m["virtualNetwork"], typVNet)
	if l.vnet == "" {
		l.refuse = "properties.virtualNetwork: the network could not be read from the reference"
	}
	p.quiet("virtualNetwork")
	if p.boolean("registrationEnabled") {
		l.registration = true
		l.losses = append(l.losses, registrationLoss("properties.registrationEnabled"))
	}
	switch rp := p.str("resolutionPolicy"); strings.ToLower(rp) {
	case "", "default":
	case "nxdomainredirect":
		p.lose("resolutionPolicy", "a name missing from the zone was looked up on the internet; on the target it is answered as not found, so fewer names resolve", false)
	default:
		l.refuse = fmt.Sprintf("properties.resolutionPolicy: %q is not one this reads", rp)
	}
	l.losses = append(append(top.rest(), p.rest()...), l.losses...)
	return l
}

// readRecord reads a record set of type typ. It reads every setting even
// when the set is refused, so that the report names all of them.
func readRecord(o snapshot.Object, typ string) *dnsRecord {
	_, rel, _ := strings.Cut(o.Name(), "/")
	r := &dnsRecord{src: source(o), rel: rel, typ: typ}
	refuse := func(why string) {
		if r.refuse == "" {
			r.refuse = why
		}
	}
	if rel == "" {
		refuse("its name has no record name after the zone")
	}
	top := newProps(spec(o), "")
	top.quiet("properties", "name", "etag", "id", "type")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet(ciKey(p.m, "fqdn"), ciKey(p.m, "provisioningState"), ciKey(p.m, "isAutoRegistered"))
	if ttl := p.integer(ciKey(p.m, "TTL")); ttl != nil && *ttl >= 0 {
		r.ttl = *ttl
	} else if typ != "SOA" {
		refuse("it has no TTL: both targets need one, and none is chosen here")
	}
	if md := obj(p.m[ciKey(p.m, "metadata")]); len(md) > 0 {
		p.lose(ciKey(p.m, "metadata"), fmt.Sprintf("%d metadata item(s): a record set on the target has no tags or labels", len(md)), false)
	}
	p.quiet(ciKey(p.m, "metadata"))
	for _, k := range []string{"targetResource", "trafficManagementProfile"} {
		k = ciKey(p.m, k)
		if id, _ := obj(p.m[k])["id"].(string); id != "" {
			refuse(fmt.Sprintf("it is an alias to the Azure resource %s: on the target an alias must point at that resource's translation, which is not translated yet", id))
		}
		p.quiet(k)
	}
	for _, t := range sortedKeys(dnsRecordKeys) {
		k := ciKey(p.m, dnsRecordKeys[t])
		v, present := p.take(k)
		if t != typ {
			if present && !emptyValue(v) {
				p.lose(k, fmt.Sprintf("%s records on a record set of type %s, which answers only %s: not carried over", t, typ, typ), false)
			}
			continue
		}
		data, losses, why := recordData(t, k, v)
		r.data, r.losses = data, append(r.losses, losses...)
		if why != "" {
			refuse(why)
		}
	}
	if typ != "SOA" && len(r.data) == 0 {
		refuse("it holds no records: a record set on either target holds at least one")
	}
	r.losses = append(append(top.rest(), p.rest()...), r.losses...)
	return r
}

func emptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// recordData writes the records of one type as text (RFC 1035 section 5),
// the form Route 53's ResourceRecords and Cloud DNS's rrdatas take. A
// record it cannot read refuses the set: a set written without one of its
// records answers differently.
func recordData(typ, key string, v any) (data []string, losses []Loss, refuse string) {
	field := "properties." + key
	items := list(v)
	if m := obj(v); m != nil {
		items = []any{m} // CNAME and SOA hold one record
	}
	for i, x := range items {
		ip := newProps(obj(x), fmt.Sprintf("%s[%d].", field, i))
		var s, bad string
		num := func(k string) int {
			n := ip.integer(ciKey(ip.m, k))
			if n == nil || *n < 0 {
				bad = k + " is missing"
				return 0
			}
			return *n
		}
		host := func(k string) string {
			h := ip.str(ciKey(ip.m, k))
			if h == "" {
				bad = k + " is missing"
			}
			return dnsHost(h)
		}
		switch typ {
		case "A", "AAAA":
			k := map[string]string{"A": "ipv4Address", "AAAA": "ipv6Address"}[typ]
			a, err := netip.ParseAddr(ip.str(ciKey(ip.m, k)))
			if err != nil || a.Is4() != (typ == "A") || a.Zone() != "" {
				bad = fmt.Sprintf("%s %q is not an %s address", k, ip.m[ciKey(ip.m, k)], map[string]string{"A": "IPv4", "AAAA": "IPv6"}[typ])
			}
			s = a.String()
		case "CNAME":
			s = host("cname")
		case "NS":
			s = host("nsdname")
		case "PTR":
			s = host("ptrdname")
		case "MX":
			pref := num("preference")
			s = fmt.Sprintf("%d %s", pref, host("exchange"))
		case "SRV":
			pr, w, port := num("priority"), num("weight"), num("port")
			s = fmt.Sprintf("%d %d %d %s", pr, w, port, host("target"))
		case "CAA":
			fl := num("flags")
			tag := ip.str(ciKey(ip.m, "tag"))
			if tag == "" {
				bad = "tag is missing"
			}
			s = fmt.Sprintf("%d %s %s", fl, tag, quoteDNS(ip.str(ciKey(ip.m, "value"))))
		case "TXT":
			var parts []string
			vs, _ := ip.take(ciKey(ip.m, "value"))
			for _, c := range list(vs) {
				str := fmt.Sprint(c)
				for len(str) > 255 {
					losses = append(losses, Loss{Field: ip.prefix + "value", Why: fmt.Sprintf("a string of %d characters is longer than a DNS string's 255; it is written as consecutive strings, which readers of SPF and DKIM join again", len(fmt.Sprint(c)))})
					parts = append(parts, quoteDNS(str[:255]))
					str = str[255:]
				}
				parts = append(parts, quoteDNS(str))
			}
			if len(parts) == 0 {
				bad = "value is empty"
			}
			s = strings.Join(parts, " ")
		case "DS":
			kt, alg := num("keyTag"), num("algorithm")
			dg := newProps(obj(ip.m[ciKey(ip.m, "digest")]), ip.prefix+"digest.")
			at := dg.integer(ciKey(dg.m, "algorithmType"))
			val := dg.str(ciKey(dg.m, "value"))
			if at == nil || val == "" {
				bad = "digest is incomplete"
				at = new(int)
			}
			ip.quiet(ciKey(ip.m, "digest"))
			losses = append(losses, dg.rest()...)
			s = fmt.Sprintf("%d %d %d %s", kt, alg, *at, val)
		case "TLSA":
			u, sel, mt := num("usage"), num("selector"), num("matchingType")
			cert := ip.str(ciKey(ip.m, "certAssociationData"))
			if cert == "" {
				bad = "certAssociationData is missing"
			}
			s = fmt.Sprintf("%d %d %d %s", u, sel, mt, cert)
		case "NAPTR":
			ord, pref := num("order"), num("preference")
			repl := ip.str(ciKey(ip.m, "replacement"))
			if repl == "" {
				repl = "."
			} else {
				repl = dnsHost(repl)
			}
			s = fmt.Sprintf("%d %d %s %s %s %s", ord, pref, quoteDNS(ip.str(ciKey(ip.m, "flags"))), quoteDNS(ip.str(ciKey(ip.m, "services"))), quoteDNS(ip.str(ciKey(ip.m, "regexp"))), repl)
		case "SOA":
			// The target writes its own: what Azure's said is named, not
			// carried over.
			var what []string
			for _, k := range []string{"email", "refreshTime", "retryTime", "expireTime", "minimumTTL"} {
				if x, ok := ip.take(ciKey(ip.m, k)); ok {
					what = append(what, fmt.Sprintf("%s %v", k, x))
				}
			}
			ip.quiet(ciKey(ip.m, "host"), ciKey(ip.m, "serialNumber"))
			if len(what) > 0 {
				losses = append(losses, Loss{Field: field, Why: "the target writes the zone's SOA record itself, with its own contact and timers (" + strings.Join(what, ", ") + "); the negative-caching TTL in it is the target's"})
			}
		}
		losses = append(losses, ip.rest()...)
		if bad != "" {
			return nil, losses, fmt.Sprintf("%s[%d]: cannot read the record: %s", field, i, bad)
		}
		if typ != "SOA" {
			data = append(data, s)
		}
	}
	return data, losses, ""
}

// dnsHost is a host name as the targets take it: absolute, with the final
// dot. Azure takes names in records as absolute with or without one.
func dnsHost(h string) string {
	if h == "" || strings.HasSuffix(h, ".") {
		return h
	}
	return h + "."
}

// quoteDNS writes a string as a quoted DNS character-string: quotes and
// backslashes escaped, and bytes outside printable ASCII as \DDD.
func quoteDNS(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
