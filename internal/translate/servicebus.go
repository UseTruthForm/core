package translate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Azure Service Bus, read into one model that every messaging destination
// translates from. Reading is where the settings are accounted for: each is
// read into the model, or named as having no equivalent anywhere, or left
// for rest() to name as unread.

const (
	sbNamespace    = "microsoft.servicebus/namespaces"
	sbQueue        = sbNamespace + "/queues"
	sbTopic        = sbNamespace + "/topics"
	sbSubscription = sbTopic + "/subscriptions"
	sbRuleKind     = sbSubscription + "/rules"
	sbNetwork      = sbNamespace + "/networkrulesets"
)

type serviceBus struct{}

func (serviceBus) claims(kind string) bool { return strings.HasPrefix(kind, sbNamespace) }

// sbNS is one namespace and what it says about all its entities.
type sbNS struct {
	src, group, name string
	obj              snapshot.Object
	losses           []Loss
	// private is set when the namespace answers only on private endpoints
	// or listed networks: a destination that cannot say the same widens.
	private string
	// closed is set when nothing but private endpoints reached it; ranges
	// are the public address ranges its rule set allowed otherwise, and
	// vnets the subnets it allowed by service endpoint.
	closed bool
	ranges []string
	vnets  int
	// keys is set when apps may sign in with shared access keys.
	keys bool
	// tls is the namespace's minimum TLS version, "" for Azure's default.
	tls string
	// cmk is set when messages are encrypted with the customer's own key.
	cmk     bool
	network *snapshot.Object
}

// sbEntity is a queue, a topic or a subscription.
type sbEntity struct {
	kind              string // queue, topic, subscription
	src, key          string // the report's name, and the map's key for names
	group, ns, name   string // a subscription's name is its own; topic is its topic
	topic             string
	lock, ttl         *float64
	dupWindow         *float64
	autoDelete        *float64
	maxDelivery       *int
	maxSizeMB         *int
	maxMsgKB          *int
	dlExpiry, session bool
	dup, ordering     bool
	dlFilterErr       bool
	forwardTo         string
	forwardDL         string
	rules             []sbRule
	losses            []Loss
	// parent is a subscription's topic; subSession is set on a topic when
	// any of its subscriptions is a session subscription.
	parent     *sbEntity
	subSession bool
}

// sbRule is one subscription rule: its filter and action.
type sbRule struct {
	src, name string
	// kind is all (matches everything), none (matches nothing),
	// correlation or sql.
	kind   string
	props  map[string]string // a correlation filter's application properties
	system map[string]string // and its system properties (label, correlationId, ...)
	sql    string
	action string
	losses []Loss
}

func (sbEntity) dlqName(n string) string { return n + "-dlq" }

func (serviceBus) translate(objs []snapshot.Object, o *out) {
	d, why := messagingDestination(o.m)
	nss := map[string]*sbNS{}
	var ents []*sbEntity
	subs := map[string]*sbEntity{}
	var rules []snapshot.Object
	for _, obj := range objs {
		k := strings.ToLower(obj.Kind())
		switch k {
		case sbNamespace:
			ns := readNamespace(obj)
			nss[strings.ToLower(ns.group+"/"+ns.name)] = ns
		case sbQueue, sbTopic, sbSubscription:
			e := readEntity(obj, k)
			ents = append(ents, e)
			if e.kind == "subscription" {
				subs[strings.ToLower(e.group+"/"+e.ns+"/"+e.topic+"/"+e.name)] = e
			}
		case sbRuleKind:
			rules = append(rules, obj)
		default:
			if strings.HasSuffix(k, "/authorizationrules") {
				o.entries = append(o.entries, Entry{Source: source(obj), State: Refused,
					Reason: "a shared access key: identity is not translated. Apps that sign in with keys move to the target's IAM or workload identity, which is a change to the app (#32)"})
				o.require("Apps that sign in to Service Bus with shared access keys or connection strings must move to the target's identity (IAM, workload identity); no key is carried over")
				continue
			}
			if k == sbNetwork {
				continue // read with its namespace, below
			}
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
		}
	}
	for _, r := range rules {
		parts := strings.Split(r.Name(), "/")
		if len(parts) != 4 {
			o.entries = append(o.entries, Entry{Source: source(r), State: Refused, Reason: "a rule's name is namespace/topic/subscription/rule"})
			continue
		}
		s := subs[strings.ToLower(r.Namespace()+"/"+strings.Join(parts[:3], "/"))]
		if s == nil {
			o.entries = append(o.entries, Entry{Source: source(r), State: Refused, Reason: "its subscription is not in the snapshot"})
			continue
		}
		s.rules = append(s.rules, readRule(r))
	}
	// A network rule set is read with the namespace it belongs to, once
	// both are known.
	finishNetworks(objs, nss, o)
	if d == nil {
		for _, ns := range sortedNS(nss) {
			o.entries = append(o.entries, Entry{Source: ns.src, State: Refused, Reason: why})
		}
		for _, e := range ents {
			o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why})
			for _, r := range e.rules {
				o.entries = append(o.entries, Entry{Source: r.src, State: Refused, Reason: why})
			}
		}
		return
	}
	// A prefix for a namespace the snapshot does not hold is a misspelt
	// key, which would leave the names it was meant for colliding.
	for _, k := range sortedKeys(o.m.Prefixes) {
		found := false
		var have []string
		for _, ns := range sortedNS(nss) {
			have = append(have, ns.group+"/"+ns.name)
			found = found || strings.EqualFold(k, ns.group+"/"+ns.name)
		}
		if !found && o.err == nil {
			o.err = fmt.Errorf("map: prefixes names %q, which is no Service Bus namespace of the snapshot (there are: %s)", k, strings.Join(have, ", "))
		}
	}
	for _, ns := range sortedNS(nss) {
		d.namespace(ns, o)
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].src < ents[j].src })
	topics := map[string]*sbEntity{}
	for _, e := range ents {
		if e.kind == "topic" {
			topics[strings.ToLower(e.group+"/"+e.ns+"/"+e.name)] = e
		}
	}
	for _, e := range ents {
		if e.kind == "subscription" {
			if t := topics[strings.ToLower(e.group+"/"+e.ns+"/"+e.topic)]; t != nil {
				e.parent = t
				t.subSession = t.subSession || e.session
			}
		}
	}
	for _, e := range ents {
		ns := nss[strings.ToLower(e.group+"/"+e.ns)]
		if ns == nil {
			o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: "its namespace is not in the snapshot"})
			continue
		}
		switch e.kind {
		case "queue":
			d.queue(ns, e, o)
		case "topic":
			d.topic(ns, e, o)
		case "subscription":
			d.subscription(ns, e, o)
		}
	}
}

// finishNetworks attaches each namespace's network rule set and reads it.
func finishNetworks(objs []snapshot.Object, nss map[string]*sbNS, o *out) {
	for _, obj := range objs {
		if strings.ToLower(obj.Kind()) != sbNetwork {
			continue
		}
		cp := obj
		ns := nss[strings.ToLower(obj.Namespace()+"/"+strings.SplitN(obj.Name(), "/", 2)[0])]
		if ns == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its namespace is not in the snapshot"})
			continue
		}
		ns.network = &cp
		o.entries = append(o.entries, Entry{Source: source(obj), State: Mapped, Reason: "read with its namespace " + ns.src})
	}
	for _, ns := range nss {
		ns.readNetwork()
	}
}

func sortedNS(nss map[string]*sbNS) []*sbNS {
	out := make([]*sbNS, 0, len(nss))
	for _, ns := range nss {
		out = append(out, ns)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

func spec(obj snapshot.Object) map[string]any {
	s, _ := obj.Body["spec"].(map[string]any)
	if s == nil {
		return map[string]any{}
	}
	return s
}

func readNamespace(obj snapshot.Object) *sbNS {
	ns := &sbNS{src: source(obj), group: obj.Namespace(), name: obj.Name(), obj: obj}
	top := newProps(spec(obj), "")
	top.quiet("location", "sku", "tags")
	if id, _ := top.take("identity"); id != nil {
		top.lose("identity", "the namespace's managed identity is not translated (identity is a separate design, #32)", false)
	}
	p := newProps(nil, "properties.")
	if m, ok := spec(obj)["properties"].(map[string]any); ok {
		p = newProps(m, "properties.")
	}
	top.quiet("properties")
	p.quiet("provisioningState", "status", "createdAt", "updatedAt", "serviceBusEndpoint", "metricId",
		"premiumMessagingPartitions", "zoneRedundant", "privateEndpointConnections")
	if pna := p.str("publicNetworkAccess"); strings.EqualFold(pna, "Disabled") {
		ns.private, ns.closed = "public network access is disabled: it answers only on private endpoints", true
	}
	ns.keys = !p.boolean("disableLocalAuth")
	ns.tls = p.str("minimumTlsVersion")
	if enc, _ := p.take("encryption"); enc != nil {
		if m, _ := enc.(map[string]any); m != nil && len(m) > 0 {
			ns.cmk = true
		}
	}
	p.unlessDefault("alternateName", "", "a geo-recovery alias has no equivalent here")
	// Azure writes geoDataReplication on every namespace, with the one
	// location it is in: nothing is replicated until there is a second.
	if g, _ := p.take("geoDataReplication"); g != nil {
		m, _ := g.(map[string]any)
		if locs, _ := m["locations"].([]any); len(locs) > 1 {
			p.lose("geoDataReplication", "replication to other regions is not translated: the target is one region's (AWS) or Google's own replication (Pub/Sub)", false)
		}
	}
	p.unlessDefault("ipAddressType", "IPv4", "the namespace answers on IPv6 too; the target's endpoints decide their own address types")
	// Confidential compute kept the namespace's data encrypted in use.
	// Disabled, as Azure writes it on every namespace, nothing is lost;
	// enabled, the target is less protected. Anything else under
	// platformCapabilities is a setting no rule reads.
	if c, _ := p.take("platformCapabilities"); c != nil {
		m, _ := c.(map[string]any)
		pc := newProps(m, "properties.platformCapabilities.")
		cc, _ := pc.take("confidentialCompute")
		ccm, _ := cc.(map[string]any)
		ccp := newProps(ccm, "properties.platformCapabilities.confidentialCompute.")
		if mode := ccp.str("mode"); !strings.EqualFold(mode, "Disabled") && mode != "" {
			ns.losses = append(ns.losses, Loss{Field: "properties.platformCapabilities.confidentialCompute.mode", Widens: true,
				Why: mode + ": confidential compute kept the namespace's data encrypted while in use; no destination here does"})
		}
		ns.losses = append(ns.losses, append(pc.rest(), ccp.rest()...)...)
	}
	// errors is what Azure reports wrong with the namespace, in no
	// published definition. Empty, there is nothing to say; otherwise it
	// is left for rest() to name as unread, since what it holds is not
	// known here.
	if e, ok := p.m["errors"].([]any); ok && len(e) == 0 {
		p.quiet("errors")
	}
	ns.losses = append(ns.losses, append(top.rest(), p.rest()...)...)
	return ns
}

func (ns *sbNS) readNetwork() {
	if ns.network == nil {
		return
	}
	p := newProps(nil, "networkRuleSets.properties.")
	if m, ok := spec(*ns.network)["properties"].(map[string]any); ok {
		p = newProps(m, "networkRuleSets.properties.")
	}
	p.quiet("trustedServiceAccessEnabled")
	def := p.str("defaultAction")
	ips, _ := p.m["ipRules"].([]any)
	vnets, _ := p.m["virtualNetworkRules"].([]any)
	p.quiet("ipRules", "virtualNetworkRules")
	if strings.EqualFold(p.str("publicNetworkAccess"), "Disabled") {
		if ns.private == "" {
			ns.private = "its network rule set disables public network access"
		}
		ns.closed = true
	}
	if strings.EqualFold(def, "Deny") && !ns.closed {
		ns.private = fmt.Sprintf("its network rule set denies by default and allows %d address range(s) and %d virtual network(s)", len(ips), len(vnets))
		var bad []string
		ns.ranges, bad = lockRanges(ips, "ipMask")
		for _, b := range bad {
			p.lose("ipRules", b+" is not an address or range this reads; it is not allowed", false)
		}
		ns.vnets = len(vnets)
	}
	ns.losses = append(ns.losses, p.rest()...)
}

func readEntity(obj snapshot.Object, kind string) *sbEntity {
	parts := strings.Split(obj.Name(), "/")
	e := &sbEntity{src: source(obj), key: obj.Namespace() + "/" + obj.Name(), group: obj.Namespace(), ns: parts[0], name: parts[len(parts)-1]}
	switch kind {
	case sbQueue:
		e.kind = "queue"
	case sbTopic:
		e.kind = "topic"
	default:
		e.kind = "subscription"
		if len(parts) == 3 {
			e.topic = parts[1]
		}
	}
	top := newProps(spec(obj), "")
	top.quiet("properties")
	p := newProps(nil, "properties.")
	if m, ok := spec(obj)["properties"].(map[string]any); ok {
		p = newProps(m, "properties.")
	}
	// The server's own figures, should a capture have kept them, and a
	// performance hint with no effect on what is delivered.
	p.quiet("createdAt", "updatedAt", "accessedAt", "sizeInBytes", "messageCount", "countDetails",
		"subscriptionCount", "enableBatchedOperations", "enablePartitioning")
	p.unlessDefault("status", "Active", "the source entity is not active; the target's is created active")
	p.unlessDefault("enableExpress", false, "an express entity keeps messages in memory first; there is no equivalent")
	p.unlessDefault("isClientAffine", false, "client-affine subscriptions have no equivalent")
	p.quiet("clientAffineProperties")
	p.unlessDefault("userMetadata", "", "free-text metadata is not carried over")
	e.lock = p.duration("lockDuration")
	e.ttl = p.duration("defaultMessageTimeToLive")
	e.autoDelete = p.duration("autoDeleteOnIdle")
	e.dup = p.boolean("requiresDuplicateDetection")
	e.dupWindow = p.duration("duplicateDetectionHistoryTimeWindow")
	e.session = p.boolean("requiresSession")
	e.dlExpiry = p.boolean("deadLetteringOnMessageExpiration")
	e.dlFilterErr = p.boolean("deadLetteringOnFilterEvaluationExceptions")
	e.maxDelivery = p.integer("maxDeliveryCount")
	e.maxSizeMB = p.integer("maxSizeInMegabytes")
	e.maxMsgKB = p.integer("maxMessageSizeInKilobytes")
	e.forwardTo = p.str("forwardTo")
	e.forwardDL = p.str("forwardDeadLetteredMessagesTo")
	e.ordering = p.boolean("supportOrdering")
	e.losses = append(top.rest(), p.rest()...)
	return e
}

func readRule(obj snapshot.Object) sbRule {
	parts := strings.Split(obj.Name(), "/")
	r := sbRule{src: source(obj), name: parts[len(parts)-1]}
	top := newProps(spec(obj), "")
	top.quiet("properties")
	p := newProps(nil, "properties.")
	if m, ok := spec(obj)["properties"].(map[string]any); ok {
		p = newProps(m, "properties.")
	}
	ft := p.str("filterType")
	if a, _ := p.take("action"); a != nil {
		if m, _ := a.(map[string]any); m != nil {
			r.action, _ = m["sqlExpression"].(string)
		}
	}
	sql, _ := p.take("sqlFilter")
	corr, _ := p.take("correlationFilter")
	switch {
	case strings.EqualFold(ft, "SqlFilter"):
		m, _ := sql.(map[string]any)
		expr, _ := m["sqlExpression"].(string)
		switch strings.Join(strings.Fields(expr), "") {
		case "1=1":
			r.kind = "all"
		case "1=0":
			r.kind = "none"
		default:
			r.kind, r.sql = "sql", expr
		}
	case strings.EqualFold(ft, "CorrelationFilter"):
		m, _ := corr.(map[string]any)
		r.kind, r.props, r.system = "correlation", map[string]string{}, map[string]string{}
		for k, v := range m {
			switch k {
			case "properties":
				pm, _ := v.(map[string]any)
				for pk, pv := range pm {
					r.props[pk] = fmt.Sprint(pv)
				}
			case "requiresPreprocessing":
			default:
				if s := fmt.Sprint(v); v != nil && s != "" {
					r.system[k] = s
				}
			}
		}
	default:
		r.kind, r.sql = "other", fmt.Sprintf("filter type %q", ft)
	}
	r.losses = append(top.rest(), p.rest()...)
	return r
}

// messaging is a destination for Service Bus.
type messaging interface {
	namespace(ns *sbNS, o *out)
	queue(ns *sbNS, e *sbEntity, o *out)
	topic(ns *sbNS, e *sbEntity, o *out)
	subscription(ns *sbNS, e *sbEntity, o *out)
}

func messagingDestination(m Map) (messaging, string) {
	switch m.Destinations.Messaging {
	case "sqs-sns":
		return sqsSNS{m: m}, ""
	case "pubsub":
		return pubSub{m: m}, ""
	case "rabbitmq":
		return rabbit{m: m}, ""
	}
	return nil, "no messaging destination is chosen: set destinations.messaging in the map (sqs-sns, pubsub or rabbitmq)"
}

// filter is a subscription's rules as one decision: everything, nothing,
// or a set of correlation matches, any of which delivers. why is set when
// the rules cannot be carried over without delivering more than they did.
type filter struct {
	all    bool
	any    []map[string]string // application properties to match, per rule
	why    string
	losses []Loss
}

// filterOf combines a subscription's rules. A Service Bus subscription
// delivers a message if any rule matches it. A rule that cannot be carried
// over refuses the subscription: dropping it would deliver more than the
// source did, or less, and nobody chose either.
func filterOf(e *sbEntity, systemOK func(string) bool, m Map) filter {
	var f filter
	if len(e.rules) == 0 {
		f.why = "it has no rules, so Service Bus delivers it nothing; give it a rule or leave it out"
		return f
	}
	sqlNames := map[string]string{}
	bools := map[string]bool{}
	var sqlAlts []map[string]string
	for _, r := range e.rules {
		f.losses = append(f.losses, r.losses...)
		if r.action != "" {
			f.why = fmt.Sprintf("rule %s has an action (%s), which changes the message; there is no equivalent", r.name, r.action)
			return f
		}
		switch r.kind {
		case "all":
			f.all = true
		case "none":
		case "other":
			f.why = fmt.Sprintf("rule %s has a filter this does not read (%s); dropping it would deliver more", r.name, r.sql)
			return f
		case "sql":
			alts, why := parseSQLFilter(r.sql)
			if why != "" {
				f.why = fmt.Sprintf("rule %s is a SQL filter (%s) that is not translated: %s. Dropping it would deliver more", r.name, r.sql, why)
				return f
			}
			// No alternative left: the filter asks one property to be
			// two values, so it is never true, like 1=0.
			// A property is one whatever its letters' case, in every SQL
			// rule of the subscription: it is written as the first rule
			// that names it does, so a sender has one name to set.
			for _, alt := range alts {
				one := map[string]string{}
				for k, v := range alt {
					if v == sqlTrue || v == sqlFalse {
						if m.Booleans != "text" {
							f.why = fmt.Sprintf("rule %s is a SQL filter (%s) that compares %s with a boolean. A message attribute on the target is text: booleans: text in the map carries it as a match on the word true or false, which senders then send. Dropping it would deliver more", r.name, r.sql, k)
							return f
						}
						v = strings.TrimPrefix(v, "\x00")
						bools[k] = true
					}
					low := strings.ToLower(k)
					if sqlNames[low] == "" {
						sqlNames[low] = k
					}
					one[sqlNames[low]] = v
				}
				f.any = append(f.any, one)
				sqlAlts = append(sqlAlts, one)
			}
		case "correlation":
			for k := range r.system {
				if systemOK == nil || !systemOK(k) {
					f.why = fmt.Sprintf("rule %s matches the system property %s, which this destination cannot filter on", r.name, k)
					return f
				}
			}
			m := map[string]string{}
			for k, v := range r.props {
				m[k] = v
			}
			for k, v := range r.system {
				m[k] = v
			}
			if len(m) == 0 {
				f.all = true
				continue
			}
			f.any = append(f.any, m)
		}
	}
	if f.all {
		f.any = nil
	} else if len(sqlAlts) > 0 {
		f.losses = append(f.losses, sqlFilterCaseLoss(sqlAlts))
		if len(bools) > 0 {
			f.losses = append(f.losses, Loss{Field: "properties.sqlFilter.sqlExpression",
				Why: "a boolean property is matched as the word true or false (booleans: text in the map), in lower case: senders set these attributes so: " + strings.Join(sortedKeys(bools), ", ")})
		}
	}
	if !f.all && len(f.any) == 0 {
		f.why = "every rule matches nothing, so Service Bus delivers it nothing; leave it out"
	}
	return f
}

// ruleEntries reports each rule as carried in its subscription's filter.
func ruleEntries(e *sbEntity, state State, reason string, targets []string, o *out) {
	for _, r := range e.rules {
		en := Entry{Source: r.src, State: state, Reason: reason}
		if state != Refused {
			en.Targets = targets
			en.Reason = "carried in its subscription's filter"
		}
		o.entries = append(o.entries, en)
	}
}

// common reports what no destination carries for an entity.
func (e *sbEntity) common(dest string) []Loss {
	l := append([]Loss(nil), e.losses...)
	if e.forwardTo != "" {
		l = append(l, Loss{Field: "properties.forwardTo", Why: fmt.Sprintf("auto-forwarding to %s has no equivalent on %s: whatever reads the target must forward, or the sender must send to both", e.forwardTo, dest)})
	}
	if e.forwardDL != "" {
		l = append(l, Loss{Field: "properties.forwardDeadLetteredMessagesTo", Why: fmt.Sprintf("forwarding dead letters to %s has no equivalent on %s: they stay in this entity's dead-letter queue", e.forwardDL, dest)})
	}
	if e.dlFilterErr {
		l = append(l, Loss{Field: "properties.deadLetteringOnFilterEvaluationExceptions", Why: "filters here do not fail on a message, so nothing is dead-lettered for it"})
	}
	return l
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
