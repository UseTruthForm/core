package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Service Bus to Pub/Sub, as objects the GCP restore creates. A queue is a
// topic with one subscription of the same name; a topic is a topic; a
// subscription is a subscription of its topic, its rules as the filter.
// Each gets a dead-letter topic, with a subscription that keeps what lands
// there.

const (
	gcpAPIVersion = "gcp.truthform.org/v1" // gcp.APIVersion
	psTopic       = "pubsub.googleapis.com/Topic"
	psSub         = "pubsub.googleapis.com/Subscription"
	gcpProject    = "projects/{{truthform|project}}"

	psMinAck       = 10
	psMaxAck       = 600
	psMinRetention = 600       // 10 minutes
	psMaxRetention = 7 * 86400 // a subscription keeps 7 days at most
	psMaxMessageKB = 10 * 1024 // 10 MB
	psMinAttempts  = 5
	psMaxAttempts  = 100
	psMaxFilter    = 256
	psMinExpiry    = 86400 // a subscription's expiration is at least a day
)

var (
	psName   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9\-_.~+%]{2,254}$`)
	psAttrID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
)

type pubSub struct{ m Map }

func gcpObject(typ, collection, schema, id string, spec map[string]any) snapshot.Object {
	rel := gcpProject + "/" + collLastOf(collection) + "/" + id
	s := map[string]any{"name": rel}
	for k, v := range spec {
		s[k] = v
	}
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": typ,
		"metadata": map[string]any{"name": rel, "annotations": map[string]any{
			"truthform.org/discovery":  "pubsub/v1",
			"truthform.org/schema":     schema,
			"truthform.org/collection": collection,
			"truthform.org/parent":     gcpProject,
		}}, "spec": s}}
}

func collLastOf(c string) string { return c[strings.LastIndex(c, ".")+1:] }

func psTopicObject(id string, spec map[string]any) snapshot.Object {
	return gcpObject(psTopic, "projects.topics", "Topic", id, spec)
}

func psSubObject(id string, spec map[string]any) snapshot.Object {
	return gcpObject(psSub, "projects.subscriptions", "Subscription", id, spec)
}

func (d pubSub) namespace(ns *sbNS, o *out) {
	e := Entry{Source: ns.src, State: Mapped, Reason: "Pub/Sub has no namespace: the project holds its topics and subscriptions"}
	e.Losses = append(e.Losses, ns.losses...)
	// Pub/Sub has no network setting of its own: what closes it is the
	// project's service perimeter, decided once everything is written.
	o.gcpClosedBy(gcpService{src: ns.src, field: "properties.publicNetworkAccess", what: "Service Bus namespace " + ns.group + "/" + ns.name,
		product: "Pub/Sub", api: "pubsub.googleapis.com", private: ns.private, ranges: ns.ranges, path: o.privatePathOf(sbNamespace, ns.group, ns.name), at: len(e.Losses)})
	if ns.cmk {
		e.Losses = append(e.Losses, Loss{Field: "properties.encryption", Widens: true,
			Why: "messages are encrypted with the customer's own key; the topics written here use Google's encryption until a Cloud KMS key is named (not translated yet)"})
	}
	if ns.tls == "1.2" || ns.tls == "1.3" {
		e.Losses = append(e.Losses, Loss{Field: "properties.minimumTlsVersion", Widens: true,
			Why: "TLS " + ns.tls + " at least on the source; Pub/Sub's floor is Google's and cannot be set per project: confirm it meets this"})
	}
	if ns.keys {
		o.require("Apps that sign in to Service Bus with shared access keys or connection strings must move to the target's identity (IAM, workload identity); no key is carried over")
	}
	o.require("Apps move from the Service Bus SDK to the Pub/Sub client: a queue is a topic with one subscription of its name, and a subscription's filter matches message attributes")
	o.entries = append(o.entries, e)
}

// subSpec builds a subscription's settings, its dead-letter topic and that
// topic's keeping subscription. It returns the objects to add beside the
// subscription and the losses.
func (d pubSub) subSpec(e *sbEntity, id, topicID string, ttlCap *float64, f *filter, o *out) (map[string]any, []snapshot.Object, []Loss, string) {
	losses := e.common("Pub/Sub")
	s := map[string]any{"topic": gcpProject + "/topics/" + topicID}
	if e.lock != nil {
		ack := clamp(*e.lock, psMinAck, psMaxAck)
		if ack != *e.lock {
			losses = append(losses, Loss{Field: "properties.lockDuration", Why: fmt.Sprintf("%s on the source; Pub/Sub's ack deadline is %ds", human(*e.lock), int(ack))})
		}
		s["ackDeadlineSeconds"] = int(ack)
	}
	ttl := e.ttl
	if ttlCap != nil && (ttl == nil || *ttlCap < *ttl) {
		ttl = ttlCap
	}
	switch {
	case ttl == nil || *ttl > psMaxRetention:
		s["messageRetentionDuration"] = strconv.Itoa(psMaxRetention) + "s"
		was := "messages never expire on the source"
		if ttl != nil {
			was = human(*ttl) + " on the source"
		}
		losses = append(losses, Loss{Field: "properties.defaultMessageTimeToLive", Why: was + "; a Pub/Sub subscription keeps one 7 days at most"})
	case *ttl < psMinRetention:
		s["messageRetentionDuration"] = strconv.Itoa(psMinRetention) + "s"
		losses = append(losses, Loss{Field: "properties.defaultMessageTimeToLive", Why: fmt.Sprintf("%s on the source; a Pub/Sub subscription keeps one at least 10 minutes", human(*ttl))})
	default:
		s["messageRetentionDuration"] = strconv.Itoa(int(*ttl)) + "s"
	}
	if e.dlExpiry {
		losses = append(losses, Loss{Field: "properties.deadLetteringOnMessageExpiration", Why: "Pub/Sub drops an expired message; it does not dead-letter it"})
	}
	// Pub/Sub deletes a subscription after 31 days without a subscriber
	// unless told otherwise; Service Bus deletes one only when asked.
	if e.autoDelete != nil {
		exp := clamp(*e.autoDelete, psMinExpiry, *e.autoDelete)
		if exp != *e.autoDelete {
			losses = append(losses, Loss{Field: "properties.autoDeleteOnIdle", Why: fmt.Sprintf("%s on the source; Pub/Sub expires an idle subscription after a day at the soonest", human(*e.autoDelete))})
		}
		s["expirationPolicy"] = map[string]any{"ttl": strconv.Itoa(int(exp)) + "s"}
	} else {
		s["expirationPolicy"] = map[string]any{}
	}
	attempts := sbDeliveries
	if e.maxDelivery != nil {
		attempts = *e.maxDelivery
	}
	if a := int(clamp(float64(attempts), psMinAttempts, psMaxAttempts)); a != attempts {
		losses = append(losses, Loss{Field: "properties.maxDeliveryCount", Why: fmt.Sprintf("%d on the source; Pub/Sub takes %d to %d delivery attempts", attempts, psMinAttempts, psMaxAttempts)})
		attempts = a
	}
	dl := e.dlqName(id)
	s["deadLetterPolicy"] = map[string]any{"deadLetterTopic": gcpProject + "/topics/" + dl, "maxDeliveryAttempts": attempts}
	extra := []snapshot.Object{
		psTopicObject(dl, nil),
		psSubObject(dl, map[string]any{"topic": gcpProject + "/topics/" + dl, "messageRetentionDuration": strconv.Itoa(psMaxRetention) + "s", "expirationPolicy": map[string]any{}}),
	}
	losses = append(losses, Loss{Field: "(dead-letter queue)", Why: "dead-lettered messages are kept 7 days at most on Pub/Sub; Service Bus keeps them until they are read"})
	o.require("Pub/Sub's service agent (service-<project-number>@gcp-sa-pubsub.iam.gserviceaccount.com) needs roles/pubsub.publisher on each dead-letter topic and roles/pubsub.subscriber on each subscription that dead-letters; no grant is written here")
	if e.session {
		s["enableMessageOrdering"] = true
		losses = append(losses, Loss{Field: "properties.requiresSession", Why: "ordered delivery: the publisher sets the ordering key to the session ID; there is no session state or session lock"})
	}
	if e.dup {
		losses = append(losses, Loss{Field: "properties.requiresDuplicateDetection", Why: "Pub/Sub does not drop a message published twice; the subscriber must"})
	}
	if e.maxSizeMB != nil {
		losses = append(losses, Loss{Field: "properties.maxSizeInMegabytes", Why: fmt.Sprintf("%d MB on the source; Pub/Sub has no size limit, so publishers are never refused for a full queue", *e.maxSizeMB)})
	}
	if e.maxMsgKB != nil && *e.maxMsgKB > psMaxMessageKB {
		losses = append(losses, Loss{Field: "properties.maxMessageSizeInKilobytes", Why: fmt.Sprintf("%d KB on the source; Pub/Sub takes 10 MB at most", *e.maxMsgKB)})
	}
	if f != nil && !f.all {
		expr, why := psFilter(f.any)
		if why != "" {
			return nil, nil, nil, why
		}
		s["filter"] = expr
	}
	return s, extra, losses, ""
}

func (d pubSub) refuseSession(e *sbEntity) string {
	if e.session && d.m.Sessions != "ordering" {
		return "a session " + e.kind + ": set sessions: ordering in the map to carry it as ordered delivery, with the session ID as the ordering key (a change to the publisher)"
	}
	return ""
}

func (d pubSub) queue(ns *sbNS, e *sbEntity, o *out) {
	id := d.m.sbName(e)
	refuse := func(why string) { o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why}) }
	if why := d.refuseSession(e); why != "" {
		refuse(why)
		return
	}
	if why := psBadName(id, e.key); why != "" {
		refuse(why)
		return
	}
	s, extra, losses, why := d.subSpec(e, id, id, nil, nil, o)
	if why != "" {
		refuse(why)
		return
	}
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	for _, obj := range append([]snapshot.Object{psTopicObject(id, nil), psSubObject(id, s)}, extra...) {
		en.Targets = append(en.Targets, o.add("gcp", e.src, obj))
	}
	o.entries = append(o.entries, en)
}

func (d pubSub) topic(ns *sbNS, e *sbEntity, o *out) {
	id := d.m.sbName(e)
	if why := psBadName(id, e.key); why != "" {
		o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why})
		return
	}
	losses := e.common("Pub/Sub")
	if e.ttl != nil {
		losses = append(losses, Loss{Field: "properties.defaultMessageTimeToLive", Why: "the topic's time to live is applied to its subscriptions"})
	}
	if e.dup {
		losses = append(losses, Loss{Field: "properties.requiresDuplicateDetection", Why: "Pub/Sub does not drop a message published twice; the subscriber must"})
	}
	if e.ordering {
		losses = append(losses, Loss{Field: "properties.supportOrdering", Why: "Pub/Sub orders per ordering key, on a subscription that asks for it; the publisher must set one"})
	}
	if e.maxSizeMB != nil {
		losses = append(losses, Loss{Field: "properties.maxSizeInMegabytes", Why: "Pub/Sub has no size limit, so publishers are never refused for a full topic"})
	}
	if e.autoDelete != nil {
		losses = append(losses, Loss{Field: "properties.autoDeleteOnIdle", Why: "Pub/Sub never deletes an idle topic"})
	}
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	en.Targets = append(en.Targets, o.add("gcp", e.src, psTopicObject(id, nil)))
	o.entries = append(o.entries, en)
}

func (d pubSub) subscription(ns *sbNS, e *sbEntity, o *out) {
	refuse := func(why string) {
		o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why})
		ruleEntries(e, Refused, "its subscription is refused: "+why, nil, o)
	}
	t := e.parent
	if t == nil {
		refuse("its topic is not in the snapshot")
		return
	}
	if why := d.refuseSession(e); why != "" {
		refuse(why)
		return
	}
	f := filterOf(e, nil)
	if f.why != "" {
		refuse(f.why)
		return
	}
	tid := d.m.sbName(t)
	id := d.m.name(e.key, tid+"-"+e.name)
	if why := psBadName(id, e.key); why != "" {
		refuse(why)
		return
	}
	s, extra, losses, why := d.subSpec(e, id, tid, t.ttl, &f, o)
	if why != "" {
		refuse(why)
		return
	}
	losses = append(losses, f.losses...)
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	for _, obj := range append([]snapshot.Object{psSubObject(id, s)}, extra...) {
		en.Targets = append(en.Targets, o.add("gcp", e.src, obj))
	}
	o.entries = append(o.entries, en)
	ruleEntries(e, Mapped, "", []string{psSub + " " + gcpProject + "/subscriptions/" + id}, o)
}

// psFilter is a Pub/Sub filter that matches when any rule does, each rule
// when all its attributes do.
func psFilter(rules []map[string]string) (string, string) {
	var ors []string
	for _, m := range rules {
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var ands []string
		for _, k := range ks {
			if !psAttrID.MatchString(k) {
				return "", fmt.Sprintf("the property %q is not a name a Pub/Sub filter can match", k)
			}
			ands = append(ands, "attributes."+k+" = "+strconv.Quote(m[k]))
		}
		ors = append(ors, strings.Join(ands, " AND "))
	}
	sort.Strings(ors)
	expr := ors[0]
	if len(ors) > 1 {
		for i := range ors {
			ors[i] = "(" + ors[i] + ")"
		}
		expr = strings.Join(ors, " OR ")
	}
	if len(expr) > psMaxFilter {
		return "", fmt.Sprintf("its rules make a filter of %d bytes; Pub/Sub takes %d at most", len(expr), psMaxFilter)
	}
	return expr, ""
}

func psBadName(id, key string) string {
	if !psName.MatchString(id) || strings.HasPrefix(strings.ToLower(id), "goog") {
		return fmt.Sprintf("%q is not a name Pub/Sub allows (a letter, then 2 to 254 of letters, digits and -_.~+%%, not starting goog): give it one under names: %q", id, key)
	}
	return ""
}
