package translate

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Service Bus to RabbitMQ in the cluster, as the custom resources of the
// RabbitMQ Cluster Operator and Messaging Topology Operator. They go into
// the Kubernetes snapshot, so the cloud needs only a cluster, and the same
// translation serves AWS, GCP or anywhere else.
//
// A namespace is a RabbitmqCluster. A queue is a quorum queue, with its
// dead-letter queue beside it through the default exchange. A topic is a
// headers exchange, and a subscription a quorum queue bound to it once per
// rule: a headers binding matches when all its headers do, and a queue
// bound several times receives a message when any binding matches, which
// is how a Service Bus subscription's rules combine.

const (
	rabbitAPIVersion = "rabbitmq.com/v1beta1"
	k8sNameMax       = 253
)

var k8sBad = regexp.MustCompile(`[^a-z0-9.-]+`)

type rabbit struct{ m Map }

// k8sName makes a Kubernetes object name from the parts, or says why it
// cannot: two source names that differ only in case would collide, which
// out.add refuses.
func k8sName(parts ...string) string {
	n := strings.Trim(k8sBad.ReplaceAllString(strings.ToLower(strings.Join(parts, ".")), "-"), "-.")
	if len(n) > k8sNameMax {
		n = n[:k8sNameMax]
	}
	return n
}

func (d rabbit) object(kind, name string, spec map[string]any) snapshot.Object {
	return snapshot.Object{Body: map[string]any{"apiVersion": rabbitAPIVersion, "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": d.m.RabbitMQ.Namespace}, "spec": spec}}
}

func (d rabbit) cluster(ns *sbNS) string { return k8sName(ns.name) }

func (d rabbit) namespace(ns *sbNS, o *out) {
	spec := map[string]any{"replicas": d.m.RabbitMQ.Replicas}
	e := Entry{Source: ns.src, State: Mapped}
	e.Losses = append(e.Losses, ns.losses...)
	if d.m.RabbitMQ.TLSSecret != "" {
		spec["tls"] = map[string]any{"secretName": d.m.RabbitMQ.TLSSecret, "disableNonTLSListeners": true}
	} else {
		e.Losses = append(e.Losses, Loss{Field: "(transport)", Widens: true,
			Why: "Service Bus takes only TLS; these brokers listen in plain text until rabbitmq.tlsSecret names a certificate in the map"})
	}
	if d.m.RabbitMQ.Replicas < 3 {
		e.Losses = append(e.Losses, Loss{Field: "(availability)", Why: fmt.Sprintf("%d broker(s): a quorum queue needs 3 to keep working when one is lost", d.m.RabbitMQ.Replicas)})
	}
	if ns.cmk {
		e.Losses = append(e.Losses, Loss{Field: "properties.encryption", Widens: true,
			Why: "messages are encrypted with the customer's own key; on the brokers they are encrypted at rest only as their volumes' storage class does"})
	}
	if ns.private != "" {
		e.Losses = append(e.Losses, Loss{Field: "properties.publicNetworkAccess",
			Why: ns.private + "; the brokers' Service is reachable inside the cluster only, unless it is exposed"})
	}
	if ns.keys {
		o.require("Apps that sign in to Service Bus with shared access keys or connection strings must move to the target's identity (IAM, workload identity); no key is carried over")
	}
	o.require("In the cluster: the RabbitMQ Cluster Operator and the Messaging Topology Operator are installed before these objects are restored")
	o.require("Run by you, not the cloud: the brokers' storage (spec.persistence: size and storage class, not set here), their resources, upgrades and backups")
	o.require("Apps move from the Service Bus SDK to an AMQP client: a queue is a quorum queue, a topic a headers exchange, and a message's application properties travel as headers, which the bindings match")
	e.Targets = append(e.Targets, o.add("kubernetes", ns.src, d.object("RabbitmqCluster", d.cluster(ns), spec)))
	o.entries = append(o.entries, e)
}

// queueSpec builds a quorum queue and its dead-letter queue.
func (d rabbit) queueSpec(ns *sbNS, e *sbEntity, qname string, ttlCap *float64) ([]snapshot.Object, []Loss) {
	losses := e.common("RabbitMQ")
	ref := map[string]any{"name": d.cluster(ns)}
	dl := e.dlqName(qname)
	args := map[string]any{
		"x-dead-letter-exchange":    "",
		"x-dead-letter-routing-key": dl,
		// At-least-once dead-lettering, so a message is never lost on its
		// way to the dead-letter queue; it needs reject-publish.
		"x-dead-letter-strategy": "at-least-once",
		"x-overflow":             "reject-publish",
	}
	deliveries := sbDeliveries
	if e.maxDelivery != nil {
		deliveries = *e.maxDelivery
	}
	args["x-delivery-limit"] = deliveries
	ttl := e.ttl
	if ttlCap != nil && (ttl == nil || *ttlCap < *ttl) {
		ttl = ttlCap
	}
	if ttl != nil {
		args["x-message-ttl"] = int64(*ttl * 1000)
		if !e.dlExpiry {
			losses = append(losses, Loss{Field: "properties.deadLetteringOnMessageExpiration", Why: "off on the source, so an expired message was dropped; RabbitMQ dead-letters expired messages too"})
		}
	}
	if e.lock != nil {
		args["x-consumer-timeout"] = int64(*e.lock * 1000)
		losses = append(losses, Loss{Field: "properties.lockDuration", Why: "a consumer that does not acknowledge in time has its channel closed and the message redelivered; there is no lock to renew"})
	}
	if e.maxSizeMB != nil {
		args["x-max-length-bytes"] = int64(*e.maxSizeMB) * 1024 * 1024
	}
	if e.autoDelete != nil {
		args["x-expires"] = int64(*e.autoDelete * 1000)
	}
	if e.session {
		args["x-single-active-consumer"] = true
		losses = append(losses, Loss{Field: "properties.requiresSession", Why: "one consumer at a time keeps the queue's order, but not per-session parallelism, session state or session locks"})
	}
	if e.dup {
		losses = append(losses, Loss{Field: "properties.requiresDuplicateDetection", Why: "RabbitMQ has no duplicate detection built in; the consumer must drop a message sent twice"})
	}
	if e.maxMsgKB != nil {
		losses = append(losses, Loss{Field: "properties.maxMessageSizeInKilobytes", Why: fmt.Sprintf("%d KB on the source; RabbitMQ's limit is the brokers' max_message_size, set for all queues", *e.maxMsgKB)})
	}
	q := map[string]any{"name": qname, "type": "quorum", "durable": true, "autoDelete": false, "arguments": args, "rabbitmqClusterReference": ref}
	dq := map[string]any{"name": dl, "type": "quorum", "durable": true, "autoDelete": false, "rabbitmqClusterReference": ref}
	c := d.cluster(ns)
	return []snapshot.Object{d.object("Queue", k8sName(c, qname), q), d.object("Queue", k8sName(c, dl), dq)}, losses
}

func (d rabbit) refuseSession(e *sbEntity) string {
	if e.session && d.m.Sessions != "single-active-consumer" {
		return "a session " + e.kind + ": set sessions: single-active-consumer in the map to carry it as a queue read by one consumer at a time (order kept, per-session parallelism lost)"
	}
	return ""
}

func (d rabbit) queue(ns *sbNS, e *sbEntity, o *out) {
	if why := d.refuseSession(e); why != "" {
		o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why})
		return
	}
	objs, losses := d.queueSpec(ns, e, d.m.sbName(e), nil)
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	for _, obj := range objs {
		en.Targets = append(en.Targets, o.add("kubernetes", e.src, obj))
	}
	o.entries = append(o.entries, en)
}

func (d rabbit) topic(ns *sbNS, e *sbEntity, o *out) {
	name := d.m.sbName(e)
	losses := e.common("RabbitMQ")
	if e.ttl != nil {
		losses = append(losses, Loss{Field: "properties.defaultMessageTimeToLive", Why: "an exchange holds no messages; the topic's time to live is applied to its subscriptions' queues"})
	}
	if e.dup {
		losses = append(losses, Loss{Field: "properties.requiresDuplicateDetection", Why: "RabbitMQ has no duplicate detection built in; the consumer must drop a message sent twice"})
	}
	if e.maxSizeMB != nil {
		losses = append(losses, Loss{Field: "properties.maxSizeInMegabytes", Why: "an exchange holds no messages; each subscription's queue has its own limit"})
	}
	if e.autoDelete != nil {
		losses = append(losses, Loss{Field: "properties.autoDeleteOnIdle", Why: "an exchange is not deleted when idle"})
	}
	ex := map[string]any{"name": name, "type": "headers", "durable": true, "autoDelete": false, "rabbitmqClusterReference": map[string]any{"name": d.cluster(ns)}}
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	en.Targets = append(en.Targets, o.add("kubernetes", e.src, d.object("Exchange", k8sName(d.cluster(ns), "x", name), ex)))
	o.entries = append(o.entries, en)
}

func (d rabbit) subscription(ns *sbNS, e *sbEntity, o *out) {
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
	tname := d.m.sbName(t)
	qname := d.m.name(e.key, tname+"."+e.name)
	objs, losses := d.queueSpec(ns, e, qname, t.ttl)
	losses = append(losses, f.losses...)
	matches := f.any
	if f.all {
		matches = []map[string]string{{}}
	}
	c := d.cluster(ns)
	var bindings []string
	for i, m := range matches {
		args := map[string]any{"x-match": "all"}
		for k, v := range m {
			args[k] = v
		}
		b := map[string]any{"source": tname, "destination": qname, "destinationType": "queue", "arguments": args,
			"rabbitmqClusterReference": map[string]any{"name": c}}
		obj := d.object("Binding", k8sName(c, "b", qname, fmt.Sprint(i)), b)
		objs = append(objs, obj)
		bindings = append(bindings, "Binding "+obj.Name())
	}
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	for _, obj := range objs {
		en.Targets = append(en.Targets, o.add("kubernetes", e.src, obj))
	}
	o.entries = append(o.entries, en)
	ruleEntries(e, Mapped, "", bindings, o)
}
