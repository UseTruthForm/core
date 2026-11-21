package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/snapshot"
)

// Service Bus to SQS and SNS, as Cloud Control types the AWS restore
// creates. A queue is an SQS queue with its dead-letter queue beside it. A
// topic is an SNS topic. A subscription is an SQS queue of its own,
// subscribed to the topic with raw delivery, its rules as the
// subscription's filter policy, and a queue policy that lets only that
// topic send to it.

const (
	awsAPIVersion = "aws.truthform.org/v1" // awscc.APIVersion
	awsQueue      = "AWS::SQS::Queue"
	awsTopic      = "AWS::SNS::Topic"
	awsSub        = "AWS::SNS::Subscription"
	awsPolicy     = "AWS::SQS::QueueInlinePolicy"
	// A topic's policy, read by its topic as the queue's is by its queue.
	// AWS::SNS::TopicPolicy has no read handler, so a restore could not
	// tell whether one is there.
	awsTopicPolicy = "AWS::SNS::TopicInlinePolicy"

	sqsMaxRetention = 1209600 // 14 days
	sqsMinRetention = 60
	sqsMaxMessage   = 1048576 // 1 MiB
	sqsMaxReceive   = 1000
	// sbDeliveries is what Service Bus uses where maxDeliveryCount is not
	// set: the source's own behaviour, not a choice made here.
	sbDeliveries = 10
)

var (
	sqsName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	snsName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
)

type sqsSNS struct{ m Map }

func awsObject(kind, name string, spec map[string]any) snapshot.Object {
	return snapshot.Object{Body: map[string]any{"apiVersion": awsAPIVersion, "kind": kind,
		"metadata": map[string]any{"name": name}, "spec": spec}}
}

// awsRef is a reference the AWS restore resolves to what the target
// account generated (awscc.refToken).
func awsRef(kind, name, attr string) string {
	return "{{truthform|" + kind + "|" + name + "|" + attr + "}}"
}

// lock is how a private namespace's queues and topics are closed, or nil:
// when it was not private, or when there is nothing to lock them to.
func (d sqsSNS) lock(ns *sbNS, o *out, services ...string) *awsLock {
	if ns == nil || ns.private == "" {
		return nil
	}
	return lockAWS(o, sbNamespace, ns.group, ns.name, services, ns.ranges)
}

// queuePolicy is a queue's policy: the statements given, and the deny that
// keeps a private namespace's queue to its private path. A queue has one
// policy, so both are in it. It is nil when there is nothing to say.
func (d sqsSNS) queuePolicy(ns *sbNS, o *out, qn string, statements ...any) *snapshot.Object {
	if l := d.lock(ns, o, "sqs"); l != nil {
		statements = append(statements, l.statement(lockSQS, awsRef(awsQueue, qn, "Arn"), false))
	}
	if len(statements) == 0 {
		return nil
	}
	p := awsObject(awsPolicy, qn, map[string]any{"Queue": awsRef(awsQueue, qn, "QueueUrl"), "PolicyDocument": awsPolicyDoc(statements...)})
	return &p
}

func (d sqsSNS) namespace(ns *sbNS, o *out) {
	e := Entry{Source: ns.src, State: Mapped, Reason: "SQS and SNS have no namespace: the account and region hold its queues and topics"}
	e.Losses = append(e.Losses, ns.losses...)
	if ns.private != "" {
		if l := d.lock(ns, o, "sqs", "sns"); l == nil {
			e.Losses = append(e.Losses, Loss{Field: "properties.publicNetworkAccess", Widens: true,
				Why: ns.private + "; " + lockNoPath + ". SQS and SNS answer on their public endpoints, guarded by IAM alone"})
		} else {
			e.Reason += "; its queues and topics answer only " + l.where()
			if ns.vnets > 0 {
				e.Losses = append(e.Losses, Loss{Field: "networkRuleSets.properties.virtualNetworkRules",
					Why: fmt.Sprintf("%d subnet(s) were allowed by service endpoint; on AWS a subnet reaches the queues and topics through its VPC's interface endpoints, and only those written for a private endpoint are let through", ns.vnets)})
			}
			lockRequireAWS(o, "Service Bus namespace "+ns.group+"/"+ns.name+"'s queues and topics answer", l)
		}
	}
	if ns.cmk {
		e.Losses = append(e.Losses, Loss{Field: "properties.encryption", Widens: true,
			Why: "messages are encrypted with the customer's own key; the queues and topics written here use SQS's managed encryption until a KMS key is named (not translated yet)"})
	}
	if ns.keys {
		o.require("Apps that sign in to Service Bus with shared access keys or connection strings must move to the target's identity (IAM, workload identity); no key is carried over")
	}
	o.require("Apps move from the Service Bus SDK to the AWS SDK: a queue is an SQS queue, a topic an SNS topic delivering to an SQS queue per subscription, and a subscription's filter matches SNS message attributes")
	o.entries = append(o.entries, e)
}

// queueSpecs builds an SQS queue and its dead-letter queue from an entity's
// settings. The second result is the entity's losses on SQS.
func (d sqsSNS) queueSpecs(e *sbEntity, name string, fifo bool, ttlCap *float64) ([]snapshot.Object, []Loss) {
	losses := e.common("SQS")
	qn, dn := name, e.dlqName(name)
	if fifo {
		qn, dn = qn+".fifo", dn+".fifo"
	}
	q := map[string]any{"QueueName": qn}
	dl := map[string]any{"QueueName": dn, "MessageRetentionPeriod": sqsMaxRetention}
	if fifo {
		q["FifoQueue"], dl["FifoQueue"] = true, true
	}
	if e.lock != nil {
		q["VisibilityTimeout"] = int(clamp(*e.lock, 0, 43200))
	}
	ttl := e.ttl
	if ttlCap != nil && (ttl == nil || *ttlCap < *ttl) {
		ttl = ttlCap
	}
	switch {
	case ttl == nil:
		q["MessageRetentionPeriod"] = sqsMaxRetention
		losses = append(losses, Loss{Field: "properties.defaultMessageTimeToLive", Why: "messages never expire on the source; SQS keeps one 14 days at most"})
	case *ttl > sqsMaxRetention:
		q["MessageRetentionPeriod"] = sqsMaxRetention
		losses = append(losses, Loss{Field: "properties.defaultMessageTimeToLive", Why: fmt.Sprintf("%s on the source; SQS keeps a message 14 days at most", human(*ttl))})
	case *ttl < sqsMinRetention:
		q["MessageRetentionPeriod"] = sqsMinRetention
		losses = append(losses, Loss{Field: "properties.defaultMessageTimeToLive", Why: fmt.Sprintf("%s on the source; SQS keeps a message at least a minute", human(*ttl))})
	default:
		q["MessageRetentionPeriod"] = int(*ttl)
	}
	losses = append(losses, Loss{Field: "(dead-letter queue)", Why: "dead-lettered messages are kept 14 days at most on SQS; Service Bus keeps them until they are read"})
	if e.dlExpiry {
		losses = append(losses, Loss{Field: "properties.deadLetteringOnMessageExpiration", Why: "SQS deletes an expired message; it does not dead-letter it"})
	}
	deliveries := sbDeliveries
	if e.maxDelivery != nil {
		deliveries = *e.maxDelivery
	}
	if deliveries > sqsMaxReceive {
		losses = append(losses, Loss{Field: "properties.maxDeliveryCount", Why: fmt.Sprintf("%d on the source; SQS allows at most %d receives", deliveries, sqsMaxReceive)})
		deliveries = sqsMaxReceive
	}
	q["RedrivePolicy"] = map[string]any{"deadLetterTargetArn": awsRef(awsQueue, dn, "Arn"), "maxReceiveCount": deliveries}
	if e.dup {
		if fifo {
			q["DeduplicationScope"] = "queue"
			if e.dupWindow != nil && *e.dupWindow != 300 {
				losses = append(losses, Loss{Field: "properties.duplicateDetectionHistoryTimeWindow", Why: fmt.Sprintf("%s on the source; SQS's window is 5 minutes", human(*e.dupWindow))})
			}
			o := "the sender sets MessageDeduplicationId (Service Bus used MessageId)"
			losses = append(losses, Loss{Field: "properties.requiresDuplicateDetection", Why: o})
		} else {
			losses = append(losses, Loss{Field: "properties.requiresDuplicateDetection", Why: "duplicate detection needs a FIFO queue on SQS, and this one is not a session queue"})
		}
	}
	if e.maxSizeMB != nil {
		losses = append(losses, Loss{Field: "properties.maxSizeInMegabytes", Why: fmt.Sprintf("%d MB on the source; an SQS queue has no size limit, so senders are never refused for a full queue", *e.maxSizeMB)})
	}
	if e.maxMsgKB != nil {
		b := *e.maxMsgKB * 1024
		if b > sqsMaxMessage {
			losses = append(losses, Loss{Field: "properties.maxMessageSizeInKilobytes", Why: fmt.Sprintf("%d KB on the source; SQS takes 1 MiB at most", *e.maxMsgKB)})
			b = sqsMaxMessage
		}
		q["MaximumMessageSize"] = b
	}
	if e.autoDelete != nil {
		losses = append(losses, Loss{Field: "properties.autoDeleteOnIdle", Why: fmt.Sprintf("deleted after %s idle on the source; SQS never deletes an idle queue", human(*e.autoDelete))})
	}
	if e.session {
		losses = append(losses, Loss{Field: "properties.requiresSession", Why: "a FIFO queue: the sender sets MessageGroupId to the session ID, and SQS keeps order per group; there is no session state or session lock"})
	}
	return []snapshot.Object{awsObject(awsQueue, qn, q), awsObject(awsQueue, dn, dl)}, losses
}

func (d sqsSNS) refuseSession(e *sbEntity) string {
	if e.session && d.m.Sessions != "fifo" {
		return "a session " + e.kind + ": set sessions: fifo in the map to carry it as a FIFO queue, with the session ID as the message group (a change to the sender)"
	}
	return ""
}

func (d sqsSNS) queue(ns *sbNS, e *sbEntity, o *out) {
	name := d.m.name(e.key, e.name)
	if why := d.refuseSession(e); why != "" {
		o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why})
		return
	}
	if why := badName(sqsName, "an SQS queue", name, e.session, e.key); why != "" {
		o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why})
		return
	}
	objs, losses := d.queueSpecs(e, name, e.session, nil)
	for _, q := range objs[:2] {
		if p := d.queuePolicy(ns, o, q.Name()); p != nil {
			objs = append(objs, *p)
		}
	}
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	for _, obj := range objs {
		en.Targets = append(en.Targets, o.add("aws", e.src, obj))
	}
	o.entries = append(o.entries, en)
}

func (d sqsSNS) topic(ns *sbNS, e *sbEntity, o *out) {
	name := d.m.name(e.key, e.name)
	fifo := e.subSession && d.m.Sessions == "fifo"
	if why := badName(snsName, "an SNS topic", name, fifo, e.key); why != "" {
		o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why})
		return
	}
	tn := name
	spec := map[string]any{}
	if fifo {
		tn += ".fifo"
		spec["FifoTopic"] = true
	}
	spec["TopicName"] = tn
	losses := e.common("SNS")
	if e.ttl != nil {
		losses = append(losses, Loss{Field: "properties.defaultMessageTimeToLive", Why: "SNS holds no messages; the topic's time to live is applied to its subscriptions' queues"})
	}
	if e.dup {
		if fifo {
			spec["ContentBasedDeduplication"] = false
			losses = append(losses, Loss{Field: "properties.requiresDuplicateDetection", Why: "the publisher sets MessageDeduplicationId (Service Bus used MessageId); the window is 5 minutes"})
		} else {
			losses = append(losses, Loss{Field: "properties.requiresDuplicateDetection", Why: "duplicate detection needs a FIFO topic on SNS, and none of this topic's subscriptions is a session subscription"})
		}
	}
	if e.ordering && !fifo {
		losses = append(losses, Loss{Field: "properties.supportOrdering", Why: "a standard SNS topic does not keep order"})
	}
	if e.maxSizeMB != nil {
		losses = append(losses, Loss{Field: "properties.maxSizeInMegabytes", Why: "SNS holds no messages, so there is no size to limit"})
	}
	if e.maxMsgKB != nil && *e.maxMsgKB > 256 {
		losses = append(losses, Loss{Field: "properties.maxMessageSizeInKilobytes", Why: fmt.Sprintf("%d KB on the source; SNS publishes 256 KB at most", *e.maxMsgKB)})
	}
	if e.autoDelete != nil {
		losses = append(losses, Loss{Field: "properties.autoDeleteOnIdle", Why: "SNS never deletes an idle topic"})
	}
	if e.subSession && d.m.Sessions != "fifo" {
		losses = append(losses, Loss{Field: "(subscriptions)", Why: "a session subscription of this topic is refused; with sessions: fifo the topic would be a FIFO topic"})
	}
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	en.Targets = append(en.Targets, o.add("aws", e.src, awsObject(awsTopic, tn, spec)))
	if l := d.lock(ns, o, "sns"); l != nil {
		// Publishing is closed; subscribing is the topic's configuration,
		// which the restore itself writes from outside.
		arn := awsRef(awsTopic, tn, "TopicArn")
		en.Targets = append(en.Targets, o.add("aws", e.src, awsObject(awsTopicPolicy, tn, map[string]any{
			"TopicArn": arn, "PolicyDocument": awsPolicyDoc(l.statement(lockSNS, arn, false))})))
	}
	o.entries = append(o.entries, en)
}

func (d sqsSNS) subscription(ns *sbNS, e *sbEntity, o *out) {
	refuse := func(why string) {
		o.entries = append(o.entries, Entry{Source: e.src, State: Refused, Reason: why})
		ruleEntries(e, Refused, "its subscription is refused: "+why, nil, o)
	}
	t := e.parent
	if t == nil {
		refuse("its topic is not in the snapshot")
		return
	}
	fifo := t.subSession && d.m.Sessions == "fifo"
	if why := d.refuseSession(e); why != "" {
		refuse(why)
		return
	}
	f := filterOf(e, nil)
	if f.why != "" {
		refuse(f.why)
		return
	}
	name := d.m.name(e.key, d.m.name(t.key, t.name)+"-"+e.name)
	if why := badName(sqsName, "an SQS queue", name, fifo, e.key); why != "" {
		refuse(why)
		return
	}
	objs, losses := d.queueSpecs(e, name, fifo, t.ttl)
	losses = append(losses, f.losses...)
	qn := objs[0].Name()
	tn := d.m.name(t.key, t.name)
	if fifo {
		tn += ".fifo"
	}
	topicArn := awsRef(awsTopic, tn, "TopicArn")
	queueArn := awsRef(awsQueue, qn, "Arn")
	sub := map[string]any{"TopicArn": topicArn, "Protocol": "sqs", "Endpoint": queueArn, "RawMessageDelivery": true}
	if !f.all {
		sub["FilterPolicyScope"] = "MessageAttributes"
		sub["FilterPolicy"] = snsFilter(f.any)
	}
	// The topic delivers as SNS itself (sns.amazonaws.com), which the deny
	// of a private namespace's queue lets through: it is not a request of
	// a principal of the account, and comes through no endpoint.
	policy := d.queuePolicy(ns, o, qn, map[string]any{
		"Effect": "Allow", "Principal": map[string]any{"Service": "sns.amazonaws.com"},
		"Action": "sqs:SendMessage", "Resource": queueArn,
		"Condition": map[string]any{"ArnEquals": map[string]any{"aws:SourceArn": topicArn}},
	})
	// A subscription has no name of its own: it is named as a capture
	// names it, by its spec, so a second restore finds the first one's.
	subObj := awsObject(awsSub, awscc.SpecName(awsSub, sub), sub)
	if dl := d.queuePolicy(ns, o, objs[1].Name()); dl != nil {
		objs = append(objs, *dl)
	}
	objs = append(objs, subObj, *policy)
	en := Entry{Source: e.src, State: Mapped, Losses: losses}
	for _, obj := range objs {
		en.Targets = append(en.Targets, o.add("aws", e.src, obj))
	}
	o.entries = append(o.entries, en)
	ruleEntries(e, Mapped, "", []string{subObj.Kind() + " " + subObj.Name()}, o)
}

// snsFilter is an SNS filter policy that matches when any of the rules
// does, each rule matching when all its properties do.
func snsFilter(rules []map[string]string) map[string]any {
	one := func(m map[string]string) map[string]any {
		out := map[string]any{}
		for k, v := range m {
			out[k] = []any{v}
		}
		return out
	}
	if len(rules) == 1 {
		return one(rules[0])
	}
	sort.Slice(rules, func(i, j int) bool { return fmt.Sprint(rules[i]) < fmt.Sprint(rules[j]) })
	ors := make([]any, len(rules))
	for i, m := range rules {
		ors[i] = one(m)
	}
	return map[string]any{"$or": ors}
}

// badName says why a name is not one the target allows, and how to give one.
func badName(re *regexp.Regexp, what, name string, fifo bool, key string) string {
	n := name
	if fifo {
		n = strings.TrimSuffix(n, ".fifo")
		if len(n)+len(".fifo") > 80 && re == sqsName {
			return fmt.Sprintf("%q is too long for a FIFO SQS queue (80 with .fifo): give it a name under names: %q", name, key)
		}
	}
	if !re.MatchString(n) {
		return fmt.Sprintf("%q is not a name %s allows: give it one under names: %q", name, what, key)
	}
	return ""
}
