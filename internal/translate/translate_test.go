package translate

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// az is an Azure object as a capture writes it.
func az(kind, group, name string, spec map[string]any) snapshot.Object {
	return snapshot.Object{Body: map[string]any{"apiVersion": "azure.truthform.org/v1", "kind": kind,
		"metadata": map[string]any{"name": name, "namespace": group}, "spec": spec}}
}

func pr(p map[string]any) map[string]any { return map[string]any{"properties": p} }

// fixture is a made-up Service Bus namespace holding one of each thing the
// destinations translate, and one each of what they refuse.
func fixture() snapshot.Snapshot {
	never := "P10675199DT2H48M5.4775807S"
	objs := []snapshot.Object{
		az("Microsoft.ServiceBus/namespaces", "rg", "shop", map[string]any{"location": "westeurope",
			"sku":        map[string]any{"name": "Standard", "tier": "Standard"},
			"properties": map[string]any{"minimumTlsVersion": "1.2", "publicNetworkAccess": "Enabled", "disableLocalAuth": false, "zoneRedundant": true}}),
		az("Microsoft.ServiceBus/namespaces/networkRuleSets", "rg", "shop/default", pr(map[string]any{
			"defaultAction": "Deny", "publicNetworkAccess": "Enabled", "ipRules": []any{map[string]any{"ipMask": "203.0.113.0/24", "action": "Allow"}},
			"virtualNetworkRules": []any{}, "trustedServiceAccessEnabled": false})),
		az("Microsoft.ServiceBus/namespaces/queues", "rg", "shop/orders", pr(map[string]any{
			"lockDuration": "PT1M", "maxSizeInMegabytes": 1024, "requiresDuplicateDetection": false, "requiresSession": false,
			"defaultMessageTimeToLive": "P14D", "deadLetteringOnMessageExpiration": true, "duplicateDetectionHistoryTimeWindow": "PT10M",
			"maxDeliveryCount": 10, "status": "Active", "enableBatchedOperations": true, "autoDeleteOnIdle": never,
			"enablePartitioning": false, "enableExpress": false})),
		az("Microsoft.ServiceBus/namespaces/queues", "rg", "shop/payments", pr(map[string]any{
			"lockDuration": "PT30S", "requiresSession": true, "requiresDuplicateDetection": true, "duplicateDetectionHistoryTimeWindow": "PT5M",
			"defaultMessageTimeToLive": never, "maxDeliveryCount": 5, "status": "Active", "autoDeleteOnIdle": never})),
		az("Microsoft.ServiceBus/namespaces/queues", "rg", "shop/legacy.feed", pr(map[string]any{
			"lockDuration": "PT1M", "maxDeliveryCount": 10, "defaultMessageTimeToLive": "P1D", "status": "Active", "someNewSetting": "x"})),
		az("Microsoft.ServiceBus/namespaces/queues/authorizationRules", "rg", "shop/orders/sender", pr(map[string]any{"rights": []any{"Send"}})),
		az("Microsoft.ServiceBus/namespaces/topics", "rg", "shop/events", pr(map[string]any{
			"defaultMessageTimeToLive": "P7D", "maxSizeInMegabytes": 1024, "requiresDuplicateDetection": false, "status": "Active",
			"supportOrdering": true, "autoDeleteOnIdle": never, "enableBatchedOperations": true})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "rg", "shop/events/audit", pr(map[string]any{
			"lockDuration": "PT1M", "maxDeliveryCount": 10, "defaultMessageTimeToLive": never, "deadLetteringOnFilterEvaluationExceptions": true, "status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop/events/audit/$Default", pr(map[string]any{
			"filterType": "SqlFilter", "sqlFilter": map[string]any{"sqlExpression": "1=1", "compatibilityLevel": 20}})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "rg", "shop/events/shipping", pr(map[string]any{
			"lockDuration": "PT2M", "maxDeliveryCount": 3, "defaultMessageTimeToLive": "P1D", "status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop/events/shipping/shipped", pr(map[string]any{
			"filterType": "CorrelationFilter", "correlationFilter": map[string]any{"properties": map[string]any{"type": "order.shipped"}}})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop/events/shipping/returned", pr(map[string]any{
			"filterType": "CorrelationFilter", "correlationFilter": map[string]any{"properties": map[string]any{"type": "order.returned", "region": "eu"}}})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "rg", "shop/events/fraud", pr(map[string]any{
			"lockDuration": "PT1M", "maxDeliveryCount": 10, "status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop/events/fraud/big", pr(map[string]any{
			"filterType": "SqlFilter", "sqlFilter": map[string]any{"sqlExpression": "amount > 1000"}})),
		az("Microsoft.Storage/storageAccounts", "rg", "shopfiles", map[string]any{"location": "westeurope"}),
		az("Microsoft.Maps/accounts", "rg", "shopmaps", map[string]any{"location": "westeurope"}),
	}
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: objs}
}

func maps() map[string]Map {
	aws := Map{To: "aws", Region: "eu-west-1", Sessions: "fifo", Names: map[string]string{"rg/shop/legacy.feed": "legacy-feed"}}
	aws.Destinations.Messaging = "sqs-sns"
	gcp := Map{To: "gcp", Sessions: "ordering"}
	gcp.Destinations.Messaging = "pubsub"
	rmq := Map{To: "aws", Region: "eu-west-1", Sessions: "single-active-consumer", RabbitMQ: &RabbitMQ{Namespace: "messaging", Replicas: 3}}
	rmq.Destinations.Messaging = "rabbitmq"
	return map[string]Map{"sqs-sns": aws, "pubsub": gcp, "rabbitmq": rmq}
}

// targets are the definitions from testdata: the AWS tests' SQS queue, SNS
// topic, VPC pieces, S3 bucket and secret, this package's SNS
// subscription, inline policy, bucket policy, ECR repository creation
// template, Route 53 and RDS types, and the Pub/Sub, Compute, Cloud
// Storage, Secret Manager, Artifact Registry, Cloud DNS and Cloud SQL
// Discovery documents.
func targets(t *testing.T) Targets {
	t.Helper()
	dir := t.TempDir()
	for src, name := range map[string]string{
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-sqs-queue.json"):             "aws-sqs-queue.json",
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-sns-topic.json"):             "aws-sns-topic.json",
		filepath.Join("testdata", "aws", "aws-sns-subscription.json"):                             "aws-sns-subscription.json",
		filepath.Join("testdata", "aws", "aws-sqs-queueinlinepolicy.json"):                        "aws-sqs-queueinlinepolicy.json",
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-ec2-vpc.json"):               "aws-ec2-vpc.json",
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-ec2-subnet.json"):            "aws-ec2-subnet.json",
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-ec2-securitygroup.json"):     "aws-ec2-securitygroup.json",
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-secretsmanager-secret.json"): "aws-secretsmanager-secret.json",
		filepath.Join("testdata", "aws", "aws-ecr-repositorycreationtemplate.json"):               "aws-ecr-repositorycreationtemplate.json",
		filepath.Join("..", "..", "testdata", "aws", "schemas", "aws-s3-bucket.json"):             "aws-s3-bucket.json",
		filepath.Join("testdata", "aws", "aws-s3-bucketpolicy.json"):                              "aws-s3-bucketpolicy.json",
		filepath.Join("testdata", "aws", "aws-route53-hostedzone.json"):                           "aws-route53-hostedzone.json",
		filepath.Join("testdata", "aws", "aws-route53-recordset.json"):                            "aws-route53-recordset.json",
		filepath.Join("testdata", "aws", "aws-rds-dbinstance.json"):                               "aws-rds-dbinstance.json",
		filepath.Join("testdata", "aws", "aws-rds-dbsubnetgroup.json"):                            "aws-rds-dbsubnetgroup.json",
		filepath.Join("testdata", "aws", "aws-rds-dbparametergroup.json"):                         "aws-rds-dbparametergroup.json",
		filepath.Join("testdata", "aws", "aws-eks-cluster.json"):                                  "aws-eks-cluster.json",
		filepath.Join("testdata", "aws", "aws-eks-nodegroup.json"):                                "aws-eks-nodegroup.json",
		filepath.Join("testdata", "aws", "aws-eks-addon.json"):                                    "aws-eks-addon.json",
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reg, err := awscc.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	gdir := t.TempDir()
	for _, src := range []string{filepath.Join("testdata", "gcp", "pubsub_v1.json"), filepath.Join("..", "..", "testdata", "gcp", "discovery", "compute_v1.json"),
		filepath.Join("testdata", "gcp", "secretmanager_v1.json"), filepath.Join("testdata", "gcp", "artifactregistry_v1.json"), filepath.Join("testdata", "gcp", "storage_v1.json"), filepath.Join("testdata", "gcp", "dns_v1.json"), filepath.Join("testdata", "gcp", "sqladmin_v1.json"), filepath.Join("testdata", "gcp", "container_v1.json")} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(gdir, filepath.Base(src)), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Targets{AWS: reg, GCP: gcp.LoadDocs(gdir)}
}

func translateFixture(t *testing.T, s snapshot.Snapshot, m Map) (Result, error) {
	t.Helper()
	return Translate(s, m, targets(t))
}

func run(t *testing.T, m Map) Result {
	t.Helper()
	r, err := translateFixture(t, fixture(), m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func entry(t *testing.T, r Result, prefix string) Entry {
	t.Helper()
	for _, e := range r.Report.Entries {
		if strings.HasPrefix(e.Source, prefix) {
			return e
		}
	}
	t.Fatalf("no entry for %s", prefix)
	return Entry{}
}

func object(t *testing.T, r Result, platform, kind, name string) map[string]any {
	t.Helper()
	for _, o := range r.Snapshots[platform].Objects {
		if o.Kind() == kind && o.Name() == name {
			s, _ := o.Body["spec"].(map[string]any)
			return s
		}
	}
	t.Fatalf("no %s %s in the %s snapshot", kind, name, platform)
	return nil
}

func hasLoss(e Entry, field string) *Loss {
	for i := range e.Losses {
		if e.Losses[i].Field == field {
			return &e.Losses[i]
		}
	}
	return nil
}

// The whole of each translation is pinned, objects and report: a change to
// any rule shows here, line by line.
func TestGolden(t *testing.T) {
	for name, m := range maps() {
		golden(t, name, run(t, m))
	}
}

func golden(t *testing.T, name string, r Result) {
	t.Helper()
	doc := map[string]any{"report": r.Report}
	objs := map[string]any{}
	for p, s := range r.Snapshots {
		var bodies []any
		for _, o := range s.Objects {
			bodies = append(bodies, o.Body)
		}
		objs[p] = bodies
	}
	doc["snapshots"] = objs
	got, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", name+".yaml")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if string(got) != string(want) {
		t.Errorf("%s: the translation differs from %s; run with -update and read the diff", name, path)
	}
}

// Every source object is in the report exactly once, and nothing is
// silently dropped.
func TestEverySourceIsReportedOnce(t *testing.T) {
	src := fixture()
	for name, m := range maps() {
		r := run(t, m)
		seen := map[string]int{}
		for _, e := range r.Report.Entries {
			seen[e.Source]++
		}
		for _, o := range src.Objects {
			if seen[source(o)] != 1 {
				t.Errorf("%s: %s is reported %d times", name, source(o), seen[source(o)])
			}
		}
		if len(seen) != len(src.Objects) {
			t.Errorf("%s: %d entries for %d objects", name, len(seen), len(src.Objects))
		}
	}
}

func TestStates(t *testing.T) {
	for name, m := range maps() {
		r := run(t, m)
		if e := entry(t, r, "Microsoft.Maps/accounts"); e.State != NotLooked {
			t.Errorf("%s: a type with no descriptor is %s", name, e.State)
		}
		if e := entry(t, r, "Microsoft.Storage/storageAccounts"); e.State != Refused || !strings.Contains(e.Reason, "destinations.storage") {
			t.Errorf("%s: a class the map does not choose a destination for is %s, %q", name, e.State, e.Reason)
		}
		if e := entry(t, r, "Microsoft.ServiceBus/namespaces/queues/authorizationRules"); e.State != Refused || !strings.Contains(e.Reason, "identity") {
			t.Errorf("%s: a shared access key: %s, %q", name, e.State, e.Reason)
		}
		// A SQL filter is refused with its subscription and rule: dropped,
		// the subscription would receive every message.
		for _, src := range []string{"Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop/events/fraud", "Microsoft.ServiceBus/namespaces/topics/subscriptions/rules rg/shop/events/fraud/big"} {
			if e := entry(t, r, src); e.State != Refused || !strings.Contains(e.Reason, "SQL filter") {
				t.Errorf("%s: %s: %s, %q", name, src, e.State, e.Reason)
			}
		}
		// A setting no rule reads fails the translation.
		e := entry(t, r, "Microsoft.ServiceBus/namespaces/queues rg/shop/legacy.feed")
		if l := hasLoss(e, "properties.someNewSetting"); name != "pubsub" && (l == nil || !l.Unread) {
			t.Errorf("%s: an unknown setting: %+v", name, e.Losses)
		}
		if !r.Report.Failed() {
			t.Errorf("%s: a translation with refusals is not failed", name)
		}
		if e := entry(t, r, "Microsoft.ServiceBus/namespaces/queues rg/shop/orders"); e.State != WithLosses {
			t.Errorf("%s: orders is %s", name, e.State)
		}
	}
}

// A namespace that answers only listed networks widens on a managed
// destination, which answers the internet; in the cluster it does not.
func TestPrivateNamespaceWidens(t *testing.T) {
	for name, m := range maps() {
		r := run(t, m)
		e := entry(t, r, "Microsoft.ServiceBus/namespaces rg/shop")
		l := hasLoss(e, "properties.publicNetworkAccess")
		if l == nil || l.Widens != (name != "rabbitmq") || !strings.Contains(l.Why, "denies by default") {
			t.Errorf("%s: %+v", name, l)
		}
		if name == "rabbitmq" {
			if l := hasLoss(e, "(transport)"); l == nil || !l.Widens {
				t.Errorf("rabbitmq with no certificate: %+v", e.Losses)
			}
		}
	}
	m := maps()["rabbitmq"]
	m.RabbitMQ.TLSSecret = "broker-tls"
	r := run(t, m)
	if l := hasLoss(entry(t, r, "Microsoft.ServiceBus/namespaces rg/shop"), "(transport)"); l != nil {
		t.Errorf("rabbitmq with a certificate: %+v", l)
	}
	if tls := object(t, r, "kubernetes", "RabbitmqCluster", "shop")["tls"]; !reflect.DeepEqual(tls, map[string]any{"secretName": "broker-tls", "disableNonTLSListeners": true}) {
		t.Errorf("tls: %v", tls)
	}
}

func TestSQSAndSNS(t *testing.T) {
	r := run(t, maps()["sqs-sns"])
	q := object(t, r, "aws", awsQueue, "orders")
	if q["VisibilityTimeout"] != 60 || q["MessageRetentionPeriod"] != 1209600 {
		t.Errorf("orders: %v", q)
	}
	if rp := q["RedrivePolicy"].(map[string]any); rp["deadLetterTargetArn"] != "{{truthform|AWS::SQS::Queue|orders-dlq|Arn}}" || rp["maxReceiveCount"] != 10 {
		t.Errorf("orders' redrive: %v", rp)
	}
	object(t, r, "aws", awsQueue, "orders-dlq")
	// A session queue is a FIFO queue with its dead-letter queue FIFO too.
	p := object(t, r, "aws", awsQueue, "payments.fifo")
	if p["FifoQueue"] != true || p["DeduplicationScope"] != "queue" {
		t.Errorf("payments: %v", p)
	}
	object(t, r, "aws", awsQueue, "payments-dlq.fifo")
	// A name SQS refuses is the map's to give.
	object(t, r, "aws", awsQueue, "legacy-feed")
	// The default rule delivers everything: no filter policy.
	if s := awsSubOf(t, r, "events-audit"); s["FilterPolicy"] != nil || s["RawMessageDelivery"] != true || s["Endpoint"] != "{{truthform|AWS::SQS::Queue|events-audit|Arn}}" {
		t.Errorf("audit: %v", s)
	}
	// Two correlation rules: either delivers.
	s := awsSubOf(t, r, "events-shipping")
	want := map[string]any{"$or": []any{
		map[string]any{"region": []any{"eu"}, "type": []any{"order.returned"}},
		map[string]any{"type": []any{"order.shipped"}},
	}}
	if !reflect.DeepEqual(s["FilterPolicy"], want) || s["FilterPolicyScope"] != "MessageAttributes" {
		t.Errorf("shipping's filter: %v", s["FilterPolicy"])
	}
	// The subscription's queue keeps what its topic and it say, the shorter.
	if q := object(t, r, "aws", awsQueue, "events-shipping"); q["MessageRetentionPeriod"] != 86400 || q["VisibilityTimeout"] != 120 {
		t.Errorf("shipping's queue: %v", q)
	}
	if q := object(t, r, "aws", awsQueue, "events-audit"); q["MessageRetentionPeriod"] != 7*86400 {
		t.Errorf("audit's queue takes its topic's time to live: %v", q)
	}
	// Only the topic may send to a subscription's queue.
	pol := object(t, r, "aws", awsPolicy, "events-shipping")["PolicyDocument"].(map[string]any)["Statement"].([]any)[0].(map[string]any)
	if pol["Condition"].(map[string]any)["ArnEquals"].(map[string]any)["aws:SourceArn"] != "{{truthform|AWS::SNS::Topic|events|TopicArn}}" {
		t.Errorf("shipping's queue policy: %v", pol)
	}
	if got := r.Snapshots["aws"].ServerVersion; got != "cloudcontrol/eu-west-1" {
		t.Errorf("server version %q", got)
	}
}

func TestPubSub(t *testing.T) {
	r := run(t, maps()["pubsub"])
	sub := object(t, r, "gcp", psSub, "projects/{{truthform|project}}/subscriptions/orders")
	if sub["topic"] != "projects/{{truthform|project}}/topics/orders" || sub["ackDeadlineSeconds"] != 60 || sub["messageRetentionDuration"] != "604800s" {
		t.Errorf("orders: %v", sub)
	}
	// Pub/Sub deletes a subscription after 31 days without a subscriber
	// unless it is told never to.
	if !reflect.DeepEqual(sub["expirationPolicy"], map[string]any{}) {
		t.Errorf("orders' expiration: %v", sub["expirationPolicy"])
	}
	if dl := sub["deadLetterPolicy"].(map[string]any); dl["deadLetterTopic"] != "projects/{{truthform|project}}/topics/orders-dlq" || dl["maxDeliveryAttempts"] != 10 {
		t.Errorf("orders' dead letters: %v", dl)
	}
	s := object(t, r, "gcp", psSub, "projects/{{truthform|project}}/subscriptions/events-shipping")
	if s["filter"] != `(attributes.region = "eu" AND attributes.type = "order.returned") OR (attributes.type = "order.shipped")` {
		t.Errorf("shipping's filter: %v", s["filter"])
	}
	if p := object(t, r, "gcp", psSub, "projects/{{truthform|project}}/subscriptions/payments"); p["enableMessageOrdering"] != true {
		t.Errorf("payments: %v", p)
	}
	// Pub/Sub's names allow a dot, so legacy.feed keeps its name.
	object(t, r, "gcp", psTopic, "projects/{{truthform|project}}/topics/legacy.feed")
	if l := hasLoss(entry(t, r, "Microsoft.ServiceBus/namespaces rg/shop"), "properties.minimumTlsVersion"); l == nil || !l.Widens {
		t.Errorf("a TLS floor Pub/Sub cannot set: %v", l)
	}
}

func TestRabbitMQ(t *testing.T) {
	r := run(t, maps()["rabbitmq"])
	if len(r.Snapshots) != 1 || r.Snapshots["kubernetes"].Platform != "kubernetes" {
		t.Fatalf("rabbitmq writes the cluster's snapshot only: %v", len(r.Snapshots))
	}
	q := object(t, r, "kubernetes", "Queue", "shop.orders")
	args := q["arguments"].(map[string]any)
	if q["type"] != "quorum" || args["x-delivery-limit"] != 10 || args["x-dead-letter-routing-key"] != "orders-dlq" || args["x-message-ttl"] != int64(14*86400*1000) || args["x-max-length-bytes"] != int64(1024*1024*1024) {
		t.Errorf("orders: %v", q)
	}
	if p := object(t, r, "kubernetes", "Queue", "shop.payments")["arguments"].(map[string]any); p["x-single-active-consumer"] != true {
		t.Errorf("payments: %v", p)
	}
	if x := object(t, r, "kubernetes", "Exchange", "shop.x.events"); x["type"] != "headers" {
		t.Errorf("events: %v", x)
	}
	// One binding per rule; the default rule binds with no headers.
	b0 := object(t, r, "kubernetes", "Binding", "shop.b.events.shipping.0")["arguments"]
	b1 := object(t, r, "kubernetes", "Binding", "shop.b.events.shipping.1")["arguments"]
	got := []any{b0, b1}
	sort.Slice(got, func(i, j int) bool { return len(got[i].(map[string]any)) < len(got[j].(map[string]any)) })
	if !reflect.DeepEqual(got, []any{
		map[string]any{"x-match": "all", "type": "order.shipped"},
		map[string]any{"x-match": "all", "type": "order.returned", "region": "eu"},
	}) {
		t.Errorf("shipping's bindings: %v", got)
	}
	if a := object(t, r, "kubernetes", "Binding", "shop.b.events.audit.0")["arguments"]; !reflect.DeepEqual(a, map[string]any{"x-match": "all"}) {
		t.Errorf("audit's binding: %v", a)
	}
	for _, o := range r.Snapshots["kubernetes"].Objects {
		if o.Namespace() != "messaging" {
			t.Errorf("%s is in %q", o.Key(), o.Namespace())
		}
	}
}

// Without a sessions choice, a session queue is refused, not carried over
// as an ordinary queue that loses its order.
func TestSessionsNeedAChoice(t *testing.T) {
	for name, m := range maps() {
		m.Sessions = ""
		r := run(t, m)
		if e := entry(t, r, "Microsoft.ServiceBus/namespaces/queues rg/shop/payments"); e.State != Refused || !strings.Contains(e.Reason, "sessions:") {
			t.Errorf("%s: %s %q", name, e.State, e.Reason)
		}
	}
}

func TestMapIsChosenNotDefaulted(t *testing.T) {
	m := Map{To: "aws", Region: "eu-west-1"}
	r := run(t, m)
	if e := entry(t, r, "Microsoft.ServiceBus/namespaces/queues rg/shop/orders"); e.State != Refused || !strings.Contains(e.Reason, "destinations.messaging") {
		t.Errorf("no destination: %s %q", e.State, e.Reason)
	}
	if len(r.Snapshots) != 0 {
		t.Errorf("no destination wrote %d snapshots", len(r.Snapshots))
	}
	bad := map[string]Map{
		"no target":          {},
		"aws without region": {To: "aws"},
	}
	m4 := Map{To: "gcp", Network: &NetworkMap{Zone: "a"}}
	m4.Destinations.Network = "vpc"
	bad["a zone on gcp"] = m4
	m5 := Map{To: "aws", Region: "r", Network: &NetworkMap{Zone: "a"}}
	bad["network settings with no network destination"] = m5
	m6 := Map{To: "aws", Region: "r"}
	m6.Destinations.Network = "subnets"
	bad["an unknown network destination"] = m6
	m1 := Map{To: "gcp"}
	m1.Destinations.Messaging = "sqs-sns"
	bad["sqs-sns on gcp"] = m1
	m2 := Map{To: "aws", Region: "r"}
	m2.Destinations.Messaging = "rabbitmq"
	bad["rabbitmq without its settings"] = m2
	m3 := maps()["sqs-sns"]
	m3.Sessions = "ordering"
	bad["a session choice for another destination"] = m3
	for name, m := range bad {
		if _, err := translateFixture(t, fixture(), m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "map.yaml")
	os.WriteFile(path, []byte("to: aws\nregion: eu-west-1\ndestinations:\n  mesaging: sqs-sns\n"), 0o644)
	if _, err := ReadMap(path); err == nil {
		t.Error("a misspelt choice was read")
	}
}

// Two sources that would make one target object are refused, naming both.
func TestCollisionsAreRefused(t *testing.T) {
	m := maps()["sqs-sns"]
	m.Names["rg/shop/orders"] = "events"
	m.Names["rg/shop/events"] = "x"
	m.Names["rg/shop/events/audit"] = "events"
	if _, err := translateFixture(t, fixture(), m); err == nil || !strings.Contains(err.Error(), "both translate to") {
		t.Errorf("collision: %v", err)
	}
}

// The objects are what the target's own definitions take: each AWS
// property is in its registry schema and not read-only, and each Pub/Sub
// field is in its Discovery schema.
func TestTargetsMatchTheirDefinitions(t *testing.T) {
	schemas := map[string]string{awsQueue: "aws-sqs-queue", awsTopic: "aws-sns-topic", awsSub: "aws-sns-subscription", awsPolicy: "aws-sqs-queueinlinepolicy"}
	r := run(t, maps()["sqs-sns"])
	for _, o := range r.Snapshots["aws"].Objects {
		var s struct {
			Properties map[string]any `json:"properties"`
			ReadOnly   []string       `json:"readOnlyProperties"`
			Required   []string       `json:"required"`
		}
		// SQS's queue and SNS's topic are the AWS tests' own; the other
		// two are this package's.
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "aws", "schemas", schemas[o.Kind()]+".json"))
		if os.IsNotExist(err) {
			b, err = os.ReadFile(filepath.Join("testdata", "aws", schemas[o.Kind()]+".json"))
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		spec := o.Body["spec"].(map[string]any)
		for k := range spec {
			if _, ok := s.Properties[k]; !ok {
				t.Errorf("%s: %s is not in the schema", o.Key(), k)
			}
			for _, ro := range s.ReadOnly {
				if ro == "/properties/"+k {
					t.Errorf("%s: %s is read-only", o.Key(), k)
				}
			}
		}
		for _, k := range s.Required {
			if _, ok := spec[k]; !ok {
				t.Errorf("%s: required %s is missing", o.Key(), k)
			}
		}
	}
	var doc struct {
		Schemas map[string]struct {
			Properties map[string]struct {
				ReadOnly bool `json:"readOnly"`
			} `json:"properties"`
		} `json:"schemas"`
	}
	b, err := os.ReadFile(filepath.Join("testdata", "gcp", "pubsub_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	r = run(t, maps()["pubsub"])
	for _, o := range r.Snapshots["gcp"].Objects {
		schema := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)["truthform.org/schema"].(string)
		for k := range o.Body["spec"].(map[string]any) {
			p, ok := doc.Schemas[schema].Properties[k]
			if !ok || p.ReadOnly {
				t.Errorf("%s: %s is not a writable field of %s", o.Key(), k, schema)
			}
		}
	}
}

// A translation writes as a snapshot and reads back the same.
func TestWritesAsASnapshot(t *testing.T) {
	for name, m := range maps() {
		r := run(t, m)
		for p, s := range r.Snapshots {
			dir := filepath.Join(t.TempDir(), p)
			if err := s.Write(dir); err != nil {
				t.Fatalf("%s %s: %v", name, p, err)
			}
			back, err := snapshot.Read(dir)
			if err != nil {
				t.Fatalf("%s %s: %v", name, p, err)
			}
			if ch := snapshot.Compare(s, back); len(ch) != 0 {
				t.Errorf("%s %s: read back differs: %v", name, p, ch)
			}
		}
	}
}

// The same snapshot and map always give the same result.
func TestDeterministic(t *testing.T) {
	for name, m := range maps() {
		a, _ := yaml.Marshal(run(t, m).Report)
		for i := 0; i < 5; i++ {
			b, _ := yaml.Marshal(run(t, m).Report)
			if string(a) != string(b) {
				t.Fatalf("%s: two runs differ", name)
			}
		}
	}
}

func TestDurations(t *testing.T) {
	for in, want := range map[string]float64{"PT1M": 60, "P14D": 14 * 86400, "PT1H30M": 5400, "PT0.5S": 0.5, "P1W": 7 * 86400, "P1DT1S": 86401} {
		if got, err := seconds(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"P", "PT", "P1Y", "1M", "PT1X"} {
		if _, err := seconds(bad); err == nil {
			t.Errorf("%s was read", bad)
		}
	}
	if got, _ := seconds("P10675199DT2H48M5.4775807S"); got < unbounded {
		t.Errorf("TimeSpan.MaxValue is %v", got)
	}
}

// awsSubOf finds the SNS subscription delivering to a queue; it is named
// by a hash of its spec, as a capture names it.
func awsSubOf(t *testing.T, r Result, queue string) map[string]any {
	t.Helper()
	for _, o := range r.Snapshots["aws"].Objects {
		s, _ := o.Body["spec"].(map[string]any)
		if o.Kind() == awsSub && s["Endpoint"] == "{{truthform|AWS::SQS::Queue|"+queue+"|Arn}}" {
			if !strings.HasPrefix(o.Name(), "h-") {
				t.Errorf("subscription to %s is named %s", queue, o.Name())
			}
			return s
		}
	}
	t.Fatalf("no subscription delivers to %s", queue)
	return nil
}

// Rules that cannot be carried over refuse their subscription on every
// destination: an action changes the message, a subscription with no rule
// receives nothing, and a match on a system property (label,
// correlationId) is not an attribute or header any destination filters on.
func TestSubscriptionsRefusedForTheirRules(t *testing.T) {
	ns := az("Microsoft.ServiceBus/namespaces", "rg", "shop", pr(map[string]any{"disableLocalAuth": true}))
	topic := az("Microsoft.ServiceBus/namespaces/topics", "rg", "shop/events", pr(map[string]any{}))
	sub := func(name string) snapshot.Object {
		return az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "rg", "shop/events/"+name, pr(map[string]any{"maxDeliveryCount": 10}))
	}
	rule := func(sub, name string, p map[string]any) snapshot.Object {
		return az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop/events/"+sub+"/"+name, pr(p))
	}
	src := snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{ns, topic,
		sub("acted"), rule("acted", "r", map[string]any{"filterType": "SqlFilter", "sqlFilter": map[string]any{"sqlExpression": "1=1"}, "action": map[string]any{"sqlExpression": "SET x = 1"}}),
		sub("empty"),
		sub("labelled"), rule("labelled", "r", map[string]any{"filterType": "CorrelationFilter", "correlationFilter": map[string]any{"label": "urgent"}}),
		sub("never"), rule("never", "r", map[string]any{"filterType": "SqlFilter", "sqlFilter": map[string]any{"sqlExpression": "1=0"}}),
	}}
	want := map[string]string{"acted": "has an action", "empty": "has no rules", "labelled": "system property label", "never": "matches nothing"}
	for name, m := range maps() {
		r, err := translateFixture(t, src, m)
		if err != nil {
			t.Fatal(err)
		}
		for s, why := range want {
			e := entry(t, r, "Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop/events/"+s)
			if e.State != Refused || !strings.Contains(e.Reason, why) {
				t.Errorf("%s: %s: %s %q", name, s, e.State, e.Reason)
			}
		}
	}
}

// What fails a translation: a refusal, a type not looked at, a setting no
// rule reads, a loss that widens. A loss named and understood does not.
func TestFailed(t *testing.T) {
	for name, c := range map[string]struct {
		e    Entry
		fail bool
	}{
		"a named loss":  {Entry{State: WithLosses, Losses: []Loss{{Field: "f", Why: "w"}}}, false},
		"mapped":        {Entry{State: Mapped}, false},
		"refused":       {Entry{State: Refused}, true},
		"not looked at": {Entry{State: NotLooked}, true},
		"unread":        {Entry{State: WithLosses, Losses: []Loss{{Field: "f", Unread: true}}}, true},
		"widens":        {Entry{State: WithLosses, Losses: []Loss{{Field: "f", Widens: true}}}, true},
	} {
		if got := (Report{Entries: []Entry{c.e}}).Failed(); got != c.fail {
			t.Errorf("%s: failed %v", name, got)
		}
	}
}
