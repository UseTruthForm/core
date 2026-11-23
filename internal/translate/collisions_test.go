package translate

import (
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/snapshot"
)

// twoNamespaces is the fixture with a second namespace beside it holding
// a queue, a topic and a subscription of the same names, as a snapshot of
// two environments in one subscription does.
func twoNamespaces() snapshot.Snapshot {
	s := fixture()
	s.Objects = append(s.Objects,
		az("Microsoft.ServiceBus/namespaces", "rg", "shop2", map[string]any{"location": "westeurope",
			"sku": map[string]any{"name": "Standard", "tier": "Standard"}, "properties": map[string]any{"minimumTlsVersion": "1.2"}}),
		az("Microsoft.ServiceBus/namespaces/queues", "rg", "shop2/orders", pr(map[string]any{"lockDuration": "PT1M", "maxDeliveryCount": 10, "status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics", "rg", "shop2/events", pr(map[string]any{"status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "rg", "shop2/events/audit", pr(map[string]any{"lockDuration": "PT1M", "maxDeliveryCount": 10, "status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop2/events/audit/$Default", pr(map[string]any{
			"filterType": "SqlFilter", "sqlFilter": map[string]any{"sqlExpression": "1=1"}})))
	return s
}

// Every name made twice is told in one error, not the first alone: a
// second namespace has one per queue, and a run per collision is no way
// to find them.
func TestEveryCollisionIsToldAtOnce(t *testing.T) {
	for _, name := range []string{"sqs-sns", "pubsub"} {
		_, err := translateFixture(t, twoNamespaces(), maps()[name])
		if err == nil {
			t.Fatalf("%s: two namespaces of the same names translated", name)
		}
		msg := err.Error()
		for _, want := range []string{
			"Microsoft.ServiceBus/namespaces/queues rg/shop/orders and Microsoft.ServiceBus/namespaces/queues rg/shop2/orders both translate to",
			"Microsoft.ServiceBus/namespaces/topics rg/shop/events and Microsoft.ServiceBus/namespaces/topics rg/shop2/events both translate to",
			"rg/shop/events/audit and Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop2/events/audit both translate to",
			"under the map's names", "under prefixes (keyed group/namespace)",
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: the error does not say %q:\n%s", name, want, msg)
			}
		}
		// Once per pair of sources, whatever each made (a queue, its
		// dead-letter queue, their policies).
		if n := strings.Count(msg, "both translate to"); n != 3 || !strings.HasPrefix(msg, "3 pair(s) of sources translate to one name") {
			t.Errorf("%s: %d collisions told:\n%s", name, n, msg)
		}
	}
}

// One prefix for one namespace tells all its queues and topics apart, on
// every destination, and a name under names is still used as it is.
func TestANamespacePrefixResolvesItsCollisions(t *testing.T) {
	for name, m := range maps() {
		m.Prefixes = map[string]string{"RG/Shop2": "two-"}
		names := map[string]string{}
		for k, v := range m.Names {
			names[k] = v
		}
		m.Names = names
		r, err := translateFixture(t, twoNamespaces(), m)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for src, want := range map[string]string{
			"Microsoft.ServiceBus/namespaces/queues rg/shop2/orders":                     "two-orders",
			"Microsoft.ServiceBus/namespaces/topics rg/shop2/events":                     "two-events",
			"Microsoft.ServiceBus/namespaces/topics/subscriptions rg/shop2/events/audit": "two-events",
		} {
			e := entry(t, r, src)
			if e.State == Refused || len(e.Targets) == 0 || !strings.Contains(strings.Join(e.Targets, " "), want) {
				t.Errorf("%s: %s: %s %v, want a target named with %q", name, src, e.State, e.Targets, want)
			}
		}
		// A subscription is of its own namespace's topic, by its new name.
		if name == "sqs-sns" {
			found := false
			for _, o := range r.Snapshots["aws"].Objects {
				sp, _ := o.Body["spec"].(map[string]any)
				if o.Kind() == awsSub && sp["Endpoint"] == awsRef(awsQueue, "two-events-audit", "Arn") {
					found = sp["TopicArn"] == awsRef(awsTopic, "two-events", "TopicArn")
				}
			}
			if !found {
				t.Error("the second namespace's subscription is not of its own topic")
			}
		}
		// The other namespace keeps its names.
		if e := entry(t, r, "Microsoft.ServiceBus/namespaces/queues rg/shop/orders"); strings.Contains(strings.Join(e.Targets, " "), "two-") {
			t.Errorf("%s: the prefix reached another namespace: %v", name, e.Targets)
		}
		// A name of its own is used as it is, with no prefix before it.
		m.Names["rg/shop2/orders"] = "second-orders"
		r, err = translateFixture(t, twoNamespaces(), m)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if e := entry(t, r, "Microsoft.ServiceBus/namespaces/queues rg/shop2/orders"); !strings.Contains(strings.Join(e.Targets, " "), "second-orders") || strings.Contains(strings.Join(e.Targets, " "), "two-") {
			t.Errorf("%s: a named queue: %v", name, e.Targets)
		}
	}
	// A prefix for no namespace of the snapshot is a misspelt key.
	m := maps()["sqs-sns"]
	m.Prefixes = map[string]string{"rg/shop3": "x-"}
	if _, err := translateFixture(t, twoNamespaces(), m); err == nil || !strings.Contains(err.Error(), `prefixes names "rg/shop3"`) || !strings.Contains(err.Error(), "rg/shop, rg/shop2") {
		t.Errorf("a prefix for no namespace: %v", err)
	}
}
