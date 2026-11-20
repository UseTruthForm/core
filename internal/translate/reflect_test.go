package translate

import (
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/snapshot"
)

// sbVersion is the Service Bus API version whose published definitions the
// readers are checked against (testdata/azure, from Azure/bicep-types-az).
const sbVersion = "2026-01-01"

// Every setting Azure's definition declares writable for a Service Bus
// type is read by a rule: carried over, named as having no equivalent, or
// named as carrying nothing. The rules are written by hand, since what a
// setting means on another cloud is no API's to say; which settings exist
// is the definition's, so a field Azure adds fails here before a capture
// ever holds it.
func TestReadersCoverTheDefinitions(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	read := map[string]func(snapshot.Object) []Loss{
		"Microsoft.ServiceBus/namespaces": func(o snapshot.Object) []Loss { return readNamespace(o).losses },
		"Microsoft.ServiceBus/namespaces/networkRuleSets": func(o snapshot.Object) []Loss {
			ns := &sbNS{network: &o}
			ns.readNetwork()
			return ns.losses
		},
		"Microsoft.ServiceBus/namespaces/queues": func(o snapshot.Object) []Loss { return readEntity(o, sbQueue).losses },
		"Microsoft.ServiceBus/namespaces/topics": func(o snapshot.Object) []Loss { return readEntity(o, sbTopic).losses },
		"Microsoft.ServiceBus/namespaces/topics/subscriptions": func(o snapshot.Object) []Loss {
			return readEntity(o, sbSubscription).losses
		},
		"Microsoft.ServiceBus/namespaces/topics/subscriptions/rules": func(o snapshot.Object) []Loss { return readRule(o).losses },
	}
	names := map[string]string{
		"Microsoft.ServiceBus/namespaces":                            "ns",
		"Microsoft.ServiceBus/namespaces/networkRuleSets":            "ns/default",
		"Microsoft.ServiceBus/namespaces/queues":                     "ns/q",
		"Microsoft.ServiceBus/namespaces/topics":                     "ns/t",
		"Microsoft.ServiceBus/namespaces/topics/subscriptions":       "ns/t/s",
		"Microsoft.ServiceBus/namespaces/topics/subscriptions/rules": "ns/t/s/r",
	}
	for typ, reader := range read {
		d, err := reg.Describe(typ, sbVersion, 2)
		if err != nil {
			t.Fatal(err)
		}
		spec := map[string]any{}
		n := 0
		parents := map[string]bool{}
		for _, f := range d.Fields {
			if top, _, nested := strings.Cut(f.Path, "."); nested {
				parents[top] = true
			}
		}
		for _, f := range d.Fields {
			if top, _, _ := strings.Cut(f.Path, "."); f.ReadOnly || isEnvelope(top) {
				continue
			}
			top, sub, nested := strings.Cut(f.Path, ".")
			if !nested {
				if _, ok := spec[top]; !ok {
					spec[top] = sample(f.Type)
					if parents[top] {
						spec[top] = map[string]any{}
					}
				}
				n++
				continue
			}
			m, ok := spec[top].(map[string]any)
			if !ok {
				m = map[string]any{}
				spec[top] = m
			}
			if strings.Contains(sub, ".") {
				continue
			}
			m[sub] = sample(f.Type)
			n++
		}
		if n == 0 {
			t.Fatalf("%s: the definition declares no settings", typ)
		}
		for _, l := range reader(az(typ, "rg", names[typ], spec)) {
			if l.Unread {
				t.Errorf("%s@%s: %s is declared and no rule reads it", typ, sbVersion, l.Field)
			}
		}
	}
}

func isEnvelope(p string) bool {
	switch p {
	// What azarm's normalize drops by name on every type (its envelope).
	case "id", "name", "type", "apiVersion", "systemData", "etag":
		return true
	}
	return false
}

func sample(kind string) any {
	switch kind {
	case "boolean":
		return true
	case "integer":
		return float64(1)
	case "object":
		return map[string]any{"k": "v"}
	case "array":
		return []any{}
	}
	return "x"
}

// Every type of the Service Bus provider with a published definition is
// either read by a rule or named here as refused or not yet looked at, so
// a type Azure adds is a decision, not a gap.
func TestEveryServiceBusTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	decided := map[string]string{
		sbNamespace: "read", sbNetwork: "read", sbQueue: "read", sbTopic: "read", sbSubscription: "read", sbRuleKind: "read",
		sbNamespace + "/authorizationrules":                         "refused: identity",
		sbQueue + "/authorizationrules":                             "refused: identity",
		sbTopic + "/authorizationrules":                             "refused: identity",
		sbNamespace + "/disasterrecoveryconfigs":                    "not looked at",
		sbNamespace + "/disasterrecoveryconfigs/authorizationrules": "refused: identity",
		sbNamespace + "/migrationconfigurations":                    "not looked at",
		sbNamespace + "/privateendpointconnections":                 "not looked at",
		sbNamespace + "/networksecurityperimeterconfigurations":     "not looked at",
	}
	for _, n := range reg.Names() {
		if !strings.HasPrefix(strings.ToLower(n), sbNamespace) {
			continue
		}
		if _, ok := decided[strings.ToLower(n)]; !ok {
			t.Errorf("%s has a definition and no decision", n)
		}
	}
	// The translation does what the table says.
	for k, want := range decided {
		if !strings.HasPrefix(want, "refused") {
			continue
		}
		parts := strings.Count(k, "/")
		name := strings.Repeat("x/", parts-1) + "x"
		r, err := translateFixture(t, snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", name, nil)}}, maps()["sqs-sns"])
		if err != nil {
			t.Fatal(err)
		}
		if e := r.Report.Entries[0]; e.State != Refused {
			t.Errorf("%s: %s", k, e.State)
		}
	}
}
