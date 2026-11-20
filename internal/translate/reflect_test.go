package translate

import (
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/snapshot"
)

// The API versions whose published definitions the readers are checked
// against (testdata/azure, from Azure/bicep-types-az).
const (
	sbVersion  = "2026-01-01"
	netVersion = "2026-03-01"
)

// reflected is one Azure type a rule reads: its definition's version, a
// name of the right shape, values the reader needs to read on (one it
// cannot parse stops it early), and the reader.
type reflected struct {
	version string
	name    string
	set     map[string]any
	read    func(snapshot.Object) []Loss
}

func readers() map[string]reflected {
	sb := func(name string, read func(snapshot.Object) []Loss) reflected {
		return reflected{version: sbVersion, name: name, read: read}
	}
	return map[string]reflected{
		"Microsoft.ServiceBus/namespaces": sb("ns", func(o snapshot.Object) []Loss { return readNamespace(o).losses }),
		"Microsoft.ServiceBus/namespaces/networkRuleSets": sb("ns/default", func(o snapshot.Object) []Loss {
			ns := &sbNS{network: &o}
			ns.readNetwork()
			return ns.losses
		}),
		"Microsoft.ServiceBus/namespaces/queues":                     sb("ns/q", func(o snapshot.Object) []Loss { return readEntity(o, sbQueue).losses }),
		"Microsoft.ServiceBus/namespaces/topics":                     sb("ns/t", func(o snapshot.Object) []Loss { return readEntity(o, sbTopic).losses }),
		"Microsoft.ServiceBus/namespaces/topics/subscriptions":       sb("ns/t/s", func(o snapshot.Object) []Loss { return readEntity(o, sbSubscription).losses }),
		"Microsoft.ServiceBus/namespaces/topics/subscriptions/rules": sb("ns/t/s/r", func(o snapshot.Object) []Loss { return readRule(o).losses }),
		"Microsoft.Network/virtualNetworks":                          {version: netVersion, name: "vn", read: func(o snapshot.Object) []Loss { return readVNet(o).losses }},
		"Microsoft.Network/virtualNetworks/subnets": {version: netVersion, name: "vn/s", read: func(o snapshot.Object) []Loss {
			_, ls := readSubnet(&vnet{}, "s", spec(o), "")
			return ls
		}},
		"Microsoft.Network/networkSecurityGroups": {version: netVersion, name: "nsg", read: func(o snapshot.Object) []Loss { return readNSG(o).losses }},
		"Microsoft.Network/networkSecurityGroups/securityRules": {version: netVersion, name: "nsg/r",
			set: map[string]any{"access": "Allow", "direction": "Inbound", "protocol": "Tcp", "priority": float64(100),
				"sourcePortRange": "*", "destinationPortRange": "443"},
			read: func(o snapshot.Object) []Loss {
				r, ls := readSecurityRule("r", spec(o), "")
				if r == nil {
					return append(ls, Loss{Field: "(the reader)", Why: "stopped early", Unread: true})
				}
				return ls
			}},
	}
}

// Every setting Azure's definition declares writable for a type a rule
// reads is read: carried over, named as having no equivalent, or named as
// carrying nothing. The rules are written by hand, since what a setting
// means on another cloud is no API's to say; which settings exist is the
// definition's, so a field Azure adds fails here before a capture ever
// holds it.
func TestReadersCoverTheDefinitions(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	for typ, rd := range readers() {
		d, err := reg.Describe(typ, rd.version, 3)
		if err != nil {
			t.Fatal(err)
		}
		spec := map[string]any{}
		n := 0
		parents := map[string]bool{}
		for _, f := range d.Fields {
			if top, rest, nested := strings.Cut(f.Path, "."); nested {
				parents[top] = true
				if sub, _, deeper := strings.Cut(rest, "."); deeper {
					parents[top+"."+sub] = true
				}
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
			if parents[top+"."+sub] {
				m[sub] = map[string]any{}
			}
			n++
		}
		if n == 0 {
			t.Fatalf("%s: the definition declares no settings", typ)
		}
		props, _ := spec["properties"].(map[string]any)
		for k, v := range rd.set {
			if props == nil {
				t.Fatalf("%s: no properties to set %s in", typ, k)
			}
			props[k] = v
		}
		for _, l := range rd.read(az(typ, "rg", rd.name, spec)) {
			if l.Unread {
				t.Errorf("%s@%s: %s is declared and no rule reads it", typ, rd.version, l.Field)
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

// Every VNet and NSG type Azure defines is read, or named here.
func TestEveryNetworkTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	decided := map[string]State{
		azVNet: Mapped, azSubnet: Mapped, azNSG: Mapped, azNSGRule: Mapped,
		azNSG + "/defaultsecurityrules": Mapped,
		azPeering:                       NotLooked,
	}
	for _, n := range reg.Names() {
		l := strings.ToLower(n)
		if !network.claims(network{}, l) {
			continue
		}
		if _, ok := decided[l]; !ok {
			t.Errorf("%s has a definition and no decision", n)
		}
	}
	m := netMaps()["aws"]
	for k, want := range decided {
		if k == azVNet || k == azNSG || k == azSubnet || k == azNSGRule {
			continue // read with what they belong to; see the network tests
		}
		r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", "x/y", nil)}}, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		if e := r.Report.Entries[0]; e.State != want {
			t.Errorf("%s: %s, want %s", k, e.State, want)
		}
	}
}
