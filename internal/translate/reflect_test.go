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
	kvVersion  = "2026-05-15"
	acrVersion = "2025-11-01"
	stVersion  = "2026-09-01"
	// Public zones: the newest stable version, and the preview that
	// alone defines DS, TLSA and NAPTR (a capture takes a preview only
	// where no stable version exists).
	dnsVersion        = "2018-05-01"
	dnsPreviewVersion = "2023-07-01-preview"
	privateDNSVersion = "2024-06-01"
	pgVersion         = "2026-10-01"
	sqlVersion        = "2025-01-01"
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
	rd := map[string]reflected{
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
		"Microsoft.KeyVault/vaults":                           {version: kvVersion, name: "kv", read: func(o snapshot.Object) []Loss { return readVault(o).losses }},
		"Microsoft.KeyVault/vaults/secrets":                   {version: kvVersion, name: "kv/s", read: func(o snapshot.Object) []Loss { return readSecret(o).losses }},
		"Microsoft.ContainerRegistry/registries":              {version: acrVersion, name: "acr", read: func(o snapshot.Object) []Loss { return readRegistry(o).losses }},
		"Microsoft.ContainerRegistry/registries/replications": {version: acrVersion, name: "acr/r", read: readReplication},
		"Microsoft.Network/networkSecurityGroups":             {version: netVersion, name: "nsg", read: func(o snapshot.Object) []Loss { return readNSG(o).losses }},
		"Microsoft.Storage/storageAccounts":                   {version: stVersion, name: "acct", read: func(o snapshot.Object) []Loss { return readAccount(o).losses }},
		"Microsoft.Storage/storageAccounts/blobServices": {version: stVersion, name: "acct/default",
			read: func(o snapshot.Object) []Loss { return readBlobService(o).losses }},
		"Microsoft.Storage/storageAccounts/blobServices/containers": {version: stVersion, name: "acct/default/c",
			read: func(o snapshot.Object) []Loss { return readContainer(o).losses }},
		"Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies": {version: stVersion, name: "acct/default/c/default",
			read: func(o snapshot.Object) []Loss { return readImmutability(o).unread }},
		"Microsoft.Storage/storageAccounts/encryptionScopes": {version: stVersion, name: "acct/s",
			read: func(o snapshot.Object) []Loss { return readScope(o).losses }},
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
		"Microsoft.Network/dnsZones":        {version: dnsVersion, name: "z.example", read: func(o snapshot.Object) []Loss { return readZone(o, false).losses }},
		"Microsoft.Network/privateDnsZones": {version: privateDNSVersion, name: "z.internal", read: func(o snapshot.Object) []Loss { return readZone(o, true).losses }},
		"Microsoft.Network/privateDnsZones/virtualNetworkLinks": {version: privateDNSVersion, name: "z.internal/l", read: func(o snapshot.Object) []Loss {
			return readLink(o).losses
		}},
	}
	record := func(version, typ string) reflected {
		return reflected{version: version, name: "z/r", read: func(o snapshot.Object) []Loss { return readRecord(o, typ).losses }}
	}
	for _, t := range []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"} {
		rd["Microsoft.Network/dnsZones/"+t] = record(dnsVersion, t)
	}
	for _, t := range []string{"DS", "TLSA", "NAPTR"} {
		rd["Microsoft.Network/dnsZones/"+t] = record(dnsPreviewVersion, t)
	}
	for _, t := range []string{"A", "AAAA", "CNAME", "MX", "PTR", "SOA", "SRV", "TXT"} {
		rd["Microsoft.Network/privateDnsZones/"+t] = record(privateDNSVersion, t)
	}
	for _, t := range []struct {
		parent, version string
		table           map[string]dbChild
	}{{typPG, pgVersion, pgChildren}, {typSQL, sqlVersion, sqlChildren}} {
		for k, c := range t.table {
			if c.read == nil {
				continue
			}
			read := c.read
			rd[t.parent+"/"+k] = reflected{version: t.version, name: "s" + strings.Repeat("/x", strings.Count(k, "/")+1), read: func(o snapshot.Object) []Loss {
				_, ls := read(&dbServer{}, "x", spec(o))
				return ls
			}}
		}
	}
	rd[typPG] = reflected{version: pgVersion, name: "pg", read: func(o snapshot.Object) []Loss { return readPGServer(o).losses }}
	rd[typSQL] = reflected{version: sqlVersion, name: "sql", read: func(o snapshot.Object) []Loss { return readSQLServer(o).losses }}
	return rd
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

// Every Key Vault vault type Azure defines is read, or named here; a
// managed HSM is a type of its own, not a vault's child.
func TestEveryKeyVaultTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	decided := map[string]State{
		azVault: Mapped, azVaultSecret: Mapped,
		azVault + "/keys":                       Refused,
		azVault + "/keys/versions":              Refused,
		azVault + "/accesspolicies":             Refused,
		azVault + "/privateendpointconnections": NotLooked,
	}
	n := 0
	for _, name := range reg.Names() {
		l := strings.ToLower(name)
		if !(keyVault{}).claims(l) {
			continue
		}
		n++
		if _, ok := decided[l]; !ok {
			t.Errorf("%s has a definition and no decision", name)
		}
	}
	if n != len(decided) {
		t.Errorf("%d types under %s, %d decided", n, azVault, len(decided))
	}
	if (keyVault{}).claims("microsoft.keyvault/managedhsms") {
		t.Error("a managed HSM is claimed as a vault")
	}
	for k, want := range decided {
		if k == azVault || k == azVaultSecret {
			continue // read; see the secrets tests
		}
		for name, m := range kvMaps() {
			r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", "x/y", nil)}}, m, targets(t))
			if err != nil {
				t.Fatal(err)
			}
			if e := r.Report.Entries[0]; e.State != want {
				t.Errorf("%s: %s: %s, want %s", name, k, e.State, want)
			}
		}
	}
}

// Every container registry type Azure defines is read, or named here.
func TestEveryRegistryTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	decided := map[string]State{azRegistry: Mapped, azReplication: Mapped}
	for k := range registryRefusals {
		decided[k] = Refused
	}
	for k := range registryNotLooked {
		decided[k] = NotLooked
	}
	n := 0
	for _, name := range reg.Names() {
		l := strings.ToLower(name)
		if !(registry{}).claims(l) {
			continue
		}
		n++
		if _, ok := decided[l]; !ok {
			t.Errorf("%s has a definition and no decision", name)
		}
	}
	if n < 10 {
		t.Errorf("only %d registry types have a definition here", n)
	}
	for k, want := range decided {
		if k == azRegistry || k == azReplication {
			continue // read; see the registry tests
		}
		for name, m := range acrMaps() {
			r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", "x/y", nil)}}, m, targets(t))
			if err != nil {
				t.Fatal(err)
			}
			if e := r.Report.Entries[0]; e.State != want {
				t.Errorf("%s: %s: %s, want %s", name, k, e.State, want)
			}
		}
	}
}

// Every storage account type Azure defines is read, or named here: files,
// queues and tables are not buckets, and local users are identity.
func TestEveryStorageTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	decided := map[string]State{
		azStorage: Mapped, azBlobSvc: Mapped, azContainer: Mapped, azImmutability: Mapped, azScope: Mapped,
		azLocalUser:                                           Refused,
		azStorage + "/fileservices":                           Mapped, // with nothing in it; see the storage tests
		azStorage + "/queueservices":                          Mapped,
		azStorage + "/tableservices":                          Mapped,
		azStorage + "/fileservices/shares":                    NotLooked,
		azStorage + "/fileservices/usages":                    NotLooked,
		azStorage + "/queueservices/queues":                   NotLooked,
		azStorage + "/tableservices/tables":                   NotLooked,
		azStorage + "/managementpolicies":                     NotLooked,
		azStorage + "/inventorypolicies":                      NotLooked,
		azStorage + "/objectreplicationpolicies":              NotLooked,
		azStorage + "/privateendpointconnections":             NotLooked,
		azStorage + "/networksecurityperimeterconfigurations": NotLooked,
		azStorage + "/advancedplatformmetrics":                NotLooked,
		azStorage + "/blobaccesspointconfigurations":          NotLooked,
		azStorage + "/connectors":                             NotLooked,
		azStorage + "/datashares":                             NotLooked,
		azStorage + "/storagetaskassignments":                 NotLooked,
		azStorage + "/accountmigrations":                      NotLooked,
	}
	for _, n := range reg.Names() {
		l := strings.ToLower(n)
		if !storage.claims(storage{}, l) {
			continue
		}
		if _, ok := decided[l]; !ok {
			t.Errorf("%s has a definition and no decision", n)
		}
	}
	m := stMaps()["aws"]
	for k, want := range decided {
		switch k {
		case azStorage, azBlobSvc, azContainer, azImmutability, azScope:
			continue // read with what they belong to; see the storage tests
		}
		name := strings.Repeat("x/", strings.Count(k, "/")-2) + "x"
		r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", name, nil)}}, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		if e := r.Report.Entries[0]; e.State != want {
			t.Errorf("%s: %s, want %s", k, e.State, want)
		}
	}
}

// Every public and private DNS zone type Azure defines is read, or named
// here. A child alone is refused: it is read with its zone.
func TestEveryDNSTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	decided := map[string]State{azDNSZone: Mapped, azPrivateZone: Mapped, azZoneLink: Refused, azDNSSEC: Refused}
	for typ := range dnsRecordKeys {
		decided[azDNSZone+"/"+strings.ToLower(typ)] = Refused
	}
	for _, typ := range []string{"a", "aaaa", "cname", "mx", "ptr", "soa", "srv", "txt"} {
		decided[azPrivateZone+"/"+typ] = Refused
	}
	for _, n := range reg.Names() {
		l := strings.ToLower(n)
		if !dnsFamily.claims(dnsFamily{}, l) {
			continue
		}
		if _, ok := decided[l]; !ok {
			t.Errorf("%s has a definition and no decision", n)
		}
		if (network{}).claims(l) {
			t.Errorf("%s is claimed by the network family too", n)
		}
	}
	m := dnsMaps()["aws"]
	for k, want := range decided {
		if k == azDNSZone || k == azPrivateZone {
			continue // see the DNS tests
		}
		r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", "x/y", nil)}}, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		if e := r.Report.Entries[0]; e.State != want || !strings.Contains(e.Reason, "its zone") {
			t.Errorf("%s: %s %q, want %s", k, e.State, e.Reason, want)
		}
	}
	// A child Azure has no definition for, met in a capture, is not looked at.
	r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(azDNSZone+"/recordsets", "rg", "x/y", nil)}}, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	if e := r.Report.Entries[0]; e.State != NotLooked {
		t.Errorf("recordsets: %s", e.State)
	}
}

// Every PostgreSQL flexible server and Azure SQL server type Azure defines
// is read with its server, or decided in the tables, and the translation
// does what the table says.
func TestEveryDatabaseTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, name := range reg.Names() {
		l := strings.ToLower(name)
		if !databases.claims(databases{}, l) || l == azPG || l == azSQL {
			continue
		}
		n++
		if _, ok := childRule(l); !ok {
			t.Errorf("%s has a definition and no decision", name)
		}
	}
	if n < 80 {
		t.Errorf("only %d child types have definitions", n)
	}
	for name, m := range dbMaps() {
		for _, parent := range []struct {
			kind  string
			table map[string]dbChild
			srv   snapshot.Object
		}{{typPG, pgChildren, find(dbFixture(), typPG, "shop-pg")}, {typSQL, sqlChildren, find(dbFixture(), typSQL, "shop-sql")}} {
			for k, c := range parent.table {
				kind := parent.kind + "/" + strings.TrimSuffix(k, "/")
				if strings.HasSuffix(k, "/") {
					kind += "/child"
				}
				child := az(kind, "data", parent.srv.Name()+strings.Repeat("/x", strings.Count(kind, "/")-1), nil)
				s := snapshot.Snapshot{Platform: "azure", Objects: append(dbFixture().Objects, child)}
				r, err := Translate(s, m, targets(t))
				if err != nil {
					t.Fatal(err)
				}
				e := entry(t, r, source(child))
				want := c.state
				if c.read != nil {
					want = Mapped
				}
				if e.State != want && !(want == Mapped && e.State == WithLosses) {
					t.Errorf("%s: %s is %s, want %s (%s)", name, kind, e.State, want, e.Reason)
				}
			}
		}
	}
}
