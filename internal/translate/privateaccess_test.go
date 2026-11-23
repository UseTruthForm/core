package translate

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

func peRef(typ, group, name string) string {
	return "{{truthform|ref|" + typ + "|" + group + "|" + name + "|id}}"
}

func pe(name, subnet, typ, target string, groups ...string) snapshot.Object {
	var gs []any
	for _, g := range groups {
		gs = append(gs, g)
	}
	return az("Microsoft.Network/privateEndpoints", "net", name, map[string]any{"location": "westeurope", "properties": map[string]any{
		"subnet": map[string]any{"id": peRef("Microsoft.Network/virtualNetworks/subnets", "net", "core/"+subnet)},
		"privateLinkServiceConnections": []any{map[string]any{"name": name, "properties": map[string]any{
			"privateLinkServiceId": peRef(typ, "shop", target), "groupIds": gs}}},
	}})
}

// peFixture is a made-up network whose services answer it on private
// endpoints in a subnet of their own, with Azure's privatelink zone for one
// of them and a zone of the customer's own beside it.
func peFixture() snapshot.Snapshot {
	link := func(zone string) snapshot.Object {
		return az("Microsoft.Network/privateDnsZones/virtualNetworkLinks", "net", zone+"/core", map[string]any{"location": "global",
			"properties": map[string]any{"virtualNetwork": map[string]any{"id": peRef("Microsoft.Network/virtualNetworks", "net", "core")}, "registrationEnabled": false}})
	}
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.Network/virtualNetworks", "net", "core", map[string]any{"location": "westeurope", "properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.30.0.0/16"}},
			"subnets": []any{
				map[string]any{"name": "app", "properties": map[string]any{"addressPrefix": "10.30.1.0/24", "defaultOutboundAccess": false}},
				map[string]any{"name": "endpoints", "properties": map[string]any{"addressPrefix": "10.30.9.0/24", "defaultOutboundAccess": false}},
			}}}),
		az("Microsoft.ServiceBus/namespaces", "shop", "shopbus", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Premium"},
			"properties": map[string]any{"publicNetworkAccess": "Disabled", "disableLocalAuth": true, "minimumTlsVersion": "1.2"}}),
		az("Microsoft.KeyVault/vaults", "shop", "shopkv", map[string]any{"location": "westeurope", "properties": map[string]any{
			"tenantId": "t", "sku": map[string]any{"family": "A", "name": "standard"}, "enableRbacAuthorization": true, "publicNetworkAccess": "Disabled"}}),
		az("Microsoft.ContainerRegistry/registries", "shop", "shopacr", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Premium"},
			"properties": map[string]any{"publicNetworkAccess": "Disabled"}}),
		az("Microsoft.Storage/storageAccounts", "shop", "shopfiles", map[string]any{"location": "westeurope", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"},
			"properties": map[string]any{"publicNetworkAccess": "Disabled", "minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": false}}),
		az("Microsoft.ServiceBus/namespaces/queues", "shop", "shopbus/orders", pr(map[string]any{"lockDuration": "PT1M", "maxDeliveryCount": 10, "defaultMessageTimeToLive": "P1D"})),
		az("Microsoft.ServiceBus/namespaces/topics", "shop", "shopbus/events", pr(map[string]any{"defaultMessageTimeToLive": "P1D"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "shop", "shopbus/events/audit", pr(map[string]any{"lockDuration": "PT1M", "maxDeliveryCount": 10, "defaultMessageTimeToLive": "P1D"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "shop", "shopbus/events/audit/all", pr(map[string]any{"filterType": "CorrelationFilter", "correlationFilter": map[string]any{"properties": map[string]any{"type": "order"}}})),
		az("Microsoft.KeyVault/vaults/secrets", "shop", "shopkv/db-password", pr(map[string]any{"attributes": map[string]any{"enabled": true}})),
		az("Microsoft.Storage/storageAccounts/blobServices/containers", "shop", "shopfiles/default/docs", pr(map[string]any{"publicAccess": "None"})),
		pe("pe-bus", "endpoints", "Microsoft.ServiceBus/namespaces", "shopbus", "namespace"),
		pe("pe-kv", "endpoints", "Microsoft.KeyVault/vaults", "shopkv", "vault"),
		pe("pe-acr", "endpoints", "Microsoft.ContainerRegistry/registries", "shopacr", "registry"),
		pe("pe-blob", "endpoints", "Microsoft.Storage/storageAccounts", "shopfiles", "blob"),
		pe("pe-file", "endpoints", "Microsoft.Storage/storageAccounts", "shopfiles", "file"),
		pe("pe-web", "app", "Microsoft.Web/sites", "shopweb", "sites"),
		az("Microsoft.Network/privateEndpoints/privateDnsZoneGroups", "net", "pe-bus/default", pr(map[string]any{
			"privateDnsZoneConfigs": []any{map[string]any{"name": "sb", "properties": map[string]any{"privateDnsZoneId": peRef("Microsoft.Network/privateDnsZones", "net", "privatelink.servicebus.windows.net")}}}})),
		az("Microsoft.Network/privateDnsZones", "net", "privatelink.servicebus.windows.net", map[string]any{"location": "global", "properties": map[string]any{}}),
		az("Microsoft.Network/privateDnsZones/A", "net", "privatelink.servicebus.windows.net/shopbus", pr(map[string]any{"ttl": 3600, "aRecords": []any{map[string]any{"ipv4Address": "10.30.9.4"}}})),
		link("privatelink.servicebus.windows.net"),
		az("Microsoft.Network/privateDnsZones", "net", "internal.shop", map[string]any{"location": "global", "properties": map[string]any{}}),
		az("Microsoft.Network/privateDnsZones/A", "net", "internal.shop/db", pr(map[string]any{"ttl": 300, "aRecords": []any{map[string]any{"ipv4Address": "10.30.1.10"}}})),
		link("internal.shop"),
	}}
}

func peMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Zone: "eu-west-1a"}}
	a.Destinations.Network, a.Destinations.Messaging, a.Destinations.Storage = "vpc", "sqs-sns", "buckets"
	a.Destinations.Secrets, a.Destinations.Registry, a.Destinations.DNS = "secret-manager", "ecr", "route53"
	g := Map{To: "gcp", Region: "europe-west1", Secrets: &SecretsMap{Replication: "automatic"}}
	g.Destinations.Network, g.Destinations.Messaging, g.Destinations.Storage = "vpc", "pubsub", "buckets"
	g.Destinations.Secrets, g.Destinations.Registry, g.Destinations.DNS = "secret-manager", "artifact-registry", "cloud-dns"
	return map[string]Map{"aws": a, "gcp": g}
}

func runPE(t *testing.T, s snapshot.Snapshot, m Map) Result {
	t.Helper()
	r, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// On AWS each kind of service a network reached privately gets an
// interface endpoint in that VPC, in the private endpoints' subnet, with
// private DNS: the AWS service's own name answers privately, as Azure's
// privatelink zone did for Azure's.
func TestPrivateEndpointsBecomeInterfaceEndpoints(t *testing.T) {
	r := runPE(t, peFixture(), peMaps()["aws"])
	for _, s := range []string{"sqs", "sns", "secretsmanager", "ecr-api", "ecr-dkr", "s3"} {
		ep := object(t, r, "aws", awsEndpoint, "core-"+s)
		want := "com.amazonaws.eu-west-1." + strings.ReplaceAll(strings.ReplaceAll(s, "ecr-api", "ecr.api"), "ecr-dkr", "ecr.dkr")
		if ep["ServiceName"] != want || ep["PrivateDnsEnabled"] != true || ep["VpcEndpointType"] != "Interface" {
			t.Errorf("%s: %v", s, ep)
		}
		if fmt.Sprint(ep["SubnetIds"]) != "["+awsRef(awsSN, "core-endpoints", "SubnetId")+"]" {
			t.Errorf("%s subnets: %v", s, ep["SubnetIds"])
		}
		if s == "s3" && fmt.Sprint(obj(ep["DnsOptions"])["PrivateDnsOnlyForInboundResolverEndpoint"]) != "AllResolvers" {
			t.Errorf("s3 answers only on-premises lookups: %v", ep["DnsOptions"])
		}
	}
	if in := ingress(t, r, "core-endpoints", "SecurityGroupIngress"); fmt.Sprint(in) != "[tcp/443-443 10.30.0.0/16]" {
		t.Errorf("endpoint security group: %v", in)
	}
	n := 0
	for _, o := range r.Snapshots["aws"].Objects {
		if o.Kind() == awsEndpoint {
			n++
		}
	}
	if n != 6 {
		t.Errorf("%d endpoints, want one per service and VPC (6)", n)
	}
	checkPEStates(t, r)
	// Azure's own zone is not copied; the customer's is.
	for _, o := range r.Snapshots["aws"].Objects {
		if o.Kind() == "AWS::Route53::HostedZone" && strings.Contains(fmt.Sprint(o.Body["spec"]), "privatelink") {
			t.Errorf("the privatelink zone was copied: %s", o.Key())
		}
	}
	if !strings.Contains(canonJSON(r.Snapshots["aws"].Objects), "internal.shop.") {
		t.Error("the customer's own private zone was not written")
	}
	if !anyRequirement(r, "one availability zone") {
		t.Errorf("the single zone is not said: %v", r.Report.Requirements)
	}
}

// On GCP the network's subnetworks reach Google's APIs privately; nothing
// else is written.
func TestPrivateEndpointsBecomePrivateGoogleAccess(t *testing.T) {
	r := runPE(t, peFixture(), peMaps()["gcp"])
	for _, sn := range []string{"core-app", "core-endpoints"} {
		s := object(t, r, "gcp", gcpSubnet, gcpProject+"/regions/europe-west1/subnetworks/"+sn)
		if s["privateIpGoogleAccess"] != true {
			t.Errorf("%s: no Private Google Access: %v", sn, s)
		}
	}
	checkPEStates(t, r)
	if !anyRequirement(r, "Private Google Access") {
		t.Errorf("no requirement: %v", r.Report.Requirements)
	}
}

func checkPEStates(t *testing.T, r Result) {
	t.Helper()
	want := map[string]State{
		"Microsoft.Network/privateEndpoints net/pe-bus":                                      Mapped,
		"Microsoft.Network/privateEndpoints net/pe-kv":                                       Mapped,
		"Microsoft.Network/privateEndpoints net/pe-acr":                                      Mapped,
		"Microsoft.Network/privateEndpoints net/pe-blob":                                     Mapped,
		"Microsoft.Network/privateEndpoints net/pe-file":                                     Refused,
		"Microsoft.Network/privateEndpoints net/pe-web":                                      Refused,
		"Microsoft.Network/privateEndpoints/privateDnsZoneGroups net/pe-bus/default":         Mapped,
		"Microsoft.Network/privateDnsZones net/privatelink.servicebus.windows.net":           Mapped,
		"Microsoft.Network/privateDnsZones/A net/privatelink.servicebus.windows.net/shopbus": Mapped,
	}
	for src, st := range want {
		if e := entry(t, r, src); e.State != st {
			t.Errorf("%s: %s (%s), want %s", src, e.State, e.Reason, st)
		}
	}
}

// A private endpoint whose service the map sends nowhere, or whose network
// is not translated, is refused, naming what to choose.
func TestPrivateEndpointsNeedTheirServices(t *testing.T) {
	m := peMaps()["aws"]
	m.Destinations.Secrets = ""
	if e := entry(t, runPE(t, peFixture(), m), "Microsoft.Network/privateEndpoints net/pe-kv"); e.State != Refused || !strings.Contains(e.Reason, "destinations.secrets") {
		t.Errorf("no secrets destination: %s %s", e.State, e.Reason)
	}
	m = peMaps()["aws"]
	m.Network = nil
	if e := entry(t, runPE(t, peFixture(), m), "Microsoft.Network/privateEndpoints net/pe-bus"); e.State != Refused || !strings.Contains(e.Reason, "not translated") {
		t.Errorf("no network: %s %s", e.State, e.Reason)
	}
	// Messaging in the cluster needs no endpoint, on either target.
	for name, m := range peMaps() {
		m.Destinations.Messaging = "rabbitmq"
		m.RabbitMQ = &RabbitMQ{Namespace: "messaging", Replicas: 3, TLSSecret: "tls"}
		r := runPE(t, peFixture(), m)
		if e := entry(t, r, "Microsoft.Network/privateEndpoints net/pe-bus"); e.State != Mapped || !strings.Contains(e.Reason, "in the cluster") {
			t.Errorf("%s: rabbitmq: %s %s", name, e.State, e.Reason)
		}
		if name == "aws" {
			for _, o := range r.Snapshots["aws"].Objects {
				if o.Name() == "core-sqs" {
					t.Error("an SQS endpoint for messaging in the cluster")
				}
			}
		}
	}
	// Azure's service zones need no DNS destination: they are not copied.
	m = peMaps()["aws"]
	m.Destinations.DNS = ""
	if e := entry(t, runPE(t, peFixture(), m), "Microsoft.Network/privateDnsZones net/privatelink.servicebus.windows.net"); e.State != Mapped {
		t.Errorf("service zone with no DNS destination: %s %s", e.State, e.Reason)
	}
}

func TestPrivateAccessRestores(t *testing.T) {
	tg := targets(t)
	s := runPE(t, peFixture(), peMaps()["aws"]).Snapshots["aws"]
	f := awscc.NewWorld(tg.AWS).Account("111111111111", "eu-west-1")
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK {
			t.Errorf("aws %s: %s", res.Key, res.Detail)
		}
	}
	// Each private service's policy is created with it: a queue's and a
	// topic's by their queue and topic, a secret's and a bucket's listed.
	if c := f.Count(); c[awsEndpoint] != 6 || c[awsPolicy] != 4 || c[awsTopicPolicy] != 1 || c[awsSecretPolicy] != 1 || c[awsBucketPolicy] != 1 {
		t.Errorf("aws created: %v", c)
	}
	for _, res := range awscc.Restore(context.Background(), f, tg.AWS, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("aws again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	gs := runPE(t, peFixture(), peMaps()["gcp"]).Snapshots["gcp"]
	gf := gcp.NewWorld(tg.GCP).Project("target-project", "123456789")
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK {
			t.Errorf("gcp %s: %s", res.Key, res.Detail)
		}
	}
	for _, res := range gcp.Restore(context.Background(), gf, tg.GCP, gs, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("gcp again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
}

func TestPrivateAccessGolden(t *testing.T) {
	for name, m := range peMaps() {
		golden(t, "privateaccess-"+name, runPE(t, peFixture(), m))
	}
}
