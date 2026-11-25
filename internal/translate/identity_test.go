package translate

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

const (
	idSub        = "/subscriptions/{{truthform|subscription}}"
	idRoleDefs   = idSub + "/providers/Microsoft.Authorization/roleDefinitions/"
	idSBSender   = "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39"
	idSBReceiver = "4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0"
	idSBOwner    = "090c5cfd-751d-490a-894a-3ce6f1109419"
	idBlobReader = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
	idBlobContr  = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
	idBlobOwner  = "b7e6dc6d-f1e8-4753-8033-0f276bb0955b"
	idKVUser     = "4633458b-17de-408a-b874-0445c86b69e6"
	idKVOfficer  = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
	idKVReader   = "21090545-7ca7-4776-b22c-e363652d74d2"
	idAcrPull    = "7f951dda-4ed3-4680-a7ca-43fe172d538d"
	idAcrPush    = "8311e382-0749-4cb8-b61a-304f252e45ec"
	idOwner      = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	idCustom     = "0d1c2b3a-4f5e-4d6c-8b7a-6f5e4d3c2b1a"

	idIssuerShop = "{{truthform|ref|Microsoft.ContainerService/managedClusters|rg|shop|properties.oidcIssuerProfile.issuerURL}}"
	idIssuerOld  = "{{truthform|ref|Microsoft.ContainerService/managedClusters|rg|old|properties.oidcIssuerProfile.issuerURL}}"
	idKubelet    = "{{truthform|ref|Microsoft.ContainerService/managedClusters|rg|shop|properties.identityProfile.kubeletidentity.objectId}}"
)

func idPrincipal(name string) string {
	return "{{truthform|ref|Microsoft.ManagedIdentity/userAssignedIdentities|rg|" + name + "|properties.principalId}}"
}

// idAssignment is a role assignment as a capture writes it: named by its
// scope within its resource group ("" for the group itself).
func idAssignment(id, scope, principal, role string, more map[string]any) snapshot.Object {
	name := "providers/Microsoft.Authorization/roleAssignments/" + id
	if scope != "" {
		name = "providers/" + scope + "/" + name
	}
	p := map[string]any{"principalId": principal, "principalType": "ServicePrincipal", "roleDefinitionId": idRoleDefs + role}
	for k, v := range more {
		p[k] = v
	}
	return az("Microsoft.Authorization/roleAssignments", "rg", name, pr(p))
}

func idCredential(identity, name, issuer, subject string) snapshot.Object {
	return az("Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials", "rg", identity+"/"+name,
		pr(map[string]any{"issuer": issuer, "subject": subject, "audiences": []any{"api://AzureADTokenExchange"}}))
}

func idPool(subnet string) map[string]any {
	return map[string]any{"name": "system", "mode": "System", "count": 3, "vmSize": "Standard_D4s_v5", "osDiskSizeGB": 128,
		"osType": "Linux", "vnetSubnetID": azSubnetID + subnet}
}

// identityFixture is a made-up shop: a cluster whose apps reach a Service
// Bus namespace, two storage accounts, two key vaults and a registry
// through two managed identities, and around them everything the family
// refuses.
func identityFixture() snapshot.Snapshot {
	queue := pr(map[string]any{"lockDuration": "PT1M", "maxDeliveryCount": 10, "defaultMessageTimeToLive": "P1D", "status": "Active"})
	account := func(name string) snapshot.Object {
		return az(stAcct, "rg", name, map[string]any{"location": "westeurope", "kind": "StorageV2", "sku": map[string]any{"name": "Standard_LRS"},
			"properties": map[string]any{"minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": true, "allowBlobPublicAccess": false, "publicNetworkAccess": "Enabled"}})
	}
	container := func(acct, name string) snapshot.Object {
		return az(stCont, "rg", acct+"/default/"+name, pr(map[string]any{"publicAccess": "None"}))
	}
	vault := func(name string, rbac bool) snapshot.Object {
		return az("Microsoft.KeyVault/vaults", "rg", name, map[string]any{"location": "westeurope",
			"properties": map[string]any{"tenantId": "00000000-0000-0000-0000-000000000001", "sku": map[string]any{"family": "A", "name": "standard"},
				"enableRbacAuthorization": rbac, "enableSoftDelete": true, "softDeleteRetentionInDays": 90, "publicNetworkAccess": "Enabled"}})
	}
	secret := func(name string) snapshot.Object {
		return az("Microsoft.KeyVault/vaults/secrets", "rg", name, pr(map[string]any{"attributes": map[string]any{"enabled": true}}))
	}
	registry := func(name string, props map[string]any) snapshot.Object {
		return az("Microsoft.ContainerRegistry/registries", "rg", name, map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard"}, "properties": props})
	}
	cluster := func(name, subnet, cidr string) snapshot.Object {
		return az("Microsoft.ContainerService/managedClusters", "rg", name, map[string]any{"location": "westeurope",
			"properties": map[string]any{"kubernetesVersion": "1.31", "enableRBAC": true, "disableLocalAccounts": true,
				"agentPoolProfiles":      []any{idPool(subnet)},
				"networkProfile":         map[string]any{"networkPlugin": "azure", "serviceCidr": cidr},
				"apiServerAccessProfile": map[string]any{"enablePrivateCluster": true}, "publicNetworkAccess": "Disabled",
				"oidcIssuerProfile": map[string]any{"enabled": true},
				"securityProfile":   map[string]any{"workloadIdentity": map[string]any{"enabled": true}},
			}})
	}
	ident := func(name string) snapshot.Object {
		return az("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", name, map[string]any{"location": "westeurope"})
	}
	const ns, kv, st, acr = "Microsoft.ServiceBus/namespaces/shop", "Microsoft.KeyVault/vaults/", "Microsoft.Storage/storageAccounts/", "Microsoft.ContainerRegistry/registries/"
	return snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: []snapshot.Object{
		az("Microsoft.Network/virtualNetworks", "net", "core", map[string]any{"location": "westeurope",
			"properties": map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.20.0.0/16"}},
				"subnets": []any{
					map[string]any{"name": "app", "properties": map[string]any{"addressPrefix": "10.20.1.0/24"}},
					map[string]any{"name": "data", "properties": map[string]any{"addressPrefix": "10.20.2.0/24"}},
				}}}),
		cluster("shop", "app", "10.0.0.0/16"),
		// A cluster the map says nothing of: it is refused.
		cluster("old", "data", "10.1.0.0/16"),

		az("Microsoft.ServiceBus/namespaces", "rg", "shop", map[string]any{"location": "westeurope", "sku": map[string]any{"name": "Standard"},
			"properties": map[string]any{"minimumTlsVersion": "1.2", "publicNetworkAccess": "Enabled", "disableLocalAuth": true}}),
		az("Microsoft.ServiceBus/namespaces/queues", "rg", "shop/orders", queue),
		// A session queue with no choice in the map: refused.
		az("Microsoft.ServiceBus/namespaces/queues", "rg", "shop/payments", pr(map[string]any{"lockDuration": "PT1M", "requiresSession": true, "status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics", "rg", "shop/events", pr(map[string]any{"status": "Active"})),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions", "rg", "shop/events/audit", queue),
		az("Microsoft.ServiceBus/namespaces/topics/subscriptions/rules", "rg", "shop/events/audit/$Default", pr(map[string]any{
			"filterType": "SqlFilter", "sqlFilter": map[string]any{"sqlExpression": "1=1"}})),

		account("shopfiles"),
		az(stBlobT, "rg", "shopfiles/default", pr(map[string]any{"isVersioningEnabled": false})),
		container("shopfiles", "images"),
		container("shopfiles", "exports"),
		account("shoplogs"),
		az(stBlobT, "rg", "shoplogs/default", pr(map[string]any{"isVersioningEnabled": true})),
		container("shoplogs", "audit"),

		vault("shopkv", true),
		secret("shopkv/db-password"),
		secret("shopkv/api-key"),
		// A vault on access policies: an Azure role gives nothing there.
		vault("oldkv", false),
		secret("oldkv/token"),

		registry("shopacr", map[string]any{"adminUserEnabled": false, "publicNetworkAccess": "Enabled"}),
		registry("abacacr", map[string]any{"adminUserEnabled": false, "publicNetworkAccess": "Enabled", "roleAssignmentMode": "AbacRepositoryPermissions"}),

		ident("orders-id"),
		idCredential("orders-id", "aks", idIssuerShop, "system:serviceaccount:shop:orders"),
		// A pipeline's credential: not a cluster in the snapshot.
		idCredential("orders-id", "ci", "https://token.actions.githubusercontent.com", "repo:shop/orders:ref:refs/heads/main"),
		az("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", "web-id", map[string]any{"location": "westeurope", "tags": map[string]any{"team": "web"}}),
		idCredential("web-id", "aks", idIssuerShop, "system:serviceaccount:shop:web"),
		idCredential("web-id", "jobs", idIssuerShop, "system:serviceaccount:jobs:web-jobs"),
		// Federated to a cluster that is not translated, and to nothing.
		ident("legacy-id"),
		idCredential("legacy-id", "aks", idIssuerOld, "system:serviceaccount:shop:legacy"),
		ident("vm-id"),

		// orders-id: one queue, the whole namespace, one container, the vault.
		idAssignment("a01", ns+"/queues/orders", idPrincipal("orders-id"), idSBReceiver, nil),
		idAssignment("a02", ns, idPrincipal("orders-id"), idSBSender, nil),
		idAssignment("a03", st+"shopfiles/blobServices/default/containers/images", idPrincipal("orders-id"), idBlobContr, nil),
		idAssignment("a04", kv+"shopkv", idPrincipal("orders-id"), idKVUser, nil),
		// web-id: the account, the resource group, one secret, the topic, the registry.
		idAssignment("b01", st+"shopfiles", idPrincipal("web-id"), idBlobReader, nil),
		idAssignment("b02", "", idPrincipal("web-id"), idBlobContr, nil),
		idAssignment("b03", kv+"shopkv/secrets/api-key", idPrincipal("web-id"), idKVOfficer, nil),
		idAssignment("b04", ns+"/topics/events", idPrincipal("web-id"), idSBOwner, nil),
		idAssignment("b05", acr+"shopacr", idPrincipal("web-id"), idAcrPush, nil),
		idAssignment("b06", kv+"shopkv", idPrincipal("web-id"), idKVReader, nil),
		idAssignment("b07", st+"shoplogs/blobServices/default/containers/audit", idPrincipal("web-id"), idBlobOwner, nil),
		// What Azure itself did not honour.
		idAssignment("c01", kv+"oldkv", idPrincipal("web-id"), idKVUser, nil),
		idAssignment("c02", acr+"abacacr", idPrincipal("web-id"), idAcrPull, nil),
		// What is refused.
		idAssignment("d01", st+"shopfiles", idPrincipal("orders-id"), idCustom, nil),
		idAssignment("d02", "", idPrincipal("web-id"), idOwner, nil),
		idAssignment("d03", st+"shopfiles", "5a1b2c3d-0000-4000-8000-00000000aaaa", idBlobOwner, map[string]any{"principalType": "User"}),
		idAssignment("d04", st+"shopfiles/blobServices/default/containers/exports", idPrincipal("orders-id"), idBlobReader,
			map[string]any{"condition": "@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringStartsWith 'public/'", "conditionVersion": "2.0"}),
		idAssignment("d05", ns, idPrincipal("legacy-id"), idSBOwner, nil),
		idAssignment("d06", st+"shopfiles", idPrincipal("vm-id"), idBlobReader, nil),
		idAssignment("d07", ns+"/queues/payments", idPrincipal("orders-id"), idSBReceiver, nil),
		idAssignment("d08", ns, idPrincipal("orders-id"), idBlobReader, nil),
		idAssignment("d09", kv+"shopkv", idKubelet, idKVUser, nil),
		idAssignment("d10", st+"shopfiles", "5a1b2c3d-0000-4000-8000-00000000bbbb", idBlobContr, nil),
		// The nodes pull their images.
		idAssignment("e01", acr+"shopacr", idKubelet, idAcrPull, nil),
		az("Microsoft.Authorization/roleDefinitions", "", "providers/Microsoft.Authorization/roleDefinitions/"+idCustom, pr(map[string]any{
			"roleName": "Shop reader", "type": "CustomRole", "assignableScopes": []any{idSub},
			"permissions": []any{map[string]any{"actions": []any{"Microsoft.Storage/storageAccounts/read"}, "dataActions": []any{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"}}}})),
	}}
}

func identityMaps() map[string]Map {
	a := Map{To: "aws", Region: "eu-west-1", Network: &NetworkMap{Zones: map[string]string{"net/core/app": "eu-west-1a", "net/core/data": "eu-west-1b"}}}
	a.Destinations.Network, a.Destinations.Clusters, a.Destinations.Messaging = "vpc", "eks", "sqs-sns"
	a.Destinations.Storage, a.Destinations.Secrets, a.Destinations.Registry, a.Destinations.Identity = "buckets", "secret-manager", "ecr", "workload"
	a.Clusters = map[string]ClusterMap{"rg/shop": {RoleARN: "arn:aws:iam::111111111111:role/eks-shop", NodeRoleARN: "arn:aws:iam::111111111111:role/eks-shop-nodes",
		Subnets: []string{"net/core/data"}, Pools: map[string]PoolMap{"system": {InstanceType: "m7i.xlarge"}}}}
	g := Map{To: "gcp", Region: "europe-west1", Secrets: &SecretsMap{Replication: "automatic"}}
	g.Destinations.Network, g.Destinations.Clusters, g.Destinations.Messaging = "vpc", "gke", "pubsub"
	g.Destinations.Storage, g.Destinations.Secrets, g.Destinations.Registry, g.Destinations.Identity = "buckets", "secret-manager", "artifact-registry", "workload"
	g.Clusters = map[string]ClusterMap{"rg/shop": {ServiceAccount: "gke-shop-nodes", PodCIDR: "10.64.0.0/14",
		Pools: map[string]PoolMap{"system": {MachineType: "n2-standard-4", Zones: []string{"europe-west1-b", "europe-west1-c", "europe-west1-d"}}}}}
	return map[string]Map{"aws": a, "gcp": g}
}

func runIdentity(t *testing.T, s snapshot.Snapshot, m Map) Result {
	t.Helper()
	r, err := Translate(s, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const (
	idRA   = "Microsoft.Authorization/roleAssignments rg/providers/"
	idUAI  = "Microsoft.ManagedIdentity/userAssignedIdentities rg/"
	idFIC  = "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials rg/"
	idTail = "/providers/Microsoft.Authorization/roleAssignments/"
)

// idEntry is the entry of the role assignment with the given ID.
func idEntry(t *testing.T, r Result, id string) Entry {
	t.Helper()
	for _, e := range r.Report.Entries {
		if strings.HasPrefix(e.Source, "Microsoft.Authorization/roleAssignments ") && strings.HasSuffix(e.Source, "/roleAssignments/"+id) {
			return e
		}
	}
	t.Fatalf("no role assignment %s", id)
	return Entry{}
}

func TestIdentityGolden(t *testing.T) {
	for name, m := range identityMaps() {
		golden(t, "identity-"+name, runIdentity(t, identityFixture(), m))
	}
}

// Every identity, credential and role assignment ends in the state its
// rule gives it, on both targets, and a refusal says why.
func TestIdentityStates(t *testing.T) {
	want := map[string]State{
		idUAI + "orders-id": Mapped, idUAI + "web-id": Mapped, idUAI + "legacy-id": Refused, idUAI + "vm-id": Refused,
		idFIC + "orders-id/aks": Mapped, idFIC + "orders-id/ci": Refused, idFIC + "web-id/aks": Mapped, idFIC + "web-id/jobs": Mapped, idFIC + "legacy-id/aks": Refused,
		"a01": WithLosses, "a02": WithLosses, "a03": WithLosses, "a04": WithLosses,
		"b01": WithLosses, "b02": WithLosses, "b03": WithLosses, "b04": WithLosses, "b05": WithLosses, "b06": WithLosses, "b07": WithLosses,
		"c01": Refused, "c02": Refused,
		"d01": Refused, "d02": Refused, "d03": Refused, "d04": Refused, "d05": Refused, "d06": Refused, "d07": Refused, "d08": Refused, "d09": Refused, "d10": Refused,
		"e01": WithLosses,
		"Microsoft.Authorization/roleDefinitions providers/Microsoft.Authorization/roleDefinitions/" + idCustom: Refused,
	}
	why := map[string]string{
		idUAI + "legacy-id": "no federated credential", idUAI + "vm-id": "no federated credential",
		idFIC + "orders-id/ci": "not a cluster in the snapshot", idFIC + "legacy-id/aks": "cluster rg/old, which is not translated",
		"c01": "access policies", "c02": "AbacRepositoryPermissions",
		"d01": "custom role Shop reader", "d02": "Owner is not translated: a control-plane role", "d03": "assigned to a user: people and pipelines",
		"d04": "it has a condition", "d05": "legacy-id is refused", "d06": "vm-id is refused", "d07": "rg/shop/payments is not translated",
		"d08": "a role for blob storage, and its scope is microsoft.servicebus/namespaces", "d09": "kubelet identity of cluster rg/shop",
		"d10": "a service principal that is no managed identity in the snapshot",
	}
	for name, m := range identityMaps() {
		r := runIdentity(t, identityFixture(), m)
		seen := 0
		for _, e := range r.Report.Entries {
			kind := strings.Fields(e.Source)[0]
			if !(identity{}).claims(strings.ToLower(kind)) {
				continue
			}
			key := e.Source
			if i := strings.LastIndex(e.Source, "/roleAssignments/"); i >= 0 {
				key = e.Source[i+len("/roleAssignments/"):]
			}
			seen++
			st, ok := want[key]
			if name == "gcp" && key == idUAI+"web-id" {
				st = WithLosses // its tag has no place on a service account
			}
			if !ok || st != e.State {
				t.Errorf("%s: %s is %s, want %s (%s)", name, e.Source, e.State, st, e.Reason)
			}
			if e.Reason == "" || !strings.Contains(e.Reason, why[key]) {
				t.Errorf("%s: %s: reason %q, want %q in it", name, key, e.Reason, why[key])
			}
			for _, l := range e.Losses {
				if l.Widens || l.Unread {
					t.Errorf("%s: %s: %+v", name, key, l)
				}
			}
			if e.State == Refused && len(e.Targets) > 0 {
				t.Errorf("%s: %s is refused and has targets %v", name, key, e.Targets)
			}
		}
		if seen != len(want) {
			t.Errorf("%s: %d identity entries, want %d", name, seen, len(want))
		}
		if !r.Report.Failed() {
			t.Errorf("%s: a translation with refusals did not fail", name)
		}
	}
}

// idGrant is one thing an identity may do on a target: a word for what
// (in Azure's own terms), and the object.
type idGrant struct{ identity, object, what string }

func idSorted(m map[idGrant]bool) []string {
	var out []string
	for g := range m {
		out = append(out, g.identity+" | "+g.object+" | "+g.what)
	}
	sort.Strings(out)
	return out
}

// idOracle is what each identity of the fixture could do on Azure, per
// target object, worked out by hand from the roles' published dataActions
// and actions (learn.microsoft.com, built-in roles) and the fixture's
// assignments. It shares nothing with the translation's tables: a grant
// the translation writes that is not here is more than the source gave.
//
//	a01 Service Bus Data Receiver on queue orders: receive/action there,
//	    and on its dead-letter sub-queue; queues/read.
//	a02 Service Bus Data Sender on namespace shop: send/action on queue
//	    orders (payments is refused) and topic events; queues/read.
//	a03 Storage Blob Data Contributor on container images: blobs/read,
//	    write, add, delete.
//	a04 Key Vault Secrets User on vault shopkv: getSecret, readMetadata on
//	    both secrets.
//	b01 Storage Blob Data Reader on account shopfiles: blobs/read on both
//	    containers.
//	b02 Storage Blob Data Contributor on the resource group: all three
//	    containers.
//	b03 Key Vault Secrets Officer on secret api-key: secrets/*.
//	b04 Service Bus Data Owner on topic events: send to it, receive from
//	    its subscription audit.
//	b05 AcrPush on registry shopacr: pull/read, push/write.
//	b06 Key Vault Reader on vault shopkv: readMetadata, and
//	    Microsoft.Authorization/*/read.
//	b07 Storage Blob Data Owner on container audit: blobs/*, which holds
//	    deleting a version.
func idOracle(to string) map[idGrant]bool {
	out := map[idGrant]bool{}
	add := func(identity, object string, what ...string) {
		for _, w := range what {
			out[idGrant{identity, object, w}] = true
		}
	}
	if to == "aws" {
		add("orders-id", "AWS::SQS::Queue orders", "receive", "send", "entity/read")
		add("orders-id", "AWS::SQS::Queue orders-dlq", "receive", "entity/read")
		add("orders-id", "AWS::SNS::Topic events", "send")
		add("orders-id", "AWS::S3::Bucket shopfiles-images", "blobs/list")
		add("orders-id", "AWS::S3::Bucket shopfiles-images/*", "blobs/read", "blobs/write", "blobs/delete")
		add("orders-id", "AWS::SecretsManager::Secret shopkv/db-password", "getSecret", "readMetadata")
		add("orders-id", "AWS::SecretsManager::Secret shopkv/api-key", "getSecret", "readMetadata")

		for _, b := range []string{"shopfiles-images", "shopfiles-exports", "shoplogs-audit"} {
			add("web-id", "AWS::S3::Bucket "+b, "blobs/list")
			add("web-id", "AWS::S3::Bucket "+b+"/*", "blobs/read", "blobs/write", "blobs/delete")
		}
		add("web-id", "AWS::S3::Bucket shoplogs-audit/*", "blobs/deleteVersion")
		add("web-id", "AWS::SecretsManager::Secret shopkv/api-key", "getSecret", "readMetadata", "setSecret")
		add("web-id", "AWS::SecretsManager::Secret shopkv/db-password", "readMetadata")
		add("web-id", "AWS::SNS::Topic events", "send")
		add("web-id", "AWS::SQS::Queue events-audit", "receive", "entity/read")
		add("web-id", "AWS::SQS::Queue events-audit-dlq", "receive", "entity/read")
		add("web-id", "repository/shopacr/*", "pull", "push")
		add("web-id", "*", "registry sign-in")
		return out
	}
	const p = "projects/{{truthform|project}}/"
	add("orders-id", p+"subscriptions/orders", "receive")
	add("orders-id", p+"subscriptions/orders-dlq", "receive")
	add("orders-id", p+"topics/orders", "send")
	add("orders-id", p+"topics/events", "send")
	// shopfiles keeps no versions: a delete is for good on both sides.
	add("orders-id", "shopfiles-images", "blobs/read", "blobs/write", "blobs/delete", "blobs/deleteVersion")
	add("orders-id", p+"secrets/shopkv_db-password", "getSecret")
	add("orders-id", p+"secrets/shopkv_api-key", "getSecret")

	add("web-id", "shopfiles-images", "blobs/read", "blobs/write", "blobs/delete", "blobs/deleteVersion")
	add("web-id", "shopfiles-exports", "blobs/read", "blobs/write", "blobs/delete", "blobs/deleteVersion")
	// shoplogs keeps versions, and web-id is its container's Owner too.
	add("web-id", "shoplogs-audit", "blobs/read", "blobs/write", "blobs/add", "blobs/delete", "blobs/deleteVersion")
	add("web-id", p+"secrets/shopkv_api-key", "getSecret", "setSecret", "readMetadata", "authorization/read")
	add("web-id", p+"secrets/shopkv_db-password", "readMetadata", "authorization/read")
	add("web-id", p+"topics/events", "send")
	add("web-id", p+"subscriptions/events-audit", "receive")
	add("web-id", p+"subscriptions/events-audit-dlq", "receive")
	// Pushing has no predefined role that does not also delete.
	add("web-id", p+"locations/europe-west1/repositories/shopacr", "pull")
	return out
}

// idAWSWords says, per IAM action, what it lets its holder do, in the
// oracle's words: from the Service Authorization Reference, by hand.
var idAWSWords = map[string]string{
	"sqs:SendMessage": "send", "sns:Publish": "send",
	"sqs:ReceiveMessage": "receive", "sqs:DeleteMessage": "receive", "sqs:ChangeMessageVisibility": "receive",
	"sqs:GetQueueAttributes": "entity/read", "sqs:GetQueueUrl": "entity/read",
	"s3:ListBucket": "blobs/list", "s3:ListBucketVersions": "blobs/list",
	"s3:GetObject": "blobs/read", "s3:GetObjectVersion": "blobs/read",
	"s3:PutObject": "blobs/write", "s3:AbortMultipartUpload": "blobs/write", "s3:ListMultipartUploadParts": "blobs/write",
	"s3:DeleteObject": "blobs/delete", "s3:DeleteObjectVersion": "blobs/deleteVersion",
	"secretsmanager:GetSecretValue": "getSecret", "secretsmanager:DescribeSecret": "readMetadata", "secretsmanager:PutSecretValue": "setSecret",
	"ecr:GetAuthorizationToken": "registry sign-in",
	"ecr:BatchGetImage":         "pull", "ecr:GetDownloadUrlForLayer": "pull", "ecr:BatchCheckLayerAvailability": "pull",
	"ecr:InitiateLayerUpload": "push", "ecr:UploadLayerPart": "push", "ecr:CompleteLayerUpload": "push", "ecr:PutImage": "push",
}

// idGCPWords says what each predefined role lets its holder do on the
// object it is granted on, from its permissions
// (docs.cloud.google.com/iam/docs/roles-permissions), by hand.
var idGCPWords = map[string][]string{
	"roles/pubsub.publisher":                 {"send"},
	"roles/pubsub.subscriber":                {"receive"},
	"roles/storage.objectViewer":             {"blobs/read"},
	"roles/storage.objectCreator":            {"blobs/add"},
	"roles/storage.objectUser":               {"blobs/read", "blobs/write", "blobs/delete", "blobs/deleteVersion"},
	"roles/secretmanager.secretAccessor":     {"getSecret"},
	"roles/secretmanager.secretVersionAdder": {"setSecret"},
	"roles/secretmanager.viewer":             {"readMetadata", "authorization/read"},
	"roles/artifactregistry.reader":          {"pull"},
}

var idTok = regexp.MustCompile(`^\{\{truthform\|([^|{}]+)\|([^|{}]+)\|[^|{}]+\}\}(/\*)?$`)

// idAWSGrants reads back, from every IAM role in the snapshot, what each
// may do: every action of every statement on every resource.
func idAWSGrants(t *testing.T, r Result) map[idGrant]bool {
	t.Helper()
	out := map[idGrant]bool{}
	for _, o := range r.Snapshots["aws"].Objects {
		if o.Kind() != awsRole {
			continue
		}
		for _, p := range list(spec(o)["Policies"]) {
			for _, st := range list(obj(obj(p)["PolicyDocument"])["Statement"]) {
				s := obj(st)
				if s["Effect"] != "Allow" || s["NotAction"] != nil || s["NotResource"] != nil || s["Principal"] != nil || s["Condition"] != nil {
					t.Errorf("%s: a statement that is not a plain allow: %v", o.Name(), s)
				}
				for _, a := range list(s["Action"]) {
					word, ok := idAWSWords[fmt.Sprint(a)]
					if !ok {
						t.Errorf("%s: action %v is in no oracle", o.Name(), a)
					}
					for _, res := range list(s["Resource"]) {
						rs := fmt.Sprint(res)
						key := rs
						if m := idTok.FindStringSubmatch(rs); m != nil {
							key = m[1] + " " + m[2] + m[3]
						} else if i := strings.Index(rs, ":repository/"); i >= 0 {
							key = rs[i+1:]
						}
						out[idGrant{o.Name(), key, word}] = true
					}
				}
			}
		}
	}
	return out
}

// idGCPGrants reads back every binding in the snapshot whose member is a
// service account the translation wrote.
func idGCPGrants(t *testing.T, r Result) map[idGrant]bool {
	t.Helper()
	out := map[idGrant]bool{}
	for _, o := range r.Snapshots["gcp"].Objects {
		if o.Kind() != gcp.BindingKind {
			continue
		}
		on := fmt.Sprint(o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)["truthform.org/parent"])
		for _, b := range list(spec(o)["bindings"]) {
			role := fmt.Sprint(obj(b)["role"])
			if role == gcpRoleWorkload {
				continue // the trust, checked on its own
			}
			words, ok := idGCPWords[role]
			if !ok {
				t.Errorf("%s: role %s is in no oracle", o.Name(), role)
			}
			for _, m := range list(obj(b)["members"]) {
				id, ok := strings.CutPrefix(fmt.Sprint(m), "serviceAccount:")
				id, ok2 := strings.CutSuffix(id, gcpEmailSuffix)
				if !ok || !ok2 {
					t.Errorf("%s: member %v is not a translated service account", o.Name(), m)
				}
				for _, w := range words {
					out[idGrant{id, on, w}] = true
				}
			}
		}
	}
	return out
}

// Never more than the source: what each identity may do on the target,
// read back from what was written, is what the oracle says it could do on
// Azure. A grant the oracle lacks is a widening and fails; one the oracle
// has and the target lacks is a loss the report must own, and fails too
// unless the oracle was written with it.
func TestIdentityNeverMoreThanTheSource(t *testing.T) {
	for name, m := range identityMaps() {
		r := runIdentity(t, identityFixture(), m)
		var got map[idGrant]bool
		if name == "aws" {
			got = idAWSGrants(t, r)
		} else {
			got = idGCPGrants(t, r)
		}
		want := idOracle(name)
		for g := range got {
			if !want[g] {
				t.Errorf("%s: MORE THAN THE SOURCE: %s may %s on %s", name, g.identity, g.what, g.object)
			}
		}
		for g := range want {
			if !got[g] {
				t.Errorf("%s: %s could %s on %s, and nothing grants it", name, g.identity, g.what, g.object)
			}
		}
		if len(got) == 0 {
			t.Errorf("%s: nothing was granted", name)
		}
	}
}

// Every policy written anywhere in an AWS translation is checked, not
// only the identity family's: nothing allows on a wildcard but the two
// forms identityAWSWildcards documents, no action is a wildcard, and
// nothing allows IAM or STS.
func TestIdentityNoWildcards(t *testing.T) {
	r := runIdentity(t, identityFixture(), identityMaps()["aws"])
	bucketObjects := regexp.MustCompile(`^\{\{truthform\|AWS::S3::Bucket\|[a-z0-9.-]+\|Arn\}\}/\*$`)
	repos := regexp.MustCompile(`^arn:aws:ecr:eu-west-1:\{\{truthform\|account\|self\|id\}\}:repository/[a-z0-9-]+/\*$`)
	one := regexp.MustCompile(`^\{\{truthform\|AWS::[A-Za-z0-9]+::[A-Za-z0-9]+\|[^|{}*?]+\|[A-Za-z]+\}\}$`)
	allows, roles := 0, 0
	var walk func(where string, v any)
	walk = func(where string, v any) {
		switch c := v.(type) {
		case string:
			if strings.HasPrefix(c, "{") && json.Valid([]byte(c)) {
				var x any
				_ = json.Unmarshal([]byte(c), &x)
				walk(where, x)
			}
		case []any:
			for _, x := range c {
				walk(where, x)
			}
		case map[string]any:
			if c["Effect"] == "Allow" {
				allows++
				acts := c["Action"]
				if s, ok := acts.(string); ok {
					acts = []any{s}
				}
				for _, a := range list(acts) {
					as := fmt.Sprint(a)
					if strings.ContainsAny(as, "*?") || strings.HasPrefix(as, "iam:") || (strings.HasPrefix(as, "sts:") && c["Principal"] == nil) {
						t.Errorf("%s allows %s", where, as)
					}
				}
				if c["NotAction"] != nil || c["NotResource"] != nil || c["NotPrincipal"] != nil {
					t.Errorf("%s allows by exclusion: %v", where, c)
				}
				res := c["Resource"]
				if s, ok := res.(string); ok {
					res = []any{s}
				}
				for _, x := range list(res) {
					rs := fmt.Sprint(x)
					switch {
					case one.MatchString(rs):
					case rs == "*":
						if !reflect.DeepEqual(c["Action"], []any{"ecr:GetAuthorizationToken"}) {
							t.Errorf("%s allows %v on every resource", where, c["Action"])
						}
					case bucketObjects.MatchString(rs):
						for _, a := range list(acts) {
							if !strings.HasPrefix(fmt.Sprint(a), "s3:") {
								t.Errorf("%s allows %v on %s", where, a, rs)
							}
						}
					case repos.MatchString(rs):
						for _, a := range list(acts) {
							if !strings.HasPrefix(fmt.Sprint(a), "ecr:") {
								t.Errorf("%s allows %v on %s", where, a, rs)
							}
						}
					default:
						t.Errorf("%s allows on %q, which is not one written object", where, rs)
					}
				}
				if strings.Contains(where, awsRole) && c["Principal"] == nil && c["Resource"] == nil {
					t.Errorf("%s: an allow with no resource: %v", where, c)
				}
			}
			for _, x := range c {
				walk(where, x)
			}
		}
	}
	for _, o := range r.Snapshots["aws"].Objects {
		if o.Kind() == awsRole {
			roles++
			if mp := spec(o)["ManagedPolicyArns"]; mp != nil {
				t.Errorf("%s attaches managed policies %v", o.Name(), mp)
			}
			if pb := spec(o)["PermissionsBoundary"]; pb != nil {
				t.Errorf("%s: %v", o.Name(), pb)
			}
		}
		walk(o.Kind()+" "+o.Name(), spec(o))
	}
	if roles != 2 || allows < 10 {
		t.Errorf("%d roles and %d allow statements checked", roles, allows)
	}
	// On GCP nothing is bound on the project, to a member that is not a
	// service account written here or one of its Kubernetes users, or
	// with a basic role.
	g := runIdentity(t, identityFixture(), identityMaps()["gcp"])
	names := map[string]string{}
	for _, o := range g.Snapshots["gcp"].Objects {
		names[o.Name()] = o.Kind()
	}
	n := 0
	for _, o := range g.Snapshots["gcp"].Objects {
		if o.Kind() != gcp.BindingKind {
			if _, has := spec(o)["iamPolicy"]; has || spec(o)["bindings"] != nil {
				t.Errorf("%s carries a policy", o.Name())
			}
			continue
		}
		n++
		ann := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		on := fmt.Sprint(ann["truthform.org/parent"])
		if names[on] == "" || names[on] == gcp.BindingKind || strings.Count(on, "/") == 1 {
			t.Errorf("%s is bound on %q, which is not an object of the snapshot", o.Name(), on)
		}
		bs := list(spec(o)["bindings"])
		if len(bs) != 1 || len(spec(o)) != 1 {
			t.Errorf("%s: %v", o.Name(), spec(o))
		}
		for _, b := range bs {
			role := fmt.Sprint(obj(b)["role"])
			if obj(b)["condition"] != nil || len(obj(b)) != 2 {
				t.Errorf("%s: %v", o.Name(), b)
			}
			if _, ok := idGCPWords[role]; !ok && role != gcpRoleWorkload {
				t.Errorf("%s binds %s", o.Name(), role)
			}
			for _, m := range list(obj(b)["members"]) {
				ms := fmt.Sprint(m)
				sa := regexp.MustCompile(`^serviceAccount:(orders-id|web-id)@\{\{truthform\|project\}\}\.iam\.gserviceaccount\.com$`)
				ksa := regexp.MustCompile(`^serviceAccount:\{\{truthform\|project\}\}\.svc\.id\.goog\[[a-z0-9-]+/[a-z0-9-]+\]$`)
				if (role == gcpRoleWorkload) != ksa.MatchString(ms) || (role != gcpRoleWorkload && !sa.MatchString(ms)) {
					t.Errorf("%s: member %s for %s", o.Name(), ms, role)
				}
				if role == gcpRoleWorkload && names[on] != gcpServiceAccount {
					t.Errorf("%s: %s is bound on a %s", o.Name(), role, names[on])
				}
			}
		}
	}
	if n < 15 {
		t.Errorf("%d bindings checked", n)
	}
}

// Trust is exact: a role or service account is usable by the service
// accounts its federated credentials named in the cluster they named, and
// by nothing else.
func TestIdentityTrustIsExact(t *testing.T) {
	r := runIdentity(t, identityFixture(), identityMaps()["aws"])
	arn := awsRef(awsEKS, "shop", "Arn")
	trust := func(pairs ...[2]string) map[string]any {
		var st []any
		for _, p := range pairs {
			st = append(st, map[string]any{"Effect": "Allow", "Principal": map[string]any{"Service": "pods.eks.amazonaws.com"},
				"Action": []any{"sts:AssumeRole", "sts:TagSession"},
				"Condition": map[string]any{"StringEquals": map[string]any{
					"aws:RequestTag/eks-cluster-arn": arn, "aws:RequestTag/kubernetes-namespace": p[0], "aws:RequestTag/kubernetes-service-account": p[1]}}})
		}
		return map[string]any{"Version": "2012-10-17", "Statement": st}
	}
	canon := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	for role, want := range map[string]map[string]any{
		"orders-id": trust([2]string{"shop", "orders"}),
		"web-id":    trust([2]string{"jobs", "web-jobs"}, [2]string{"shop", "web"}),
	} {
		if got := object(t, r, "aws", awsRole, role)["AssumeRolePolicyDocument"]; canon(got) != canon(want) {
			t.Errorf("%s is trusted by\n%s\nwant\n%s", role, canon(got), canon(want))
		}
	}
	var assoc []string
	for _, o := range r.Snapshots["aws"].Objects {
		switch o.Kind() {
		case awsPodAssociation:
			s := spec(o)
			if len(s) != 4 || s["ClusterName"] != awsRef(awsEKS, "shop", "identifier") {
				t.Errorf("association %v", s)
			}
			assoc = append(assoc, fmt.Sprintf("%v/%v -> %v", s["Namespace"], s["ServiceAccount"], s["RoleArn"]))
		case awsRole:
			if o.Name() != "orders-id" && o.Name() != "web-id" {
				t.Errorf("a role for %s", o.Name())
			}
		}
	}
	sort.Strings(assoc)
	if want := []string{"jobs/web-jobs -> " + awsRef(awsRole, "web-id", "Arn"), "shop/orders -> " + awsRef(awsRole, "orders-id", "Arn"), "shop/web -> " + awsRef(awsRole, "web-id", "Arn")}; !reflect.DeepEqual(assoc, want) {
		t.Errorf("associations %v", assoc)
	}
	if a := object(t, r, "aws", awsAddon, "shop_"+awsPodAgent); a["AddonName"] != awsPodAgent || a["ClusterName"] != awsRef(awsEKS, "shop", "identifier") {
		t.Errorf("the agent add-on: %v", a)
	}

	g := runIdentity(t, identityFixture(), identityMaps()["gcp"])
	users := map[string][]string{}
	for _, o := range g.Snapshots["gcp"].Objects {
		if o.Kind() != gcp.BindingKind {
			continue
		}
		ann := o.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
		for _, b := range list(spec(o)["bindings"]) {
			if obj(b)["role"] == gcpRoleWorkload {
				for _, m := range list(obj(b)["members"]) {
					users[fmt.Sprint(ann["truthform.org/parent"])] = append(users[fmt.Sprint(ann["truthform.org/parent"])], fmt.Sprint(m))
				}
				// The pool is the cluster's to make.
				if ann["truthform.org/after"] != gcpProject+"/locations/europe-west1/clusters/shop" {
					t.Errorf("%s does not wait for its cluster: %v", o.Name(), ann["truthform.org/after"])
				}
			} else if ann["truthform.org/after"] != gcpSAName("orders-id") && ann["truthform.org/after"] != gcpSAName("web-id") {
				t.Errorf("%s does not wait for its service account: %v", o.Name(), ann["truthform.org/after"])
			}
		}
	}
	for _, l := range users {
		sort.Strings(l)
	}
	const pool = "serviceAccount:{{truthform|project}}.svc.id.goog"
	if want := map[string][]string{gcpSAName("orders-id"): {pool + "[shop/orders]"}, gcpSAName("web-id"): {pool + "[jobs/web-jobs]", pool + "[shop/web]"}}; !reflect.DeepEqual(users, want) {
		t.Errorf("who may act as each service account: %v", users)
	}
	c := object(t, g, "gcp", gkeCluster, gcpProject+"/locations/europe-west1/clusters/shop")
	if obj(c["workloadIdentityConfig"])["workloadPool"] != "{{truthform|project}}.svc.id.goog" {
		t.Errorf("the cluster has no workload identity pool: %v", c["workloadIdentityConfig"])
	}
	for _, p := range list(c["nodePools"]) {
		if obj(obj(obj(p)["config"])["workloadMetadataConfig"])["mode"] != "GKE_METADATA" {
			t.Errorf("pool %v reaches its node's service account", obj(p)["name"])
		}
	}
	// Without identity the cluster is as its own family wrote it.
	m := identityMaps()["gcp"]
	m.Destinations.Identity = ""
	if c := object(t, runIdentity(t, identityFixture(), m), "gcp", gkeCluster, gcpProject+"/locations/europe-west1/clusters/shop"); c["workloadIdentityConfig"] != nil {
		t.Error("a workload identity pool with no identity destination")
	}
}

// With no destination, identity is refused as it was, by the map's key,
// and nothing is written for it; what a rule refuses keeps its own reason.
func TestIdentityNeedsADestination(t *testing.T) {
	for name, m := range identityMaps() {
		m.Destinations.Identity = ""
		r := runIdentity(t, identityFixture(), m)
		for _, e := range r.Report.Entries {
			if !(identity{}).claims(strings.ToLower(strings.Fields(e.Source)[0])) {
				continue
			}
			if e.State != Refused || len(e.Targets) > 0 {
				t.Errorf("%s: %s is %s %v", name, e.Source, e.State, e.Targets)
			}
		}
		for _, id := range []string{"a01", "b02", "e01"} {
			if e := idEntry(t, r, id); !strings.Contains(e.Reason, "destinations.identity") {
				t.Errorf("%s: %s: %s", name, id, e.Reason)
			}
		}
		if e := idEntry(t, r, "d03"); !strings.Contains(e.Reason, "assigned to a user") {
			t.Errorf("%s: d03: %s", name, e.Reason)
		}
		for _, o := range r.Snapshots[name].Objects {
			if o.Kind() == awsRole || o.Kind() == awsPodAssociation || o.Kind() == gcpServiceAccount || o.Kind() == gcp.BindingKind || strings.Contains(o.Name(), awsPodAgent) {
				t.Errorf("%s: %s %s was written", name, o.Kind(), o.Name())
			}
		}
	}
	m := identityMaps()["aws"]
	m.Destinations.Identity = "irsa"
	if _, err := Translate(identityFixture(), m, targets(t)); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Errorf("identity: irsa: %v", err)
	}
	m.Destinations.Identity = "workload"
	if d := m.destinationList(); !reflect.DeepEqual(d[1], "identity: workload") {
		t.Errorf("destinations: %v", d)
	}
	only := Map{To: "aws", Region: "eu-west-1"}
	only.Destinations.Identity = "workload"
	if !only.NeedsAWS() || only.NeedsGCP() {
		t.Error("identity on aws needs the AWS definitions")
	}
	only.To = "gcp"
	if only.NeedsAWS() || !only.NeedsGCP() {
		t.Error("identity on gcp needs the GCP definitions")
	}
}

// idWith is the fixture with objects added and, by role assignment ID or
// source name, changed.
func idWith(add []snapshot.Object, edit map[string]func(props map[string]any)) snapshot.Snapshot {
	s := identityFixture()
	for _, o := range s.Objects {
		for k, f := range edit {
			if strings.HasSuffix(o.Name(), k) {
				f(obj(spec(o)["properties"]))
			}
		}
	}
	s.Objects = append(s.Objects, add...)
	return s
}

// The narrowing of a scope wider than one object is named, and so is what
// a role held that no target is granted.
func TestIdentityLossesAreNamed(t *testing.T) {
	for name, m := range identityMaps() {
		r := runIdentity(t, identityFixture(), m)
		// A queue: one entity, no narrowing to name.
		for _, id := range []string{"a01", "a03", "b03", "b07"} {
			if l := hasLoss(idEntry(t, r, id), "scope"); l != nil {
				t.Errorf("%s: %s, on one queue, container or secret: %v", name, id, l)
			}
		}
		for id, want := range map[string]string{
			"a02": "rg/shop/payments is not translated",
			"b02": "assigned on resource group rg",
			"b01": "assigned on microsoft.storage/storageaccounts rg/shopfiles",
			"a04": "assigned on microsoft.keyvault/vaults rg/shopkv",
			"b04": "assigned on microsoft.servicebus/namespaces/topics rg/shop/events",
		} {
			found := false
			for _, l := range idEntry(t, r, id).Losses {
				if l.Field == "scope" && strings.Contains(l.Why, want) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: %s does not name %q: %v", name, id, want, idEntry(t, r, id).Losses)
			}
		}
		for id, want := range map[string]string{
			"b04": "managed the namespace", "b07": "POSIX ownership", "b03": "create, delete, recover, purge", "a03": "create and delete containers",
			"a01": "dead-letter a message itself",
		} {
			found := false
			for _, l := range idEntry(t, r, id).Losses {
				if l.Field == "properties.roleDefinitionId" && strings.Contains(l.Why, want) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: %s does not name %q: %v", name, id, want, idEntry(t, r, id).Losses)
			}
		}
		// The nodes' pull is asked for, not written.
		e := idEntry(t, r, "e01")
		if len(e.Targets) != 0 || len(e.Losses) != 1 || !strings.Contains(e.Losses[0].Why, "nothing is granted to the nodes'") {
			t.Errorf("%s: the kubelet's AcrPull: %+v", name, e)
		}
		pull := false
		for _, q := range r.Report.Requirements {
			pull = pull || (strings.Contains(q, "kubelet identity's AcrPull") && strings.Contains(q, "shopacr"))
		}
		if !pull {
			t.Errorf("%s: no requirement that the nodes can pull", name)
		}
	}
	a := runIdentity(t, identityFixture(), identityMaps()["aws"])
	for id, want := range map[string]string{"b05": "ecr:CreateRepository is not granted", "a03": "s3:DeleteObjectVersion", "b03": "creating a secret is not granted"} {
		if !strings.Contains(fmt.Sprint(idEntry(t, a, id).Losses), want) {
			t.Errorf("aws: %s does not name %q", id, want)
		}
	}
	if strings.Contains(fmt.Sprint(idEntry(t, a, "b07").Losses), "s3:DeleteObjectVersion") {
		t.Error("aws: an Owner is told it cannot delete versions")
	}
	g := runIdentity(t, identityFixture(), identityMaps()["gcp"])
	for id, want := range map[string]string{
		"b05": "pushing is not granted", "b02": "on bucket shoplogs-audit, which keeps versions", "a04": "reading a secret's properties is not granted",
	} {
		if !strings.Contains(fmt.Sprint(idEntry(t, g, id).Losses), want) {
			t.Errorf("gcp: %s does not name %q: %v", id, want, idEntry(t, g, id).Losses)
		}
	}
	// A Contributor of a bucket that keeps versions cannot overwrite or
	// delete there; of one that keeps none, it can.
	bindings := func(id string) []string {
		var got []string
		for _, x := range idEntry(t, g, id).Targets {
			if n, ok := strings.CutPrefix(x, gcp.BindingKind+" "); ok {
				got = append(got, n)
			}
		}
		return got
	}
	if got := bindings("a03"); !reflect.DeepEqual(got, []string{"shopfiles-images#storage.objectUser#orders-id"}) {
		t.Errorf("gcp: a03: %v", got)
	}
	if got := bindings("b02"); !reflect.DeepEqual(got, []string{"shopfiles-exports#storage.objectUser#web-id", "shopfiles-images#storage.objectUser#web-id",
		"shoplogs-audit#storage.objectCreator#web-id", "shoplogs-audit#storage.objectViewer#web-id"}) {
		t.Errorf("gcp: b02: %v", got)
	}
}

// What each refusal rule refuses, one change to the fixture at a time.
func TestIdentityRefusals(t *testing.T) {
	sa := func(ns, name string) string { return "system:serviceaccount:" + ns + ":" + name }
	cases := []struct {
		name string
		s    snapshot.Snapshot
		edit func(m *Map)
		src  string // a role assignment's ID, or a source's prefix
		want string
	}{
		{"a vault that does not say how it authorizes", idWith(nil, map[string]func(map[string]any){"shopkv": func(p map[string]any) { delete(p, "enableRbacAuthorization") }}), nil,
			"a04", "does not say whether it authorizes with Azure RBAC"},
		{"an unknown role", idWith([]snapshot.Object{idAssignment("x01", "Microsoft.Storage/storageAccounts/shopfiles", idPrincipal("web-id"), "11111111-2222-4333-8444-555555555555", nil)}, nil), nil,
			"x01", "is not one of the built-in data roles this translates"},
		{"a role that is no ID", idWith(nil, map[string]func(map[string]any){"a01": func(p map[string]any) { p["roleDefinitionId"] = "Storage Blob Data Reader" }}), nil,
			"a01", "is not a role definition's ID"},
		{"Contributor", idWith(nil, map[string]func(map[string]any){"a01": func(p map[string]any) { p["roleDefinitionId"] = idRoleDefs + "b24988ac-6180-42a0-ab88-20f7382dd24c" }}), nil,
			"a01", "Contributor is not translated: a control-plane role"},
		{"Reader", idWith(nil, map[string]func(map[string]any){"a01": func(p map[string]any) { p["roleDefinitionId"] = idRoleDefs + "acdd72a7-3385-48ef-bd42-f606fba81ae7" }}), nil,
			"a01", "Reader is not translated: a control-plane role"},
		{"User Access Administrator", idWith(nil, map[string]func(map[string]any){"a01": func(p map[string]any) { p["roleDefinitionId"] = idRoleDefs + "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" }}), nil,
			"a01", "User Access Administrator is not translated: a control-plane role"},
		{"Key Vault Administrator", idWith(nil, map[string]func(map[string]any){"a04": func(p map[string]any) { p["roleDefinitionId"] = idRoleDefs + "00482a5a-887f-4fb3-b363-3b7fe8e74483" }}), nil,
			"a04", "Key Vault Administrator is not translated"},
		{"a group", idWith(nil, map[string]func(map[string]any){"a01": func(p map[string]any) {
			p["principalId"], p["principalType"] = "5a1b2c3d-0000-4000-8000-00000000cccc", "Group"
		}}), nil,
			"a01", "assigned to a group"},
		{"another resource's identity", idWith(nil, map[string]func(map[string]any){"a01": func(p map[string]any) {
			p["principalId"] = "{{truthform|ref|Microsoft.Web/sites|rg|shop-web|identity.principalId}}"
		}}), nil, "a01", "the identity of Microsoft.Web/sites rg/shop-web"},
		{"a delegated assignment", idWith(nil, map[string]func(map[string]any){"a01": func(p map[string]any) { p["delegatedManagedIdentityResourceId"] = "/subscriptions/x" }}), nil,
			"a01", "delegated assignment"},
		{"a setting nobody reads", idWith(nil, map[string]func(map[string]any){"a01": func(p map[string]any) { p["somethingNew"] = true }}), nil,
			"a01", "a setting no rule reads (properties.somethingNew)"},
		{"a scope under a scope", idWith([]snapshot.Object{az("Microsoft.Authorization/roleAssignments", "rg",
			"providers/Microsoft.Storage/storageAccounts/shopfiles/providers/Microsoft.Insights/diagnosticSettings/x/providers/Microsoft.Authorization/roleAssignments/x02",
			pr(map[string]any{"principalId": idPrincipal("web-id"), "roleDefinitionId": idRoleDefs + idBlobReader}))}, nil), nil,
			"x02", "is not a resource, a resource group or the subscription"},
		{"nothing of the service in scope", idWith([]snapshot.Object{az("Microsoft.Authorization/roleAssignments", "net",
			"providers/Microsoft.Authorization/roleAssignments/x03", pr(map[string]any{"principalId": idPrincipal("web-id"), "roleDefinitionId": idRoleDefs + idBlobReader}))}, nil), nil,
			"x03", "nothing of blob storage in that scope is in the snapshot"},
		{"a sender on a subscription", idWith([]snapshot.Object{idAssignment("x04", "Microsoft.ServiceBus/namespaces/shop/topics/events/subscriptions/audit", idPrincipal("web-id"), idSBSender, nil)}, nil), nil,
			"x04", "gives nothing on what is in its scope"},
		{"a credential by expression", idWith(nil, map[string]func(map[string]any){"orders-id/aks": func(p map[string]any) {
			p["claimsMatchingExpression"] = map[string]any{"value": "claims['sub'] matches 'system:serviceaccount:shop:*'"}
		}}), nil,
			idFIC + "orders-id/aks", "matches tokens by an expression"},
		{"a subject with a wildcard", idWith(nil, map[string]func(map[string]any){"orders-id/aks": func(p map[string]any) { p["subject"] = "system:serviceaccount:shop:*" }}), nil,
			idFIC + "orders-id/aks", "is not one Kubernetes service account"},
		{"a subject that is no service account", idWith(nil, map[string]func(map[string]any){"orders-id/aks": func(p map[string]any) { p["subject"] = "repo:shop/orders" }}), nil,
			idFIC + "orders-id/aks", "is not one Kubernetes service account"},
		{"a credential setting nobody reads", idWith(nil, map[string]func(map[string]any){"orders-id/aks": func(p map[string]any) { p["somethingNew"] = "x" }}), nil,
			idFIC + "orders-id/aks", "a setting no rule reads"},
		{"an issuer that is another resource of a cluster's name", idWith(nil, map[string]func(map[string]any){"orders-id/aks": func(p map[string]any) {
			p["issuer"] = "{{truthform|ref|Microsoft.Web/sites|rg|shop|properties.defaultHostName}}"
		}}), nil, idFIC + "orders-id/aks", "is not a cluster in the snapshot"},
		{"a credential whose identity is gone", idWith([]snapshot.Object{idCredential("gone-id", "aks", idIssuerShop, sa("shop", "gone"))}, nil), nil,
			idFIC + "gone-id/aks", "its identity is not in the snapshot"},
		{"an assignment whose identity is gone", idWith([]snapshot.Object{idAssignment("x05", "", idPrincipal("gone-id"), idBlobReader, nil)}, nil), nil,
			"x05", "its identity rg/gone-id is not in the snapshot"},
		{"two identities for one service account", idWith([]snapshot.Object{idCredential("web-id", "also-orders", idIssuerShop, sa("shop", "orders"))}, nil), nil,
			idFIC + "web-id/also-orders", "is federated to 2 identities (rg/orders-id, rg/web-id)"},
		{"the other of the two", idWith([]snapshot.Object{idCredential("web-id", "also-orders", idIssuerShop, sa("shop", "orders"))}, nil), nil,
			idFIC + "orders-id/aks", "is federated to 2 identities"},
		{"an identity left with no credential", idWith([]snapshot.Object{idCredential("web-id", "also-orders", idIssuerShop, sa("shop", "orders"))}, nil), nil,
			idUAI + "orders-id", "no federated credential"},
		{"a name no target takes", idWith([]snapshot.Object{
			az("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", "id", map[string]any{"location": "westeurope"}),
			idCredential("id", "aks", idIssuerShop, sa("shop", "tiny"))}, nil), func(m *Map) { m.Names = map[string]string{"rg/id": "not a name!"} },
			idUAI + "id", "give it one in the map's names (rg/id)"},
		{"its credential", idWith([]snapshot.Object{
			az("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", "id", map[string]any{"location": "westeurope"}),
			idCredential("id", "aks", idIssuerShop, sa("shop", "tiny"))}, nil), func(m *Map) { m.Names = map[string]string{"rg/id": "not a name!"} },
			idFIC + "id/aks", "its identity " + idUAI + "id is refused"},
		{"RabbitMQ", identityFixture(), func(m *Map) {
			m.Destinations.Messaging = "rabbitmq"
			m.RabbitMQ = &RabbitMQ{Namespace: "messaging", Replicas: 3, TLSSecret: "tls"}
		}, "a01", "RabbitMQ, which signs apps in with a user name and a password"},
		{"a system-assigned identity", idWith([]snapshot.Object{az("Microsoft.ManagedIdentity/identities", "rg", "providers/Microsoft.Web/sites/web/providers/Microsoft.ManagedIdentity/identities/default", nil)}, nil), nil,
			"Microsoft.ManagedIdentity/identities", "a system-assigned identity is made with its resource"},
	}
	for _, c := range cases {
		for name, m := range identityMaps() {
			if c.edit != nil {
				c.edit(&m)
			}
			r := runIdentity(t, c.s, m)
			var e Entry
			if len(c.src) == 3 {
				e = idEntry(t, r, c.src)
			} else {
				e = entry(t, r, c.src)
			}
			if e.State != Refused || !strings.Contains(e.Reason, c.want) || len(e.Targets) > 0 {
				t.Errorf("%s (%s): %s is %s: %s", c.name, name, c.src, e.State, e.Reason)
			}
		}
	}
	// A refused assignment leaves nothing behind in the role: with RabbitMQ,
	// orders-id holds its container and its secrets, and no queue.
	m := identityMaps()["aws"]
	m.Destinations.Messaging = "rabbitmq"
	m.RabbitMQ = &RabbitMQ{Namespace: "messaging", Replicas: 3, TLSSecret: "tls"}
	r := runIdentity(t, identityFixture(), m)
	if p := fmt.Sprint(object(t, r, "aws", awsRole, "orders-id")["Policies"]); strings.Contains(p, "sqs:") || strings.Contains(p, "sns:") || !strings.Contains(p, "s3:GetObject") {
		t.Errorf("with RabbitMQ, orders-id may: %s", p)
	}
	for _, o := range r.Snapshots["kubernetes"].Objects {
		if o.Kind() == "User" || o.Kind() == "Permission" || o.Kind() == "TopicPermission" || o.Kind() == "Secret" {
			t.Errorf("a RabbitMQ %s was written", o.Kind())
		}
	}
	req := false
	for _, q := range r.Report.Requirements {
		req = req || strings.Contains(q, "RabbitMQ has no workload identity")
	}
	if !req {
		t.Error("no requirement for RabbitMQ users")
	}
}

// A new field on a type an identity's rules read is a refusal, not a
// grant: nothing is written for an assignment whose settings are not all
// understood.
func TestIdentityWritesNothingForWhatItRefuses(t *testing.T) {
	for name, m := range identityMaps() {
		base := runIdentity(t, identityFixture(), m)
		// Every refused assignment of the fixture taken out: the same
		// objects are written.
		var kept []snapshot.Object
		for _, o := range identityFixture().Objects {
			if strings.Contains(o.Name(), "/roleAssignments/c") || strings.Contains(o.Name(), "/roleAssignments/d") || strings.HasPrefix(o.Name(), "legacy-id") || o.Name() == "vm-id" || o.Name() == "orders-id/ci" {
				continue
			}
			kept = append(kept, o)
		}
		less := runIdentity(t, snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: kept}, m)
		a, _ := json.Marshal(base.Snapshots[name].Objects)
		b, _ := json.Marshal(less.Snapshots[name].Objects)
		if string(a) != string(b) {
			t.Errorf("%s: the refused assignments changed what is written", name)
		}
	}
}

// On GKE a second cluster of the project shares the pool: a credential
// for one cluster's service account lets in the other's of the same name,
// which is reported as widening unless the identity was federated to both.
func TestIdentitySamenessOnGKE(t *testing.T) {
	two := func(m *Map) {
		c := m.Clusters["rg/shop"]
		m.Clusters["rg/old"] = c
		if m.To == "aws" {
			c.Subnets = []string{"net/core/app"}
			m.Clusters["rg/old"] = c
		}
	}
	g := identityMaps()["gcp"]
	two(&g)
	r := runIdentity(t, identityFixture(), g)
	e := entry(t, r, idFIC+"orders-id/aks")
	if l := hasLoss(e, "properties.issuer"); l == nil || !l.Widens || !strings.Contains(l.Why, "in old too") {
		t.Errorf("a credential for one of two clusters: %+v", e)
	}
	// legacy-id is now usable, by old's service account, and shop's of
	// that name too.
	if l := hasLoss(entry(t, r, idFIC+"legacy-id/aks"), "properties.issuer"); l == nil || !l.Widens || !strings.Contains(l.Why, "in shop too") {
		t.Errorf("legacy-id: %+v", entry(t, r, idFIC+"legacy-id/aks"))
	}
	// Federated to both: the same principal is what was meant.
	both := idWith([]snapshot.Object{idCredential("orders-id", "old", idIssuerOld, "system:serviceaccount:shop:orders")}, nil)
	r = runIdentity(t, both, g)
	for _, c := range []string{"orders-id/aks", "orders-id/old"} {
		if e := entry(t, r, idFIC+c); e.State != Mapped || len(e.Losses) > 0 {
			t.Errorf("%s, federated to both clusters: %+v", c, e)
		}
	}
	// On EKS the role names its cluster, so there is nothing to report.
	a := identityMaps()["aws"]
	two(&a)
	r = runIdentity(t, both, a)
	for _, c := range []string{"orders-id/aks", "orders-id/old", "web-id/aks"} {
		if e := entry(t, r, idFIC+c); e.State != Mapped || len(e.Losses) > 0 {
			t.Errorf("aws: %s: %+v", c, e)
		}
	}
	trust := fmt.Sprint(object(t, r, "aws", awsRole, "orders-id")["AssumeRolePolicyDocument"])
	if !strings.Contains(trust, awsRef(awsEKS, "shop", "Arn")) || !strings.Contains(trust, awsRef(awsEKS, "old", "Arn")) {
		t.Errorf("orders-id, federated to two clusters, trusts %s", trust)
	}
	if strings.Contains(fmt.Sprint(object(t, r, "aws", awsRole, "web-id")["AssumeRolePolicyDocument"]), awsRef(awsEKS, "old", "Arn")) {
		t.Error("web-id trusts a cluster it was not federated to")
	}
}

// The limits of a role: its name, its trust policy's size, and a cluster
// with Windows nodes, where EKS Pod Identity gives a pod nothing.
func TestIdentityOnEKS(t *testing.T) {
	var many []snapshot.Object
	for i := 0; i < 9; i++ {
		many = append(many, idCredential("web-id", fmt.Sprintf("more%d", i), idIssuerShop, fmt.Sprintf("system:serviceaccount:team-%d:worker", i)))
	}
	r := runIdentity(t, idWith(many, nil), identityMaps()["aws"])
	if e := entry(t, r, idUAI+"web-id"); e.State != Refused || !strings.Contains(e.Reason, "trust policy of about") {
		t.Errorf("11 credentials: %s %s", e.State, e.Reason)
	}
	if e := idEntry(t, r, "b01"); e.State != Refused || !strings.Contains(e.Reason, "web-id is refused") {
		t.Errorf("its assignment: %s %s", e.State, e.Reason)
	}
	for _, o := range r.Snapshots["aws"].Objects {
		if o.Kind() == awsRole && o.Name() == "web-id" {
			t.Error("the role was written")
		}
	}
	long := strings.Repeat("a", 65)
	m := identityMaps()["aws"]
	m.Names = map[string]string{"rg/web-id": long}
	if e := entry(t, runIdentity(t, identityFixture(), m), idUAI+"web-id"); e.State != Refused || !strings.Contains(e.Reason, "64 at most") {
		t.Errorf("a 65 character name: %s", e.Reason)
	}
	m.Names = map[string]string{"rg/web-id": "shop-web"}
	r = runIdentity(t, identityFixture(), m)
	if object(t, r, "aws", awsRole, "shop-web")["RoleName"] != "shop-web" {
		t.Error("the map's name is not the role's")
	}
	// A Windows pool.
	win := idWith([]snapshot.Object{az("Microsoft.ContainerService/managedClusters/agentPools", "rg", "shop/win", pr(map[string]any{
		"mode": "User", "count": 1, "vmSize": "Standard_D4s_v5", "osType": "Windows", "osSKU": "Windows2022", "vnetSubnetID": azSubnetID + "app"}))}, nil)
	m = identityMaps()["aws"]
	c := m.Clusters["rg/shop"]
	c.Pools = map[string]PoolMap{"system": {InstanceType: "m7i.xlarge"}, "win": {InstanceType: "m7i.xlarge"}}
	m.Clusters["rg/shop"] = c
	r = runIdentity(t, win, m)
	if l := hasLoss(entry(t, r, idFIC+"orders-id/aks"), "properties.subject"); l == nil || !strings.Contains(l.Why, "Windows nodes") {
		t.Errorf("a cluster with Windows nodes: %+v", entry(t, r, idFIC+"orders-id/aks"))
	}
	// Tags are the role's; AWS's own prefix is not.
	if tags := fmt.Sprint(object(t, runIdentity(t, identityFixture(), identityMaps()["aws"]), "aws", awsRole, "web-id")["Tags"]); tags != "[map[Key:team Value:web]]" {
		t.Errorf("tags: %s", tags)
	}
}

// A service account's ID has its own rules; its tags have no place.
func TestIdentityOnGKE(t *testing.T) {
	short := idWith([]snapshot.Object{
		az("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", "Api", map[string]any{"location": "westeurope"}),
		idCredential("Api", "aks", idIssuerShop, "system:serviceaccount:shop:api")}, nil)
	m := identityMaps()["gcp"]
	if e := entry(t, runIdentity(t, short, m), idUAI+"Api"); e.State != Refused || !strings.Contains(e.Reason, "6 to 30") {
		t.Errorf("a 3 character ID: %s %s", e.State, e.Reason)
	}
	m.Names = map[string]string{"rg/Api": "shop-api"}
	r := runIdentity(t, short, m)
	if s := object(t, r, "gcp", gcpServiceAccount, gcpSAName("shop-api")); s["displayName"] != "Api" || s["description"] != "From Azure managed identity rg/Api" || s["name"] != gcpSAName("shop-api") {
		t.Errorf("the service account: %v", s)
	}
	r = runIdentity(t, identityFixture(), identityMaps()["gcp"])
	if l := hasLoss(entry(t, r, idUAI+"web-id"), "tags"); l == nil || l.Widens {
		t.Errorf("web-id's tags: %+v", entry(t, r, idUAI+"web-id").Losses)
	}
	req := map[string]bool{}
	for _, q := range r.Report.Requirements {
		for _, want := range []string{"iam.gke.io/gcp-service-account: orders-id@<project>.iam.gserviceaccount.com", "iam.gke.io/gcp-service-account: web-id@<project>.iam.gserviceaccount.com",
			"is the same principal and gets the same access", "hostNetwork", "GKE metadata server"} {
			if strings.Contains(q, want) {
				req[want] = true
			}
		}
	}
	if len(req) != 5 {
		t.Errorf("requirements: %v", req)
	}
	a := runIdentity(t, identityFixture(), identityMaps()["aws"])
	req = map[string]bool{}
	for _, q := range a.Report.Requirements {
		for _, want := range []string{"needs no annotation for EKS Pod Identity", "eks-auth:AssumeRoleForPodIdentity", "pod-id-minimum-sdk", "iam:PassRole"} {
			if strings.Contains(q, want) {
				req[want] = true
			}
		}
	}
	if len(req) != 4 {
		t.Errorf("aws requirements: %v", req)
	}
}

// An identity the cluster names as its kubelet's is the nodes': it is not
// written, and its AcrPull is asked for.
func TestIdentityOfTheKubelet(t *testing.T) {
	s := idWith([]snapshot.Object{
		az("Microsoft.ManagedIdentity/userAssignedIdentities", "rg", "shop-kubelet", map[string]any{"location": "westeurope"}),
		idAssignment("k01", "Microsoft.ContainerRegistry/registries/shopacr", idPrincipal("shop-kubelet"), idAcrPull, nil),
		idAssignment("k02", "Microsoft.Storage/storageAccounts/shopfiles", idPrincipal("shop-kubelet"), idBlobReader, nil),
	}, map[string]func(map[string]any){"shop": func(p map[string]any) {
		if p["kubernetesVersion"] != nil {
			p["identityProfile"] = map[string]any{"kubeletidentity": map[string]any{
				"resourceId": idSub + "/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/shop-kubelet"}}
		}
	}})
	for name, m := range identityMaps() {
		r := runIdentity(t, s, m)
		if e := entry(t, r, idUAI+"shop-kubelet"); e.State != Mapped || len(e.Targets) > 0 || !strings.Contains(e.Reason, "the kubelet identity of cluster rg/shop") {
			t.Errorf("%s: %+v", name, e)
		}
		if e := idEntry(t, r, "k01"); e.State != WithLosses || len(e.Targets) > 0 {
			t.Errorf("%s: its AcrPull: %+v", name, e)
		}
		if e := idEntry(t, r, "k02"); e.State != Refused || !strings.Contains(e.Reason, "every pod on a node can reach") {
			t.Errorf("%s: its blob role: %+v", name, e)
		}
		for _, o := range r.Snapshots[name].Objects {
			if strings.Contains(o.Name(), "kubelet") {
				t.Errorf("%s: %s %s was written", name, o.Kind(), o.Name())
			}
		}
	}
}

// The scope is read from the assignment's name, as a capture writes it.
func TestIdentityScope(t *testing.T) {
	ra := func(group, name string) snapshot.Object {
		return az("Microsoft.Authorization/roleAssignments", group, name, nil)
	}
	for _, c := range []struct {
		o    snapshot.Object
		want idScope
		bad  bool
	}{
		{o: ra("rg", "providers/Microsoft.Authorization/roleAssignments/x"), want: idScope{group: "rg"}},
		{o: ra("", "providers/Microsoft.Authorization/roleAssignments/x"), want: idScope{}},
		{o: ra("rg", "providers/Microsoft.Storage/storageAccounts/Acct/providers/Microsoft.Authorization/roleAssignments/x"), want: idScope{group: "rg", kind: azStorage, name: "acct"}},
		{o: ra("rg", "providers/Microsoft.Storage/storageAccounts/acct/blobServices/default/containers/c/providers/Microsoft.Authorization/roleAssignments/x"),
			want: idScope{group: "rg", kind: azContainer, name: "acct/default/c"}},
		{o: ra("rg", "x"), bad: true},
		{o: ra("rg", "providers/Microsoft.Storage/storageAccounts/providers/Microsoft.Authorization/roleAssignments/x"), bad: true},
		{o: ra("", "providers/Microsoft.Storage/storageAccounts/acct/providers/Microsoft.Authorization/roleAssignments/x"), bad: true},
	} {
		got, why := identityScope(c.o)
		if (why != "") != c.bad || (!c.bad && got != c.want) {
			t.Errorf("%s/%s: %+v %q", c.o.Namespace(), c.o.Name(), got, why)
		}
	}
	acct := az(stAcct, "rg", "acct", nil)
	cont1 := az(stCont, "rg", "acct/default/c", nil)
	other := az(stCont, "rg", "acct2/default/c", nil)
	elsewhere := az(stCont, "rg2", "acct/default/c", nil)
	s := idScope{group: "rg", kind: azStorage, name: "acct"}
	if !s.covers(acct) || !s.covers(cont1) || s.covers(other) || s.covers(elsewhere) {
		t.Error("an account's scope")
	}
	if g := (idScope{group: "rg"}); !g.covers(cont1) || !g.covers(other) || g.covers(elsewhere) {
		t.Error("a group's scope")
	}
	if !(idScope{}).covers(elsewhere) {
		t.Error("the subscription's scope")
	}
	// A subscription-wide assignment reaches every group's containers.
	sub := idWith([]snapshot.Object{az("Microsoft.Authorization/roleAssignments", "", "providers/Microsoft.Authorization/roleAssignments/s01",
		pr(map[string]any{"principalId": idPrincipal("orders-id"), "roleDefinitionId": idRoleDefs + idBlobReader}))}, nil)
	r := runIdentity(t, sub, identityMaps()["aws"])
	var e Entry
	for _, x := range r.Report.Entries {
		if strings.HasSuffix(x.Source, "/s01") {
			e = x
		}
	}
	if e.State != WithLosses || !strings.Contains(e.Reason, "shoplogs-audit") || !strings.Contains(fmt.Sprint(e.Losses), "assigned on the subscription") {
		t.Errorf("a subscription-wide assignment: %+v", e)
	}
}

// The table of roles is the published one: each GUID once, each role's
// capabilities those of its definition.
func TestIdentityRolesTable(t *testing.T) {
	want := map[string]string{
		idSBSender: "Azure Service Bus Data Sender: send", idSBReceiver: "Azure Service Bus Data Receiver: receive", idSBOwner: "Azure Service Bus Data Owner: send receive",
		idBlobReader: "Storage Blob Data Reader: blob-read", idBlobContr: "Storage Blob Data Contributor: blob-read blob-write blob-delete",
		idBlobOwner: "Storage Blob Data Owner: blob-read blob-write blob-delete blob-delete-version",
		idKVUser:    "Key Vault Secrets User: secret-read secret-meta", idKVOfficer: "Key Vault Secrets Officer: secret-read secret-meta secret-write secret-authz",
		idKVReader: "Key Vault Reader: secret-meta secret-authz", idAcrPull: "AcrPull: pull", idAcrPush: "AcrPush: pull push",
	}
	if len(identityRoles) != len(want) {
		t.Errorf("%d roles translated, %d expected", len(identityRoles), len(want))
	}
	for g, r := range identityRoles {
		if got := r.name + ": " + strings.Join(r.caps, " "); got != want[g] {
			t.Errorf("%s: %s, want %s", g, got, want[g])
		}
		if !strings.HasPrefix(r.doc, "https://learn.microsoft.com/") || identityServices[r.service].root == "" {
			t.Errorf("%s: doc %q, service %q", r.name, r.doc, r.service)
		}
		if _, both := identityRefusedRoles[g]; both {
			t.Errorf("%s is translated and refused", r.name)
		}
	}
	for g, r := range identityRefusedRoles {
		if !identityGUID.MatchString("/providers/Microsoft.Authorization/roleDefinitions/"+g) || r[0] == "" || r[1] == "" {
			t.Errorf("%s: %v", g, r)
		}
	}
}

func idRestoreAWS(t *testing.T, s snapshot.Snapshot) *awscc.Fake {
	t.Helper()
	reg := targets(t).AWS
	f := awscc.NewWorld(reg).Account("111111111111", "eu-west-1")
	results := awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{})
	if len(results) != len(s.Objects) {
		t.Fatalf("%d results for %d objects", len(results), len(s.Objects))
	}
	for _, res := range results {
		if !res.OK {
			t.Errorf("%s: %s", res.Key, res.Detail)
		}
	}
	for _, res := range awscc.Restore(context.Background(), f, reg, s, awscc.RestoreOptions{}, awscc.Tuning{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	return f
}

// The AWS translation restores into the fake account, and again: the
// roles, their associations and the agent add-on, every reference
// resolved to what the account made.
func TestIdentityRestoresOnAWS(t *testing.T) {
	s := runIdentity(t, identityFixture(), identityMaps()["aws"]).Snapshots["aws"]
	f := idRestoreAWS(t, s)
	if c := f.Count(); c[awsRole] != 2 || c[awsPodAssociation] != 3 {
		t.Errorf("created: %v", c)
	}
	role := f.Stored(awsRole, "web-id")
	text, _ := json.Marshal(role)
	if strings.Contains(string(text), "{{truthform") {
		t.Errorf("an unresolved reference in the role: %s", text)
	}
	for _, want := range []string{`"arn:aws:eks:eu-west-1:111111111111:cluster/shop"`, `arn:aws:ecr:eu-west-1:111111111111:repository/shopacr/*`, `"arn:aws:sns:eu-west-1:111111111111:`} {
		if !strings.Contains(string(text), want) {
			t.Errorf("web-id lacks %s: %s", want, text)
		}
	}
	for _, id := range f.IDs(awsPodAssociation) {
		if arn, _ := f.Stored(awsPodAssociation, id)["RoleArn"].(string); !strings.HasPrefix(arn, "arn:aws:iam::111111111111:role/") {
			t.Errorf("association %s: role %q", id, arn)
		}
	}
}

// The GCP translation restores into the fake project, and again: the
// service accounts, then each binding on its object's own allow policy,
// which holds exactly what the oracle says and nothing on anything else.
func TestIdentityRestoresOnGCP(t *testing.T) {
	docs := targets(t).GCP
	r := runIdentity(t, identityFixture(), identityMaps()["gcp"])
	s := r.Snapshots["gcp"]
	f := gcp.NewWorld(docs).Project("target-project", "123456789")
	f.EmailNames = true
	results := gcp.Restore(context.Background(), f, docs, s, gcp.RestoreOptions{})
	if len(results) != len(s.Objects) {
		t.Fatalf("%d results for %d objects", len(results), len(s.Objects))
	}
	for _, res := range results {
		if !res.OK {
			t.Errorf("%s: %s", res.Key, res.Detail)
		}
	}
	writes := f.PolicyWrites
	for _, res := range gcp.Restore(context.Background(), f, docs, s, gcp.RestoreOptions{}) {
		if !res.OK || res.Detail != "already present and identical" {
			t.Errorf("again: %s: %v %s", res.Key, res.OK, res.Detail)
		}
	}
	if f.PolicyWrites != writes || writes == 0 {
		t.Errorf("%d policy writes, then %d more", writes, f.PolicyWrites-writes)
	}
	// What the project now holds, read back from the policies.
	got := map[idGrant]bool{}
	for _, n := range f.Names() {
		for role, members := range f.Policy(n) {
			for _, m := range members {
				if role == gcpRoleWorkload {
					continue
				}
				id := strings.TrimSuffix(strings.TrimPrefix(m, "serviceAccount:"), "@target-project.iam.gserviceaccount.com")
				for _, w := range idGCPWords[role] {
					got[idGrant{id, strings.ReplaceAll(n, "projects/target-project/", "projects/{{truthform|project}}/"), w}] = true
				}
			}
		}
	}
	if want := idOracle("gcp"); !reflect.DeepEqual(got, want) {
		t.Errorf("the project's policies give\n%s\nwant\n%s", strings.Join(idSorted(got), "\n"), strings.Join(idSorted(want), "\n"))
	}
	if p := f.Policy("projects/target-project/serviceAccounts/web-id@target-project.iam.gserviceaccount.com"); !reflect.DeepEqual(p[gcpRoleWorkload], []string{"serviceAccount:target-project.svc.id.goog[shop/web]", "serviceAccount:target-project.svc.id.goog[jobs/web-jobs]"}) &&
		!reflect.DeepEqual(p[gcpRoleWorkload], []string{"serviceAccount:target-project.svc.id.goog[jobs/web-jobs]", "serviceAccount:target-project.svc.id.goog[shop/web]"}) {
		t.Errorf("who may act as web-id: %v", p)
	}
}

func init() {
	moreReaders = append(moreReaders, func(rd map[string]reflected) {
		rd["Microsoft.ManagedIdentity/userAssignedIdentities"] = reflected{version: idMSIVersion, name: "id", read: func(o snapshot.Object) []Loss { return readIdentity(o).losses }}
		rd["Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials"] = reflected{version: idMSIVersion, name: "id/c", read: func(o snapshot.Object) []Loss {
			r := &identityRun{o: &out{}, idents: map[string]*idIdent{}}
			_, _, why := r.readCred(o)
			if strings.Contains(why, "no rule reads") {
				return []Loss{{Field: why, Unread: true}}
			}
			return nil
		}}
		rd["Microsoft.Authorization/roleAssignments"] = reflected{version: idAuthzVersion, name: "providers/Microsoft.Authorization/roleAssignments/x", read: func(o snapshot.Object) []Loss {
			r := &identityRun{o: &out{reqs: map[string]bool{}}, idents: map[string]*idIdent{}}
			_, _, e := r.readAssign(o, nil)
			if strings.Contains(e.Reason, "no rule reads") {
				return []Loss{{Field: e.Reason, Unread: true}}
			}
			return nil
		}}
		rd["Microsoft.Authorization/roleDefinitions"] = reflected{version: idAuthzVersion, name: "providers/Microsoft.Authorization/roleDefinitions/x", read: func(o snapshot.Object) []Loss {
			_, ls := readRoleDefinition(o)
			return ls
		}}
	})
}

// The versions of Azure's definitions the identity readers are checked
// against.
const (
	idMSIVersion   = "2024-11-30"
	idAuthzVersion = "2022-04-01"
)

// Every type under the prefixes identity claims is read, or decided here;
// and every Microsoft.Authorization type about roles, which Azure defines
// across many API versions, is the identity family's or decided.go's.
func TestEveryIdentityTypeIsDecided(t *testing.T) {
	reg, err := azarm.LoadDefinitions("testdata/azure")
	if err != nil {
		t.Fatal(err)
	}
	decided := map[string]State{azIdentity: Refused, azFedCred: Refused, azSysIdentity: Refused, azRoleAssign: Refused, azRoleDef: Refused}
	n := 0
	for _, name := range reg.Names() {
		l := strings.ToLower(name)
		if !(identity{}).claims(l) {
			continue
		}
		n++
		if _, ok := decided[l]; !ok {
			t.Errorf("%s has a definition and no decision", name)
		}
	}
	if n != len(decided) {
		t.Errorf("%d identity types have a definition here, %d decided", n, len(decided))
	}
	m := identityMaps()["aws"]
	// Alone, with nothing to be for, each is refused with its reason.
	for k, want := range decided {
		name := "x"
		if k == azFedCred {
			name = "x/y"
		}
		r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(k, "rg", name, nil)}}, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		if e := r.Report.Entries[0]; e.State != want || e.Reason == "" {
			t.Errorf("%s: %s (%s), want %s", k, e.State, e.Reason, want)
		}
	}
	r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az("Microsoft.ManagedIdentity/somethingNew", "rg", "x", nil)}}, m, targets(t))
	if err != nil {
		t.Fatal(err)
	}
	if e := r.Report.Entries[0]; e.State != NotLooked {
		t.Errorf("an undecided identity type: %s", e.State)
	}
	// The other role types of Microsoft.Authorization (bicep-types-az's
	// index, 2026-11-20) stay refused, each for what it is.
	for typ, want := range map[string]string{
		"Microsoft.Authorization/roleAssignmentScheduleRequests":  "Privileged Identity Management",
		"Microsoft.Authorization/roleAssignmentSchedules":         "Privileged Identity Management",
		"Microsoft.Authorization/roleAssignmentScheduleInstances": "Privileged Identity Management",
		"Microsoft.Authorization/roleAssignmentApprovals":         "Privileged Identity Management",
		"Microsoft.Authorization/roleAssignmentApprovals/stages":  "Privileged Identity Management",
		"Microsoft.Authorization/roleEligibilityScheduleRequests": "Privileged Identity Management",
		"Microsoft.Authorization/roleEligibilitySchedules":        "Privileged Identity Management",
		"Microsoft.Authorization/roleManagementPolicies":          "Privileged Identity Management",
		"Microsoft.Authorization/roleManagementPolicyAssignments": "Privileged Identity Management",
		"Microsoft.Authorization/roleManagementAlerts":            "Privileged Identity Management",
		"Microsoft.Authorization/denyAssignments":                 "a deny assignment is Azure's own",
		"Microsoft.Authorization/locks":                           "locks are not translated",
		"Microsoft.Authorization/policyAssignments":               "Azure Policy is not translated",
	} {
		if (identity{}).claims(strings.ToLower(typ)) {
			t.Errorf("identity claims %s", typ)
		}
		r, err := Translate(snapshot.Snapshot{Platform: "azure", Objects: []snapshot.Object{az(typ, "rg", "x", nil)}}, m, targets(t))
		if err != nil {
			t.Fatal(err)
		}
		if e := r.Report.Entries[0]; e.State != Refused || !strings.Contains(e.Reason, want) {
			t.Errorf("%s: %s (%s)", typ, e.State, e.Reason)
		}
	}
}

// Each role alone: an identity with one assignment, on a scope that holds
// one of everything its service has, is granted exactly what this table
// says, written by hand from the role's definition. Together in the
// fixture, one role's grant can hide another's being too wide; here none
// can.
func TestIdentityEachRoleAlone(t *testing.T) {
	const ns, kvs, st, acr = "Microsoft.ServiceBus/namespaces/shop", "Microsoft.KeyVault/vaults/shopkv", "Microsoft.Storage/storageAccounts/shoplogs", "Microsoft.ContainerRegistry/registries/shopacr"
	const p = "projects/{{truthform|project}}/"
	type on map[string][]string // object -> what
	cases := []struct {
		role, scope string
		aws, gcp    on
	}{
		{idSBSender, ns,
			on{"AWS::SQS::Queue orders": {"send", "entity/read"}, "AWS::SNS::Topic events": {"send"}},
			on{p + "topics/orders": {"send"}, p + "topics/events": {"send"}}},
		{idSBReceiver, ns,
			on{"AWS::SQS::Queue orders": {"receive", "entity/read"}, "AWS::SQS::Queue orders-dlq": {"receive", "entity/read"},
				"AWS::SQS::Queue events-audit": {"receive", "entity/read"}, "AWS::SQS::Queue events-audit-dlq": {"receive", "entity/read"}},
			on{p + "subscriptions/orders": {"receive"}, p + "subscriptions/orders-dlq": {"receive"},
				p + "subscriptions/events-audit": {"receive"}, p + "subscriptions/events-audit-dlq": {"receive"}}},
		{idSBReceiver, ns + "/topics/events",
			on{"AWS::SQS::Queue events-audit": {"receive", "entity/read"}, "AWS::SQS::Queue events-audit-dlq": {"receive", "entity/read"}},
			on{p + "subscriptions/events-audit": {"receive"}, p + "subscriptions/events-audit-dlq": {"receive"}}},
		{idSBSender, ns + "/queues/orders",
			on{"AWS::SQS::Queue orders": {"send", "entity/read"}},
			on{p + "topics/orders": {"send"}}},
		{idSBOwner, ns + "/queues/orders",
			on{"AWS::SQS::Queue orders": {"send", "receive", "entity/read"}, "AWS::SQS::Queue orders-dlq": {"receive", "entity/read"}},
			on{p + "topics/orders": {"send"}, p + "subscriptions/orders": {"receive"}, p + "subscriptions/orders-dlq": {"receive"}}},
		// shoplogs keeps versions.
		{idBlobReader, st,
			on{"AWS::S3::Bucket shoplogs-audit": {"blobs/list"}, "AWS::S3::Bucket shoplogs-audit/*": {"blobs/read"}},
			on{"shoplogs-audit": {"blobs/read"}}},
		{idBlobContr, st,
			on{"AWS::S3::Bucket shoplogs-audit": {"blobs/list"}, "AWS::S3::Bucket shoplogs-audit/*": {"blobs/read", "blobs/write", "blobs/delete"}},
			on{"shoplogs-audit": {"blobs/read", "blobs/add"}}},
		{idBlobOwner, st,
			on{"AWS::S3::Bucket shoplogs-audit": {"blobs/list"}, "AWS::S3::Bucket shoplogs-audit/*": {"blobs/read", "blobs/write", "blobs/delete", "blobs/deleteVersion"}},
			on{"shoplogs-audit": {"blobs/read", "blobs/write", "blobs/delete", "blobs/deleteVersion"}}},
		{idKVUser, kvs + "/secrets/api-key",
			on{"AWS::SecretsManager::Secret shopkv/api-key": {"getSecret", "readMetadata"}},
			on{p + "secrets/shopkv_api-key": {"getSecret"}}},
		{idKVOfficer, kvs + "/secrets/api-key",
			on{"AWS::SecretsManager::Secret shopkv/api-key": {"getSecret", "readMetadata", "setSecret"}},
			on{p + "secrets/shopkv_api-key": {"getSecret", "setSecret", "readMetadata", "authorization/read"}}},
		{idKVReader, kvs + "/secrets/api-key",
			on{"AWS::SecretsManager::Secret shopkv/api-key": {"readMetadata"}},
			on{p + "secrets/shopkv_api-key": {"readMetadata", "authorization/read"}}},
		{idAcrPull, acr,
			on{"repository/shopacr/*": {"pull"}, "*": {"registry sign-in"}},
			on{p + "locations/europe-west1/repositories/shopacr": {"pull"}}},
		{idAcrPush, acr,
			on{"repository/shopacr/*": {"pull", "push"}, "*": {"registry sign-in"}},
			on{p + "locations/europe-west1/repositories/shopacr": {"pull"}}},
	}
	if len(cases) < len(identityRoles) {
		t.Fatalf("%d cases for %d roles", len(cases), len(identityRoles))
	}
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.role] = true
		var objs []snapshot.Object
		for _, o := range identityFixture().Objects {
			if o.Kind() != "Microsoft.Authorization/roleAssignments" {
				objs = append(objs, o)
			}
		}
		objs = append(objs, idAssignment("z01", c.scope, idPrincipal("web-id"), c.role, nil))
		for name, m := range identityMaps() {
			r := runIdentity(t, snapshot.Snapshot{Platform: "azure", Policy: "default", Objects: objs}, m)
			got, wantOn := idAWSGrants(t, r), c.aws
			if name == "gcp" {
				got, wantOn = idGCPGrants(t, r), c.gcp
			}
			want := map[idGrant]bool{}
			for obj, ws := range wantOn {
				for _, w := range ws {
					want[idGrant{"web-id", obj, w}] = true
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: %s on %s gives\n  %s\nwant\n  %s", name, identityRoles[c.role].name, c.scope, strings.Join(idSorted(got), "\n  "), strings.Join(idSorted(want), "\n  "))
			}
		}
	}
	for g := range identityRoles {
		if !seen[g] {
			t.Errorf("%s has no case", identityRoles[g].name)
		}
	}
}

// The translations are snapshots: written to disk and read back, bindings
// included, they are the same.
func TestIdentityWritesAsASnapshot(t *testing.T) {
	for name, m := range identityMaps() {
		s := runIdentity(t, identityFixture(), m).Snapshots[name]
		dir := t.TempDir() + "/" + name
		if err := s.Write(dir); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		back, err := snapshot.Read(dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ch := snapshot.Compare(s, back); len(ch) != 0 || len(back.Objects) != len(s.Objects) {
			t.Errorf("%s: read back differs: %v", name, ch)
		}
	}
}
