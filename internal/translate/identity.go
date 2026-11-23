package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Workload identity: what an app in a cluster could reach on Azure through
// its managed identity, it can reach on the target, and nothing more.
//
// This is the family where a wrong translation is a security bug, so it is
// the narrowest. The rule above the others: a grant is written only when
// it is no more than the source's; in doubt, the assignment is refused and
// says why.
//
// What is read:
//
//   - user-assigned managed identities and their federated credentials
//     whose issuer is a translated AKS cluster and whose subject is one
//     Kubernetes service account (AKS workload identity);
//   - role assignments of those identities, with one of the built-in data
//     roles in identityRoles, on something the translation wrote, or on a
//     resource group or the subscription, which is narrowed to what the
//     translation wrote inside it.
//
// What is refused, each with its reason: control-plane roles (Owner,
// Contributor, Reader, ...), custom roles, assignments with a condition,
// assignments to users, groups and service principals (people and
// pipelines are the customer's directory, not workload identity), and a
// credential for an issuer that is not a translated cluster.
//
// A grant is never a wildcard. The capabilities a role gives are a fixed
// table (identityRoles), from Azure's published definition of the role;
// what each capability becomes on a target is another fixed table
// (identity_aws.go, identity_gcp.go), on the objects by name. What a role
// allowed that has no rule is not granted, and is named as a loss.

const (
	azIdentity    = "microsoft.managedidentity/userassignedidentities"
	azFedCred     = azIdentity + "/federatedidentitycredentials"
	azSysIdentity = "microsoft.managedidentity/identities"
	azRoleAssign  = "microsoft.authorization/roleassignments"
	azRoleDef     = "microsoft.authorization/roledefinitions"

	identityWhyNoDest = "the map chooses no destination for identity (destinations.identity)"
)

type identity struct{}

func (identity) claims(kind string) bool {
	return strings.HasPrefix(kind, "microsoft.managedidentity/") || kind == azRoleAssign || kind == azRoleDef
}

// The services a data role belongs to.
const (
	identitySB   = "Service Bus"
	identityBlob = "blob storage"
	identityKV   = "Key Vault secrets"
	identityACR  = "container registry"
)

// The capabilities a role gives. Each is what the role's published
// actions and dataActions allow, in words a target's table maps.
const (
	capSend    = "send"    // Microsoft.ServiceBus/*/send/action
	capReceive = "receive" // Microsoft.ServiceBus/*/receive/action

	capBlobRead   = "blob-read"   // .../containers/blobs/read: "Returns a blob or a list of blobs"
	capBlobWrite  = "blob-write"  // .../containers/blobs/write, add/action
	capBlobDelete = "blob-delete" // .../containers/blobs/delete
	// capBlobPurge is deleting a blob's version for good, which only the
	// wildcard of Storage Blob Data Owner (containers/blobs/*) holds.
	capBlobPurge = "blob-delete-version"

	capSecretRead  = "secret-read"  // vaults/secrets/getSecret/action
	capSecretMeta  = "secret-meta"  // vaults/secrets/readMetadata/action
	capSecretWrite = "secret-write" // vaults/secrets/* (setSecret)
	// capSecretAuthz is reading who may read the secret
	// (Microsoft.Authorization/*/read among the role's actions).
	capSecretAuthz = "secret-authz"

	capPull = "pull" // Microsoft.ContainerRegistry/registries/pull/read
	capPush = "push" // Microsoft.ContainerRegistry/registries/push/write
)

// identityRole is one built-in role this translates.
type identityRole struct {
	name    string
	service string
	caps    []string
	// beyond is what the role allowed on Azure that no target is granted.
	beyond string
	// doc is the role's published definition.
	doc string
}

const identityRolesDoc = "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/"

// identityRoles are the built-in data roles that are translated, by role
// definition GUID. Each entry is from the role's definition on
// learn.microsoft.com (the JSON under the anchor in doc), read on
// 2026-11-20; the actions quoted are the definition's own.
var identityRoles = map[string]identityRole{
	// actions: Microsoft.ServiceBus/*/queues/read, */topics/read,
	// */topics/subscriptions/read; dataActions: Microsoft.ServiceBus/*/send/action.
	"69a216fc-b8fb-44d8-bc22-1f3c2cd27a39": {name: "Azure Service Bus Data Sender", service: identitySB, caps: []string{capSend},
		doc: identityRolesDoc + "integration#azure-service-bus-data-sender"},
	// The same actions; dataActions: Microsoft.ServiceBus/*/receive/action.
	"4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0": {name: "Azure Service Bus Data Receiver", service: identitySB, caps: []string{capReceive},
		doc: identityRolesDoc + "integration#azure-service-bus-data-receiver"},
	// actions and dataActions: Microsoft.ServiceBus/*.
	"090c5cfd-751d-490a-894a-3ce6f1109419": {name: "Azure Service Bus Data Owner", service: identitySB, caps: []string{capSend, capReceive},
		beyond: "the role also managed the namespace (creating and deleting queues, topics, subscriptions and rules, its keys): only sending and receiving on what the translation wrote is granted",
		doc:    identityRolesDoc + "integration#azure-service-bus-data-owner"},

	// actions: .../blobServices/containers/read, generateUserDelegationKey/action;
	// dataActions: .../blobServices/containers/blobs/read.
	"2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": {name: "Storage Blob Data Reader", service: identityBlob, caps: []string{capBlobRead},
		beyond: "the role could also sign a user delegation SAS for what it may read: there is no SAS on the target, and nothing is granted for one",
		doc:    identityRolesDoc + "storage#storage-blob-data-reader"},
	// actions: containers/delete, read, write, generateUserDelegationKey/action;
	// dataActions: containers/blobs/delete, read, write, move/action, add/action.
	"ba92f5b4-2d11-453d-a403-e96b0029c9fe": {name: "Storage Blob Data Contributor", service: identityBlob, caps: []string{capBlobRead, capBlobWrite, capBlobDelete},
		beyond: "the role could also create and delete containers and sign a user delegation SAS: the buckets are the translation's, and neither is granted",
		doc:    identityRolesDoc + "storage#storage-blob-data-contributor"},
	// actions: containers/*, generateUserDelegationKey/action;
	// dataActions: containers/blobs/*.
	"b7e6dc6d-f1e8-4753-8033-0f276bb0955b": {name: "Storage Blob Data Owner", service: identityBlob, caps: []string{capBlobRead, capBlobWrite, capBlobDelete, capBlobPurge},
		beyond: "the role also set POSIX ownership and ACLs, blob tags, legal holds and immutability, and created and deleted containers: only reading, writing and deleting objects is granted",
		doc:    identityRolesDoc + "storage#storage-blob-data-owner"},

	// actions: none; dataActions: vaults/secrets/getSecret/action,
	// vaults/secrets/readMetadata/action.
	"4633458b-17de-408a-b874-0445c86b69e6": {name: "Key Vault Secrets User", service: identityKV, caps: []string{capSecretRead, capSecretMeta},
		doc: identityRolesDoc + "security#key-vault-secrets-user"},
	// actions: Microsoft.Authorization/*/read, Microsoft.KeyVault/vaults/*/read, ...;
	// dataActions: vaults/secrets/*.
	"b86a8fe4-44ce-4948-aee5-eccb2c155cd7": {name: "Key Vault Secrets Officer", service: identityKV, caps: []string{capSecretRead, capSecretMeta, capSecretWrite, capSecretAuthz},
		beyond: "the role could also create, delete, recover, purge, back up and restore secrets in the vault: only reading the translated secrets and giving them new versions is granted",
		doc:    identityRolesDoc + "security#key-vault-secrets-officer"},
	// actions: Microsoft.Authorization/*/read, Microsoft.KeyVault/vaults/*/read, ...;
	// dataActions: vaults/*/read, vaults/secrets/readMetadata/action.
	"21090545-7ca7-4776-b22c-e363652d74d2": {name: "Key Vault Reader", service: identityKV, caps: []string{capSecretMeta, capSecretAuthz},
		beyond: "the role also read the vault's own settings and the properties of its keys and certificates: only the translated secrets' properties are granted",
		doc:    identityRolesDoc + "security#key-vault-reader"},

	// actions: Microsoft.ContainerRegistry/registries/pull/read; no dataActions.
	"7f951dda-4ed3-4680-a7ca-43fe172d538d": {name: "AcrPull", service: identityACR, caps: []string{capPull},
		doc: identityRolesDoc + "containers#acrpull"},
	// actions: registries/pull/read, registries/push/write; no dataActions.
	"8311e382-0749-4cb8-b61a-304f252e45ec": {name: "AcrPush", service: identityACR, caps: []string{capPull, capPush},
		doc: identityRolesDoc + "containers#acrpush"},
}

// identityRefusedRoles are built-in roles that are known and refused,
// with why. Any other role is refused too, as one this does not know.
var identityRefusedRoles = map[string][2]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": {"Owner", identityControlPlane},
	"b24988ac-6180-42a0-ab88-20f7382dd24c": {"Contributor", identityControlPlane},
	"acdd72a7-3385-48ef-bd42-f606fba81ae7": {"Reader", identityControlPlane},
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": {"User Access Administrator", identityControlPlane},
	"f58310d9-a9f6-439a-9e8d-f62e7b41a168": {"Role Based Access Control Administrator", identityControlPlane},
	"00482a5a-887f-4fb3-b363-3b7fe8e74483": {"Key Vault Administrator", "it gives everything in a vault, keys and certificates included, which are not translated: grant the app Key Vault Secrets User or Officer on Azure and translate that"},
	"12338af0-0e69-4776-bea7-57ae8d297424": {"Key Vault Crypto User", "keys are not translated"},
	"db79e9a7-68ee-4b58-9aeb-b90e7c24fcba": {"Key Vault Certificate User", "certificates are not translated"},
	"c2f4ef07-c644-48eb-af81-4b1b4947fb11": {"AcrDelete", "deleting images is not translated: no table says what it becomes"},
	"b93aa761-3e63-49ed-ac28-beffa264f7ac": {"Container Registry Repository Reader", "a role of a registry with repository permissions (ABAC), whose assignments carry conditions on repository names: not translated"},
	"2a1e307c-b015-4ebd-883e-5b7698a07328": {"Container Registry Repository Writer", "a role of a registry with repository permissions (ABAC), whose assignments carry conditions on repository names: not translated"},
	"2efddaa5-3f1f-4df3-97df-af3f13818f4c": {"Container Registry Repository Contributor", "a role of a registry with repository permissions (ABAC), whose assignments carry conditions on repository names: not translated"},
	"db58b8e5-c6ad-4a2a-8342-4190687cbf4a": {"Storage Blob Delegator", "it signs user delegation SAS tokens, and there is no SAS on the target"},
	"974c5e8b-45b9-4653-ba55-5f855dd0fb88": {"Storage Queue Data Contributor", "storage queues are not translated"},
	"8a0f0c08-91a1-4084-bc3d-661d67233fed": {"Storage Queue Data Message Processor", "storage queues are not translated"},
	"c6a89b2d-59bc-44d0-9896-0f6e12d7b80a": {"Storage Queue Data Message Sender", "storage queues are not translated"},
	"19e7f393-937e-4f77-808e-94535e297925": {"Storage Queue Data Reader", "storage queues are not translated"},
}

const identityControlPlane = "a control-plane role: it manages Azure resources through Azure Resource Manager, which has no counterpart in what an app reads and writes; who manages the target's resources is the target's own IAM, set on its own"

// identityServices says, per service, the kinds a role acts on and the
// kind every scope of its own must be under.
var identityServices = map[string]struct {
	root  string
	kinds []string
}{
	identitySB:   {sbNamespace, []string{sbQueue, sbTopic, sbSubscription}},
	identityBlob: {azStorage, []string{azContainer}},
	identityKV:   {azVault, []string{azVaultSecret}},
	identityACR:  {azRegistry, []string{azRegistry}},
}

// idIdent is one user-assigned identity.
type idIdent struct {
	src, group, name, key string
	tags                  map[string]string
	losses                []Loss
	creds                 []*idCred
	assigns               []*idAssign
	// kubelet is the cluster (group/name) whose nodes run as it.
	kubelet string
}

// idCred is a federated credential that names one service account of a
// translated cluster.
type idCred struct {
	src, name string
	ns, sa    string
	cluster   *idCluster
	losses    []Loss
}

// idCluster is a translated AKS cluster.
type idCluster struct {
	src, key string // source name; group/name, lower case
	target   string // the target cluster object's name
	short    string // and the cluster's own name there
	spec     map[string]any
	windows  bool
}

// idAssign is a role assignment that is translated.
type idAssign struct {
	src    string
	role   identityRole
	scope  idScope
	losses []Loss
	// found are the target objects in its scope, with what each is.
	found []idFound
	// items are what a target's table made of it.
	items []idItem
}

// idFound is one target object in an assignment's scope.
type idFound struct {
	slot string
	obj  snapshot.Object
	from string // the Azure source it was written for
}

// idItem is one grant as a target writes it: on AWS the actions and the
// resource, on GCP the role and the object.
type idItem struct {
	cap      string
	sid      string
	actions  []string
	resource any
	role     string
	obj      snapshot.Object
}

// The slots: what a target object is to the Azure object it was written
// for. A capability is granted on a slot, never on a kind: a sender may
// send to a queue's queue, not to a subscription's.
const (
	slotQueue    = "queue"        // AWS: a queue's queue
	slotDLQ      = "dlq"          // AWS: its dead-letter queue
	slotSubQueue = "sub-queue"    // AWS: a subscription's queue
	slotSubDLQ   = "sub-dlq"      // AWS: and its dead-letter queue
	slotTopic    = "topic"        // an SNS topic; a Pub/Sub topic that is published to
	slotSub      = "subscription" // GCP: a subscription that is pulled
	slotDLSub    = "dl-subscription"
	slotBucket   = "bucket"
	slotSecret   = "secret"
	slotRegistry = "registry"
)

// idScope is where a role assignment applies.
type idScope struct {
	group string // "" for the subscription
	kind  string // lower case; "" for a resource group or the subscription
	name  string // lower case
}

func (s idScope) String() string {
	switch {
	case s.kind != "":
		return s.kind + " " + s.group + "/" + s.name
	case s.group != "":
		return "resource group " + s.group
	}
	return "the subscription"
}

const identityAssignMark = "providers/microsoft.authorization/roleassignments/"

// identityScope reads an assignment's scope from its name, as a capture
// writes it: providers/<type>/<name>.../providers/Microsoft.Authorization/roleAssignments/<id>
// in the scope's resource group, or the last part alone on a group or the
// subscription.
func identityScope(o snapshot.Object) (idScope, string) {
	n := strings.ToLower(o.Name())
	i := strings.LastIndex(n, identityAssignMark)
	if i < 0 {
		return idScope{}, "its name is not a role assignment's (…/providers/Microsoft.Authorization/roleAssignments/<id>)"
	}
	s := idScope{group: o.Namespace()}
	rest := strings.Trim(n[:i], "/")
	if rest == "" {
		return s, ""
	}
	parts := strings.Split(rest, "/")
	if parts[0] != "providers" || len(parts) < 4 || len(parts)%2 != 0 || strings.Contains(rest[1:], "/providers/") || s.group == "" {
		return idScope{}, "its scope (" + rest + ") is not a resource, a resource group or the subscription"
	}
	kind := parts[1]
	var names []string
	for j := 2; j+1 < len(parts); j += 2 {
		kind += "/" + parts[j]
		names = append(names, parts[j+1])
	}
	s.kind, s.name = kind, strings.Join(names, "/")
	return s, ""
}

// covers reports whether an object is in the scope.
func (s idScope) covers(o snapshot.Object) bool {
	if s.group != "" && !strings.EqualFold(s.group, o.Namespace()) {
		return false
	}
	if s.kind == "" {
		return true
	}
	k, n := strings.ToLower(o.Kind()), strings.ToLower(o.Name())
	return (k == s.kind && n == s.name) || (strings.HasPrefix(k, s.kind+"/") && strings.HasPrefix(n, s.name+"/"))
}

var (
	identityGUID    = regexp.MustCompile(`(?i)/providers/microsoft\.authorization/roledefinitions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	identityRef     = regexp.MustCompile(`^\{\{truthform\|ref\|([^|{}]+)\|([^|{}]*)\|([^|{}]+)\|([^|{}]*)\}\}$`)
	identitySubject = regexp.MustCompile(`^system:serviceaccount:([a-z0-9]([-a-z0-9]*[a-z0-9])?):([a-z0-9]([-a-z0-9.]*[a-z0-9])?)$`)
)

// identityWriter writes the model for one target.
type identityWriter interface {
	platform() string
	clusterKind() string
	// slots says what each object written for an Azure source is.
	slots(kind string, objs []snapshot.Object) []idFound
	// plan turns an assignment's capabilities on what was found into
	// grants, and names what has no rule.
	plan(a *idAssign)
	// nameOf is the identity's name on the target, or why it has none.
	nameOf(id *idIdent) (string, string)
	// write writes an identity, its trust and its grants. It returns the
	// identity's entry and the targets of each credential and assignment.
	write(id *idIdent, name string, o *out) (Entry, map[string][]string)
	// nodes says what stands for a cluster's kubelet identity.
	nodes(c *idCluster, o *out) string
	pullRequirement(c *idCluster, reg idFound, o *out) string
}

type identityRun struct {
	o        *out
	w        identityWriter
	idents   map[string]*idIdent
	clusters map[string]*idCluster
	// by is every source object by its kind and group/name, lower case.
	by map[string]snapshot.Object
	// written are the target objects by the Azure source they were
	// written for, lower case.
	written map[string][]snapshot.Object
	// refusedIdent is why an identity is not written.
	refusedIdent map[string]string
}

func (identity) translate(objs []snapshot.Object, o *out) {
	r := &identityRun{o: o, idents: map[string]*idIdent{}, clusters: map[string]*idCluster{}, by: map[string]snapshot.Object{},
		written: map[string][]snapshot.Object{}, refusedIdent: map[string]string{}}
	if o.m.Destinations.Identity == identityWorkload {
		switch o.m.To {
		case "aws":
			r.w = &identityAWS{m: o.m, addons: map[string]bool{}}
		case "gcp":
			r.w = &identityGCP{m: o.m, pools: map[string]bool{}}
		}
	}
	for _, s := range o.src {
		r.by[strings.ToLower(s.Kind()+" "+s.Namespace()+"/"+s.Name())] = s
	}
	for _, t := range o.objects[o.m.To] {
		if src, ok := o.keys[o.m.To+"|"+t.Key()]; ok {
			r.written[strings.ToLower(src)] = append(r.written[strings.ToLower(src)], t)
		}
	}
	r.readClusters()
	if g, ok := r.w.(*identityGCP); ok {
		g.all = r.clusters
	}

	sort.Slice(objs, func(i, j int) bool { return source(objs[i]) < source(objs[j]) })
	var creds, assigns []snapshot.Object
	custom := map[string]string{} // role definition GUID -> name
	for _, obj := range objs {
		switch k := strings.ToLower(obj.Kind()); k {
		case azIdentity:
			id := readIdentity(obj)
			id.kubelet = r.kubeletOf(obj)
			r.idents[id.key] = id
		case azFedCred:
			creds = append(creds, obj)
		case azRoleAssign:
			assigns = append(assigns, obj)
		case azRoleDef:
			name, losses := readRoleDefinition(obj)
			custom[strings.ToLower(obj.Name()[strings.LastIndex(obj.Name(), "/")+1:])] = name
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Losses: losses,
				Reason: fmt.Sprintf("a custom role (%s): its actions are Azure's own, and no fixed table says what each becomes on the target; an assignment of it is refused. Give the app one of the built-in data roles on Azure, or grant the target's equivalent on its own", orDefault(name, "unnamed"))})
		case azSysIdentity:
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused,
				Reason: "a system-assigned identity is made with its resource and is not translated: on the target the resource runs as what the target or the map gives it, and each role assignment to it is reported on its own"})
		default:
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
		}
	}
	credEntry := map[*idCred]*Entry{}
	var held []*Entry
	hold := func(e Entry) *Entry { held = append(held, &e); return held[len(held)-1] }
	for _, obj := range creds {
		c, id, why := r.readCred(obj)
		if why != "" {
			hold(Entry{Source: source(obj), State: Refused, Reason: why})
			continue
		}
		id.creds = append(id.creds, c)
		credEntry[c] = hold(Entry{Source: c.src, State: Mapped, Losses: c.losses})
	}
	// A service account takes one identity on either target: "Each
	// Kubernetes service account in a cluster can be associated with one
	// IAM role" (EKS Pod Identity), and one iam.gke.io/gcp-service-account
	// annotation (GKE). On Azure a pod could ask for either by client ID.
	users := map[string][]*idIdent{}
	for _, id := range r.sortedIdents() {
		for _, c := range id.creds {
			k := c.cluster.key + " " + c.ns + "/" + c.sa
			if n := len(users[k]); n == 0 || users[k][n-1] != id {
				users[k] = append(users[k], id)
			}
		}
	}
	for _, id := range r.sortedIdents() {
		var keep []*idCred
		for _, c := range id.creds {
			ids := users[c.cluster.key+" "+c.ns+"/"+c.sa]
			if len(ids) < 2 {
				keep = append(keep, c)
				continue
			}
			var ns []string
			for _, x := range ids {
				ns = append(ns, x.group+"/"+x.name)
			}
			credEntry[c].State, credEntry[c].Losses = Refused, nil
			credEntry[c].Reason = fmt.Sprintf("service account %s/%s of cluster %s is federated to %d identities (%s), and on the target a service account acts as one: choosing which is not the translation's, so none is written for it", c.ns, c.sa, c.cluster.key, len(ids), strings.Join(ns, ", "))
		}
		id.creds = keep
	}
	// An identity nothing on the target could use is not written.
	for _, id := range r.sortedIdents() {
		switch {
		case r.w == nil:
			r.refusedIdent[id.key] = identityWhyNoDest
		case id.kubelet != "":
		case len(id.creds) == 0:
			r.refusedIdent[id.key] = "no federated credential of it names a service account of a translated cluster: nothing on the target could use it. An identity of a VM, an app service or a pipeline is not workload identity, and what runs there is given its access on the target on its own"
		default:
			if _, why := r.w.nameOf(id); why != "" {
				r.refusedIdent[id.key] = why
			}
		}
	}
	assignEntry := map[*idAssign]*Entry{}
	for _, obj := range assigns {
		a, id, e := r.readAssign(obj, custom)
		if a == nil {
			hold(e)
			continue
		}
		id.assigns = append(id.assigns, a)
		assignEntry[a] = hold(Entry{Source: a.src, State: Mapped, Losses: a.losses})
	}
	for _, id := range r.sortedIdents() {
		if id.kubelet != "" && r.w != nil {
			c := r.clusters[id.kubelet]
			e := Entry{Source: id.src, State: Mapped, Losses: id.losses, Reason: "the kubelet identity of cluster " + id.kubelet + ": on the target its nodes run as " + r.nodesOf(c) + ", which is not written here"}
			o.entries = append(o.entries, e)
			continue
		}
		if why := r.refusedIdent[id.key]; why != "" {
			o.entries = append(o.entries, Entry{Source: id.src, State: Refused, Reason: why})
			for _, c := range id.creds {
				credEntry[c].State, credEntry[c].Reason, credEntry[c].Losses = Refused, "its identity "+id.src+" is refused: "+why, nil
			}
			continue
		}
		e, targets := r.w.write(id, r.nameOfIdent(id), o)
		if e.State == Refused {
			o.entries = append(o.entries, e)
			for _, c := range id.creds {
				credEntry[c].State, credEntry[c].Reason, credEntry[c].Losses = Refused, "its identity "+id.src+" is refused: "+e.Reason, nil
			}
			for _, a := range id.assigns {
				assignEntry[a].State, assignEntry[a].Reason, assignEntry[a].Losses = Refused, "its identity "+id.src+" is refused: "+e.Reason, nil
			}
			continue
		}
		e.Losses = append(append([]Loss(nil), id.losses...), e.Losses...)
		o.entries = append(o.entries, e)
		for _, c := range id.creds {
			credEntry[c].Targets = targets[c.src]
			credEntry[c].Losses = c.losses
			credEntry[c].Reason = fmt.Sprintf("service account %s in namespace %s of cluster %s may act as %s", c.sa, c.ns, c.cluster.short, r.nameOfIdent(id))
		}
		for _, a := range id.assigns {
			assignEntry[a].Targets = targets[a.src]
			assignEntry[a].Reason = identityGrantText(a)
		}
	}
	for _, e := range held {
		o.entries = append(o.entries, *e)
	}
}

func (r *identityRun) nameOfIdent(id *idIdent) string {
	n, _ := r.w.nameOf(id)
	return n
}

func (r *identityRun) nodesOf(c *idCluster) string {
	if c == nil || r.w == nil {
		return "what the map names for the cluster's nodes"
	}
	return r.w.nodes(c, r.o)
}

func (r *identityRun) sortedIdents() []*idIdent {
	out := make([]*idIdent, 0, len(r.idents))
	for _, id := range r.idents {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	return out
}

// readClusters finds the AKS clusters the clusters family wrote.
func (r *identityRun) readClusters() {
	if r.w == nil {
		return
	}
	for _, s := range r.o.src {
		if strings.ToLower(s.Kind()) != azAKS {
			continue
		}
		for _, t := range r.written[strings.ToLower(source(s))] {
			if t.Kind() != r.w.clusterKind() {
				continue
			}
			c := &idCluster{src: source(s), key: strings.ToLower(s.Namespace() + "/" + s.Name()), target: t.Name(), short: t.Name()[strings.LastIndex(t.Name(), "/")+1:]}
			c.spec, _ = t.Body["spec"].(map[string]any)
			for _, p := range list(obj(spec(s)["properties"])["agentPoolProfiles"]) {
				if strings.EqualFold(fmt.Sprint(obj(p)["osType"]), "Windows") {
					c.windows = true
				}
			}
			for _, p := range r.o.src {
				if strings.ToLower(p.Kind()) == azAKSPool && strings.EqualFold(p.Namespace(), s.Namespace()) && strings.HasPrefix(strings.ToLower(p.Name()), strings.ToLower(s.Name())+"/") &&
					strings.EqualFold(fmt.Sprint(obj(spec(p)["properties"])["osType"]), "Windows") {
					c.windows = true
				}
			}
			r.clusters[c.key] = c
		}
	}
}

// kubeletOf is the cluster (group/name, lower case) whose kubelet
// identity an identity is, or "".
func (r *identityRun) kubeletOf(id snapshot.Object) string {
	want := strings.ToLower("/resourcegroups/" + id.Namespace() + "/providers/microsoft.managedidentity/userassignedidentities/" + id.Name())
	tok := strings.ToLower("|" + id.Namespace() + "|" + id.Name() + "|")
	for _, s := range r.o.src {
		if strings.ToLower(s.Kind()) != azAKS {
			continue
		}
		rid := strings.ToLower(fmt.Sprint(obj(obj(obj(spec(s)["properties"])["identityProfile"])["kubeletidentity"])["resourceId"]))
		if strings.HasSuffix(rid, want) || (strings.Contains(rid, "microsoft.managedidentity/userassignedidentities"+tok) && strings.HasPrefix(rid, "{{truthform|ref|")) {
			return strings.ToLower(s.Namespace() + "/" + s.Name())
		}
	}
	return ""
}

func readIdentity(o snapshot.Object) *idIdent {
	id := &idIdent{src: source(o), group: o.Namespace(), name: o.Name(), key: strings.ToLower(o.Namespace() + "/" + o.Name())}
	top := newProps(spec(o), "")
	// The region an identity is kept in configures nothing on a target,
	// where a role and a service account are global.
	top.quiet("location", "properties")
	id.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("tenantId", "principalId", "clientId")
	if s := p.str("isolationScope"); s != "" && !strings.EqualFold(s, "None") {
		p.lose("isolationScope", s+": the identity was kept to its region; the target's role or service account is global", false)
	}
	id.losses = append(top.rest(), p.rest()...)
	return id
}

// readRoleDefinition reads a custom role: its name, and its settings, all
// of which the refusal stands for.
func readRoleDefinition(o snapshot.Object) (string, []Loss) {
	top := newProps(spec(o), "")
	top.quiet("properties")
	p := newProps(obj(top.m["properties"]), "properties.")
	name := p.str("roleName")
	p.quiet("description", "type", "permissions", "assignableScopes", "createdOn", "updatedOn", "createdBy", "updatedBy")
	return name, append(top.rest(), p.rest()...)
}

// readCred reads a federated credential. It is taken only when it names
// one service account of a translated cluster.
func (r *identityRun) readCred(o snapshot.Object) (*idCred, *idIdent, string) {
	parent, name, _ := strings.Cut(o.Name(), "/")
	c := &idCred{src: source(o), name: name}
	top := newProps(spec(o), "")
	top.quiet("properties")
	p := newProps(obj(top.m["properties"]), "properties.")
	issuer, subject := p.str("issuer"), p.str("subject")
	aud, _ := p.take("audiences")
	if l := list(aud); len(l) != 1 || l[0] != "api://AzureADTokenExchange" {
		p.lose("audiences", fmt.Sprintf("%v: the token's audience is the target's own; whatever asked for another audience on Azure gets none here", aud), false)
	}
	expr, hasExpr := p.take("claimsMatchingExpression")
	c.losses = append(top.rest(), p.rest()...)
	for _, l := range c.losses {
		if l.Unread {
			return nil, nil, "it has a setting no rule reads (" + l.Field + "): what it lets in is not known"
		}
	}
	id := r.idents[strings.ToLower(o.Namespace()+"/"+parent)]
	switch {
	case id == nil:
		return nil, nil, "its identity is not in the snapshot"
	case hasExpr && expr != nil:
		return nil, nil, "it matches tokens by an expression (claimsMatchingExpression), which can let in more than one service account: only a credential for one named service account is translated"
	}
	m := identityRef.FindStringSubmatch(issuer)
	if m == nil || strings.ToLower(m[1]) != azAKS {
		return nil, nil, fmt.Sprintf("its issuer (%s) is not a cluster in the snapshot: only the service accounts of a translated cluster are given the identity. A pipeline's or another cluster's tokens are trusted on the target on their own", issuer)
	}
	key := strings.ToLower(m[2] + "/" + m[3])
	sm := identitySubject.FindStringSubmatch(subject)
	if sm == nil {
		return nil, nil, fmt.Sprintf("its subject (%s) is not one Kubernetes service account (system:serviceaccount:<namespace>:<name>)", subject)
	}
	c.ns, c.sa = sm[1], sm[3]
	if r.w == nil {
		return nil, nil, identityWhyNoDest
	}
	if c.cluster = r.clusters[key]; c.cluster == nil {
		return nil, nil, "its issuer is cluster " + key + ", which is not translated (" + r.stateOf(azAKS, m[2], m[3]) + "): there is no cluster on the target whose service account could be trusted"
	}
	return c, id, ""
}

// stateOf says how a source object ended, for a reason.
func (r *identityRun) stateOf(kind, group, name string) string {
	want := strings.ToLower(kind + " " + group + "/" + name)
	for _, e := range r.o.entries {
		if strings.ToLower(e.Source) == want {
			if e.Reason != "" && e.State != Mapped {
				return string(e.State) + ": " + e.Reason
			}
			return string(e.State)
		}
	}
	return "not in the snapshot"
}

// readAssign reads a role assignment. It returns the assignment and the
// identity it is for, or the entry that refuses it.
func (r *identityRun) readAssign(o snapshot.Object, custom map[string]string) (*idAssign, *idIdent, Entry) {
	src := source(o)
	refuse := func(why string, a ...any) (*idAssign, *idIdent, Entry) {
		return nil, nil, Entry{Source: src, State: Refused, Reason: fmt.Sprintf(why, a...)}
	}
	top := newProps(spec(o), "")
	top.quiet("properties")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("scope", "createdOn", "updatedOn", "createdBy", "updatedBy", "description")
	principal, ptype, roleID := p.str("principalId"), p.str("principalType"), p.str("roleDefinitionId")
	cond, cver := p.str("condition"), p.str("conditionVersion")
	delegated := p.str("delegatedManagedIdentityResourceId")
	losses := append(top.rest(), p.rest()...)
	for _, l := range losses {
		if l.Unread {
			return refuse("it has a setting no rule reads (%s): what it grants is not known", l.Field)
		}
	}
	gm := identityGUID.FindStringSubmatch(roleID)
	if gm == nil {
		return refuse("its role (%s) is not a role definition's ID", roleID)
	}
	guid := strings.ToLower(gm[1])
	role, known := identityRoles[guid]
	roleName := role.name
	if !known {
		roleName = guid
		if rr, ok := identityRefusedRoles[guid]; ok {
			roleName = rr[0]
		} else if n, ok := custom[guid]; ok {
			roleName = "custom role " + orDefault(n, guid)
		}
	}
	// Who it is for comes first: an assignment to a person is refused as
	// that, whatever its role.
	var id *idIdent
	var kubelet *idCluster
	rm := identityRef.FindStringSubmatch(principal)
	switch {
	case rm == nil:
		what := map[string]string{"user": "a user", "group": "a group", "foreigngroup": "a group of another directory", "device": "a device",
			"serviceprincipal": "a service principal that is no managed identity in the snapshot (an app registration, a pipeline, or an identity of another subscription)"}[strings.ToLower(ptype)]
		if what == "" {
			what = "a principal of type " + orDefault(ptype, "unknown")
		}
		r.o.require("People, groups and pipelines are not translated: who had roles in Azure (each refused role assignment names one) is given access on the target through its own IAM and the customer's directory")
		return refuse("%s on %s is assigned to %s: people and pipelines are the customer's directory, not workload identity; their access on the target is set on its own", roleName, r.scopeText(o), what)
	case strings.ToLower(rm[1]) == azIdentity:
		if id = r.idents[strings.ToLower(rm[2]+"/"+rm[3])]; id == nil {
			return refuse("its identity %s/%s is not in the snapshot", rm[2], rm[3])
		}
		if id.kubelet != "" {
			if r.w == nil {
				return refuse("%s", identityWhyNoDest)
			}
			kubelet = r.clusters[id.kubelet]
			if kubelet == nil {
				return refuse("it is for the kubelet identity of cluster %s, which is not translated (%s)", id.kubelet, r.stateOfKey(azAKS, id.kubelet))
			}
		}
	case strings.ToLower(rm[1]) == azAKS && strings.HasPrefix(strings.ToLower(rm[4]), "properties.identityprofile.kubeletidentity."):
		key := strings.ToLower(rm[2] + "/" + rm[3])
		if kubelet = r.clusters[key]; kubelet == nil {
			if r.w == nil {
				return refuse("%s", identityWhyNoDest)
			}
			return refuse("it is for the kubelet identity of cluster %s, which is not translated (%s)", key, r.stateOf(azAKS, rm[2], rm[3]))
		}
	default:
		return refuse("%s on %s is assigned to the identity of %s %s/%s (%s), which is not a user-assigned identity with federated credentials: what that resource may reach on the target is granted to what it runs as there, on its own", roleName, r.scopeText(o), rm[1], rm[2], rm[3], rm[4])
	}
	switch {
	case cond != "":
		return refuse("it has a condition (%s%s): a grant written without it would give more, and conditions are Azure's own language", cond, map[bool]string{true: ", version " + cver}[cver != ""])
	case delegated != "":
		return refuse("it is a delegated assignment from another tenant (delegatedManagedIdentityResourceId): not translated")
	}
	if !known {
		if rr, ok := identityRefusedRoles[guid]; ok {
			return refuse("%s is not translated: %s", rr[0], rr[1])
		}
		if _, ok := custom[guid]; ok {
			return refuse("%s is not translated: its actions are Azure's own, and no fixed table says what each becomes on the target", roleName)
		}
		return refuse("role %s is not one of the built-in data roles this translates (%s): nothing is granted for a role whose actions are not in the table", guid, identityRoleNames())
	}
	scope, why := identityScope(o)
	if why != "" {
		return refuse("%s", why)
	}
	svc := identityServices[role.service]
	if scope.kind != "" && scope.kind != svc.root && !strings.HasPrefix(scope.kind, svc.root+"/") {
		return refuse("%s is a role for %s, and its scope is %s: it gives nothing there on Azure, and nothing is written", role.name, role.service, scope)
	}
	if r.w == nil {
		return refuse("%s", identityWhyNoDest)
	}
	if role.service == identitySB && r.o.m.Destinations.Messaging == "rabbitmq" {
		r.o.require("RabbitMQ has no workload identity: for each app that used Service Bus through a managed identity, create a User and a Permission (Messaging Topology Operator) whose configure, write and read expressions name only its queues and exchanges, and give the app the generated credentials Secret; each refused role assignment names the app's identity and what it could do")
		return refuse("%s on %s: messaging goes to RabbitMQ, which signs apps in with a user name and a password, not the pod's service account. The Messaging Topology Operator keeps a User's password in a Secret that any pod of its namespace may mount, so more than the one service account could use it; and sending to a queue goes through the default exchange, where a write permission lets a user publish to every queue of the virtual host (https://www.rabbitmq.com/docs/access-control). Neither is no more than the source gave, so no user is written", role.name, scope)
	}
	if id != nil && kubelet == nil {
		if why := r.refusedIdent[id.key]; why != "" {
			return refuse("its identity %s is refused: %s", id.src, why)
		}
	}
	a := &idAssign{src: src, role: role, scope: scope, losses: losses}
	missing, why := r.find(a)
	if why != "" {
		return refuse("%s", why)
	}
	if kubelet != nil {
		return r.kubeletAssign(a, kubelet, src)
	}
	r.w.plan(a)
	if len(a.items) == 0 {
		return refuse("%s gives nothing on what is in its scope (%s) that has a place on the target: %s", role.name, scope, identityLossText(a.losses))
	}
	if !identityExact(scope, a) {
		a.losses = append(a.losses, Loss{Field: "scope", Why: fmt.Sprintf("assigned on %s: on the target it is granted on each translated object in it, by name (%s); what is made there later is not covered, as it was on Azure", scope, identityFoundText(a.found))})
	}
	for _, m := range missing {
		a.losses = append(a.losses, Loss{Field: "scope", Why: m})
	}
	if role.beyond != "" {
		a.losses = append(a.losses, Loss{Field: "properties.roleDefinitionId", Why: role.name + ": " + role.beyond})
	}
	return a, id, Entry{}
}

// identityExact reports a scope that is one entity and nothing under it:
// a queue, a container, a secret. Anything wider (a topic with its
// subscriptions, a namespace, an account, a vault, a group) is written as
// the objects in it today.
func identityExact(s idScope, a *idAssign) bool {
	from := map[string]bool{}
	for _, f := range a.found {
		from[f.from] = true
	}
	if len(from) != 1 {
		return false
	}
	for _, k := range identityServices[a.role.service].kinds {
		if s.kind == k {
			return true
		}
	}
	return false
}

func (r *identityRun) stateOfKey(kind, key string) string {
	g, n, _ := strings.Cut(key, "/")
	return r.stateOf(kind, g, n)
}

func (r *identityRun) scopeText(o snapshot.Object) string {
	s, why := identityScope(o)
	if why != "" {
		return "its scope"
	}
	return s.String()
}

// kubeletAssign is a grant to the nodes' identity. The nodes run as what
// the map names, which is the customer's: nothing is written, and pulling
// images is asked for as a requirement.
func (r *identityRun) kubeletAssign(a *idAssign, c *idCluster, src string) (*idAssign, *idIdent, Entry) {
	if a.role.service != identityACR || a.role.name != "AcrPull" {
		return nil, nil, Entry{Source: src, State: Refused, Reason: fmt.Sprintf("%s on %s is assigned to the kubelet identity of cluster %s: on the target the nodes run as %s, which every pod on a node can reach unless it is kept from it; nothing is granted to it here. If an app needs this, give its own service account a managed identity with a federated credential", a.role.name, a.scope, c.key, r.w.nodes(c, r.o))}
	}
	e := Entry{Source: src, State: Mapped, Reason: "the nodes of cluster " + c.short + " pulled images with this: on the target they run as " + r.w.nodes(c, r.o)}
	for _, f := range a.found {
		e.Losses = append(e.Losses, Loss{Field: "properties.principalId", Why: r.w.pullRequirement(c, f, r.o)})
	}
	return nil, nil, e
}

// find fills an assignment's target objects: what was written for each
// Azure object of the role's service in its scope. It returns what is in
// scope and not written, and why nothing can be granted at all.
func (r *identityRun) find(a *idAssign) (missing []string, why string) {
	svc := identityServices[a.role.service]
	var in []snapshot.Object
	for _, s := range r.o.src {
		k := strings.ToLower(s.Kind())
		for _, want := range svc.kinds {
			if k == want && a.scope.covers(s) {
				in = append(in, s)
			}
		}
	}
	sort.Slice(in, func(i, j int) bool { return source(in[i]) < source(in[j]) })
	if len(in) == 0 {
		return nil, fmt.Sprintf("%s on %s: nothing of %s in that scope is in the snapshot, so there is nothing to grant it on", a.role.name, a.scope, a.role.service)
	}
	for _, s := range in {
		if no := r.honoured(a.role, s); no != "" {
			missing = append(missing, no)
			continue
		}
		found := r.w.slots(strings.ToLower(s.Kind()), r.written[strings.ToLower(source(s))])
		if len(found) == 0 {
			missing = append(missing, fmt.Sprintf("%s is not translated (%s): no access to it is written", source(s), r.stateOf(s.Kind(), s.Namespace(), s.Name())))
			continue
		}
		for _, f := range found {
			f.from = source(s)
			a.found = append(a.found, f)
		}
	}
	if len(a.found) == 0 {
		return nil, fmt.Sprintf("%s on %s: nothing in that scope has a place on the target: %s", a.role.name, a.scope, strings.Join(missing, "; "))
	}
	return missing, ""
}

// honoured says why Azure itself did not honour the role on an object:
// then it granted nothing there, and nothing is written.
func (r *identityRun) honoured(role identityRole, s snapshot.Object) string {
	switch role.service {
	case identityKV:
		// "Only works for key vaults that use the 'Azure role-based
		// access control' permission model" (each Key Vault data role's
		// description).
		vault, _, _ := strings.Cut(s.Name(), "/")
		v, ok := r.by[azVault+" "+strings.ToLower(s.Namespace()+"/"+vault)]
		rbac, set := obj(spec(v)["properties"])["enableRbacAuthorization"].(bool)
		switch {
		case !ok:
			return fmt.Sprintf("%s: its vault is not in the snapshot, so whether it authorizes with Azure RBAC is not known: no access to it is written", source(s))
		case !set:
			return fmt.Sprintf("%s: its vault does not say whether it authorizes with Azure RBAC (properties.enableRbacAuthorization); under access policies this role gave nothing: no access to it is written", source(s))
		case !rbac:
			return fmt.Sprintf("%s: its vault authorizes with access policies, where this role gave nothing: no access to it is written", source(s))
		}
	case identityACR:
		// In a registry with repository permissions the legacy roles are
		// not data-plane roles
		// (https://learn.microsoft.com/en-us/azure/container-registry/container-registry-rbac-built-in-roles-directory-reference).
		if mode := fmt.Sprint(obj(spec(s)["properties"])["roleAssignmentMode"]); strings.EqualFold(mode, "AbacRepositoryPermissions") {
			return fmt.Sprintf("%s authorizes by repository (roleAssignmentMode AbacRepositoryPermissions), where %s gave no access to images: no access to it is written", source(s), role.name)
		}
	}
	return ""
}

func identityRoleNames() string {
	var ns []string
	for _, r := range identityRoles {
		ns = append(ns, r.name)
	}
	sort.Strings(ns)
	return strings.Join(ns, ", ")
}

func identityLossText(ls []Loss) string {
	var out []string
	for _, l := range ls {
		out = append(out, l.Why)
	}
	if len(out) == 0 {
		return "no rule grants it there"
	}
	return strings.Join(out, "; ")
}

func identityFoundText(fs []idFound) string {
	var ns []string
	for _, f := range fs {
		ns = append(ns, f.obj.Kind()+" "+f.obj.Name())
	}
	return strings.Join(uniqueSorted(ns), ", ")
}

// identityGrantText says what an assignment became.
func identityGrantText(a *idAssign) string {
	return a.role.name + " on " + a.scope.String() + ": " + identityItemsText(a.items)
}

// identityItemsText lists grants as "what on which object".
func identityItemsText(items []idItem) string {
	by := map[string][]string{}
	for _, it := range items {
		what := it.role
		if what == "" {
			what = strings.Join(it.actions, ", ")
		}
		on := "every resource (the action takes no resource)"
		if it.obj.Body != nil {
			on = it.obj.Kind() + " " + it.obj.Name()
		}
		by[what] = append(by[what], on)
	}
	var out []string
	for _, what := range sortedMapKeys(by) {
		out = append(out, what+" on "+strings.Join(uniqueSorted(by[what]), ", "))
	}
	return strings.Join(out, "; ")
}

// identityAllItems are an identity's grants, each once.
func identityAllItems(id *idIdent) []idItem {
	var out []idItem
	seen := map[string]bool{}
	for _, a := range id.assigns {
		for _, it := range a.items {
			k := it.sid + "\x00" + it.role + "\x00" + strings.Join(it.actions, ",") + "\x00" + fmt.Sprint(it.resource) + "\x00" + it.obj.Key()
			if !seen[k] {
				seen[k] = true
				out = append(out, it)
			}
		}
	}
	return out
}

// identityTrustText lists who may act as an identity.
func identityTrustText(id *idIdent) string {
	var ns []string
	for _, c := range id.creds {
		ns = append(ns, fmt.Sprintf("system:serviceaccount:%s:%s of cluster %s", c.ns, c.sa, c.cluster.short))
	}
	return strings.Join(uniqueSorted(ns), ", ")
}

// identityMay is the report's line for an identity: who may use it, and
// exactly what it may do.
func identityMay(what string, id *idIdent) string {
	may := identityItemsText(identityAllItems(id))
	if may == "" {
		may = "nothing: none of its role assignments is translated"
	}
	return fmt.Sprintf("%s. Used by: %s. It may: %s", what, identityTrustText(id), may)
}
