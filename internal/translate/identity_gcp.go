package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/snapshot"
)

// Workload identity on GCP: an IAM service account per managed identity,
// used through Workload Identity Federation for GKE.
//
// The Kubernetes service accounts a federated credential names may act as
// the service account: roles/iam.workloadIdentityUser on it, for the member
// serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/KSA], and the
// iam.gke.io/gcp-service-account annotation on the Kubernetes service
// account, which the manifests carry ("Both the IAM allow policy and the
// annotation are required when you use this method",
// https://docs.cloud.google.com/kubernetes-engine/docs/how-to/workload-identity).
// Google's other form grants roles to the Kubernetes service account's own
// principal, with no service account between; this one is written because a
// managed identity is one thing with several users, as the service account
// is, and the annotation is the counterpart of the client ID a pod named on
// AKS.
//
// What the service account may do is a binding on each object: a topic, a
// subscription, a bucket, a secret, a repository. Never on the project.
// Each role is a predefined one whose permissions were read on
// docs.cloud.google.com/iam/docs/roles-permissions (2026-11-20) and do not
// go beyond the Azure role's; where the narrowest predefined role that
// would do still goes beyond it, it is not granted, and the loss says so.
//
// A binding is an object of gcp.BindingKind: the restore adds it to the
// object's allow policy and removes nothing (internal/gcp/iam.go).

const (
	gcpServiceAccount = "iam.googleapis.com/ServiceAccount"
	gcpPoolSuffix     = "{{truthform|project}}.svc.id.goog"
	gcpEmailSuffix    = "@{{truthform|project}}.iam.gserviceaccount.com"

	// roles/iam.workloadIdentityUser: iam.serviceAccounts.get,
	// getAccessToken, getOpenIdToken, list. "Impersonate service accounts
	// from federated workloads."
	gcpRoleWorkload = "roles/iam.workloadIdentityUser"
	// roles/pubsub.publisher: pubsub.topics.publish.
	gcpRolePublisher = "roles/pubsub.publisher"
	// roles/pubsub.subscriber: pubsub.snapshots.seek,
	// pubsub.subscriptions.consume, pubsub.topics.attachSubscription. On a
	// subscription it is consuming it; the other two are a snapshot's and
	// a topic's.
	gcpRoleSubscriber = "roles/pubsub.subscriber"
	// roles/storage.objectViewer: storage.objects.get and list, and the
	// same on folders and managed folders.
	gcpRoleObjectViewer = "roles/storage.objectViewer"
	// roles/storage.objectCreator: storage.objects.create, multipart
	// uploads. "Does not give permission to view, delete, or overwrite
	// objects."
	gcpRoleObjectCreator = "roles/storage.objectCreator"
	// roles/storage.objectUser: storage.objects.create, delete, get, list,
	// move, restore, update, multipart uploads, folders. storage.objects.delete
	// deletes a noncurrent version for good too.
	gcpRoleObjectUser = "roles/storage.objectUser"
	// roles/secretmanager.secretAccessor: secretmanager.versions.access.
	gcpRoleSecretAccessor = "roles/secretmanager.secretAccessor"
	// roles/secretmanager.secretVersionAdder: secretmanager.versions.add,
	// secretmanager.secrets.rotate.
	gcpRoleSecretAdder = "roles/secretmanager.secretVersionAdder"
	// roles/secretmanager.viewer: secretmanager.secrets.get, getIamPolicy,
	// list; versions.get, list. No versions.access.
	gcpRoleSecretViewer = "roles/secretmanager.viewer"
	// roles/artifactregistry.reader: repositories.downloadArtifacts, get,
	// list; the read of images, files, tags and versions.
	gcpRoleRepoReader = "roles/artifactregistry.reader"
)

var gcpAccountID = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])$`)

type identityGCP struct {
	m Map
	// pools are the clusters already given the workload identity pool.
	pools map[string]bool
	// all are the translated clusters, by group/name.
	all map[string]*idCluster
}

func (*identityGCP) platform() string    { return "gcp" }
func (*identityGCP) clusterKind() string { return gkeCluster }

func (*identityGCP) slots(kind string, objs []snapshot.Object) []idFound {
	var out []idFound
	// A queue's or subscription's own subscription is the one that
	// dead-letters; the one that does not keeps its dead letters. A
	// queue's topic is the one its own subscription reads.
	mainTopic := ""
	for _, t := range objs {
		s, _ := t.Body["spec"].(map[string]any)
		if _, main := s["deadLetterPolicy"]; t.Kind() == psSub && main {
			mainTopic, _ = s["topic"].(string)
		}
	}
	for _, t := range objs {
		s, _ := t.Body["spec"].(map[string]any)
		slot := ""
		switch {
		case t.Kind() == psSub && (kind == sbQueue || kind == sbSubscription):
			slot = slotDLSub
			if _, main := s["deadLetterPolicy"]; main {
				slot = slotSub
			}
		case t.Kind() == psTopic && kind == sbQueue && t.Name() == mainTopic:
			slot = slotTopic
		case t.Kind() == psTopic && kind == sbTopic:
			slot = slotTopic
		case t.Kind() == gcsBucket && kind == azContainer:
			slot = slotBucket
		case t.Kind() == gcpSecret && kind == azVaultSecret:
			slot = slotSecret
		case t.Kind() == gcpRepo && kind == azRegistry:
			slot = slotRegistry
		}
		if slot != "" {
			out = append(out, idFound{slot: slot, obj: t})
		}
	}
	return out
}

// plan is the table: for each object in scope, the predefined roles that
// give the role's capabilities there and no more.
func (d *identityGCP) plan(a *idAssign) {
	has := func(c string) bool { return identityHas(a.role, c) }
	lose := func(why string) {
		a.losses = append(a.losses, Loss{Field: "properties.roleDefinitionId", Why: a.role.name + ": " + why})
	}
	grant := func(f idFound, cap, role string) {
		a.items = append(a.items, idItem{cap: cap, role: role, obj: f.obj})
	}
	notes := map[string]bool{}
	for _, f := range a.found {
		switch f.slot {
		case slotTopic:
			if has(capSend) {
				grant(f, capSend, gcpRolePublisher)
			}
		case slotSub, slotDLSub:
			// A Service Bus dead-letter queue is a sub-queue of its
			// entity, inside the assignment's scope: a receiver of the
			// queue could read it, and may here.
			if has(capReceive) {
				grant(f, capReceive, gcpRoleSubscriber)
				notes["a receiver could dead-letter a message itself; on Pub/Sub a message reaches the dead-letter topic only by being delivered too often, and publishing to that topic is not granted"] = true
			}
		case slotBucket:
			s, _ := f.obj.Body["spec"].(map[string]any)
			versioned := truthy(obj(s["versioning"])["enabled"])
			switch {
			case has(capBlobWrite) && has(capBlobDelete) && (has(capBlobPurge) || !versioned):
				grant(f, capBlobWrite, gcpRoleObjectUser)
			case has(capBlobWrite) && has(capBlobDelete):
				// The bucket keeps versions, and the only predefined
				// role that overwrites and deletes also deletes a
				// version for good, which this role could not.
				grant(f, capBlobRead, gcpRoleObjectViewer)
				grant(f, capBlobWrite, gcpRoleObjectCreator)
				notes["on bucket "+f.obj.Name()+", which keeps versions, it may read and create objects but not overwrite or delete them: the narrowest predefined role that does (roles/storage.objectUser) also deletes a version for good (storage.objects.delete), which this role could not on Azure. Grant that role by hand once that is accepted, or a custom role without it"] = true
			case has(capBlobRead):
				grant(f, capBlobRead, gcpRoleObjectViewer)
			}
		case slotSecret:
			if has(capSecretRead) {
				grant(f, capSecretRead, gcpRoleSecretAccessor)
			}
			if has(capSecretWrite) {
				grant(f, capSecretWrite, gcpRoleSecretAdder)
			}
			switch {
			case has(capSecretMeta) && has(capSecretAuthz):
				grant(f, capSecretMeta, gcpRoleSecretViewer)
			case has(capSecretMeta):
				notes["reading a secret's properties is not granted: the narrowest predefined role with it (roles/secretmanager.viewer) also reads who may read the secret (secretmanager.secrets.getIamPolicy), which this role could not"] = true
			}
		case slotRegistry:
			if has(capPull) {
				grant(f, capPull, gcpRoleRepoReader)
			}
			if has(capPush) {
				notes["pushing is not granted: the narrowest predefined role that pushes (roles/artifactregistry.writer) also deletes what is attached to an image (artifactregistry.attachments.delete), and AcrPush deleted nothing. Grant that role by hand once that is accepted, or a custom role without it"] = true
			}
		}
	}
	for _, n := range sortedMapKeys(notes) {
		lose(n)
	}
}

func (d *identityGCP) nameOf(id *idIdent) (string, string) {
	name := d.m.name(id.group+"/"+id.name, strings.ToLower(id.name))
	// "must be 6-30 characters long, and match the regular expression
	// [a-z]([-a-z0-9]*[a-z0-9])"
	// (https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/create).
	if !gcpAccountID.MatchString(name) || len(name) < 6 || len(name) > 30 {
		return "", fmt.Sprintf("%q is not an ID a service account takes (6 to 30 of lowercase letters, digits and dashes, a letter first): give it one in the map's names (%s/%s)", name, id.group, id.name)
	}
	return name, ""
}

func gcpSAName(id string) string { return gcpProject + "/serviceAccounts/" + id + gcpEmailSuffix }

// gcpBinding is a grant on an object's allow policy: the object it is on
// says which API's policy calls to use.
//
// It is named by its object, its role and a short word for its member
// (who), which together are one grant: a snapshot keeps an object in a
// file of its name, and a member's whole string would make it too long.
func gcpBinding(on snapshot.Object, role, member, who string, after ...string) snapshot.Object {
	ann, _ := on.Body["metadata"].(map[string]any)["annotations"].(map[string]any)
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": gcp.BindingKind,
		"metadata": map[string]any{"name": on.Name() + "#" + strings.TrimPrefix(role, "roles/") + "#" + who, "annotations": map[string]any{
			"truthform.org/discovery":  ann["truthform.org/discovery"],
			"truthform.org/schema":     "Policy",
			"truthform.org/collection": ann["truthform.org/collection"],
			"truthform.org/parent":     on.Name(),
			"truthform.org/after":      strings.Join(after, ","),
		}}, "spec": map[string]any{"bindings": []any{map[string]any{"role": role, "members": []any{member}}}}}}
}

func (d *identityGCP) write(id *idIdent, name string, o *out) (Entry, map[string][]string) {
	e := Entry{Source: id.src, State: Mapped}
	targets := map[string][]string{}
	rel := gcpSAName(name)
	email := name + gcpEmailSuffix
	display := id.name
	if len(display) > 100 {
		display = display[:100]
	}
	sa := snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": gcpServiceAccount,
		"metadata": map[string]any{"name": rel, "annotations": map[string]any{
			"truthform.org/discovery":  "iam/v1",
			"truthform.org/schema":     "ServiceAccount",
			"truthform.org/collection": "projects.serviceAccounts",
			"truthform.org/parent":     gcpProject,
		}}, "spec": map[string]any{"name": rel, "displayName": display, "description": "From Azure managed identity " + id.group + "/" + id.name}}}
	saT := o.add("gcp", id.src, sa)
	e.Targets = append(e.Targets, saT)
	if len(id.tags) > 0 {
		e.Losses = append(e.Losses, Loss{Field: "tags", Why: fmt.Sprintf("%d tag(s): a service account takes no labels", len(id.tags))})
	}
	seen := map[string]string{}
	cs := append([]*idCred(nil), id.creds...)
	sort.Slice(cs, func(i, j int) bool { return cs[i].src < cs[j].src })
	for _, c := range cs {
		d.pool(c.cluster, o)
		member := "serviceAccount:" + gcpPoolSuffix + "[" + c.ns + "/" + c.sa + "]"
		if prev, dup := seen[member]; dup {
			targets[c.src] = []string{prev}
		} else {
			// The pool is made by the cluster, so the cluster comes first.
			t := o.add("gcp", c.src, gcpBinding(sa, gcpRoleWorkload, member, c.ns+"."+c.sa, c.cluster.target))
			seen[member] = t
			targets[c.src] = []string{t}
		}
		// "IAM doesn't distinguish between the clusters making the
		// calls": every cluster of the project shares one pool
		// (https://docs.cloud.google.com/kubernetes-engine/docs/concepts/workload-identity).
		var others []string
		for _, key := range sortedMapKeys(d.all) {
			if other := d.all[key]; other != c.cluster && !identityFederated(id, other, c.ns, c.sa) {
				others = append(others, other.short)
			}
		}
		if len(others) > 0 {
			c.losses = append(c.losses, Loss{Field: "properties.issuer", Widens: true,
				Why: fmt.Sprintf("on Azure only cluster %s's service account %s/%s was trusted; a GKE cluster's workload identity pool is its project's, so the service account of that name in every other cluster of the project is the same principal: in %s too, which this credential did not name. Put the clusters in separate projects, or keep that namespace and name out of the others", c.cluster.short, c.ns, c.sa, strings.Join(others, ", "))})
		}
		o.require(fmt.Sprintf("Kubernetes manifests (Git): service account %s in namespace %s of cluster %s carries the annotation iam.gke.io/gcp-service-account: %s@<project>.iam.gserviceaccount.com, in place of azure.workload.identity/client-id; remove the azure.workload.identity/use labels", c.sa, c.ns, c.cluster.short, name))
	}
	bound := map[string]string{}
	for _, a := range id.assigns {
		ts := []string{saT}
		for _, it := range a.items {
			k := it.obj.Key() + "\x00" + it.role
			if bound[k] == "" {
				bound[k] = o.add("gcp", a.src, gcpBinding(it.obj, it.role, "serviceAccount:"+email, name, rel))
				e.Targets = append(e.Targets, bound[k])
			}
			ts = append(ts, bound[k])
		}
		targets[a.src] = uniqueSorted(ts)
	}
	e.Reason = identityMay("service account "+name, id)
	o.require("A GKE cluster's workload identity pool is its project's (<project>.svc.id.goog): a service account of the same namespace and name in any other cluster of the target project, now or later, is the same principal and gets the same access. Keep clusters that must not share identities in separate projects")
	o.require("Apps that reached Azure through a managed identity use Google's client libraries with Application Default Credentials. A pod on the host network (hostNetwork: true) does not get its service account's identity on GKE: it acts as the node's service account")
	o.require("The IAM Service Account Credentials API (iamcredentials.googleapis.com) is enabled in the target project: a workload acts as its service account through it")
	return e, targets
}

// identityFederated reports whether an identity has a credential for the
// service account in a cluster.
func identityFederated(id *idIdent, c *idCluster, ns, sa string) bool {
	for _, x := range id.creds {
		if x.cluster == c && x.ns == ns && x.sa == sa {
			return true
		}
	}
	return false
}

// pool gives a cluster the project's workload identity pool, and its node
// pools the GKE metadata server, without which a pod reaches the node's
// own service account ("GKE_METADATA: Run the GKE Metadata Server on this
// node ... can only be enabled if Workload Identity is enabled at the
// cluster level"). AKS's workload identity needed neither a setting of the
// cluster's network nor one per pool, so nothing in the cluster's own
// translation says this: it is set here, on the cluster it wrote.
func (d *identityGCP) pool(c *idCluster, o *out) {
	if d.pools[c.key] {
		return
	}
	d.pools[c.key] = true
	c.spec["workloadIdentityConfig"] = map[string]any{"workloadPool": gcpPoolSuffix}
	for _, p := range list(c.spec["nodePools"]) {
		conf := obj(obj(p)["config"])
		if conf == nil {
			conf = map[string]any{}
			obj(p)["config"] = conf
		}
		conf["workloadMetadataConfig"] = map[string]any{"mode": "GKE_METADATA"}
	}
	if doc, err := o.tg.GCP.DocFor("container", "v1"); err != nil {
		if o.err == nil {
			o.err = err
		}
	} else if err := doc.CheckSpec("Cluster", c.spec); err != nil && o.err == nil {
		o.err = fmt.Errorf("%s: %w", c.src, err)
	}
	o.require(fmt.Sprintf("GKE cluster %s is given the project's workload identity pool and its node pools the GKE metadata server (workloadMetadataConfig GKE_METADATA), for workload identity: a pod no longer reaches its node's service account through the metadata server, and a pod that relied on the node's identity needs a service account of its own", c.short))
}

func (d *identityGCP) nodes(c *idCluster, o *out) string {
	return "the service account the map names for its node pools (clusters." + c.key + ".serviceAccount, or a pool's own)"
}

func (d *identityGCP) pullRequirement(c *idCluster, reg idFound, o *out) string {
	repo := reg.obj.Name()
	id := repo[strings.LastIndex(repo, "/")+1:]
	why := fmt.Sprintf("nothing is granted to the nodes' service account, which is the map's (clusters.%s): until it may read repository %s, the cluster's pods cannot start from images there", c.key, id)
	// "Even with Workload Identity Federation for GKE configured on a
	// cluster, GKE still uses the configured IAM service account for the
	// node pool to pull container images".
	o.require(fmt.Sprintf("GKE cluster %s's nodes pulled their images with the kubelet identity's AcrPull: grant each node pool's service account roles/artifactregistry.reader on the repository: gcloud artifacts repositories add-iam-policy-binding %s --location=%s --member=serviceAccount:<node service account> --role=roles/artifactregistry.reader", c.short, id, d.m.Region))
	return why
}
