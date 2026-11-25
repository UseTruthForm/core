package translate

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/usetruthform/core/internal/snapshot"
)

// Azure container registries, read into a model the AWS and GCP writers
// share.
//
// A registry holds image repositories, and ARM has no object for one: they
// come into being when an image is pushed. So a registry becomes what
// makes repositories as images arrive. On AWS there is no registry object
// either (the account has one per region): a repository creation template
// for the registry's prefix makes each repository on its first push, with
// the settings the registry had. On GCP it is one Artifact Registry
// repository of Docker images, in the map's region.
//
// Images are never copied: the requirement says so. Who may push and
// pull (the admin user, tokens and scope maps, role assignments) is
// identity, which is not translated (#32).

const (
	azRegistry    = "microsoft.containerregistry/registries"
	azReplication = azRegistry + "/replications"
	awsRepoTmpl   = "AWS::ECR::RepositoryCreationTemplate"
	gcpRepo       = "artifactregistry.googleapis.com/Repository"
)

var (
	// What ECR takes as a template's prefix, without its ROOT and a
	// trailing slash.
	ecrPrefix = regexp.MustCompile(`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*$`)
	arRepoID  = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

type registry struct{}

func (registry) claims(kind string) bool {
	return kind == azRegistry || strings.HasPrefix(kind, azRegistry+"/")
}

type acr struct {
	src, group, name string
	key              string
	tags             map[string]string
	losses           []Loss
	private          string   // why its endpoint answered only some networks, or ""
	ranges           []string // the public address ranges its firewall allowed
	cmk              bool     // encrypted with the customer's own key
	anonymous        bool     // anyone could pull without signing in
	admin            bool     // the admin user was on
	quarantine       bool
}

// registryRefusals are the registry's children with no place on either
// target, and why.
var registryRefusals = map[string]string{
	azRegistry + "/scopemaps":           "identity is not translated (#32): a scope map says what a repository-scoped token may do; who used one signs in with IAM on the target",
	azRegistry + "/tokens":              "identity is not translated (#32): a token is a credential for some of the registry's repositories; who used one signs in with IAM on the target",
	azRegistry + "/credentialsets":      "identity is not translated (#32): a credential set holds the sign-in to an upstream registry a cache rule pulls from",
	azRegistry + "/connectedregistries": "a connected registry is a registry on premises or at the edge that syncs with this one; neither target has one",
	azRegistry + "/tasks":               "ACR Tasks build and run images in Azure; neither target's registry does: move the builds into the pipeline that pushes images (CodeBuild, Cloud Build)",
	azRegistry + "/taskruns":            "ACR Tasks build and run images in Azure; neither target's registry does: move the builds into the pipeline that pushes images (CodeBuild, Cloud Build)",
	azRegistry + "/runs":                "ACR Tasks build and run images in Azure; neither target's registry does: move the builds into the pipeline that pushes images (CodeBuild, Cloud Build)",
	azRegistry + "/agentpools":          "an agent pool runs ACR Tasks, which neither target's registry has",
	azRegistry + "/exportpipelines":     "a transfer pipeline copies images between registries through a storage account; neither target has one",
	azRegistry + "/importpipelines":     "a transfer pipeline copies images between registries through a storage account; neither target has one",
	azRegistry + "/pipelineruns":        "a transfer pipeline copies images between registries through a storage account; neither target has one",
}

// registryNotLooked are children not translated yet, and why.
var registryNotLooked = map[string]string{
	azRegistry + "/webhooks":                   "webhooks are not translated yet: ECR sends push events to EventBridge, Artifact Registry to Pub/Sub",
	azRegistry + "/cacherules":                 "pull-through cache rules are not translated yet (ECR pull-through cache rules, Artifact Registry remote repositories)",
	azRegistry + "/privateendpointconnections": "made when its private endpoint is created; private endpoints are not translated yet",
	azRegistry + "/privatelinkresources":       "the registry's private link sub-resources; private endpoints are not translated yet",
}

func (registry) translate(objs []snapshot.Object, o *out) {
	regs := map[string]*acr{}
	var replObjs []snapshot.Object
	for _, obj := range objs {
		k := strings.ToLower(obj.Kind())
		switch {
		case k == azRegistry:
			r := readRegistry(obj)
			regs[r.key] = r
		case k == azReplication:
			replObjs = append(replObjs, obj)
		case registryRefusals[k] != "":
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: registryRefusals[k]})
		case registryNotLooked[k] != "":
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: registryNotLooked[k]})
		default:
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
		}
	}
	for _, obj := range replObjs {
		parent, name, _ := strings.Cut(obj.Name(), "/")
		r := regs[strings.ToLower(obj.Namespace()+"/"+parent)]
		if r == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its registry is not in the snapshot"})
			continue
		}
		r.losses = append(r.losses, prefixed(readReplication(obj), "replications/"+name+": ")...)
		o.entries = append(o.entries, Entry{Source: source(obj), State: Mapped, Reason: "read with its registry " + r.src})
	}
	for _, r := range sortedRegs(regs) {
		switch {
		case o.m.Destinations.Registry == "":
			o.entries = append(o.entries, Entry{Source: r.src, State: Refused, Reason: "the map chooses no destination for container registries (destinations.registry)"})
		case o.m.To == "aws":
			ecrRegistry(r, o)
		default:
			arRegistry(r, o)
		}
	}
}

func sortedRegs(m map[string]*acr) []*acr {
	out := make([]*acr, 0, len(m))
	for _, k := range sortedKeys(m) {
		out = append(out, m[k])
	}
	return out
}

func readRegistry(o snapshot.Object) *acr {
	r := &acr{src: source(o), group: o.Namespace(), name: o.Name(), key: strings.ToLower(o.Namespace() + "/" + o.Name())}
	top := newProps(spec(o), "")
	// The registry's region: the target's is the map's.
	top.quiet("location", "name", "properties")
	r.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	sku := newProps(obj(top.m["sku"]), "sku.")
	sku.quiet("tier")
	if n := sku.str("name"); n != "" {
		sku.lose("name", n+": a service tier (included storage, throughput, which features) has no equivalent: the target bills by use", false)
	}
	top.quiet("sku")
	if t, _ := obj(top.m["identity"])["type"].(string); t != "" && !strings.EqualFold(t, "None") {
		top.lose("identity", t+": identity is not translated (#32); the registry used it to reach its customer-managed key and its tasks' sources", false)
	}
	top.quiet("identity")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("loginServer", "creationDate", "provisioningState", "status", "dataEndpointHostNames", "privateEndpointConnections")
	if p.boolean("adminUserEnabled") {
		r.admin = true
		p.lose("adminUserEnabled", "the admin user is a shared user name and password; neither target has one, and identity is not translated (#32): it is not carried over", false)
	}
	public := p.str("publicNetworkAccess")
	nrs := newProps(obj(p.m["networkRuleSet"]), "properties.networkRuleSet.")
	deny := strings.EqualFold(nrs.str("defaultAction"), "Deny")
	ips := len(list(nrs.m["ipRules"]))
	nrs.quiet("ipRules")
	// Which Azure services may pass the firewall means nothing once it is
	// gone; it goes with the loss below.
	p.quiet("networkRuleSet", "networkRuleBypassOptions", "networkRuleBypassAllowedForTasks")
	switch {
	case strings.EqualFold(public, "Disabled"):
		r.private = "its public network access is disabled: it answered private endpoints only"
	case deny:
		r.private = fmt.Sprintf("its firewall denies by default, allowing %d address range(s)", ips)
		var bad []string
		r.ranges, bad = lockRanges(list(nrs.m["ipRules"]), "value")
		for _, b := range bad {
			nrs.lose("ipRules", b+" is not an address or range this reads; it is not allowed", false)
		}
	}
	pol := newProps(obj(p.m["policies"]), "properties.policies.")
	var sub []Loss
	policy := func(k string) (*props, string) {
		q := newProps(obj(pol.m[k]), "properties.policies."+k+".")
		pol.quiet(k)
		return q, strings.ToLower(q.str("status"))
	}
	q, st := policy("quarantinePolicy")
	r.quarantine = st == "enabled"
	sub = append(sub, q.rest()...)
	q, st = policy("trustPolicy")
	q.quiet("type")
	if st == "enabled" {
		q.lose("status", "content trust (Docker Content Trust, Notary v1): its signatures are not on the target, so a client that requires them cannot pull until the images are signed again (Notation, Sigstore)", false)
	}
	sub = append(sub, q.rest()...)
	q, st = policy("retentionPolicy")
	days := q.integer("days")
	q.quiet("lastUpdatedTime")
	if st == "enabled" {
		d := "a set number of days"
		if days != nil {
			d = fmt.Sprintf("%d days", *days)
		}
		q.lose("status", "untagged manifests were deleted "+d+" after they lost their tag; on the target they are kept (an ECR lifecycle policy or Artifact Registry cleanup policy counts from the push, which would delete sooner, so none is written)", false)
	}
	sub = append(sub, q.rest()...)
	q, st = policy("exportPolicy")
	if st == "disabled" {
		q.lose("status", "export was disabled: Azure would not copy its images to another registry (import, transfer pipelines); a pull still could, on the source as on the target, so who may pull decides who can copy", false)
	}
	sub = append(sub, q.rest()...)
	q, st = policy("azureADAuthenticationAsArmPolicy")
	if st == "disabled" {
		q.lose("status", "disabled: tokens for Azure Resource Manager's audience were refused; identity is not translated (#32)", false)
	}
	sub = append(sub, q.rest()...)
	sub = append(sub, pol.rest()...)
	p.quiet("policies")
	enc := newProps(obj(p.m["encryption"]), "properties.encryption.")
	kv := newProps(obj(enc.m["keyVaultProperties"]), "properties.encryption.keyVaultProperties.")
	kv.quiet("versionedKeyIdentifier", "keyRotationEnabled", "lastKeyRotationTimestamp", "identity")
	key := kv.str("keyIdentifier")
	r.cmk = strings.EqualFold(enc.str("status"), "enabled") || key != ""
	enc.quiet("keyVaultProperties")
	p.quiet("encryption")
	if p.boolean("dataEndpointEnabled") {
		p.lose("dataEndpointEnabled", "dedicated data endpoints, for firewalls that name them, have no equivalent: the target serves layers from its own storage endpoints", false)
	}
	p.unlessDefault("zoneRedundancy", "Disabled", "there is no setting: the target keeps images across its region's zones itself")
	r.anonymous = p.boolean("anonymousPullEnabled")
	p.unlessDefault("roleAssignmentMode", "LegacyRegistryPermissions", "role assignments scoped to repositories (ABAC) are identity, which is not translated (#32)")
	r.losses = append(append(append(append(append(top.rest(), sku.rest()...), p.rest()...), nrs.rest()...), sub...), append(enc.rest(), kv.rest()...)...)
	return r
}

// readReplication reads a geo-replica as a loss of its registry: the
// target keeps images in the map's region only.
func readReplication(o snapshot.Object) []Loss {
	top := newProps(spec(o), "")
	top.quiet("name", "id", "type", "properties", "tags")
	loc := top.str("location")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("provisioningState", "status", "regionEndpointEnabled", "zoneRedundancy")
	return append(append([]Loss{{Field: "location", Why: "its images were also kept and served in " + loc + "; the target keeps them in the map's region only (ECR replication, an Artifact Registry multi-region location: not translated yet)"}},
		top.rest()...), p.rest()...)
}

func (r *acr) imageRequirement(o *out, to string) {
	o.require(fmt.Sprintf("Images are not copied: copy each from %s.azurecr.io to %s (crane copy, skopeo copy) before a restore of what pulls them. The Kubernetes image references are not rewritten: the translation's Kubernetes change list names each one and what it becomes, for the repository's owner to change", strings.ToLower(r.name), to))
	if r.admin {
		o.require(fmt.Sprintf("Registry %s/%s had its admin user on: whoever pushed or pulled with that user name and password signs in with IAM on the target", r.group, r.name))
	}
	if r.anonymous {
		o.require(fmt.Sprintf("Registry %s/%s let anyone pull without signing in; the target does not: such clients sign in, or the images are published on purpose", r.group, r.name))
	}
}

// Registries on AWS: a repository creation template per registry, which
// makes each repository under the registry's prefix on its first push.
func ecrRegistry(r *acr, o *out) {
	key := r.group + "/" + r.name
	prefix := o.m.name(key, strings.ToLower(r.name))
	if !ecrPrefix.MatchString(prefix) {
		o.entries = append(o.entries, Entry{Source: r.src, State: Refused, Reason: fmt.Sprintf("%q is not a prefix ECR takes: give it one in the map's names (%s)", prefix, key)})
		return
	}
	e := Entry{Source: r.src, State: Mapped, Losses: append([]Loss(nil), r.losses...),
		Reason: "ECR has one registry per account and region: a repository creation template makes each repository under " + prefix + "/ on its first push, with these settings"}
	// A private registry's repositories take a policy that denies pulls
	// and pushes from anywhere but its private path. The template gives it
	// to each repository it makes; the layers themselves come from S3 by a
	// URL ecr:GetDownloadUrlForLayer hands out, which the deny covers.
	var lock *awsLock
	if r.private != "" {
		if lock = lockAWS(o, azRegistry, r.group, r.name, []string{"ecr.api", "ecr.dkr"}, r.ranges); lock == nil {
			e.Losses = append(e.Losses, Loss{Field: "properties.networkRuleSet", Widens: true,
				Why: r.private + "; " + lockNoPath + ". ECR answers on its public endpoint, guarded by IAM alone"})
		} else {
			e.Reason += "; they answer pulls and pushes only " + lock.where()
			lockRequireAWS(o, "Registry "+key+"'s repositories under "+prefix+"/ answer pulls and pushes", lock)
			o.require("A repository under " + prefix + "/ made any other way than by its first push (ecr:CreateRepository by hand, replication) does not get the template's policy: give it the same one")
		}
	}
	if r.cmk {
		e.Losses = append(e.Losses, Loss{Field: "properties.encryption", Widens: true,
			Why: "its images were encrypted with the customer's own key; the repositories use ECR's AES-256 encryption until a KMS key is named, which needs a role ECR assumes (identity, not translated: #32)"})
	}
	if r.quarantine {
		e.Losses = append(e.Losses, Loss{Field: "properties.policies.quarantinePolicy.status", Widens: true,
			Why: "a pushed image could not be pulled until a scanner released it; ECR lets every image be pulled as soon as it is pushed"})
	}
	if r.anonymous {
		e.Losses = append(e.Losses, Loss{Field: "properties.anonymousPullEnabled",
			Why: "anyone could pull without signing in; the repositories are private, so such a pull fails until it signs in (ECR Public is not translated)"})
	}
	if len(r.tags) > 0 {
		e.Losses = append(e.Losses, Loss{Field: "tags", Why: fmt.Sprintf("%d tag(s): ECR has no registry object to hold them, and tagging the repositories a template makes needs a role ECR assumes (CustomRoleArn): identity is not translated (#32)", len(r.tags))})
	}
	tmpl := map[string]any{
		"Prefix":                  prefix,
		"AppliedFor":              []any{"CREATE_ON_PUSH"},
		"Description":             "From Azure Container Registry " + key,
		"ImageTagMutability":      "MUTABLE",
		"EncryptionConfiguration": map[string]any{"EncryptionType": "AES256"},
	}
	if lock != nil {
		// A repository policy names no resource: it is the repository's.
		tmpl["RepositoryPolicy"] = awsPolicyJSON(awsPolicyDoc(lock.statement(lockECR, nil, false)))
	}
	e.Targets = append(e.Targets, o.add("aws", r.src, awsObject(awsRepoTmpl, prefix, tmpl)))
	o.entries = append(o.entries, e)
	r.imageRequirement(o, fmt.Sprintf("<account>.dkr.ecr.%s.amazonaws.com/%s/<repository>", o.m.Region, prefix))
	o.require("A repository is made on push only for a principal allowed ecr:CreateRepository as well as to push: grant the pipelines that push images both (identity, not translated: #32)")
}

// Registries on GCP: an Artifact Registry repository of Docker images per
// registry, in the map's region.
func arRegistry(r *acr, o *out) {
	key := r.group + "/" + r.name
	if o.m.Region == "" {
		o.entries = append(o.entries, Entry{Source: r.src, State: Refused, Reason: "the map names no region (region): an Artifact Registry repository is in one"})
		return
	}
	id := o.m.name(key, strings.ToLower(r.name))
	if !arRepoID.MatchString(id) {
		o.entries = append(o.entries, Entry{Source: r.src, State: Refused, Reason: fmt.Sprintf("%q is not a repository ID Artifact Registry takes (a lowercase letter first, then lowercase letters, digits and dashes): give it one in the map's names (%s)", id, key)})
		return
	}
	e := Entry{Source: r.src, State: Mapped, Losses: append([]Loss(nil), r.losses...)}
	o.gcpClosedBy(gcpService{src: r.src, field: "properties.networkRuleSet", what: "Registry " + key,
		product: "Artifact Registry", api: "artifactregistry.googleapis.com", private: r.private, ranges: r.ranges, path: o.privatePathOf(azRegistry, r.group, r.name), at: len(e.Losses)})
	if r.cmk {
		e.Losses = append(e.Losses, Loss{Field: "properties.encryption", Widens: true,
			Why: "its images were encrypted with the customer's own key; the repository uses Google's encryption until a Cloud KMS key is named (kmsKeyName), which Artifact Registry's service agent must be granted (identity, not translated: #32)"})
	}
	if r.quarantine {
		e.Losses = append(e.Losses, Loss{Field: "properties.policies.quarantinePolicy.status", Widens: true,
			Why: "a pushed image could not be pulled until a scanner released it; Artifact Registry lets every image be pulled as soon as it is pushed"})
	}
	if r.anonymous {
		e.Losses = append(e.Losses, Loss{Field: "properties.anonymousPullEnabled",
			Why: "anyone could pull without signing in; the repository is private, so such a pull fails until it signs in (granting allUsers read is not done here)"})
	}
	spec := map[string]any{"format": "DOCKER", "mode": "STANDARD_REPOSITORY", "description": "From Azure Container Registry " + key}
	labels, ll := gcpLabels(r.tags)
	e.Losses = append(e.Losses, ll...)
	if len(labels) > 0 {
		spec["labels"] = labels
	}
	e.Targets = append(e.Targets, o.add("gcp", r.src, repoObject(o.m.Region, id, spec)))
	o.entries = append(o.entries, e)
	r.imageRequirement(o, fmt.Sprintf("%s-docker.pkg.dev/<project>/%s/<repository>", o.m.Region, id))
}

// repoObject is an Artifact Registry repository as the GCP restore
// creates it (POST .../repositories?repositoryId=).
func repoObject(region, id string, spec map[string]any) snapshot.Object {
	parent := gcpProject + "/locations/" + region
	rel := parent + "/repositories/" + id
	s := map[string]any{"name": rel}
	for k, v := range spec {
		s[k] = v
	}
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": gcpRepo,
		"metadata": map[string]any{"name": rel, "annotations": map[string]any{
			"truthform.org/discovery":  "artifactregistry/v1",
			"truthform.org/schema":     "Repository",
			"truthform.org/collection": "projects.locations.repositories",
			"truthform.org/parent":     parent,
		}}, "spec": s}}
}
