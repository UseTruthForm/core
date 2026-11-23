package translate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/snapshot"
)

// Key Vault secrets, read into a model the AWS and GCP writers share.
//
// A vault has no object on either target: Secrets Manager keeps secrets
// per account and region, Secret Manager per project. Each secret becomes
// one, named after its vault and itself, so two vaults' secrets of one
// name stay apart: <vault>/<secret> on AWS, whose names take a slash, and
// <vault>_<secret> on GCP, whose take neither a slash nor a dot. Key
// Vault's names hold only letters, digits and dashes, so neither can be
// read two ways.
//
// Only names and settings move. A capture never holds a secret's value,
// and a translation writes none: the requirement says where each comes
// from at restore. Keys are refused: their material never leaves the
// vault. Who may read a vault (access policies, Azure RBAC) is identity,
// which is not translated (#32).

const (
	azVault         = "microsoft.keyvault/vaults"
	azVaultSecret   = azVault + "/secrets"
	awsSecret       = "AWS::SecretsManager::Secret"
	awsSecretPolicy = "AWS::SecretsManager::ResourcePolicy"
	gcpSecret       = "secretmanager.googleapis.com/Secret"

	kvRetention = 90 // Key Vault's soft-delete retention when unset, in days
)

var (
	awsSecretName = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,512}$`)
	gcpSecretID   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)
	// AWS advises against a name ending in a hyphen and six characters: a
	// lookup by partial ARN can then match the wrong secret.
	awsARNSuffix = regexp.MustCompile(`-[A-Za-z0-9]{6}$`)
	gcpLabelKey  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	gcpLabelVal  = regexp.MustCompile(`^[a-z0-9_-]{0,63}$`)
)

type keyVault struct{}

func (keyVault) claims(kind string) bool {
	return kind == azVault || strings.HasPrefix(kind, azVault+"/")
}

type kvVault struct {
	src, group, name string
	key              string // group/name, lower case
	tags             map[string]string
	losses           []Loss
	private          string // why its endpoint answered only some networks, or ""
	// ranges are the public address ranges its firewall allowed, vnets the
	// subnets it allowed by service endpoint, and trusted whether Azure's
	// trusted services passed it.
	ranges          []string
	vnets           int
	trusted         bool
	softDelete      bool
	retention       int // days
	purgeProtection bool
	access          string // who it let read its secrets, when said: "3 access policies"
	secrets         []*kvSecret
}

type kvSecret struct {
	src, name   string
	tags        map[string]string
	contentType string
	disabled    bool
	losses      []Loss
}

func (keyVault) translate(objs []snapshot.Object, o *out) {
	vaults := map[string]*kvVault{}
	var secretObjs []snapshot.Object
	kms := map[string]string{"aws": "AWS KMS", "gcp": "Cloud KMS"}[o.m.To]
	for _, obj := range objs {
		refuse := func(why string) {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: why})
		}
		switch k := strings.ToLower(obj.Kind()); k {
		case azVault:
			v := readVault(obj)
			vaults[v.key] = v
		case azVaultSecret:
			secretObjs = append(secretObjs, obj)
		case azVault + "/keys", azVault + "/keys/versions":
			refuse("a key's material never leaves its vault (its HSM or software protection), so it cannot be copied: make a new key in " + kms + " and re-encrypt or re-sign what this one protected")
		case azVault + "/accesspolicies":
			refuse("identity is not translated (#32): an access policy grants an Azure identity rights on the vault; grant the app's new identity read on its secrets instead")
		case azVault + "/privateendpointconnections":
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "made when its private endpoint is created; private endpoints are not translated yet"})
		default:
			o.entries = append(o.entries, Entry{Source: source(obj), State: NotLooked, Reason: "no descriptor for " + obj.Kind() + " yet"})
		}
	}
	for _, obj := range secretObjs {
		parent, _, _ := strings.Cut(obj.Name(), "/")
		v := vaults[strings.ToLower(obj.Namespace()+"/"+parent)]
		if v == nil {
			o.entries = append(o.entries, Entry{Source: source(obj), State: Refused, Reason: "its vault is not in the snapshot, so what guarded it (its network rules, purge protection) is not known"})
			continue
		}
		v.secrets = append(v.secrets, readSecret(obj))
	}
	all := sortedVaults(vaults)
	refuseAll := func(why string) {
		for _, v := range all {
			o.entries = append(o.entries, Entry{Source: v.src, State: Refused, Reason: why})
			for _, s := range v.secrets {
				o.entries = append(o.entries, Entry{Source: s.src, State: Refused, Reason: why})
			}
		}
	}
	switch {
	case o.m.Destinations.Secrets == "":
		refuseAll("the map chooses no destination for secrets (destinations.secrets)")
		return
	case o.m.To == "gcp" && o.m.Secrets == nil: // validate refuses one set without a replication
		refuseAll("the map chooses no replication for Secret Manager (secrets.replication: automatic, or user-managed with secrets.locations); a secret's cannot be changed once it is made")
		return
	}
	for _, v := range all {
		if o.m.To == "aws" {
			awsVault(v, o)
		} else {
			gcpVault(v, o)
		}
	}
}

func sortedVaults(m map[string]*kvVault) []*kvVault {
	out := make([]*kvVault, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].src < out[j].src })
	for _, v := range out {
		sort.Slice(v.secrets, func(i, j int) bool { return v.secrets[i].name < v.secrets[j].name })
	}
	return out
}

func readVault(o snapshot.Object) *kvVault {
	v := &kvVault{src: source(o), group: o.Namespace(), name: o.Name(), key: strings.ToLower(o.Namespace() + "/" + o.Name())}
	top := newProps(spec(o), "")
	top.quiet("location", "name", "properties")
	v.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	p := newProps(obj(top.m["properties"]), "properties.")
	// The tenant whose identities the vault trusts is identity, read
	// with the access settings below; the rest is the server's, or an
	// instruction to the create (createMode) rather than a setting.
	p.quiet("tenantId", "vaultUri", "provisioningState", "hsmPoolResourceId", "privateEndpointConnections", "createMode")
	sku := newProps(obj(p.m["sku"]), "properties.sku.")
	sku.quiet("family")
	if strings.EqualFold(sku.str("name"), "premium") {
		sku.lose("name", "premium: its keys could be HSM-protected; its secrets were stored as a standard vault's are, and keys are not translated", false)
	}
	p.quiet("sku")
	policies := len(list(p.m["accessPolicies"]))
	p.quiet("accessPolicies")
	switch {
	case p.boolean("enableRbacAuthorization"):
		v.access = "Azure RBAC role assignments"
		p.lose("enableRbacAuthorization", "who may read its secrets was set by Azure RBAC role assignments: a managed identity's Key Vault Secrets role is carried over with destinations.identity: workload, and any other assignment is not, so on the target only those its IAM lets read them can", false)
	case policies > 0:
		v.access = fmt.Sprintf("%d access policies", policies)
		p.lose("accessPolicies", v.access+" set who may read its secrets: identity is not translated (#32), so on the target only those its IAM lets read them can", false)
	}
	p.unlessDefault("enabledForDeployment", false, "Azure VMs could read its certificates as secrets; nothing on the target does so")
	p.unlessDefault("enabledForDiskEncryption", false, "Azure Disk Encryption could read its secrets; nothing on the target does so")
	p.unlessDefault("enabledForTemplateDeployment", false, "ARM deployments could read its secrets; nothing on the target does so")
	// Azure turns soft delete on for every vault and no longer lets it be
	// turned off, so a vault that does not say has it.
	v.softDelete = true
	if sd, ok := p.take("enableSoftDelete"); ok && sd == false {
		v.softDelete = false
	}
	v.retention = kvRetention
	if r := p.integer("softDeleteRetentionInDays"); r != nil {
		v.retention = *r
	}
	v.purgeProtection = p.boolean("enablePurgeProtection")
	public := p.str("publicNetworkAccess")
	acl := newProps(obj(p.m["networkAcls"]), "properties.networkAcls.")
	deny := strings.EqualFold(acl.str("defaultAction"), "Deny")
	ips, nets := len(list(acl.m["ipRules"])), len(list(acl.m["virtualNetworkRules"]))
	// Azure's trusted services pass the firewall when bypass says so; a
	// snapshot that does not say is read as the stricter None.
	bypass := acl.str("bypass")
	acl.quiet("ipRules", "virtualNetworkRules")
	switch {
	case strings.EqualFold(public, "Disabled"):
		v.private = "its public network access is disabled: it answered private endpoints only"
	case deny:
		v.private = fmt.Sprintf("its firewall denies by default, allowing %d address range(s) and %d network(s)", ips, nets)
		var bad []string
		v.ranges, bad = lockRanges(list(acl.m["ipRules"]), "value")
		for _, b := range bad {
			acl.lose("ipRules", b+" is not an address or range this reads; it is not allowed", false)
		}
		v.vnets = nets
	}
	v.trusted = v.private != "" && strings.EqualFold(bypass, "AzureServices")
	p.quiet("networkAcls")
	v.losses = append(append(append(top.rest(), p.rest()...), sku.rest()...), acl.rest()...)
	return v
}

func readSecret(o snapshot.Object) *kvSecret {
	_, name, _ := strings.Cut(o.Name(), "/")
	s := &kvSecret{src: source(o), name: name}
	top := newProps(spec(o), "")
	top.quiet("name", "id", "type", "location", "properties")
	s.tags = stringTags(top.m["tags"])
	top.quiet("tags")
	p := newProps(obj(top.m["properties"]), "properties.")
	p.quiet("secretUri", "secretUriWithVersion")
	if p.str("value") != "" {
		p.lose("value", "a value in the snapshot is not carried over: a translation writes no secret value", false)
	}
	s.contentType = p.str("contentType")
	a := newProps(obj(p.m["attributes"]), "properties.attributes.")
	a.quiet("created", "updated")
	if en, ok := a.take("enabled"); ok && en == false {
		s.disabled = true
	}
	for _, k := range []string{"nbf", "exp"} {
		if n := a.integer(k); n != nil {
			what := map[string]string{"nbf": "not before", "exp": "expires"}[k]
			a.lose(k, fmt.Sprintf("%s %s: Key Vault only records it (a read works outside it); Secrets Manager has no such date, and Secret Manager's expireTime deletes the secret, so it is not written", what, time.Unix(int64(*n), 0).UTC().Format(time.RFC3339)), false)
		}
	}
	p.quiet("attributes")
	s.losses = append(append(top.rest(), p.rest()...), a.rest()...)
	return s
}

// vaultEntry is the report for a vault: no object of its own on either
// target, and the losses that apply to all its secrets.
func vaultEntry(v *kvVault, where string) Entry {
	e := Entry{Source: v.src, State: Mapped, Losses: append([]Loss(nil), v.losses...),
		Reason: where + " has no vault: its secrets are written as secrets of their own, named after the vault"}
	if len(v.tags) > 0 {
		e.Losses = append(e.Losses, Loss{Field: "tags", Why: fmt.Sprintf("%d tag(s): %s has no vault to hold them (each secret keeps its own)", len(v.tags), where)})
	}
	return e
}

// secretName is the target's name for a secret, the map's if it gives
// one, and why it cannot be used when it cannot.
func secretName(m Map, v *kvVault, s *kvSecret, sep string, valid *regexp.Regexp) (string, string) {
	key := v.group + "/" + v.name + "/" + s.name
	n := m.name(key, v.name+sep+s.name)
	if !valid.MatchString(n) {
		return "", fmt.Sprintf("%q is not a name the target takes (%s): give it one in the map's names (%s)", n, valid, key)
	}
	return n, ""
}

func (v *kvVault) secretList(name func(*kvSecret) string) string {
	var ns []string
	for _, s := range v.secrets {
		if n := name(s); n != "" {
			ns = append(ns, n)
		}
	}
	return strings.Join(ns, ", ")
}

func (v *kvVault) identityRequirement(o *out, grant string) {
	if v.access != "" {
		o.require(fmt.Sprintf("Key Vault %s/%s let %s read its secrets; a managed identity's Key Vault Secrets role is carried over with destinations.identity: workload; for anyone else (people, pipelines, access policies) grant %s on the secrets they read", v.group, v.name, v.access, grant))
	}
}

// Secrets on AWS: a Secrets Manager secret per Key Vault secret, named
// <vault>/<secret>, with no value.
func awsVault(v *kvVault, o *out) {
	e := vaultEntry(v, "Secrets Manager")
	var lock *awsLock
	if v.private != "" {
		lock = lockAWS(o, azVault, v.group, v.name, []string{"secretsmanager"}, v.ranges)
		switch {
		case lock == nil:
			e.Losses = append(e.Losses, Loss{Field: "properties.networkAcls", Widens: true,
				Why: v.private + "; " + lockNoPath + ". Secrets Manager answers on its public endpoint, guarded by IAM alone"})
		default:
			// A secret's value is read by GetSecretValue, which the
			// secret's own Cloud Control handlers call: it stays open to
			// AWS's services acting with the caller's credentials.
			via := "its secrets answer only " + lock.where() + ", but a value can still be read from elsewhere through an AWS service that acts with the caller's credentials (CloudFormation resolving a reference to the secret), by a principal allowed secretsmanager:GetSecretValue: Cloud Control reads a secret that way, so that path cannot be denied without locking out the restore"
			if v.trusted {
				e.Losses = append(e.Losses, Loss{Field: "properties.networkAcls",
					Why: v.private + ", and Azure's trusted services passed it; " + via})
			} else {
				e.Losses = append(e.Losses, Loss{Field: "properties.networkAcls", Widens: true,
					Why: v.private + ", and no Azure service passed it; " + via})
			}
			if v.vnets > 0 {
				e.Losses = append(e.Losses, Loss{Field: "properties.networkAcls.virtualNetworkRules",
					Why: fmt.Sprintf("%d subnet(s) were allowed by service endpoint; on AWS a subnet reaches the secrets through its VPC's interface endpoint, and only those written for a private endpoint are let through", v.vnets)})
			}
			lockRequireAWS(o, "Key Vault "+v.group+"/"+v.name+"'s secrets answer", lock)
		}
	}
	switch {
	case v.softDelete && v.purgeProtection:
		e.Losses = append(e.Losses, Loss{Field: "properties.enablePurgeProtection", Widens: true,
			Why: fmt.Sprintf("no one could purge a deleted secret before its %d days were out; Secrets Manager sets the recovery window on each delete, and a delete may skip it (ForceDeleteWithoutRecovery) until IAM or a resource policy denies that (identity, not translated: #32)", v.retention)})
	case v.softDelete:
		e.Losses = append(e.Losses, Loss{Field: "properties.softDeleteRetentionInDays",
			Why: fmt.Sprintf("a deleted secret was kept %d days unless purged; Secrets Manager keeps one for the recovery window each delete chooses (7 to 30 days, 30 unless told), and a delete may skip it, as a purge could", v.retention)})
	}
	written := map[*kvSecret]string{}
	for _, s := range v.secrets {
		name, why := secretName(o.m, v, s, "/", awsSecretName)
		if why != "" {
			o.entries = append(o.entries, Entry{Source: s.src, State: Refused, Reason: why})
			continue
		}
		se := Entry{Source: s.src, State: Mapped, Losses: append([]Loss(nil), s.losses...)}
		if awsARNSuffix.MatchString(name) {
			se.Losses = append(se.Losses, Loss{Field: "name", Why: name + " ends in a hyphen and six characters, which AWS advises against: a lookup by partial ARN can match the wrong secret; give it another in the map's names"})
		}
		desc := "From Azure Key Vault " + v.group + "/" + v.name + ", secret " + s.name
		if s.contentType != "" {
			desc += "; content type " + s.contentType
		}
		spec := map[string]any{"Name": name, "Description": desc}
		tags, tl := awsSecretTags(s.tags)
		se.Losses = append(se.Losses, tl...)
		if len(tags) > 0 {
			spec["Tags"] = tags
		}
		if s.disabled {
			se.Losses = append(se.Losses, Loss{Field: "properties.attributes.enabled",
				Why: "disabled on the source, so no read returned its value; Secrets Manager has no disabled secret: it is written without a value, and stays unreadable only while none is supplied"})
			o.require(fmt.Sprintf("Secret %s was disabled on the source: restore it without a value (leave it out of --values) for as long as it should stay unreadable", name))
		}
		se.Targets = append(se.Targets, o.add("aws", s.src, awsObject(awsSecret, name, spec)))
		if lock != nil {
			// The policy is named as a capture names one: by its spec.
			arn := awsRef(awsSecret, name, "Id")
			pol := map[string]any{"SecretId": arn, "ResourcePolicy": awsPolicyDoc(
				lock.statement(lockSecrets, arn, false), lock.statement(lockSecretsManaged, arn, true))}
			se.Targets = append(se.Targets, o.add("aws", s.src, awsObject(awsSecretPolicy, awscc.SpecName(awsSecretPolicy, pol), pol)))
		}
		o.entries = append(o.entries, se)
		written[s] = name
	}
	o.entries = append(o.entries, e)
	if len(written) > 0 {
		o.require(fmt.Sprintf("Key Vault %s/%s's secrets (%s) hold no value: a capture never reads one, and a translation writes none. Supply each at restore with --values (AWS::SecretsManager::Secret/<name>: {SecretString: ...}), read from where its value is kept; the restore lists each one created without it", v.group, v.name, v.secretList(func(s *kvSecret) string { return written[s] })))
		o.require(fmt.Sprintf("Apps that read Key Vault %s/%s (its SDK, Key Vault references, the Secrets Store CSI driver) read Secrets Manager instead, by the new names (<vault>/<secret>)", v.group, v.name))
	}
	v.identityRequirement(o, "secretsmanager:GetSecretValue")
}

// awsSecretTags are a secret's tags as AWS takes them. A capture names a
// secret by its Name tag when it has one, so a tag of that name would
// rename it; AWS reserves aws:.
func awsSecretTags(tags map[string]string) ([]any, []Loss) {
	var out []any
	var losses []Loss
	for _, k := range sortedKeys(tags) {
		switch {
		case strings.EqualFold(k, "Name"):
			losses = append(losses, Loss{Field: "tags." + k, Why: "a tag Name would be read as the secret's name; it is not carried over"})
		case strings.HasPrefix(strings.ToLower(k), "aws:"):
			losses = append(losses, Loss{Field: "tags." + k, Why: "AWS reserves tags that begin aws:"})
		default:
			out = append(out, map[string]any{"Key": k, "Value": tags[k]})
		}
	}
	return out, losses
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Secrets on GCP: a Secret Manager secret per Key Vault secret, named
// <vault>_<secret>, with no version, replicated as the map says.
func gcpVault(v *kvVault, o *out) {
	e := vaultEntry(v, "Secret Manager")
	o.gcpClosedBy(gcpService{src: v.src, field: "properties.networkAcls", what: "Key Vault " + v.group + "/" + v.name,
		product: "Secret Manager", api: "secretmanager.googleapis.com", private: v.private, ranges: v.ranges, path: o.privatePathOf(azVault, v.group, v.name), at: len(e.Losses)})
	if v.softDelete {
		e.Losses = append(e.Losses, Loss{Field: "properties.enableSoftDelete", Widens: true,
			Why: fmt.Sprintf("a deleted secret was kept %d days and could be recovered; Secret Manager deletes a secret at once, with every version, until an IAM deny policy denies secretmanager.secrets.delete (identity, not translated: #32)", v.retention)})
	}
	if v.softDelete && v.purgeProtection {
		e.Losses = append(e.Losses, Loss{Field: "properties.enablePurgeProtection", Widens: true,
			Why: "no one could purge a deleted secret before its retention was out; on Secret Manager whoever may delete a secret destroys it"})
	}
	repl := map[string]any{"automatic": map[string]any{}}
	if o.m.Secrets.Replication == "user-managed" {
		var rs []any
		for _, l := range o.m.Secrets.Locations {
			rs = append(rs, map[string]any{"location": l})
		}
		repl = map[string]any{"userManaged": map[string]any{"replicas": rs}}
	}
	written := map[*kvSecret]string{}
	for _, s := range v.secrets {
		id, why := secretName(o.m, v, s, "_", gcpSecretID)
		if why != "" {
			o.entries = append(o.entries, Entry{Source: s.src, State: Refused, Reason: why})
			continue
		}
		se := Entry{Source: s.src, State: Mapped, Losses: append([]Loss(nil), s.losses...)}
		spec := map[string]any{"replication": repl}
		labels, ll := gcpLabels(s.tags)
		se.Losses = append(se.Losses, ll...)
		if len(labels) > 0 {
			spec["labels"] = labels
		}
		if s.contentType != "" {
			spec["annotations"] = map[string]any{"content-type": s.contentType}
		}
		if s.disabled {
			se.Losses = append(se.Losses, Loss{Field: "properties.attributes.enabled",
				Why: "disabled on the source, so no read returned its value; a Secret Manager secret is not disabled, its versions are: it is written with no version, and stays unreadable only while none is added"})
			o.require(fmt.Sprintf("Secret %s was disabled on the source: add no version to it (or add one disabled) for as long as it should stay unreadable", id))
		}
		se.Targets = append(se.Targets, o.add("gcp", s.src, secretObject(id, spec)))
		o.entries = append(o.entries, se)
		written[s] = id
	}
	o.entries = append(o.entries, e)
	if len(written) > 0 {
		o.require(fmt.Sprintf("Key Vault %s/%s's secrets (%s) are created with no version: a capture never reads a value, a translation writes none, and the GCP restore takes none. After the restore, add each one's value as a version (gcloud secrets versions add <id> --data-file=-), read from where it is kept", v.group, v.name, v.secretList(func(s *kvSecret) string { return written[s] })))
		o.require(fmt.Sprintf("Apps that read Key Vault %s/%s (its SDK, Key Vault references, the Secrets Store CSI driver) read Secret Manager instead, by the new names (<vault>_<secret>)", v.group, v.name))
	}
	v.identityRequirement(o, "roles/secretmanager.secretAccessor")
}

// gcpLabels are the tags GCP's labels can hold as they are: a lowercase
// key, a lowercase value. A tag that would have to change is named.
func gcpLabels(tags map[string]string) (map[string]any, []Loss) {
	out := map[string]any{}
	var losses []Loss
	for _, k := range sortedKeys(tags) {
		if gcpLabelKey.MatchString(k) && gcpLabelVal.MatchString(tags[k]) {
			out[k] = tags[k]
			continue
		}
		losses = append(losses, Loss{Field: "tags." + k, Why: "a GCP label takes lowercase letters, digits, _ and - only (a key starts with a letter), so it is not carried over"})
	}
	return out, losses
}

// secretObject is a Secret Manager secret as the GCP restore creates it
// (POST .../secrets?secretId=). Its name is output only, so the spec has
// none.
func secretObject(id string, spec map[string]any) snapshot.Object {
	rel := gcpProject + "/secrets/" + id
	return snapshot.Object{Body: map[string]any{"apiVersion": gcpAPIVersion, "kind": gcpSecret,
		"metadata": map[string]any{"name": rel, "annotations": map[string]any{
			"truthform.org/discovery":  "secretmanager/v1",
			"truthform.org/schema":     "Secret",
			"truthform.org/collection": "projects.secrets",
			"truthform.org/parent":     gcpProject,
		}}, "spec": spec}}
}
