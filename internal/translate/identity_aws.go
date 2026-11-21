package translate

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/snapshot"
)

// Workload identity on AWS: an IAM role per managed identity, used through
// EKS Pod Identity.
//
// Pod Identity, not IAM roles for service accounts (IRSA). IRSA's trust
// policy names the cluster's OIDC issuer, in the role's principal and in
// the names of its condition keys, without its https:// ("$oidc_provider:sub",
// https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html):
// EKS gives the issuer when it makes the cluster, so nothing written
// before that can hold it, and a reference cannot stand in the name of a
// key. A Pod Identity association names the cluster, the namespace, the
// service account and the role, all known here, and AWS recommends it
// ("AWS recommends using EKS Pod Identities ... whenever possible",
// https://docs.aws.amazon.com/eks/latest/userguide/service-accounts.html).
//
// The trust is written twice, and both must hold. The association maps
// the role to one service account of one namespace of one cluster. The
// role's own trust policy, which by itself would let EKS hand the role to
// any association in the account, names the same three in conditions on
// the session tags Pod Identity sets ("You can use these tags in the
// condition keys in the trust policy to restrict which service accounts,
// namespaces, and clusters can use this role",
// https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html; the
// tags are eks-cluster-arn, kubernetes-namespace and
// kubernetes-service-account, pod-id-abac.html).
//
// The permissions are an inline policy of the role. Every statement names
// its resources: the ARN of each queue, topic, bucket and secret the
// translation wrote, by reference. Two forms are not a single object's
// ARN, and there are no others (identityAWSWildcards).

const (
	awsRole           = "AWS::IAM::Role"
	awsPodAssociation = "AWS::EKS::PodIdentityAssociation"
	awsPodAgent       = "eks-pod-identity-agent"
	awsPolicyName     = "translated-access"
	// IAM's limits: a role's name, its trust policy and the sum of its
	// inline policies
	// (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html).
	awsRoleNameMax = 64
	awsTrustMax    = 2048
	awsInlineMax   = 10240
)

var awsRoleName = regexp.MustCompile(`^[\w+=,.@-]+$`)

type identityAWS struct {
	m      Map
	addons map[string]bool
}

func (*identityAWS) platform() string    { return "aws" }
func (*identityAWS) clusterKind() string { return awsEKS }

func (*identityAWS) slots(kind string, objs []snapshot.Object) []idFound {
	var out []idFound
	for _, t := range objs {
		s, _ := t.Body["spec"].(map[string]any)
		slot := ""
		switch {
		case t.Kind() == awsQueue && (kind == sbQueue || kind == sbSubscription):
			// The queue that names a dead-letter queue is the entity's
			// own; the one it names is its dead-letter queue.
			_, main := s["RedrivePolicy"]
			slot = map[string]map[bool]string{
				sbQueue:        {true: slotQueue, false: slotDLQ},
				sbSubscription: {true: slotSubQueue, false: slotSubDLQ},
			}[kind][main]
		case t.Kind() == awsTopic && kind == sbTopic:
			slot = slotTopic
		case t.Kind() == awsBucket && kind == azContainer:
			slot = slotBucket
		case t.Kind() == awsSecret && kind == azVaultSecret:
			slot = slotSecret
		case t.Kind() == awsRepoTmpl && kind == azRegistry:
			slot = slotRegistry
		}
		if slot != "" {
			out = append(out, idFound{slot: slot, obj: t})
		}
	}
	return out
}

// identityAWSRule is what a capability on a slot becomes: actions on one
// form of the object's ARN.
type identityAWSRule struct {
	sid     string
	actions []string
	// form is how the object is named: arn (itself), objects (a
	// bucket's objects), repositories (a registry's), any (the action
	// takes no resource).
	form string
}

// The actions are from the Service Authorization Reference
// (https://docs.aws.amazon.com/service-authorization/latest/reference/),
// each on the resource type the reference gives it. A batch call is
// authorized by its single action (SendMessageBatch by sqs:SendMessage).
var (
	awsReceive = []identityAWSRule{{"ReceiveFromQueues", []string{"sqs:ChangeMessageVisibility", "sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:ReceiveMessage"}, "arn"}}

	// identityAWSRules is the whole table: capability, then slot.
	identityAWSRules = map[string]map[string][]identityAWSRule{
		// The role's actions hold */queues/read, so the queue's
		// settings and URL can be read too.
		capSend: {
			slotQueue: {{"SendToQueues", []string{"sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:SendMessage"}, "arn"}},
			slotTopic: {{"PublishToTopics", []string{"sns:Publish"}, "arn"}},
		},
		// A Service Bus dead-letter queue is a sub-queue of its entity
		// (<queue>/$deadletterqueue), inside the assignment's scope, so a
		// receiver of the queue could read it: it may here.
		capReceive: {slotQueue: awsReceive, slotDLQ: awsReceive, slotSubQueue: awsReceive, slotSubDLQ: awsReceive},
		// "List Blobs" and "Get Blob" are both blobs/read, versions
		// included.
		capBlobRead: {slotBucket: {
			{"ListBuckets", []string{"s3:ListBucket", "s3:ListBucketVersions"}, "arn"},
			{"ReadObjects", []string{"s3:GetObject", "s3:GetObjectVersion"}, "objects"}}},
		// A multipart upload is authorized by s3:PutObject; ending one
		// and listing its parts are the uploader's.
		capBlobWrite:  {slotBucket: {{"WriteObjects", []string{"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:PutObject"}, "objects"}}},
		capBlobDelete: {slotBucket: {{"DeleteObjects", []string{"s3:DeleteObject"}, "objects"}}},
		capBlobPurge:  {slotBucket: {{"DeleteObjectVersions", []string{"s3:DeleteObjectVersion"}, "objects"}}},

		capSecretRead:  {slotSecret: {{"ReadSecrets", []string{"secretsmanager:GetSecretValue"}, "arn"}}},
		capSecretMeta:  {slotSecret: {{"DescribeSecrets", []string{"secretsmanager:DescribeSecret"}, "arn"}}},
		capSecretWrite: {slotSecret: {{"PutSecretVersions", []string{"secretsmanager:PutSecretValue"}, "arn"}}},

		// ecr:GetAuthorizationToken "does not support resource-level
		// permissions" (its resource column is empty): it is granted on
		// every resource, and gives a token, not an image.
		capPull: {slotRegistry: {
			{"RegistrySignIn", []string{"ecr:GetAuthorizationToken"}, "any"},
			{"PullImages", []string{"ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"}, "repositories"}}},
		capPush: {slotRegistry: {{"PushImages", []string{"ecr:CompleteLayerUpload", "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart"}, "repositories"}}},
	}

	// identityAWSNotes are what a capability had on Azure that its rules
	// here leave out.
	identityAWSNotes = map[string]string{
		capReceive:     "a receiver could dead-letter a message itself; on SQS a message reaches the dead-letter queue only by being received too often, and sending to that queue is not granted",
		capBlobDelete:  "deleting a version of an object for good (s3:DeleteObjectVersion) is not granted with this role: in a versioned bucket a delete leaves the version, as Azure's did",
		capSecretWrite: "a new value can be put on each translated secret; creating a secret is not granted, as it would need every name in the account",
		capPush:        "pushing to a repository that does not exist yet fails: ecr:CreateRepository is not granted, so someone makes each repository first, or grants it on the registry's prefix",
		capSecretAuthz: "reading who may read a secret (its resource policy) is not granted",
	}
)

// identityAWSWildcards documents the only two resources in a written
// policy that are not one object's ARN:
//
//   - "*" for ecr:GetAuthorizationToken alone, which takes no resource;
//   - a bucket's objects (<bucket ARN>/*) and a registry's repositories
//     (repository/<prefix>/*): the objects of one translated bucket, and
//     the repositories a translated registry's template makes on push,
//     which do not exist yet. Each is the whole of what the Azure role had
//     on that container or registry, and nothing outside it.
const identityAWSWildcards = "ecr:GetAuthorizationToken on *, <bucket>/*, repository/<prefix>/*"

func (d *identityAWS) resource(f idFound, form string) any {
	if form == "any" {
		return "*"
	}
	name := f.obj.Name()
	switch f.obj.Kind() {
	case awsQueue:
		return awsRef(awsQueue, name, "Arn")
	case awsTopic:
		return awsRef(awsTopic, name, "TopicArn")
	case awsSecret:
		// The secret's ARN, whose last six characters AWS chooses.
		return awsRef(awsSecret, name, "Id")
	case awsBucket:
		if form == "objects" {
			return awsRef(awsBucket, name, "Arn") + "/*"
		}
		return awsRef(awsBucket, name, "Arn")
	case awsRepoTmpl:
		s, _ := f.obj.Body["spec"].(map[string]any)
		return "arn:aws:ecr:" + d.m.Region + ":" + awsRef("account", "self", "id") + ":repository/" + fmt.Sprint(s["Prefix"]) + "/*"
	}
	return nil
}

func (d *identityAWS) plan(a *idAssign) {
	for _, cap := range a.role.caps {
		for _, f := range a.found {
			for _, rule := range identityAWSRules[cap][f.slot] {
				res := d.resource(f, rule.form)
				if res == nil {
					continue
				}
				it := idItem{cap: cap, sid: rule.sid, actions: rule.actions, resource: res}
				if rule.form != "any" {
					it.obj = f.obj
				}
				a.items = append(a.items, it)
			}
		}
		if note := identityAWSNotes[cap]; note != "" && !(cap == capBlobDelete && identityHas(a.role, capBlobPurge)) {
			a.losses = append(a.losses, Loss{Field: "properties.roleDefinitionId", Why: a.role.name + ": " + note})
		}
	}
}

func identityHas(r identityRole, cap string) bool {
	for _, c := range r.caps {
		if c == cap {
			return true
		}
	}
	return false
}

func (d *identityAWS) nameOf(id *idIdent) (string, string) {
	name := d.m.name(id.group+"/"+id.name, id.name)
	if !awsRoleName.MatchString(name) || len(name) > awsRoleNameMax {
		return "", fmt.Sprintf("%q is not a name an IAM role takes (letters, digits and +=,.@-_, 64 at most): give it one in the map's names (%s/%s)", name, id.group, id.name)
	}
	if n := awsPolicySize(d.trust(id)); n > awsTrustMax {
		return "", fmt.Sprintf("its %d federated credentials make a trust policy of about %d characters, and a role's takes %d: split the identity, or raise the account's quota and write the role by hand", len(id.creds), n, awsTrustMax)
	}
	return name, ""
}

// trust is the role's trust policy: EKS Pod Identity, for each service
// account a credential names and no other.
func (d *identityAWS) trust(id *idIdent) map[string]any {
	seen := map[string]bool{}
	var st []any
	for _, c := range d.sortedCreds(id) {
		k := c.cluster.target + "\x00" + c.ns + "\x00" + c.sa
		if seen[k] {
			continue
		}
		seen[k] = true
		st = append(st, map[string]any{
			"Effect":    "Allow",
			"Principal": map[string]any{"Service": "pods.eks.amazonaws.com"},
			"Action":    []any{"sts:AssumeRole", "sts:TagSession"},
			"Condition": map[string]any{"StringEquals": map[string]any{
				"aws:RequestTag/eks-cluster-arn":            awsRef(awsEKS, c.cluster.target, "Arn"),
				"aws:RequestTag/kubernetes-namespace":       c.ns,
				"aws:RequestTag/kubernetes-service-account": c.sa,
			}},
		})
	}
	return awsPolicyDoc(st...)
}

func (*identityAWS) sortedCreds(id *idIdent) []*idCred {
	cs := append([]*idCred(nil), id.creds...)
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		return a.cluster.target+"\x00"+a.ns+"\x00"+a.sa+"\x00"+a.src < b.cluster.target+"\x00"+b.ns+"\x00"+b.sa+"\x00"+b.src
	})
	return cs
}

var awsTokenRE = regexp.MustCompile(`\{\{truthform\|[^{}]*\}\}`)

// awsPolicySize is a policy's size as IAM counts it, without white space,
// each reference taken for an ARN of a usual length.
func awsPolicySize(doc map[string]any) int {
	b, _ := json.Marshal(doc)
	return len(awsTokenRE.ReplaceAllString(string(b), strings.Repeat("x", 80)))
}

// policy is the role's permissions: one statement per kind of grant, its
// resources each once and in order.
func (d *identityAWS) policy(id *idIdent) map[string]any {
	type stmt struct {
		actions []string
		res     map[string]any
	}
	by := map[string]*stmt{}
	for _, it := range identityAllItems(id) {
		s := by[it.sid]
		if s == nil {
			s = &stmt{actions: it.actions, res: map[string]any{}}
			by[it.sid] = s
		}
		s.res[fmt.Sprint(it.resource)] = it.resource
	}
	var st []any
	for _, sid := range sortedMapKeys(by) {
		s := by[sid]
		var res []any
		for _, k := range sortedMapKeys(s.res) {
			res = append(res, s.res[k])
		}
		st = append(st, map[string]any{"Sid": sid, "Effect": "Allow", "Action": anyStrings(s.actions), "Resource": res})
	}
	if len(st) == 0 {
		return nil
	}
	return awsPolicyDoc(st...)
}

func (d *identityAWS) write(id *idIdent, name string, o *out) (Entry, map[string][]string) {
	e := Entry{Source: id.src, State: Mapped}
	targets := map[string][]string{}
	spec := map[string]any{
		"RoleName":                 name,
		"Description":              "From Azure managed identity " + id.group + "/" + id.name,
		"AssumeRolePolicyDocument": d.trust(id),
	}
	if doc := d.policy(id); doc != nil {
		if n := awsPolicySize(doc); n > awsInlineMax {
			return Entry{Source: id.src, State: Refused, Reason: fmt.Sprintf("what it is granted makes a policy of about %d characters, and a role's inline policies take %d: narrow its role assignments on Azure to the queues, containers and secrets the app uses", n, awsInlineMax)}, nil
		}
		spec["Policies"] = []any{map[string]any{"PolicyName": awsPolicyName, "PolicyDocument": doc}}
	}
	tags, tl := awsBucketTags(id.tags)
	e.Losses = append(e.Losses, tl...)
	if len(tags) > 0 {
		var ts []any
		for _, k := range sortedKeys(tags) {
			ts = append(ts, map[string]any{"Key": k, "Value": tags[k]})
		}
		spec["Tags"] = ts
	}
	role := o.add("aws", id.src, awsObject(awsRole, name, spec))
	e.Targets = append(e.Targets, role)
	for _, a := range id.assigns {
		targets[a.src] = []string{role}
	}
	seen := map[string]string{}
	for _, c := range d.sortedCreds(id) {
		cl := c.cluster
		if !d.addons[cl.target] {
			d.addons[cl.target] = true
			// Named as a capture names it: cluster|addon, made safe.
			e.Targets = append(e.Targets, o.add("aws", id.src, awsObject(awsAddon, cl.target+"_"+awsPodAgent, map[string]any{
				"ClusterName": awsRef(awsEKS, cl.target, "identifier"), "AddonName": awsPodAgent})))
			o.require(fmt.Sprintf("EKS cluster %s: workload identity is EKS Pod Identity, whose agent add-on (%s) is written here. Its nodes' role (clusters.%s.nodeRoleArn) must allow eks-auth:AssumeRoleForPodIdentity (the managed policy AmazonEKSWorkerNodePolicy does), and nodes with no route to the internet reach the EKS Auth API through an interface endpoint (com.amazonaws.%s.eks-auth)", cl.target, awsPodAgent, cl.key, d.m.Region))
			if cl.windows {
				o.require(fmt.Sprintf("EKS cluster %s has Windows nodes: \"Pods that run on Windows Amazon EC2 instances aren't supported\" by EKS Pod Identity, so a pod there does not get its service account's role; on AKS it did", cl.target))
			}
		}
		k := cl.target + "\x00" + c.ns + "\x00" + c.sa
		if prev, dup := seen[k]; dup {
			// Two credentials for one service account are one association.
			targets[c.src] = []string{prev}
			continue
		}
		as := map[string]any{"ClusterName": awsRef(awsEKS, cl.target, "identifier"), "Namespace": c.ns, "ServiceAccount": c.sa,
			"RoleArn": awsRef(awsRole, name, "Arn")}
		// It has no name of its own: named as a capture names it, by its
		// spec.
		t := o.add("aws", c.src, awsObject(awsPodAssociation, awscc.SpecName(awsPodAssociation, as), as))
		seen[k] = t
		targets[c.src] = []string{t}
		if cl.windows {
			c.losses = append(c.losses, Loss{Field: "properties.subject", Why: "cluster " + cl.target + " has Windows nodes, where EKS Pod Identity gives a pod no role: a pod of this service account there has no access"})
		}
	}
	e.Reason = identityMay("IAM role "+name, id)
	o.require("Kubernetes manifests (Git): a service account needs no annotation for EKS Pod Identity, which binds by cluster, namespace and name; remove the azure.workload.identity/client-id annotations and azure.workload.identity/use labels.")
	o.require("Apps that reached Azure through a managed identity use the AWS SDK's default credential chain, at a version that knows EKS Pod Identity (https://docs.aws.amazon.com/eks/latest/userguide/pod-id-minimum-sdk.html), and no static credential earlier in that chain")
	o.require("An IAM role written for a managed identity can be given to another service account by whoever may create EKS Pod Identity associations and pass the role (eks:CreatePodIdentityAssociation, iam:PassRole), as whoever could write the identity's federated credentials could on Azure; the role's own trust policy also names each cluster, namespace and service account, so such an association gets no credentials until that is changed too")
	if len(o.private) > 0 {
		o.require("A service that answers only on its private path denies everyone else, these roles included: an app reaches it through the VPC's interface endpoints, as it did through the private endpoint on Azure")
	}
	return e, targets
}

func (d *identityAWS) nodes(c *idCluster, o *out) string {
	return "the IAM role the map names (clusters." + c.key + ".nodeRoleArn)"
}

func (d *identityAWS) pullRequirement(c *idCluster, reg idFound, o *out) string {
	s, _ := reg.obj.Body["spec"].(map[string]any)
	res := "arn:aws:ecr:" + d.m.Region + ":<account>:repository/" + fmt.Sprint(s["Prefix"]) + "/*"
	why := fmt.Sprintf("nothing is granted to the nodes' role, which is the map's (clusters.%s.nodeRoleArn): until it may pull from %s, the cluster's pods cannot start from images there", c.key, res)
	o.require(fmt.Sprintf("EKS cluster %s's nodes pulled their images with the kubelet identity's AcrPull: let the node role (clusters.%s.nodeRoleArn) pull from ECR, with ecr:GetAuthorizationToken on * and ecr:BatchGetImage, ecr:GetDownloadUrlForLayer and ecr:BatchCheckLayerAvailability on %s (the managed policy AmazonEC2ContainerRegistryPullOnly gives the same on every repository)", c.target, c.key, res))
	return why
}
