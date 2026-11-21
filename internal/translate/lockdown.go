package translate

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Lockdown: a service that answered only on its private endpoints (public
// network access disabled), or only its firewall's ranges, answers only
// there on the target too.
//
// Private access (privateaccess.go) records, per Azure service, the private
// path it wrote. The service's family reads it and closes everything else:
//
// On AWS, with a resource policy that only denies. It grants nobody
// anything, so it is not identity; it denies the service's data actions to
// a request that comes neither through the service's interface endpoints
// (aws:SourceVpce) nor from an allowed public range (aws:SourceIp). The
// management actions are left alone, as Azure's management plane (ARM) kept
// working with public network access disabled: a deny on them would lock
// out the restore that wrote the policy, a later capture, and the console,
// which is the lockout AWS's own examples warn of
// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies-vpc-endpoint.html,
// https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies-access-policy-examples.html).
//
// On GCP, a bucket's IP filter names the VPC networks. Pub/Sub, Secret
// Manager and Artifact Registry have no setting of their own for where a
// request comes from (gcpPerimeter).
//
// A private service with no private endpoint in the snapshot, and no
// public range, could be reached from nowhere this knows: there is nothing
// to lock it to, and it stays reported as less protected.

// privatePath is the private path written for one Azure service.
type privatePath struct {
	// endpoints are the logical names of the interface VPC endpoints, per
	// AWS service (sqs, s3, ecr.api, ...).
	endpoints map[string][]string
	// networks are the GCP VPC networks whose subnetworks reach Google's
	// APIs privately, with their address ranges.
	networks map[string][]string
}

func privateKey(typ, target string) string { return strings.ToLower(typ + "|" + target) }

// privatePathFor is the path of an Azure service (its ARM type, and its
// group/name), made when there is none yet.
func (o *out) privatePathFor(typ, target string) *privatePath {
	k := privateKey(typ, target)
	if o.private[k] == nil {
		o.private[k] = &privatePath{endpoints: map[string][]string{}, networks: map[string][]string{}}
	}
	return o.private[k]
}

// privatePathOf is the path written for an Azure service, or nil.
func (o *out) privatePathOf(typ, group, name string) *privatePath {
	return o.private[privateKey(typ, group+"/"+name)]
}

func (p *privatePath) addEndpoint(service, name string) {
	for _, n := range p.endpoints[service] {
		if n == name {
			return
		}
	}
	p.endpoints[service] = append(p.endpoints[service], name)
	sort.Strings(p.endpoints[service])
}

func (p *privatePath) addNetwork(name string, prefixes []netip.Prefix) {
	var rs []string
	for _, pf := range prefixes {
		rs = append(rs, pf.String())
	}
	p.networks[name] = rs
}

// lockRanges reads a firewall's allowed address ranges: each rule's
// address or range under key, as a range. A rule that is not one is named
// in bad, and allows nothing.
func lockRanges(rules []any, key string) (ranges, bad []string) {
	for _, x := range rules {
		v, _ := obj(x)[key].(string)
		if act, _ := obj(x)["action"].(string); act != "" && !strings.EqualFold(act, "Allow") {
			bad = append(bad, v+" ("+act+")")
			continue
		}
		pf, err := netip.ParsePrefix(v)
		if err != nil {
			ad, err2 := netip.ParseAddr(v)
			if err2 != nil {
				bad = append(bad, v)
				continue
			}
			pf = netip.PrefixFrom(ad, ad.BitLen())
		}
		ranges = append(ranges, pf.Masked().String())
	}
	return ranges, bad
}

const lockNoPath = "no private endpoint to it is translated, and it allowed no public address range: there is no private path to lock it to"

// awsLock is where a private service answers on AWS: through these
// interface endpoints, and from these public ranges.
type awsLock struct {
	endpoints []string // logical names
	ranges    []string
}

// lockAWS decides how a private Azure service is closed on AWS: through
// the interface endpoints written for it for the given AWS services, and
// from the public ranges its firewall allowed. It is nil when there is
// neither.
func lockAWS(o *out, typ, group, name string, services, ranges []string) *awsLock {
	l := &awsLock{ranges: ranges}
	if p := o.privatePathOf(typ, group, name); p != nil {
		for _, s := range services {
			l.endpoints = append(l.endpoints, p.endpoints[s]...)
		}
	}
	if len(l.endpoints) == 0 && len(l.ranges) == 0 {
		return nil
	}
	return l
}

// where says where the service answers, for the report.
func (l *awsLock) where() string {
	var parts []string
	if len(l.endpoints) > 0 {
		parts = append(parts, "through the interface endpoint(s) "+strings.Join(l.endpoints, ", "))
	}
	if len(l.ranges) > 0 {
		parts = append(parts, "from "+strings.Join(l.ranges, ", "))
	}
	return strings.Join(parts, " and ")
}

const (
	lockSid = "DenyOutsidePrivateAccess"
	// lockSidManaged is the statement for a data action the type's own
	// Cloud Control handlers call.
	lockSidManaged = "DenyOutsidePrivateAccessButThroughAWS"
)

// statement is the deny for a service's data actions. All of its
// conditions must hold for the deny, so a request is let through (to
// whatever IAM allows it) when any fails:
//
//   - StringNotEquals aws:SourceVpce: the key is "included in the request
//     context only if the requester uses a VPC endpoint", and a negated
//     operator is true when the key is absent, so a request from the
//     internet matches and one through a listed endpoint does not.
//   - NotIpAddress aws:SourceIp, where the source allowed public ranges:
//     the key is "included in the request context, except when the
//     requester uses a VPC endpoint", so a request from an allowed range
//     does not match, and one through another VPC's endpoint does.
//   - aws:PrincipalIsAWSService false: an AWS service acting as itself
//     (SNS delivering to a subscription's queue, as sns.amazonaws.com)
//     does not come through an endpoint. AWS's note on both keys above:
//     "exclude service principals from your Deny statements by adding the
//     aws:PrincipalIsAWSService condition key with a value of false". Such
//     a principal still needs an allow of its own, which this never gives.
//
// managed adds aws:ViaAWSService false: a request an AWS service makes
// with the caller's credentials (a forward access session) passes. It is
// for the few data actions a type's Cloud Control handlers call themselves,
// which Cloud Control makes with "a temporary session created using your
// AWS user credentials" and never through an endpoint ("the condition key
// values for aws:SourceVpce ... from the initial request are not used in
// FAS requests"). Without it the restore and a later capture could not
// read what they wrote.
//
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
// https://docs.aws.amazon.com/IAM/latest/UserGuide/access_forward_access_sessions.html
// https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_GetResource.html
func (l *awsLock) statement(actions []string, resource any, managed bool) map[string]any {
	sid := lockSid
	services := map[string]any{"aws:PrincipalIsAWSService": "false"}
	if managed {
		sid = lockSidManaged
		services["aws:ViaAWSService"] = "false"
	}
	cond := map[string]any{"BoolIfExists": services}
	if len(l.endpoints) > 0 {
		var ids []any
		for _, n := range l.endpoints {
			ids = append(ids, awsRef(awsEndpoint, n, "Id"))
		}
		cond["StringNotEquals"] = map[string]any{"aws:SourceVpce": ids}
	}
	if len(l.ranges) > 0 {
		cond["NotIpAddress"] = map[string]any{"aws:SourceIp": anyStrings(l.ranges)}
	}
	st := map[string]any{"Sid": sid, "Effect": "Deny", "Principal": "*", "Action": anyStrings(actions), "Condition": cond}
	if resource != nil {
		st["Resource"] = resource
	}
	return st
}

// The data actions denied, per service. None is one its type's Cloud
// Control handlers call to read, update, list or delete the resource
// (TestLockdownLeavesManagementAlone holds them to the registry's own
// list); the managed ones are, and pass through AWS's services.
var (
	// S3: what reads, writes and deletes objects and their versions, tags,
	// holds and uploads (the service reference's data-plane actions on the
	// object, https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html).
	// AWS's own example for an endpoint denies PutObject, GetObject and
	// DeleteObject (https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-s3.html).
	// aws:SourceVpce holds for gateway and interface endpoints alike
	// (https://docs.aws.amazon.com/AmazonS3/latest/userguide/privatelink-interface-endpoints.html).
	lockS3Objects = []string{
		"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAcl", "s3:GetObjectVersionAcl",
		"s3:GetObjectAttributes", "s3:GetObjectVersionAttributes", "s3:GetObjectTagging", "s3:GetObjectVersionTagging",
		"s3:GetObjectRetention", "s3:GetObjectLegalHold",
		"s3:PutObject", "s3:PutObjectTagging", "s3:PutObjectVersionTagging", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
		"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging",
		"s3:RestoreObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts",
	}
	// Listing a bucket's objects, their versions and its uploads.
	lockS3Lists = []string{"s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}
	// s3:ListBucket lists the objects, and is also what HeadBucket needs
	// (https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html),
	// which the bucket's handlers call to read it: managed.
	lockS3Managed = []string{"s3:ListBucket"}
	// SQS: sending, receiving and deleting messages, and emptying the
	// queue. AWS's example denies SendMessage and ReceiveMessage, and warns
	// against denying the administrative actions
	// (https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies-access-policy-examples.html).
	lockSQS = []string{"sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:PurgeQueue", "sqs:StartMessageMoveTask", "sqs:CancelMessageMoveTask"}
	// SNS: publishing is the one data action a topic policy takes
	// (https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html,
	// "Restrict publication to an Amazon SNS topic only from a specific VPC endpoint").
	lockSNS = []string{"sns:Publish"}
	// Secrets Manager: writing a secret's value. Reading it
	// (GetSecretValue, AWS's example:
	// https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html)
	// is what the secret's read and update handlers call too: managed.
	lockSecrets        = []string{"secretsmanager:PutSecretValue"}
	lockSecretsManaged = []string{"secretsmanager:GetSecretValue"}
	// ECR: pulling and pushing images. ecr:GetAuthorizationToken is the
	// account's, not a repository's, and no repository policy reaches it
	// (https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html).
	lockECR = []string{"ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability",
		"ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage"}
)

// awsPolicyDoc is a policy document of these statements.
func awsPolicyDoc(statements ...any) map[string]any {
	return map[string]any{"Version": "2012-10-17", "Statement": statements}
}

// awsPolicyJSON is a policy document as the text a type takes it in.
func awsPolicyJSON(doc map[string]any) string {
	b, _ := json.Marshal(doc)
	return string(b)
}

// lockRequireAWS says what the lock asks of whoever uses the service.
func lockRequireAWS(o *out, what string, l *awsLock) {
	o.require(fmt.Sprintf("%s only %s, as on Azure: a resource policy denies the data actions to every other request, whoever makes it. The settings can still be read and changed from anywhere IAM allows, as Azure's management plane could; apps and people that read or write the data from elsewhere must come that way", what, l.where()))
}

// gcpPerimeter says why a private Azure service stays less protected on
// one of Google's services with no network setting of its own, and what
// closes it.
//
// Pub/Sub, Secret Manager and Artifact Registry take no network
// restriction per resource: IAM conditions know no source network ("The
// access levels attribute is available only when you use Identity-Aware
// Proxy", https://docs.cloud.google.com/iam/docs/conditions-attribute-reference),
// and deny policies' conditions "only recognize resource tag functions"
// (https://docs.cloud.google.com/iam/docs/deny-overview). Google's answer
// is a VPC Service Controls perimeter, which this does not write:
//
//   - it is the organization's, not the project's: a service perimeter
//     belongs to an access policy whose parent is organizations/{id}, and
//     names the project by its number
//     (https://accesscontextmanager.googleapis.com/$discovery/rest?version=v1,
//     ServicePerimeterConfig.resources);
//   - it restricts a service for the whole project, and "a single Google
//     Cloud project ... can only belong to a single regular Service
//     Perimeter": one Azure namespace's setting would close every topic,
//     secret or repository of the project, and collide with a perimeter
//     the organization already has;
//   - it closes the management calls too ("VPC Service Controls protection
//     applies to all administrator operations, publisher operations, and
//     subscriber operations",
//     https://docs.cloud.google.com/vpc-service-controls/docs/supported-products):
//     the restore that wrote it, and a later capture, would be refused
//     from outside until an ingress rule admits who runs them, and who
//     that is, is identity (#32).
//
// So the service stays reported as less protected, with the perimeter to
// create named exactly.
func gcpPerimeter(o *out, private, what, api string, p *privatePath) string {
	var nets []string
	if p != nil {
		nets = sortedKeys(p.networks)
	}
	from := "no network of this translation reached it privately"
	if len(nets) > 0 {
		var rs []string
		for _, n := range nets {
			rs = append(rs, "//compute.googleapis.com/"+gcpProject+"/global/networks/"+n)
		}
		from = "its VPC network(s) " + strings.Join(nets, ", ") + " are the project's own, and so inside it"
		o.require(fmt.Sprintf("To close %s to the internet as %s was: in the organization's access policy, create a VPC Service Controls perimeter (accessPolicies/<policy>/servicePerimeters) whose resources are the target project (projects/<project number>) and whose restrictedServices hold %s; requests from the project's own networks (%s) are inside it. It closes that service for the whole project, management calls included: add an ingress rule for whoever restores and captures from outside, and try it first as a dry run (useExplicitDryRunSpec)", what, private, api, strings.Join(rs, ", ")))
	} else {
		o.require(fmt.Sprintf("To close %s to the internet as %s was: in the organization's access policy, create a VPC Service Controls perimeter (accessPolicies/<policy>/servicePerimeters) whose resources are the target project (projects/<project number>) and whose restrictedServices hold %s. It closes that service for the whole project, management calls included: add an ingress rule for whoever restores and captures from outside, and try it first as a dry run (useExplicitDryRunSpec)", what, private, api))
	}
	return fmt.Sprintf("%s answers on Google's public endpoint to whoever IAM allows: it has no network setting of its own, and the VPC Service Controls perimeter that would close it (%s for the whole project; %s) is the organization's to create, and is not written", what, api, from)
}
