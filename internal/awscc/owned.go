package awscc

import "strings"

// Cloud Control lists what an account can see, not only what it owns. The
// first full capture of a near-empty account (us-east-2, 2026-10-21) came
// back with 2,391 resources, of which about 2,300 were AWS's own: 1,226
// AWS-managed IAM policies, 825 AWS-published SSM documents, 127 RAM
// permissions, MediaLive templates, default parameter groups. Captured,
// they read as the customer's configuration, and a restore would try to
// recreate them. They are skipped as AWS-owned, by two rules.

// OwnedByAWS is the reason recorded for every such skip.
const OwnedByAWS = "owned by AWS, the same in every account: "

// OtherAccount is the reason for resources another account owns.
const OtherAccount = "owned by another account (AWS's own, or shared into this one): "

// otherAccount reports an ARN naming a 12-digit account other than the one
// being read: AWS's own (the default SSM patch baselines belong to account
// 733109147000) or a resource shared into this account from another. Either
// way it is not this account's to capture or restore.
func otherAccount(s, account string) string {
	p := strings.SplitN(s, ":", 6)
	if len(p) == 6 && p[0] == "arn" && isAccountID(p[4]) && p[4] != account {
		return p[4]
	}
	return ""
}

// awsOwnedARN reports an ARN in AWS's own namespace: the account field is
// "aws" (arn:aws:iam::aws:policy/..., arn:aws:ec2:us-east-2:aws:prefix-list/
// ...), or it is empty while the region is set (arn:aws:medialive:us-east-2::
// ...). A customer's resource always carries its 12-digit account; S3
// bucket ARNs have an empty account but an empty region too, so they are
// not matched.
func awsOwnedARN(s string) bool {
	p := strings.SplitN(s, ":", 6)
	if len(p) != 6 || p[0] != "arn" {
		return false
	}
	return p[4] == "aws" || (p[4] == "" && p[3] != "")
}

// reservedPrefixes are name prefixes AWS reserves for its own resources of
// a type, so no customer resource can carry them. Matched case-insensitively
// against the identifier.
var reservedPrefixes = map[string][]string{
	// SSM refuses customer documents named aws*, amazon* or amzn*.
	"AWS::SSM::Document": {"aws", "amazon", "amzn"},
	// alias/aws/ is reserved for AWS-managed KMS keys.
	"AWS::KMS::Alias": {"alias/aws/"},
	// The built-in deployment configurations.
	"AWS::CodeDeploy::DeploymentConfig": {"codedeploydefault."},
	// Default parameter groups AWS provides per engine version.
	"AWS::ElastiCache::ParameterGroup": {"default."},
	"AWS::MemoryDB::ParameterGroup":    {"default."},
}

// ownedByID decides from the identifier alone, before a read, which keeps a
// full capture from spending thousands of throttled reads on AWS's content.
func ownedByID(typeName, id, account string) string {
	for _, part := range strings.Split(id, "|") {
		if awsOwnedARN(part) {
			return OwnedByAWS + "its ARN is in AWS's namespace"
		}
		if other := otherAccount(part, account); other != "" {
			return OtherAccount + other
		}
	}
	lower := strings.ToLower(id)
	for _, p := range reservedPrefixes[typeName] {
		if strings.HasPrefix(lower, p) {
			return OwnedByAWS + "the name prefix " + p + " is reserved by AWS"
		}
	}
	return ""
}

// ownedByProps decides after a read, from the resource's own ARN: only
// read-only properties, which describe the resource itself. A writable
// property ending in Arn is a reference, and a customer's resource pointing
// at an AWS-managed policy is still the customer's.
func ownedByProps(t *TypeInfo, props map[string]any, account string) string {
	for _, k := range sortedKeys(props) {
		s, ok := props[k].(string)
		if !ok || !t.IsReadOnly(k) || !(strings.HasSuffix(k, "Arn") || strings.HasSuffix(k, "ARN")) {
			continue
		}
		if awsOwnedARN(s) {
			return OwnedByAWS + "its " + k + " is in AWS's namespace"
		}
		if other := otherAccount(s, account); other != "" {
			return OtherAccount + other
		}
	}
	return ""
}
