package access

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/usetruthform/core/internal/readonly"
)

// awsNeeds are the calls a capture cannot do without; awsWrites are a
// sample of writes across the services a role should not be able to touch
// when it only captures. A sample, not a proof of read-only: the proof is
// the capture-only binary, which cannot send a write at all.
var (
	awsNeeds  = []string{"cloudformation:ListResources", "cloudformation:GetResource", "sts:GetCallerIdentity"}
	awsWrites = []string{
		"cloudformation:CreateResource", "cloudformation:UpdateResource", "cloudformation:DeleteResource",
		"iam:CreateRole", "iam:AttachRolePolicy", "iam:CreateAccessKey",
		"s3:PutBucketPolicy", "s3:DeleteBucket", "ec2:RunInstances", "ec2:TerminateInstances",
		"kms:ScheduleKeyDeletion", "organizations:CreateAccount",
	}
	awsRestore = []string{"cloudformation:CreateResource", "cloudformation:UpdateResource", "cloudformation:GetResourceRequestStatus"}
)

// AWS reports the identity a profile resolves to. access is what it is
// for: capture (then any write is more than needed) or restore.
func AWS(ctx context.Context, profile, region, access string) (Report, error) {
	r := Report{Platform: "aws"}
	opts := []func(*config.LoadOptions) error{config.WithRegion(region), config.WithHTTPClient(readonly.Client())}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return r, fmt.Errorf("aws config: %w", err)
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return r, fmt.Errorf("aws credentials: %w", err)
	}
	switch {
	case strings.HasPrefix(creds.AccessKeyID, "AKIA"):
		r.warn("Long-lived access key (" + creds.Source + "). It works until someone deletes it; a role through SSO or an assumed role expires on its own.")
	case creds.CanExpire:
		r.fact(fmt.Sprintf("Temporary credentials (%s), expiring %s", creds.Source, creds.Expires.UTC().Format("2006-01-02 15:04 MST")))
	default:
		r.fact("Credentials from " + creds.Source)
	}
	id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return r, fmt.Errorf("who am I (sts:GetCallerIdentity): %w", err)
	}
	arn, account := aws.ToString(id.Arn), aws.ToString(id.Account)
	r.Who = arn
	r.fact("Account " + account)

	source := ""
	ic := iam.NewFromConfig(cfg)
	switch {
	case strings.HasSuffix(arn, ":root"):
		r.Kind = "root user"
		r.warn("This is the account's root user: it holds every permission, and no policy can limit it. Use the role from truthform permissions --platform aws instead.")
		return r, nil
	case strings.Contains(arn, ":user/"):
		r.Kind, source = "IAM user", arn
	case strings.Contains(arn, ":assumed-role/"):
		r.Kind = "assumed role"
		// The session ARN has no path; the simulator needs the role's own.
		name := strings.Split(strings.SplitN(arn, ":assumed-role/", 2)[1], "/")[0]
		got, err := ic.GetRole(ctx, &iam.GetRoleInput{RoleName: &name})
		if err != nil {
			r.unchecked("What the role may do: iam:GetRole " + name + " refused: " + short(err))
			return r, nil
		}
		source = aws.ToString(got.Role.Arn)
		r.fact("Role " + source)
	default:
		r.Kind = "other (" + arn + ")"
		r.unchecked("What this identity may do: IAM's policy simulator takes users and roles only")
		return r, nil
	}

	actions := append(append(append([]string{}, awsNeeds...), awsWrites...), awsRestore...)
	allowed := map[string]bool{}
	var tok *string
	for {
		out, err := ic.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{PolicySourceArn: &source, ActionNames: dedupe(actions), Marker: tok})
		if err != nil {
			r.unchecked("What it may do beyond reading: iam:SimulatePrincipalPolicy refused: " + short(err))
			return r, nil
		}
		for _, e := range out.EvaluationResults {
			allowed[aws.ToString(e.EvalActionName)] = e.EvalDecision == "allowed"
		}
		if !out.IsTruncated {
			break
		}
		tok = out.Marker
	}
	r.fact("Permissions from IAM's policy simulator, for all resources: the identity's own policies. Resource policies (bucket and key policies) and organization policies are not part of this result.")
	for _, a := range awsNeeds {
		if !allowed[a] {
			r.warn(a + " is not allowed: a capture needs it")
		}
	}
	var writes []string
	for _, a := range awsWrites {
		if allowed[a] {
			writes = append(writes, a)
		}
	}
	switch {
	case access == "restore":
		for _, a := range awsRestore {
			if !allowed[a] {
				r.warn(a + " is not allowed: a restore needs it")
			}
		}
		if len(writes) > 0 {
			r.fact("May write, as a restore needs: " + strings.Join(writes, ", "))
		}
	case len(writes) > 0:
		r.warn("May write (" + strings.Join(writes, ", ") + "): more than a capture needs. Capture with the read-only role from truthform permissions, or at least with the capture-only binary.")
	default:
		r.fact("None of " + fmt.Sprint(len(awsWrites)) + " sampled writes is allowed")
	}
	return r, nil
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// short is an error's message without the SDK's request IDs.
func short(err error) string {
	s := err.Error()
	if i := strings.Index(s, "api error "); i >= 0 {
		s = s[i+len("api error "):]
	}
	return s
}
