package onboard

import (
	"fmt"
	"strings"
)

func buildAWS(r Request) (Plan, error) {
	var miss MissingError
	if r.Account == "" {
		miss = append(miss, Missing{"account", "the 12-digit ID of the account StackDNA reads (the role is created there)",
			"aws sts get-caller-identity --query Account --output text   (run with the administrator's credentials for that account)"})
	}
	if r.Principal == "" {
		miss = append(miss, Missing{"principal", "the ARN of the IAM user or role that will run StackDNA and assume the new role",
			"aws sts get-caller-identity --query Arn --output text   (run with that identity's credentials)"})
	}
	if len(miss) > 0 {
		return Plan{}, miss
	}
	var warn []string
	if !accountRE.MatchString(r.Account) {
		return Plan{}, fmt.Errorf("--account: %q is not a 12-digit AWS account ID", r.Account)
	}
	principal := r.Principal
	// get-caller-identity prints a session ARN for a role; the trust
	// needs the role. Its path is not in a session ARN, so a role with one
	// must be given in full.
	if m := sessionARNRE.FindStringSubmatch(principal); m != nil {
		principal = fmt.Sprintf("arn:%s:iam::%s:role/%s", m[1], m[2], m[3])
		warn = append(warn, fmt.Sprintf("--principal was a role session; the trust names the role, %s. If the role has a path, give its ARN from: aws iam get-role --role-name %s --query Role.Arn --output text", principal, m[3]))
	}
	m := iamARNRE.FindStringSubmatch(principal)
	if m == nil {
		return Plan{}, fmt.Errorf("--principal: %q is not the ARN of an IAM user or role (arn:aws:iam::<account>:user/<name> or :role/<name>)", r.Principal)
	}
	if m[2] == "root" {
		warn = append(warn, "--principal names a whole account: every user and role there that may call sts:AssumeRole could use this role. Name the one user or role that runs StackDNA.")
	}
	if m[1] != r.Account && r.ExternalID == "" {
		warn = append(warn, fmt.Sprintf("The principal is in another account (%s). Agree an external ID with whoever runs StackDNA and pass it with --external-id: it stops anyone else that account acts for from using this role.", m[1]))
	}
	if r.ExternalID != "" && (len(r.ExternalID) < 2 || len(r.ExternalID) > 1224 || !externalIDRE.MatchString(r.ExternalID)) {
		return Plan{}, fmt.Errorf("--external-id: 2 to 1224 letters, digits or + = , . @ : / - _")
	}
	region := r.Region
	if region == "" {
		region = "us-east-1"
	}
	if !regionRE.MatchString(region) {
		return Plan{}, fmt.Errorf("--region: %q is not an AWS region name", region)
	}
	for flag, v := range map[string]string{"source-profile": r.SourceProfile, "admin-profile": r.AdminProfile} {
		if v != "" && !profileRE.MatchString(v) {
			return Plan{}, fmt.Errorf("--%s: %q is not a profile name StackDNA can put in a command (letters, digits, . _ -)", flag, v)
		}
	}

	role := "stackdna-reader"
	if r.Access == "restore" {
		role = "stackdna-restorer"
	}
	partition := strings.SplitN(principal, ":", 3)[1]
	roleARN := fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, r.Account, role)
	admin := func(a ...string) string {
		if r.AdminProfile != "" {
			a = append(a, "--profile", r.AdminProfile)
		}
		return cmd(a...)
	}
	b, err := render("stackdna-aws.yaml", nil)
	if err != nil {
		return Plan{}, err
	}
	tpl := file(r, "stackdna-aws.yaml")

	p := Plan{Files: map[string][]byte{"stackdna-aws.yaml": b}, Warnings: warn}
	trust := "assumable by " + principal
	if r.ExternalID != "" {
		trust += " with the agreed external ID"
	}
	p.Grants = []string{fmt.Sprintf("IAM role %s in account %s, %s, holding AWS's managed ReadOnlyAccess", roleARN, r.Account, trust)}
	if r.Access == "restore" {
		p.Grants = append(p.Grants, "and AWS's managed PowerUserAccess: create, change and delete every service's resources except IAM and Organizations, and create service-linked roles")
		p.Warnings = append(p.Warnings, "Restore access writes. Grant it for the restore and remove it afterwards; capture and diff need only the capture role.",
			"IAM roles and policies in a snapshot are not restorable with this role: add an IAM grant scoped to the names being restored (docs/permissions.md).")
	} else {
		p.Grants = append(p.Grants, "Nothing that writes. Run StackDNA's capture-only binary with it too: one that cannot send a write at all.")
		p.Warnings = append(p.Warnings, "ReadOnlyAccess reads data as well as configuration: S3 objects, DynamoDB items, queue messages. StackDNA reads configuration only and never writes data to a snapshot, but whoever holds this role could read the data.")
	}
	if r.Access == "restore" {
		p.Status = "Expected. PowerUserAccess restored the drill's 14 types, held by a user, not through this role."
	} else {
		p.Status = "Expected. Captures have run with ReadOnlyAccess and PowerUserAccess together; this role, holding ReadOnlyAccess alone, has not yet captured an account."
	}

	p.Before = []Step{
		{Title: "Check the administrator's credentials are for account " + r.Account + " (it prints the account ID)",
			Command: admin("aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text")},
		{Title: "Check the role is not there already (expect NoSuchEntity)",
			Command: admin("aws", "iam", "get-role", "--role-name", role),
			Note:    "If it is, find out who made it and why before replacing it."},
	}
	params := []string{"TrustedPrincipalArn=" + principal, "Access=" + r.Access, "RoleName=" + role}
	if r.ExternalID != "" {
		params = append(params, "ExternalId="+r.ExternalID)
	}
	p.Grant = []Step{
		{Title: "Deploy the role as a CloudFormation stack",
			Command: admin(append([]string{"aws", "cloudformation", "deploy", "--stack-name", role, "--template-file", tpl,
				"--capabilities", "CAPABILITY_NAMED_IAM", "--region", region, "--parameter-overrides"}, params...)...)},
	}
	if r.SourceProfile != "" {
		set := func(k, v string) Step {
			return Step{Title: "Profile " + role + ": " + k, Command: cmd("aws", "configure", "set", k, v, "--profile", role)}
		}
		p.Verify = append(p.Verify, set("role_arn", roleARN), set("source_profile", r.SourceProfile), set("region", region))
		if r.ExternalID != "" {
			p.Verify = append(p.Verify, set("external_id", r.ExternalID))
		}
		p.Verify = append(p.Verify, Step{Title: "Check what the role can read, type by type, and that it can write nothing it should not",
			Command: cmd("stackdna", "check", "--platform", "aws", "--region", region, "--profile", role, "--access", r.Access)})
	} else {
		p.Verify = append(p.Verify, Step{Title: "Use the role from a profile that assumes it (role_arn " + roleARN + ", source_profile set to the principal's own profile), then run stackdna check --platform aws with that profile",
			Note: "Pass --source-profile with the principal's profile name to have these commands written out in full."})
	}
	p.Undo = []Step{
		{Title: "Delete the stack, which deletes the role", Command: admin("aws", "cloudformation", "delete-stack", "--stack-name", role, "--region", region)},
		{Title: "Wait for it to finish", Command: admin("aws", "cloudformation", "wait", "stack-delete-complete", "--stack-name", role, "--region", region)},
		{Title: "Check the role is gone (expect NoSuchEntity)", Command: admin("aws", "iam", "get-role", "--role-name", role)},
	}
	if r.SourceProfile != "" {
		p.Undo = append(p.Undo, Step{Title: "Remove the [profile " + role + "] section from the AWS config file (aws configure has no command to delete a profile)"})
	}
	return p, nil
}
