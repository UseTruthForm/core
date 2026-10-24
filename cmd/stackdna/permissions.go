package main

import (
	"flag"
	"fmt"

	"github.com/stackdna/core/internal/onboard"
)

// permissionsCmd prints what to grant StackDNA on a platform and the
// commands to grant, verify and remove it, with the values given filled
// in. It grants nothing: the administrator runs the commands. --write puts
// the template files where the commands expect them.
func permissionsCmd(args []string) int {
	fs := flag.NewFlagSet("permissions", flag.ContinueOnError)
	r, write := permissionFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return fail(err)
	}
	if fs.NArg() > 0 {
		return fail(fmt.Errorf("permissions takes no positional arguments"))
	}
	if *write != "" {
		r.Dir, r.Written = *write, true
	}
	p, err := onboard.Build(*r)
	if err != nil {
		return fail(err)
	}
	if *write != "" {
		wrote, err := p.Write(*write)
		for _, w := range wrote {
			fmt.Println("wrote", w)
		}
		if err != nil {
			return fail(err)
		}
		fmt.Println()
	}
	if jsonOut {
		files := map[string]string{}
		for k, v := range p.Files {
			files[k] = string(v)
		}
		emit(map[string]any{"schema": jsonSchema, "command": "permissions", "plan": p, "files": files})
		return 0
	}
	fmt.Print(p.Text())
	return 0
}

func permissionFlags(fs *flag.FlagSet) (*onboard.Request, *string) {
	r := &onboard.Request{}
	s := func(p *string, name, usage string) { fs.StringVar(p, name, "", usage) }
	s(&r.Platform, "platform", "aws, azure, gcp, kubernetes, github or cloudflare")
	fs.StringVar(&r.Access, "access", "capture", "capture (read-only) or restore (writes)")
	s(&r.Account, "account", "aws: the account ID the role goes in; github: the organisation; cloudflare: the account ID")
	s(&r.Principal, "principal", "aws: ARN of the IAM user or role that runs StackDNA")
	s(&r.ExternalID, "external-id", "aws: external ID the trust requires (for a principal in another account)")
	s(&r.Region, "region", "aws: region of the CloudFormation stack (default us-east-1)")
	s(&r.SourceProfile, "source-profile", "aws: the principal's profile, to write the commands that set up a profile for the role")
	s(&r.AdminProfile, "admin-profile", "aws: the profile the administrator deploys with")
	s(&r.Subscription, "subscription", "azure: subscription ID")
	s(&r.PrincipalID, "principal-id", "azure: object ID of the user, group or service principal")
	s(&r.PrincipalType, "principal-type", "azure: User, Group or ServicePrincipal")
	s(&r.Location, "location", "azure: region of the deployment stack (default eastus)")
	s(&r.Project, "project", "gcp: project ID")
	s(&r.Member, "member", "gcp: user:EMAIL, serviceAccount:EMAIL or group:EMAIL")
	s(&r.Context, "context", "kubernetes: the administrator's kubeconfig context")
	s(&r.Subject, "subject", "kubernetes: User:NAME, Group:NAME or ServiceAccount:NAMESPACE/NAME")
	write := fs.String("write", "", "write the template files into this directory")
	return r, write
}
