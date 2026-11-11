package onboard

import (
	"fmt"
	"strings"
)

func buildGCP(r Request) (Plan, error) {
	var miss MissingError
	if r.Project == "" {
		miss = append(miss, Missing{"project", "the ID of the project Truthform reads", "gcloud projects list --format 'value(projectId)'"})
	}
	if r.Member == "" {
		miss = append(miss, Missing{"member", "who will run Truthform, as IAM writes it: user:EMAIL, serviceAccount:EMAIL or group:EMAIL",
			"gcloud config get-value account   (yourself)"})
	}
	if len(miss) > 0 {
		return Plan{}, miss
	}
	if !projectRE.MatchString(r.Project) {
		return Plan{}, fmt.Errorf("--project: %q is not a project ID", r.Project)
	}
	if !memberRE.MatchString(r.Member) {
		return Plan{}, fmt.Errorf("--member: %q is not user:EMAIL, serviceAccount:EMAIL or group:EMAIL", r.Member)
	}
	tf, err := render("truthform-gcp.tf", nil)
	if err != nil {
		return Plan{}, err
	}
	vars := fmt.Sprintf("project = %q\nmember  = %q\naccess  = %q\n", r.Project, r.Member, r.Access)
	p := Plan{Files: map[string][]byte{"truthform-gcp.tf": tf, "terraform.tfvars": []byte(vars)}}
	dir := strings.TrimSuffix(file(r, "x"), "/x")
	tfc := func(a ...string) string { return cmd(append([]string{"terraform", "-chdir=" + dir}, a...)...) }
	roles := cmd("gcloud", "projects", "get-iam-policy", r.Project, "--flatten", "bindings[].members",
		"--filter", "bindings.members:"+r.Member, "--format", "value(bindings.role)")

	if r.Access == "restore" {
		p.Grants = []string{"roles/editor, roles/iam.serviceAccountAdmin, roles/iam.roleAdmin and roles/cloudasset.viewer on project " + r.Project + " for " + r.Member}
		p.Warnings = []string{"Restore access writes, and roles/iam.serviceAccountAdmin can act on every service account in the project. Grant it for the restore and remove it afterwards."}
		p.Status = "Expected. Restores have run as the project's owner, not with these roles."
	} else {
		p.Grants = []string{"roles/viewer and roles/cloudasset.viewer on project " + r.Project + " for " + r.Member + ", read-only",
			"The Cloud Asset and Cloud Resource Manager APIs enabled in the project if they are not (removing Truthform's access leaves them on)"}
		p.Status = "Verified (2026-10-23) for the roles: a service account holding exactly these captured the sandbox project to the same digest as its owner. This Terraform has been validated, not yet applied."
	}
	p.Warnings = append(p.Warnings, "Keep "+dir+" after applying: the Terraform state in it is what destroy reads. Without it the grants stay until removed by hand.")
	if strings.HasPrefix(r.Member, "group:") {
		p.Warnings = append(p.Warnings, "A group grant reaches whoever is added to the group later. truthform check cannot see group membership; it reports the roles granted to the identity directly.")
	}
	p.Before = []Step{
		{Title: "Check the administrator can see project " + r.Project + " (it prints its ID)", Command: cmd("gcloud", "projects", "describe", r.Project, "--format", "value(projectId)")},
		{Title: "List the roles " + r.Member + " already holds in it", Command: roles,
			Note: "Truthform's grant is added beside these, never in place of them."},
	}
	p.Grant = []Step{
		{Title: "Fetch the Google provider", Command: tfc("init")},
		{Title: "Apply: it shows what it will grant and asks before granting it", Command: tfc("apply")},
	}
	p.Verify = []Step{
		{Title: "List the roles again: the granted ones are there now", Command: roles},
		{Title: "As " + r.Member + ", check what it can read, type by type", Command: cmd("truthform", "check", "--platform", "gcp", "--project", r.Project, "--access", r.Access)},
	}
	p.Undo = []Step{
		{Title: "Remove the grants (the APIs stay enabled)", Command: tfc("destroy")},
		{Title: "List the roles: the granted ones are gone", Command: roles},
	}
	return p, nil
}
