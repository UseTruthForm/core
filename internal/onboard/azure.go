package onboard

import "fmt"

func buildAzure(r Request) (Plan, error) {
	var miss MissingError
	if r.Subscription == "" {
		miss = append(miss, Missing{"subscription", "the ID of the subscription StackDNA reads", "az account list --query '[].[id,name]' --output tsv"})
	}
	if r.PrincipalID == "" {
		miss = append(miss, Missing{"principal-id", "the object ID of the user, group or service principal that will run StackDNA",
			"az ad signed-in-user show --query id --output tsv   (yourself), or the Object ID on the service principal's Enterprise application page"})
	}
	if r.PrincipalType == "" {
		miss = append(miss, Missing{"principal-type", "User, Group or ServicePrincipal: what --principal-id is (Azure records it, and a wrong one fails or misleads later)", ""})
	}
	if len(miss) > 0 {
		return Plan{}, miss
	}
	if !guidRE.MatchString(r.Subscription) {
		return Plan{}, fmt.Errorf("--subscription: %q is not a subscription ID", r.Subscription)
	}
	if !guidRE.MatchString(r.PrincipalID) {
		return Plan{}, fmt.Errorf("--principal-id: %q is not an object ID", r.PrincipalID)
	}
	switch r.PrincipalType {
	case "User", "Group", "ServicePrincipal":
	default:
		return Plan{}, fmt.Errorf("--principal-type is User, Group or ServicePrincipal, not %q", r.PrincipalType)
	}
	loc := r.Location
	if loc == "" {
		loc = "eastus"
	}
	if !locationRE.MatchString(loc) {
		return Plan{}, fmt.Errorf("--location: %q is not an Azure region name", loc)
	}
	b, err := render("stackdna-azure.json", nil)
	if err != nil {
		return Plan{}, err
	}
	stack := "stackdna-reader"
	if r.Access == "restore" {
		stack = "stackdna-restorer"
	}
	sub := []string{"--subscription", r.Subscription}
	az := func(a ...string) string { return cmd(append(a, sub...)...) }
	roles := az("az", "role", "assignment", "list", "--assignee", r.PrincipalID, "--all", "--query", "[].roleDefinitionName", "--output", "tsv")

	p := Plan{Files: map[string][]byte{"stackdna-azure.json": b}}
	if r.Access == "restore" {
		p.Grants = []string{"Contributor on subscription " + r.Subscription + " for " + r.PrincipalID + ": create and change every resource",
			"User Access Administrator there: role assignments and locks, which Contributor cannot write"}
		p.Warnings = []string{"User Access Administrator can grant any role, Owner included: together with Contributor this is as much as Owner. Grant it for the restore and remove it afterwards."}
		p.Status = "Expected. Restores have run as the subscription's Owner, not with these two roles."
	} else {
		p.Grants = []string{"Reader on subscription " + r.Subscription + " for " + r.PrincipalID + ": every resource, role assignment, custom role, lock, policy assignment and diagnostic setting, read-only"}
		p.Status = "Verified (2026-10-23) for the role: a service principal holding only Reader captured the sandbox subscription to the same digest as its owner. This template has been checked with what-if, not yet deployed."
	}
	p.Before = []Step{
		{Title: "Check the administrator is signed in to subscription " + r.Subscription + " (it prints its ID)",
			Command: az("az", "account", "show", "--query", "id", "--output", "tsv")},
		{Title: "List the roles the principal already holds in it", Command: roles,
			Note: "StackDNA's grant is added beside these, never in place of them. If it already holds more than this grant, it does not need this one."},
		{Title: "Check no StackDNA stack is there already (expect DeploymentStackNotFound)", Command: az("az", "stack", "sub", "show", "--name", stack)},
	}
	p.Grant = []Step{{
		Title: "Deploy the role assignments as a deployment stack",
		Command: az("az", "stack", "sub", "create", "--name", stack, "--location", loc, "--template-file", file(r, "stackdna-azure.json"),
			"--parameters", "principalId="+r.PrincipalID, "principalType="+r.PrincipalType, "access="+r.Access,
			"--action-on-unmanage", "deleteAll", "--deny-settings-mode", "none"),
		Note: "A deployment stack, not a plain deployment: deleting a deployment leaves its role assignments behind; deleting this stack removes them.",
	}}
	p.Verify = []Step{
		{Title: "List the principal's roles again: the granted ones are there now", Command: roles},
		{Title: "Signed in as the principal, check what it can read, type by type",
			Command: cmd("stackdna", "check", "--platform", "azure", "--subscription", r.Subscription, "--access", r.Access)},
	}
	p.Undo = []Step{
		{Title: "Delete the stack and the role assignments it made", Command: az("az", "stack", "sub", "delete", "--name", stack, "--action-on-unmanage", "deleteAll", "--yes")},
		{Title: "List the principal's roles: the granted ones are gone", Command: roles},
	}
	return p, nil
}
