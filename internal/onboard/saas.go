package onboard

import (
	"fmt"
	"strings"
)

// tokenNote says how to put a token in the environment without it landing
// in the shell's history or on screen. It is the one step that differs by
// shell, so it is a note naming each, not a command.
func tokenNote(env string) string {
	// Not Read-Host -MaskInput: Windows PowerShell 5.1 has no such
	// parameter, takes it as prompt text and echoes the token (review of
	// #23). -AsSecureString masks on 5.1 and 7 alike.
	return fmt.Sprintf("Set %s without echoing it. PowerShell: $env:%s = [Net.NetworkCredential]::new('', (Read-Host -AsSecureString 'token')).Password   bash/zsh: read -rs %s && export %s", env, env, env, env)
}

func buildGitHub(r Request) (Plan, error) {
	if r.Account == "" {
		return Plan{}, MissingError{{"account", "the GitHub organisation Truthform reads", ""}}
	}
	if !orgRE.MatchString(r.Account) {
		return Plan{}, fmt.Errorf("--account: %q is not a GitHub organisation name", r.Account)
	}
	level := "Read-only"
	if r.Access == "restore" {
		level = "Read and write"
	}
	perms := "Organization: Administration, Custom properties, Webhooks, Secrets, Variables, Self-hosted runners, Actions policies. Repository: Administration, Actions, Environments, Secrets, Variables, Webhooks, Pages, Metadata."
	p := Plan{
		Grants: []string{"A fine-grained personal access token, resource owner " + r.Account + ", all repositories, " + strings.ToLower(level) + ": " + perms},
		Status: "Partly verified: a classic token without admin:org was refused exactly the ten organisation collections above, each reported as failed. A capture with this fine-grained token has not been run.",
	}
	p.Before = []Step{
		{Title: "Check the organisation lets fine-grained tokens in, and whether it must approve them: https://github.com/organizations/" + r.Account + "/settings/personal-access-tokens"},
	}
	p.Grant = []Step{
		{Title: "Create the token at https://github.com/settings/personal-access-tokens/new",
			Note: "Resource owner " + r.Account + "; Repository access: All repositories; each permission above set to " + level + "; an expiry, 90 days or less. A classic token would need repo and admin:org, which both write."},
	}
	p.Verify = []Step{
		{Title: "Put the token in the environment", Note: tokenNote("GITHUB_TOKEN")},
		{Title: "Check what it can read, type by type", Command: cmd("truthform", "check", "--platform", "github", "--account", r.Account, "--access", r.Access)},
	}
	p.Undo = []Step{{Title: "Delete the token at https://github.com/settings/personal-access-tokens"}}
	return p, nil
}

func buildCloudflare(r Request) (Plan, error) {
	if r.Account == "" {
		return Plan{}, MissingError{{"account", "the Cloudflare account ID Truthform reads (32 hex digits)", "the Account ID on the account's overview page in the Cloudflare dashboard"}}
	}
	if !cfAccountRE.MatchString(r.Account) {
		return Plan{}, fmt.Errorf("--account: %q is not a Cloudflare account ID (32 hex digits)", r.Account)
	}
	level := "Read"
	if r.Access == "restore" {
		level = "Edit"
	}
	p := Plan{
		Grants: []string{"An API token with Zone: " + level + " and DNS: " + level + ", for every zone in account " + r.Account},
		Status: "Expected. Truthform has not yet been run against Cloudflare.",
	}
	p.Grant = []Step{
		{Title: "Create a custom token at https://dash.cloudflare.com/profile/api-tokens",
			Note: "Permissions: Zone / Zone / " + level + " and Zone / DNS / " + level + ". Zone resources: Include, All zones from an account, " + r.Account + ". Set an end date."},
	}
	p.Verify = []Step{
		{Title: "Put the token in the environment", Note: tokenNote("CLOUDFLARE_API_TOKEN")},
		{Title: "Check what it can read, type by type", Command: cmd("truthform", "check", "--platform", "cloudflare", "--account", r.Account, "--access", r.Access)},
	}
	p.Undo = []Step{{Title: "Delete the token at https://dash.cloudflare.com/profile/api-tokens"}}
	return p, nil
}
