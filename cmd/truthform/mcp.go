package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/usetruthform/core/internal/awscc"
	"github.com/usetruthform/core/internal/azarm"
	"github.com/usetruthform/core/internal/describe"
	"github.com/usetruthform/core/internal/gcp"
	"github.com/usetruthform/core/internal/mcp"
	"github.com/usetruthform/core/internal/onboard"
	"github.com/usetruthform/core/internal/saas"
)

// mcpCmd serves Truthform's tools to an agent over MCP on stdin and stdout.
// No tool writes to a cloud: describing types reads public schemas, and
// capture and diff run through the read-only guard, as they always do.
// capture writes a snapshot to local disk, into a new or empty directory
// only, so it is not marked read-only; nothing else writes at all.
// There is deliberately no restore tool. A restore creates and changes
// live resources; that stays a command a person runs, with the snapshot
// and the plan in front of them.
func mcpCmd(ctx context.Context, args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "mcp: takes no arguments; it serves on stdin and stdout")
		return 1
	}
	s := &mcp.Server{Name: "truthform", Version: version, Instructions: mcpInstructions, Tools: mcpTools()}
	if err := s.Serve(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		return 1
	}
	return 0
}

const mcpInstructions = `Truthform captures the live configuration of AWS, Azure, GCP, Kubernetes, GitHub and Cloudflare into deterministic snapshots, and diffs them against what is running.

Use describe_type before writing configuration: it says which fields a resource type takes, which are required, which the platform sets (read-only), which are never returned (write-only, secret), and which are fixed at creation, with the platform's own documentation links. These come from the same schemas Truthform captures and restores with.

capture and diff only read (the read-only guard refuses any write). They use the credentials of the environment this server runs in. There is no restore tool: restoring changes live resources and is run by a person with the CLI.

Setting up access: permissions gives the template and every command to grant Truthform access, with the person's values filled in; check_access then shows who Truthform runs as and what it can read. Neither grants anything. Follow docs/agents.md: look at what is there before granting, let the person run the grant, never hand over a command with a placeholder in it, and verify with check_access, not with the grant's exit code.

Planning a restore: report and a diff into the target, with --json, say what it needs. Read the report's sections on what will not come back, references to other subscriptions and access a restore needs outside its target (access_elsewhere in the diff document), and follow "Planning a restore" in docs/agents.md. The person decides each grant, each object left out and when the restore runs.

For building and changing resources, use the platform's own MCP server alongside this one; platforms lists them.`

// companions are the platforms' own MCP servers, checked 2026-10-22 on
// each provider's repository. Truthform says what exists and what each
// field means; these act on the platform.
var companions = map[string][]string{
	"aws":        {"AWS MCP Server (remote, in preview), AWS IaC MCP Server, AWS Documentation MCP Server: https://github.com/awslabs/mcp (the Cloud Control API MCP Server there is deprecated in favour of the IaC server)"},
	"azure":      {"Azure MCP Server: https://github.com/microsoft/mcp (servers/Azure.Mcp.Server)"},
	"gcp":        {"Google-managed remote servers (Compute Engine, GKE, Cloud Run, Cloud Storage, Resource Manager) and the gcloud MCP server: https://github.com/google/mcp (the repository notes it is not an officially supported Google product)"},
	"github":     {"GitHub's official MCP server: https://github.com/github/github-mcp-server (remote: https://api.githubcopilot.com/mcp/; --read-only mode)"},
	"cloudflare": {"Cloudflare API MCP Server: https://mcp.cloudflare.com/mcp (https://github.com/cloudflare/mcp-server-cloudflare)"},
	"kubernetes": {"No single official server; kubectl and the cluster's API are the reference."},
}

func mcpTools() []mcp.Tool {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	obj := func(req []string, props map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": req}
	}
	platform := str("aws, azure, gcp, github or cloudflare (kubernetes for capture and diff)")
	target := map[string]any{
		"platform": platform, "region": str("aws: the region"), "profile": str("aws: the shared-config profile"),
		"subscription": str("azure: the subscription ID"), "project": str("gcp: the project ID"),
		"account": str("github: the organisation; cloudflare: the account ID"),
		"context": str("kubernetes: the kubeconfig context"), "types": str("type patterns to limit to, e.g. 'AWS::S3::*'"),
		"baseline": str("snapshot directory (or comma-separated, one per region) of what a fresh account holds"),
		"parallel": str("aws, azure, gcp: API calls in flight at once; lower it if the platform throttles"),
	}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range target {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	return []mcp.Tool{
		{Name: "platforms", ReadOnly: true, Schema: obj(nil, map[string]any{}),
			Description: "What Truthform covers on each platform, and each platform's own MCP server to use alongside it.",
			Call:        func(context.Context, map[string]any) (string, error) { return platformsText(), nil }},
		{Name: "list_types", ReadOnly: true,
			Description: "List the resource types Truthform knows on a platform, from the platform's published schemas. gcp lists one API's collections.",
			Schema: obj([]string{"platform"}, map[string]any{"platform": platform, "filter": str("case-insensitive substring to keep"),
				"region": str("aws: whose schema bundle (default us-east-1)"), "api": str("gcp: the API (iam, compute, monitoring...)"),
				"version": str("gcp: the API version (default v1)")}),
			Call: listTypes},
		{Name: "describe_type", ReadOnly: true,
			Description: "Describe a resource type: every field, which are required, read-only (set by the platform), write-only, secret, or fixed at creation, and the platform's documentation links.",
			Schema: obj([]string{"platform", "type"}, map[string]any{"platform": platform,
				"type":    str("aws: AWS::SQS::Queue; azure: Microsoft.Network/virtualNetworks; gcp: a collection (projects.serviceAccounts); github/cloudflare: a kind (github/label)"),
				"version": str("azure: API version (default newest); gcp: API version (default v1)"), "api": str("gcp: the API (iam, compute...)"),
				"region": str("aws: whose schema bundle (default us-east-1)"), "max_depth": map[string]any{"type": "integer", "description": "field path depth (default 3)"}}),
			Call: describeType},
		{Name: "capture",
			Description: "Capture a live account, subscription, project, cluster or organisation into a new snapshot directory. Reads the target only; writes the snapshot and its REPORT.md to local disk. Returns the summary.",
			Schema:      obj([]string{"platform", "out"}, with(map[string]any{"out": str("directory to write the snapshot to; must not exist yet, or be empty")})),
			Call: func(ctx context.Context, a map[string]any) (string, error) {
				// The CLI replaces an existing snapshot in place; an agent
				// must not be able to wipe one (a baseline, a golden copy)
				// that way.
				if ents, err := os.ReadDir(arg(a, "out", "")); err == nil && len(ents) > 0 {
					return "", fmt.Errorf("%s exists and is not empty; capture writes only into a new or empty directory", arg(a, "out", ""))
				}
				return runTruthform(ctx, "capture", a, "out")
			}},
		{Name: "diff", ReadOnly: true,
			Description: "Compare a live target with a snapshot, read-only. Exit 0 means no differences, 2 means differences (listed).",
			Schema: obj([]string{"platform", "from"}, with(map[string]any{"from": str("the snapshot directory to compare with"),
				"rename":                  str("azure: file of new names, to compare a snapshot with where it was restored under them"),
				"leave-out":               str("azure: file listing the objects it was restored without"),
				"new-role-assignment-ids": str("azure: true if it was restored with --new-role-assignment-ids")})),
			Call: func(ctx context.Context, a map[string]any) (string, error) {
				return runTruthform(ctx, "diff", a, "from")
			}},
		{Name: "permissions", ReadOnly: true,
			Description: "What to grant Truthform on a platform, for capture (read-only) or restore: the template to deploy, every command to check what is there, grant it, verify it and remove it, with the given values filled in, and what has been verified. Grants nothing. A value it needs and was not given is an error saying how to find it: ask the person for it, never substitute a placeholder.",
			Schema: obj([]string{"platform"}, map[string]any{
				"platform": str("aws, azure, gcp, kubernetes, github or cloudflare"), "access": str("capture (default) or restore"),
				"account":   str("aws: the account ID the role goes in; github: the organisation; cloudflare: the account ID"),
				"principal": str("aws: ARN of the IAM user or role that will run Truthform"), "external_id": str("aws: external ID for a principal in another account"),
				"region": str("aws: region of the CloudFormation stack"), "source_profile": str("aws: the principal's shared-config profile"),
				"admin_profile": str("aws: the administrator's profile"), "subscription": str("azure: subscription ID"),
				"principal_id": str("azure: object ID"), "principal_type": str("azure: User, Group or ServicePrincipal"),
				"location": str("azure: deployment stack region"), "project": str("gcp: project ID"),
				"member": str("gcp: user:EMAIL, serviceAccount:EMAIL or group:EMAIL"), "context": str("kubernetes: the administrator's kubeconfig context"),
				"subject": str("kubernetes: User:NAME, Group:NAME or ServiceAccount:NAMESPACE/NAME")}),
			Call: permissionsTool},
		{Name: "check_access", ReadOnly: true,
			Description: "Who Truthform runs as here, what that identity holds beyond what it needs (root, long-lived keys, write access for a capture), what could not be checked, and what it can read, type by type, from a trial capture written nowhere. DENIED types are refused for want of permission and are not empty. Exit 3 means some types cannot be read.",
			Schema:      obj([]string{"platform"}, with(map[string]any{"access": str("capture (default) or restore: what the identity is for")})),
			Call: func(ctx context.Context, a map[string]any) (string, error) {
				return runTruthform(ctx, "check", a, "platform")
			}},
		{Name: "report", ReadOnly: true,
			Description: "Read a snapshot's REPORT.md: what was captured, what was not and why, what a restore needs.",
			Schema:      obj([]string{"from"}, map[string]any{"from": str("the snapshot directory")}),
			Call:        readReport},
	}
}

func platformsText() string {
	var b strings.Builder
	b.WriteString("Truthform reads each platform's configuration through its published schemas and restores it from a snapshot.\n\n")
	for _, p := range []struct{ name, what string }{
		{"aws", "every Cloud Control type in the CloudFormation registry, one account and region"},
		{"azure", "every ARM type with a published definition, one subscription"},
		{"gcp", "resources Cloud Asset Inventory lists, driven by each API's Discovery document, one project"},
		{"kubernetes", "every API resource a cluster serves, CRDs included"},
		{"github", "an organisation's repositories, labels, webhooks, rulesets and the configuration collections GitHub's description groups as such"},
		{"cloudflare", "an account's zones and DNS records"},
	} {
		fmt.Fprintf(&b, "%s: %s\n  companion MCP server: %s\n", p.name, p.what, strings.Join(companions[p.name], "; "))
	}
	return b.String()
}

func cacheDir(sub string) (string, error) {
	c, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(c, "truthform", sub), nil
}

// arg reads a string, and also the number or boolean an agent may send for one:
// dropped, "parallel": 2 would have changed nothing, without a word.
func arg(a map[string]any, k, def string) string {
	switch v := a[k].(type) {
	case string:
		if v != "" {
			return v
		}
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return def
}

func listTypes(_ context.Context, a map[string]any) (string, error) {
	var names []string
	switch p := arg(a, "platform", ""); p {
	case "aws":
		dir, err := cacheDir("aws")
		if err != nil {
			return "", err
		}
		reg, err := awscc.LoadBundle(arg(a, "region", "us-east-1"), dir, 24*time.Hour)
		if err != nil {
			return "", err
		}
		names = reg.Names()
	case "azure":
		reg, err := azureRegistry()
		if err != nil {
			return "", err
		}
		names = reg.Names()
	case "gcp":
		api := arg(a, "api", "")
		if api == "" {
			return "", errors.New("gcp: give api (iam, compute, monitoring, logging...); each API's Discovery document lists its own collections")
		}
		docs, err := gcpDocs()
		if err != nil {
			return "", err
		}
		if names, err = docs.Collections(api, arg(a, "version", "v1")); err != nil {
			return "", err
		}
	case "github", "cloudflare":
		c, err := saasClient(p)
		if err != nil {
			return "", err
		}
		names = c.Kinds()
	default:
		return "", fmt.Errorf("unknown platform %q (aws, azure, gcp, github, cloudflare)", p)
	}
	f := strings.ToLower(arg(a, "filter", ""))
	var keep []string
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), f) {
			keep = append(keep, n)
		}
	}
	sort.Strings(keep)
	const most = 400
	note := ""
	if len(keep) > most {
		note = fmt.Sprintf("\n... and %d more; narrow with filter", len(keep)-most)
		keep = keep[:most]
	}
	return fmt.Sprintf("%d types\n%s%s", len(keep), strings.Join(keep, "\n"), note), nil
}

func describeType(_ context.Context, a map[string]any) (string, error) {
	depth := 3
	if v, ok := a["max_depth"].(float64); ok && v > 0 {
		depth = int(v)
	}
	typ := arg(a, "type", "")
	var d describe.Type
	var err error
	switch p := arg(a, "platform", ""); p {
	case "aws":
		dir, derr := cacheDir("aws")
		if derr != nil {
			return "", derr
		}
		reg, lerr := awscc.LoadBundle(arg(a, "region", "us-east-1"), dir, 24*time.Hour)
		if lerr != nil {
			return "", lerr
		}
		d, err = reg.Describe(typ)
		var kept []describe.Field
		for _, f := range d.Fields {
			if describe.Depth(f.Path) <= depth {
				kept = append(kept, f)
			}
		}
		d.Fields = kept
	case "azure":
		reg, rerr := azureRegistry()
		if rerr != nil {
			return "", rerr
		}
		d, err = reg.Describe(typ, arg(a, "version", ""), depth)
	case "gcp":
		docs, derr := gcpDocs()
		if derr != nil {
			return "", derr
		}
		d, err = docs.Describe(arg(a, "api", ""), arg(a, "version", "v1"), typ, depth)
	case "github", "cloudflare":
		c, cerr := saasClient(p)
		if cerr != nil {
			return "", cerr
		}
		d, err = c.Describe(typ, depth)
	default:
		return "", fmt.Errorf("unknown platform %q (aws, azure, gcp, github, cloudflare)", p)
	}
	if err != nil {
		return "", err
	}
	d.Notes = append(d.Notes, "Companion MCP server for building on "+d.Platform+": "+strings.Join(companions[d.Platform], "; "))
	b, err := json.MarshalIndent(d, "", " ")
	return string(b), err
}

func azureRegistry() (*azarm.Registry, error) {
	dir, err := cacheDir("azure")
	if err != nil {
		return nil, err
	}
	return azarm.FetchDefinitions(dir, 24*time.Hour)
}

func gcpDocs() (*gcp.Docs, error) {
	dir, err := cacheDir("gcp")
	if err != nil {
		return nil, err
	}
	return gcp.FetchDocs(dir, 24*time.Hour), nil
}

// saasClient reads the provider's description; describing needs no account
// and no token, and the client is read-only besides.
func saasClient(name string) (*saas.Client, error) {
	p := saas.Providers[name]
	dir, err := cacheDir("saas")
	if err != nil {
		return nil, err
	}
	spec, err := saas.FetchSpec(p, dir, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	return saas.NewClient(p, spec, "", "", true), nil
}

// mcpFlags are the only arguments each command is passed. Each is sent as
// --name=value, so a value can never become another flag, and the command
// itself is fixed by the tool: nothing an agent sends can turn a capture
// into a restore. Per command, because a flag the command does not define
// makes it exit 2 with its usage, which read as "differences found".
var mcpFlags = map[string][]string{
	"capture": {"platform", "region", "profile", "subscription", "project", "account", "context", "types", "baseline", "parallel", "out"},
	"diff":    {"platform", "region", "profile", "subscription", "project", "account", "context", "types", "baseline", "parallel", "rename", "leave-out", "new-role-assignment-ids", "from"},
	"check":   {"platform", "region", "profile", "subscription", "project", "account", "context", "types", "parallel", "access"},
}

// permissionsTool builds the plan in-process: it reads nothing and writes
// nothing, so the files come back inline for the person to save (or for
// them to write with the --write command the plan names).
func permissionsTool(_ context.Context, a map[string]any) (string, error) {
	r := onboard.Request{Platform: arg(a, "platform", ""), Access: arg(a, "access", "capture"), Account: arg(a, "account", ""),
		Principal: arg(a, "principal", ""), ExternalID: arg(a, "external_id", ""), Region: arg(a, "region", ""),
		SourceProfile: arg(a, "source_profile", ""), AdminProfile: arg(a, "admin_profile", ""), Subscription: arg(a, "subscription", ""),
		PrincipalID: arg(a, "principal_id", ""), PrincipalType: arg(a, "principal_type", ""), Location: arg(a, "location", ""),
		Project: arg(a, "project", ""), Member: arg(a, "member", ""), Context: arg(a, "context", ""), Subject: arg(a, "subject", "")}
	p, err := onboard.Build(r)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(p.Text())
	names := make([]string, 0, len(p.Files))
	for n := range p.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "\n----- %s -----\n%s", n, p.Files[n])
	}
	return b.String(), nil
}

// runTruthform runs this binary's capture or diff. Running it as a separate
// process keeps its progress lines off stdout, which is the protocol.
func runTruthform(ctx context.Context, cmd string, a map[string]any, need string) (string, error) {
	if arg(a, need, "") == "" {
		return "", fmt.Errorf("%s needs %s", cmd, need)
	}
	if r := arg(a, "region", ""); r != "" {
		if err := awscc.CheckRegion(r); err != nil {
			return "", err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	c := exec.CommandContext(ctx, self, mcpArgv(cmd, a)...)
	c.Stdout, c.Stderr = &out, &out
	runErr := c.Run()
	text := tail(out.String(), 200)
	code := 0
	var ee *exec.ExitError
	if errors.As(runErr, &ee) {
		code = ee.ExitCode()
	} else if runErr != nil {
		return "", runErr
	}
	// A Go panic also exits 2; only a diff that ran to its end means
	// "differences" by it.
	panicked := strings.Contains(text, "panic:") || strings.Contains(text, "goroutine ")
	switch {
	case code == 0:
		return text, nil
	case code == 2 && cmd == "diff" && !panicked:
		return text + "\n(exit 2: differences found)", nil
	case code == 3 && !panicked:
		return text + "\n(exit 3: incomplete; see above for what was not read)", nil
	}
	return "", fmt.Errorf("truthform %s failed (exit %d):\n%s", cmd, code, text)
}

// mcpArgv builds the command line for a tool: the fixed command, then only
// the known flags, each as one --name=value argument.
func mcpArgv(cmd string, a map[string]any) []string {
	argv := []string{cmd}
	for _, k := range mcpFlags[cmd] {
		if v := arg(a, k, ""); v != "" {
			argv = append(argv, "--"+k+"="+v)
		}
	}
	return argv
}

func tail(s string, lines int) string {
	ls := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(ls) > lines {
		ls = append([]string{fmt.Sprintf("... %d earlier lines omitted", len(ls)-lines)}, ls[len(ls)-lines:]...)
	}
	return strings.Join(ls, "\n")
}

func readReport(_ context.Context, a map[string]any) (string, error) {
	dir := arg(a, "from", "")
	if dir == "" {
		return "", errors.New("report needs from")
	}
	b, err := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	if err != nil {
		return "", fmt.Errorf("%s has no REPORT.md (capture writes one; for an older snapshot run: truthform report %s): %w", dir, dir, err)
	}
	return string(b), nil
}
