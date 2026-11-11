// Package onboard says what to grant Truthform on a platform and how, as
// files to deploy and commands to run, with the customer's own values
// filled in.
//
// It grants nothing itself. A grant is made by the customer's administrator
// with the platform's own tool, from a template that deploys in one step
// and is removed in one step, so the access is never applied by hand and
// never outlives its use unnoticed. An agent guiding someone through it
// (truthform mcp) gets the same plan.
//
// Every command it prints is complete: no placeholder to substitute. A
// placeholder pasted as is fails, and not always harmlessly: PowerShell
// reads <name> as a redirection (2026-10-23, granting the drill policy).
// So a value it needs and was not given is an error naming how to find it,
// and every value is checked against what the platform accepts, which also
// keeps each command safe to paste into PowerShell or a POSIX shell alike.
package onboard

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

//go:embed templates
var templates embed.FS

// Request is what the plan is for. Which fields apply depends on Platform.
type Request struct {
	Platform string // aws, azure, gcp, kubernetes, github, cloudflare
	Access   string // capture (read-only, the default) or restore

	// Dir is where the template files are, or will be, written; the
	// commands name them there. Default ".".
	Dir string
	// Written is true when the files are already in Dir (written by
	// --write), so the plan does not tell the reader to write them.
	Written bool

	// aws
	Account       string // aws: the account the role goes in; github: the organisation; cloudflare: the account ID
	Principal     string // the IAM user or role that runs Truthform
	ExternalID    string
	Region        string // where the CloudFormation stack lives (IAM is global)
	SourceProfile string // the shared-config profile of Principal, to set up a profile for the role
	AdminProfile  string // the profile the administrator deploys with

	// azure
	Subscription  string
	PrincipalID   string // object ID
	PrincipalType string // User, Group or ServicePrincipal
	Location      string // where the deployment stack's metadata lives

	// gcp
	Project string
	Member  string // user:..., serviceAccount:..., group:...

	// kubernetes
	Context string
	Subject string // User:name, Group:name or ServiceAccount:namespace/name

}

// Step is one thing to do. A step with no Command is done by a person (in
// a web page) and says where.
type Step struct {
	Title   string `json:"title"`
	Command string `json:"command,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Plan is the whole of one grant: what it gives, the files, the steps to
// grant and verify it, and the steps to remove it.
type Plan struct {
	Platform string            `json:"platform"`
	Access   string            `json:"access"`
	Grants   []string          `json:"grants"`
	Files    map[string][]byte `json:"-"`      // name in Dir -> content
	Before   []Step            `json:"before"` // look before granting
	Grant    []Step            `json:"grant"`
	Verify   []Step            `json:"verify"`
	Undo     []Step            `json:"undo"`
	Warnings []string          `json:"warnings"`
	Status   string            `json:"status"` // what has been run for real with exactly this grant
}

// Missing is a value a plan needs and was not given, with how to find it.
type Missing struct {
	Flag, What, HowToFind string
}

// MissingError lists every value missing at once, so the reader fixes them
// in one pass rather than one per run.
type MissingError []Missing

func (m MissingError) Error() string {
	var b strings.Builder
	b.WriteString("permissions needs these values (no command is printed with a placeholder in it):")
	for _, x := range m {
		fmt.Fprintf(&b, "\n  --%s: %s", x.Flag, x.What)
		if x.HowToFind != "" {
			fmt.Fprintf(&b, "\n      find it with: %s", x.HowToFind)
		}
	}
	return b.String()
}

var (
	accountRE    = regexp.MustCompile(`^[0-9]{12}$`)
	iamARNRE     = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}):(root|user/[\w+=,.@/-]+|role/[\w+=,.@/-]+)$`)
	sessionARNRE = regexp.MustCompile(`^arn:(aws[a-z-]*):sts::([0-9]{12}):assumed-role/([\w+=,.@-]+)/[\w+=,.@-]+$`)
	externalIDRE = regexp.MustCompile(`^[\w+=,.@:/-]+$`) // 2 to 1224 long, checked apart: Go's regexp repeats at most 1000
	regionRE     = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	profileRE    = regexp.MustCompile(`^[\w.-]{1,64}$`)
	guidRE       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	locationRE   = regexp.MustCompile(`^[a-z0-9]{2,40}$`)
	projectRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	memberRE     = regexp.MustCompile(`^(user|serviceAccount|group):[\w.+-]+@[\w.-]+$`)
	contextRE    = regexp.MustCompile(`^[\w.:/@+-]{1,253}$`)
	k8sNameRE    = regexp.MustCompile(`^[\w.:@+-]{1,253}$`)
	dnsLabelRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	orgRE        = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	cfAccountRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// A directory is named in the commands, quoted only when it holds a
	// space. Anything wider was injectable: az is a batch file on Windows,
	// and cmd.exe ran "whoami" from a directory named x&whoami; PowerShell
	// ends a single-quoted string at a typographic quote too (review of
	// #23).
	dirRE = regexp.MustCompile(`^[A-Za-z0-9 _./\\:-]+$`)
)

// Build makes the plan for a request.
func Build(r Request) (Plan, error) {
	if r.Access == "" {
		r.Access = "capture"
	}
	if r.Access != "capture" && r.Access != "restore" {
		return Plan{}, fmt.Errorf("--access is capture or restore, not %q", r.Access)
	}
	if r.Dir == "" {
		r.Dir = "."
	}
	// Terraform reads every .tf file in its directory: written into one
	// that holds other configuration, apply would plan that too.
	if r.Platform == "gcp" && r.Dir == "." {
		r.Dir = "truthform-gcp"
	}
	if !dirRE.MatchString(r.Dir) {
		return Plan{}, fmt.Errorf(`--write: %q holds a character that cannot be named safely in a command; use letters, digits, spaces and _ . / \ : -`, r.Dir)
	}
	var p Plan
	var err error
	switch r.Platform {
	case "aws":
		p, err = buildAWS(r)
	case "azure":
		p, err = buildAzure(r)
	case "gcp":
		p, err = buildGCP(r)
	case "kubernetes":
		p, err = buildKubernetes(r)
	case "github":
		p, err = buildGitHub(r)
	case "cloudflare":
		p, err = buildCloudflare(r)
	default:
		return Plan{}, fmt.Errorf("--platform is aws, azure, gcp, kubernetes, github or cloudflare, not %q", r.Platform)
	}
	if err != nil {
		return Plan{}, err
	}
	p.Platform, p.Access = r.Platform, r.Access
	if len(p.Files) > 0 && !r.Written {
		where := r.Dir
		if where == "." {
			where = "the current directory"
		}
		p.Before = append(p.Before, Step{
			Title:   "Write the template files into " + where,
			Command: cmd(append(rebuild(r), "--write", r.Dir)...),
			Note:    "Read them before deploying: they are what is granted.",
		})
	}
	return p, nil
}

// file is a template file's path as the commands name it.
func file(r Request, name string) string {
	if r.Dir == "." {
		return "./" + name
	}
	return filepath.ToSlash(filepath.Join(r.Dir, name))
}

// rebuild is the truthform permissions command line for r, so a step can
// say exactly how to write the files.
func rebuild(r Request) []string {
	a := []string{"truthform", "permissions", "--platform", r.Platform, "--access", r.Access}
	add := func(flag, v string) {
		if v != "" {
			a = append(a, "--"+flag, v)
		}
	}
	add("account", r.Account)
	add("principal", r.Principal)
	add("external-id", r.ExternalID)
	add("region", r.Region)
	add("source-profile", r.SourceProfile)
	add("admin-profile", r.AdminProfile)
	add("subscription", r.Subscription)
	add("principal-id", r.PrincipalID)
	add("principal-type", r.PrincipalType)
	add("location", r.Location)
	add("project", r.Project)
	add("member", r.Member)
	add("context", r.Context)
	add("subject", r.Subject)
	return a
}

// safeArg is what both PowerShell and a POSIX shell pass through as one
// literal argument, unquoted. Anything else is single-quoted, which both
// shells also take literally; values holding a single quote are refused
// before they get here. "." is not in it: PowerShell splits an unquoted
// argument that starts with "-" at its first ".". Nor is ",": unquoted,
// PowerShell makes a,b an array and passes it as two arguments.
var safeArg = regexp.MustCompile(`^[A-Za-z0-9_/:=+-]+$`)

func quote(s string) string {
	if safeArg.MatchString(s) {
		return s
	}
	return "'" + s + "'"
}

// cmd joins one command line from its arguments.
func cmd(args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = quote(a)
	}
	return strings.Join(q, " ")
}

func render(name string, data any) ([]byte, error) {
	b, err := templates.ReadFile("templates/" + name)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(name, ".tmpl") {
		return b, nil
	}
	q := func(s string) (string, error) {
		b, err := json.Marshal(s)
		return string(b), err
	}
	t, err := template.New(name).Option("missingkey=error").Funcs(template.FuncMap{"q": q}).Parse(string(b))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Text is the plan for a person, in the order to do it.
func (p Plan) Text() string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	w("Truthform %s access on %s\n\n", p.Access, p.Platform)
	if len(p.Warnings) > 0 {
		w("WARNINGS\n")
		for _, x := range p.Warnings {
			w("  - %s\n", x)
		}
		w("\n")
	}
	w("What is granted\n")
	for _, g := range p.Grants {
		w("  - %s\n", g)
	}
	w("  Status: %s\n\n", p.Status)
	n := 0
	section := func(title string, steps []Step) {
		if len(steps) == 0 {
			return
		}
		w("%s\n", title)
		for _, s := range steps {
			n++
			w("%2d. %s\n", n, s.Title)
			if s.Command != "" {
				w("      %s\n", s.Command)
			}
			if s.Note != "" {
				w("      %s\n", s.Note)
			}
		}
		w("\n")
	}
	section("Before granting", p.Before)
	section("Grant", p.Grant)
	section("Verify", p.Verify)
	n = 0
	section("To remove it again", p.Undo)
	w("Every command is complete and runs unchanged in PowerShell or a POSIX shell.\n")
	return b.String()
}

// Write puts the plan's files in dir, refusing to replace a file that is
// there with different content: it may be a customer's edited copy, or the
// file a deployed stack was made from.
func (p Plan) Write(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var wrote []string
	for _, name := range sortedKeys(p.Files) {
		path := filepath.Join(dir, name)
		if old, err := os.ReadFile(path); err == nil {
			if bytes.Equal(old, p.Files[name]) {
				wrote = append(wrote, path+" (unchanged)")
				continue
			}
			return wrote, fmt.Errorf("%s exists with different content; move it aside or write elsewhere", path)
		}
		if err := os.WriteFile(path, p.Files[name], 0o644); err != nil {
			return wrote, err
		}
		wrote = append(wrote, path)
	}
	return wrote, nil
}

func sortedKeys(m map[string][]byte) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
